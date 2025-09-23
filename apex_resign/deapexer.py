#!/usr/bin/env python
#
# Copyright (C) 2019 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""deapexer is a tool that prints out content of an APEX.

To print content of an APEX to stdout:
  deapexer list foo.apex

To extract content of an APEX to the given directory:
  deapexer extract foo.apex dest
"""
from __future__ import print_function

import argparse
import apex_manifest
import enum
import os
import re
import shutil
import sys
import subprocess
import tempfile
import zipfile

BLOCK_SIZE = 4096

# See apexd/apex_file.cpp#RetrieveFsType
FS_TYPES = [
    ('f2fs', 1024, b'\x10\x20\xf5\xf2'),
    ('ext4', 1024 + 0x38, b'\123\357'),
    ('erofs', 1024, b'\xe2\xe1\xf5\xe0'),
]


def RetrieveFileSystemType(file):
  """Returns filesystem type with magic"""
  with open(file, 'rb') as f:
    for fs_type, offset, magic in FS_TYPES:
      buf = bytearray(len(magic))
      f.seek(offset, os.SEEK_SET)
      f.readinto(buf)
      if buf == magic:
        return fs_type
  raise ValueError('Failed to retrieve filesystem type')

class ApexImageEntry(object):
  """Represents an entry in APEX payload"""
  def __init__(self, name, *, base_dir, permissions, size, ino, extents,
               is_directory, is_symlink, security_context):
    self._name = name
    self._base_dir = base_dir
    self._permissions = permissions
    self._size = size
    self._is_directory = is_directory
    self._is_symlink = is_symlink
    self._ino = ino
    self._extents = extents
    self._security_context = security_context
    self._entries = []

  @property
  def name(self):
    return self._name

  @property
  def root(self):
    return self._base_dir == './' and self._name == '.'

  @property
  def full_path(self):
    if self.root:
      return self._base_dir  # './'
    path = os.path.join(self._base_dir, self._name)
    if self.is_directory:
      path += '/'
    return path

  @property
  def is_directory(self):
    return self._is_directory

  @property
  def is_symlink(self):
    return self._is_symlink

  @property
  def is_regular_file(self):
    return not self.is_directory and not self.is_symlink

  @property
  def permissions(self):
    return self._permissions

  @property
  def size(self):
    return self._size

  @property
  def ino(self):
    return self._ino

  @property
  def entries(self):
    return self._entries

  @property
  def extents(self):
    return self._extents

  @property
  def security_context(self):
    return self._security_context

  def __str__(self):
    ret = ''
    if self._is_directory:
      ret += 'd'
    elif self._is_symlink:
      ret += 'l'
    else:
      ret += '-'

    def MaskAsString(m):
      ret = 'r' if m & 4 == 4 else '-'
      ret += 'w' if m & 2 == 2 else '-'
      ret += 'x' if m & 1 == 1 else '-'
      return ret

    ret += MaskAsString(self._permissions >> 6)
    ret += MaskAsString((self._permissions >> 3) & 7)
    ret += MaskAsString(self._permissions & 7)

    return ret + ' ' + self._size + ' ' + self._name


class Apex(object):
  """Represents an APEX file"""
  def __init__(self, args):
    self._debugfs = args.debugfs_path
    self._fsckerofs = args.fsckerofs_path
    self._apex = args.apex
    self._tempdir = tempfile.mkdtemp()
    with zipfile.ZipFile(self._apex, 'r') as zip_ref:
      self._payload = zip_ref.extract('apex_payload.img', path=self._tempdir)
    self._payload_fs_type = RetrieveFileSystemType(self._payload)

  def __del__(self):
    shutil.rmtree(self._tempdir)

  def __enter__(self):
    return self

  def __exit__(self, ex_type, value, traceback):
    pass

  def list(self):
    if self._payload_fs_type not in ['ext4']:
      sys.exit(f'{self._payload_fs_type} is not supported for `list`.')

    yield from self.entries()

  def read_dir(self, path) -> ApexImageEntry:
    assert path.endswith('/')
    assert self.payload_fs_type == 'ext4'

    res = subprocess.check_output([self._debugfs, '-R', f'ls -l -p {path}', self._payload],
                                  text=True, stderr=subprocess.DEVNULL)
    dir_entry = None
    entries = []
    for line in res.split('\n'):
      if not line:
        continue
      parts = line.split('/')
      if len(parts) != 8:
        continue
      name = parts[5]
      if not name:
        continue
      if name == '..':
        continue
      if name == 'lost+found' and path == './':
        continue
      ino = parts[1]
      bits = parts[2]
      size = parts[6]
      extents = []
      is_symlink = bits[1]=='2'
      is_directory=bits[1]=='4'

      if not is_symlink and not is_directory:
        stdout = subprocess.check_output([self._debugfs, '-R', f'dump_extents <{ino}>',
                                          self._payload], text=True, stderr=subprocess.DEVNULL)
        # Output of dump_extents for an inode fragmented in 3 blocks (length and addresses represent
        # block-sized sections):
        # Level Entries       Logical      Physical Length Flags
        # 0/ 0   1/  3     0 -     0    18 -    18      1
        # 0/ 0   2/  3     1 -    15    20 -    34     15
        # 0/ 0   3/  3    16 -  1863    37 -  1884   1848
        res = stdout.splitlines()
        res.pop(0) # the first line contains only columns names
        left_length = int(size)
        try: # dump_extents sometimes has an unexpected output
          for line in res:
            tokens = line.split()
            offset = int(tokens[7]) * BLOCK_SIZE
            length = min(int(tokens[-1]) * BLOCK_SIZE, left_length)
            left_length -= length
            extents.append((offset, length))
          if left_length != 0: # dump_extents sometimes fails to display "hole" blocks
            raise ValueError
        except: # pylint: disable=bare-except
          extents = [] # [] means that we failed to retrieve the file location successfully

      # get 'security.selinux' attribute
      entry_path = os.path.join(path, name)
      stdout = subprocess.check_output([
        self._debugfs,
        '-R',
        f'ea_get -V {entry_path} security.selinux',
        self._payload
      ], text=True, stderr=subprocess.DEVNULL)
      security_context = stdout.rstrip('\n\x00')

      entry = ApexImageEntry(name,
                             base_dir=path,
                             permissions=int(bits[3:], 8),
                             size=size,
                             is_directory=is_directory,
                             is_symlink=is_symlink,
                             ino=ino,
                             extents=extents,
                             security_context=security_context)
      if name == '.':
        dir_entry = entry
      elif is_directory:
        sub_dir_entry = self.read_dir(path + name + '/')
        # sub_dir_entry should be the same inode
        assert entry.ino == sub_dir_entry.ino
        entry.entries.extend(sub_dir_entry.entries)
        entries.append(entry)
      else:
        entries.append(entry)

    assert dir_entry
    dir_entry.entries.extend(sorted(entries, key=lambda e: e.name))
    return dir_entry

  def extract(self, dest):
    """Recursively dumps contents of the payload with retaining mode bits, but not owner/group"""
    if self._payload_fs_type == 'erofs':
      subprocess.run([self._fsckerofs, f'--extract={dest}', '--overwrite',
                     '--no-preserve-owner', self._payload], stdout=subprocess.DEVNULL, check=True)
    elif self._payload_fs_type == 'ext4':
      # Extract entries one by one using `dump` because `rdump` doesn't support
      # "no-perserve" mode
      for entry in self.entries():
        self.write_entry(entry, dest)
    else:
      # TODO(b/279688635) f2fs is not supported yet.
      sys.exit(f'{self._payload_fs_type} is not supported for `extract`.')

  @property
  def payload_fs_type(self) -> str:
    return self._payload_fs_type

  def entries(self):
    """Generator to visit all entries in the payload starting from root(./)"""

    def TopDown(entry):
      yield entry
      for child in entry.entries:
        yield from TopDown(child)

    root = self.read_dir('./')
    yield from TopDown(root)

  def read_symlink(self, entry):
    assert entry.is_symlink
    assert self.payload_fs_type == 'ext4'

    stdout = subprocess.check_output([self._debugfs, '-R', f'stat {entry.full_path}',
                                      self._payload], text=True, stderr=subprocess.DEVNULL)
    # Output of stat for a symlink should have the following line:
    #   Fast link dest: \"%.*s\"
    m = re.search(r'\bFast link dest: \"(.+)\"\n', stdout)
    if m:
      return m.group(1)

    # if above match fails, it means it's a slow link. Use cat.
    output = subprocess.check_output([self._debugfs, '-R', f'cat {entry.full_path}',
                                      self._payload], text=True, stderr=subprocess.DEVNULL)

    if not output:
      sys.exit('failed to read symlink target')
    return output

  def write_entry(self, entry, out_dir):
    dest = os.path.normpath(os.path.join(out_dir, entry.full_path))
    if entry.is_directory:
      if not os.path.exists(dest):
        os.makedirs(dest, mode=0o755)
    elif entry.is_symlink:
      os.symlink(self.read_symlink(entry), dest)
    else:
      subprocess.check_output([self._debugfs, '-R', f'dump {entry.full_path} {dest}',
        self._payload], text=True, stderr=subprocess.DEVNULL)
      # retain mode bits
      os.chmod(dest, entry.permissions)


def RunList(args):
  if GetType(args.apex) == ApexType.COMPRESSED:
    with tempfile.TemporaryDirectory() as temp:
      decompressed_apex = os.path.join(temp, 'temp.apex')
      Decompress(args.apex, decompressed_apex)
      args.apex = decompressed_apex

      RunList(args)
      return

  with Apex(args) as apex:
    for e in apex.list():
      # dot(., ..) directories
      if not e.root and e.name in ('.', '..'):
        continue
      res = ''
      if args.size:
        res += e.size + ' '
      res += e.full_path
      if args.extents:
        res += ' [' + '-'.join(str(x) for x in e.extents) + ']'
      if args.contexts:
        res += ' ' + e.security_context
      print(res)


def RunExtract(args):
  if GetType(args.apex) == ApexType.COMPRESSED:
    with tempfile.TemporaryDirectory() as temp:
      decompressed_apex = os.path.join(temp, 'temp.apex')
      Decompress(args.apex, decompressed_apex)
      args.apex = decompressed_apex

      RunExtract(args)
      return

  with Apex(args) as apex:
    if not os.path.exists(args.dest):
      os.makedirs(args.dest, mode=0o755)
    apex.extract(args.dest)
    if os.path.isdir(os.path.join(args.dest, 'lost+found')):
      shutil.rmtree(os.path.join(args.dest, 'lost+found'))

class ApexType(enum.Enum):
  INVALID = 0
  UNCOMPRESSED = 1
  COMPRESSED = 2


def GetType(apex_path):
  with zipfile.ZipFile(apex_path, 'r') as zip_file:
    names = zip_file.namelist()
    has_payload = 'apex_payload.img' in names
    has_original_apex = 'original_apex' in names
    if has_payload and has_original_apex:
      return ApexType.INVALID
    if has_payload:
      return ApexType.UNCOMPRESSED
    if has_original_apex:
      return ApexType.COMPRESSED
    return ApexType.INVALID


def RunInfo(args):
  if args.print_type:
    res = GetType(args.apex)
    if res == ApexType.INVALID:
      print(args.apex + ' is not a valid apex')
      sys.exit(1)
    print(res.name)
  elif args.print_payload_type:
    print(Apex(args).payload_fs_type)
  else:
    manifest = apex_manifest.fromApex(args.apex)
    print(apex_manifest.toJsonString(manifest))


def RunDecompress(args):
  """RunDecompress takes path to compressed APEX and decompresses it to
  produce the original uncompressed APEX at give output path

  See apex_compression_tool.py#RunCompress for details on compressed APEX
  structure.

  Args:
      args.input: file path to compressed APEX
      args.output: file path to where decompressed APEX will be placed
  """
  if GetType(args.input) == ApexType.UNCOMPRESSED and args.copy_if_uncompressed:
    shutil.copyfile(args.input, args.output)
    return

  compressed_apex_fp = args.input
  decompressed_apex_fp = args.output
  return Decompress(compressed_apex_fp, decompressed_apex_fp)


def Decompress(compressed_apex_fp, decompressed_apex_fp):
  if os.path.exists(decompressed_apex_fp):
    print("Output path '" + decompressed_apex_fp + "' already exists")
    sys.exit(1)

  with zipfile.ZipFile(compressed_apex_fp, 'r') as zip_obj:
    if 'original_apex' not in zip_obj.namelist():
      print(compressed_apex_fp + ' is not a compressed APEX. Missing '
                                 "'original_apex' file inside it.")
      sys.exit(1)
    # Rename original_apex file to what user provided as output filename
    original_apex_info = zip_obj.getinfo('original_apex')
    original_apex_info.filename = os.path.basename(decompressed_apex_fp)
    # Extract the original_apex as desired name
    zip_obj.extract(original_apex_info,
                    path=os.path.dirname(decompressed_apex_fp))


def main(argv):
  parser = argparse.ArgumentParser()

  debugfs_default = None
  fsckerofs_default = None
  if 'ANDROID_HOST_OUT' in os.environ:
    debugfs_default = os.path.join(os.environ['ANDROID_HOST_OUT'], 'bin/debugfs_static')
    fsckerofs_default = os.path.join(os.environ['ANDROID_HOST_OUT'], 'bin/fsck.erofs')
  parser.add_argument(
      '--debugfs_path', help='The path to debugfs binary', default=debugfs_default)
  parser.add_argument(
      '--fsckerofs_path', help='The path to fsck.erofs binary', default=fsckerofs_default)
  # TODO(b/279858383) remove the argument
  parser.add_argument('--blkid_path', help='NOT USED')

  subparsers = parser.add_subparsers(required=True, dest='cmd')

  parser_list = subparsers.add_parser(
      'list', help='prints content of an APEX to stdout')
  parser_list.add_argument('apex', type=str, help='APEX file')
  parser_list.add_argument(
      '--size', help='also show the size of the files', action='store_true')
  parser_list.add_argument(
      '--extents', help='also show the location of the files', action='store_true')
  parser_list.add_argument('-Z', '--contexts',
                           help='also show the security context of the files',
                           action='store_true')
  parser_list.set_defaults(func=RunList)

  parser_extract = subparsers.add_parser('extract', help='extracts content of an APEX to the given '
                                                         'directory')
  parser_extract.add_argument('apex', type=str, help='APEX file')
  parser_extract.add_argument('dest', type=str, help='Directory to extract content of APEX to')
  parser_extract.set_defaults(func=RunExtract)

  parser_info = subparsers.add_parser('info', help='prints APEX manifest')
  parser_info.add_argument('apex', type=str, help='APEX file')
  parser_info.add_argument('--print-type',
                           help='Prints type of the apex (COMPRESSED or UNCOMPRESSED)',
                           action='store_true')
  parser_info.add_argument('--print-payload-type',
                           help='Prints filesystem type of the apex payload',
                           action='store_true')
  parser_info.set_defaults(func=RunInfo)

  # Handle sub-command "decompress"
  parser_decompress = subparsers.add_parser('decompress',
                                            help='decompresses a compressed '
                                                 'APEX')
  parser_decompress.add_argument('--input', type=str, required=True,
                                 help='path to compressed APEX file that '
                                      'will be decompressed')
  parser_decompress.add_argument('--output', type=str, required=True,
                                 help='path to the output APEX file')
  parser_decompress.add_argument('--copy-if-uncompressed',
                                 help='just copy the input if not compressed',
                                 action='store_true')
  parser_decompress.set_defaults(func=RunDecompress)

  args = parser.parse_args(argv)

  debugfs_required_for_cmd = ['list', 'extract']
  if args.cmd in debugfs_required_for_cmd and not args.debugfs_path:
    print('ANDROID_HOST_OUT environment variable is not defined, --debugfs_path must be set',
          file=sys.stderr)
    sys.exit(1)

  if args.cmd == 'extract':
    if not args.fsckerofs_path:
      print('ANDROID_HOST_OUT environment variable is not defined, --fsckerofs_path must be set',
            file=sys.stderr)
      sys.exit(1)

    if not os.path.isfile(args.fsckerofs_path):
      print(f'Cannot find fsck.erofs specified at {args.fsckerofs_path}',
            file=sys.stderr)
      sys.exit(1)

  args.func(args)


if __name__ == '__main__':
  main(sys.argv[1:])
