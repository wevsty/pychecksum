#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import argparse
import hashlib
import codecs


def enum_paths(
        buffer_list: list,
        root_dir: str,
        *,
        include_file: bool = True,
        include_dir: bool = False,
        recursion: bool = True,
        **kwargs
) -> None:
    try:
        for sub_path in os.listdir(root_dir):
            sub_full_path = os.path.join(root_dir, sub_path)
            is_dir = os.path.isdir(sub_full_path)
            if is_dir is True:
                if include_dir is True:
                    buffer_list.append(sub_full_path)
                if recursion is True:
                    enum_paths(buffer_list,
                               sub_full_path,
                               include_file=include_file,
                               include_dir=include_dir,
                               recursion=recursion,
                               **kwargs)
            else:
                if include_file is True:
                    buffer_list.append(sub_full_path)
            pass
    except OSError as _err:
        pass
    return


def ensure_folder(dir_path):
    try:
        if os.path.exists(dir_path) is True:
            return
        os.makedirs(dir_path)
    except OSError:
        pass
    finally:
        pass


class CheckFile:

    def __init__(self):
        self.file_path = ''
        self.file_name = ''
        self.file_hash = ''

    def get_file_path(self) -> str:
        return self.file_path

    def get_file_name(self) -> str:
        return self.file_name

    def get_file_hash(self) -> str:
        return self.file_hash

    def set_file_path(self, file_path: str) -> None:
        if os.path.isabs(file_path) is True:
            self.file_path = file_path
            self.file_name = os.path.basename(file_path)
        else:
            self.file_path = file_path
            self.file_name = file_path

    def set_file_name(self, filename: str) -> None:
        self.file_name = filename

    def set_file_hash(self, file_hash: str) -> None:
        self.file_hash = file_hash.lower()

    def checksum(self) -> str:
        return '%s *%s' % (self.file_hash, self.file_name)

    def load_line(self, text_line: str) -> None:
        split_list = text_line.split(sep=' ', maxsplit=1)
        # split_list[0] is hash
        file_hash = split_list[0].strip()
        self.set_file_hash(file_hash)
        # split_list[1] is filename
        filename = split_list[1].strip().lstrip('*')
        self.set_file_path(filename)
        pass

    def create_line(self) -> str:
        return self.checksum() + '\n'

    @staticmethod
    def create_hash_algorithm_object(hash_algorithm_name: str = 'SHA1'):
        hash_algorithm_name = hash_algorithm_name.upper()
        if hash_algorithm_name == 'MD5':
            algorithm_class_obj = hashlib.md5()
        elif hash_algorithm_name == 'SHA1':
            algorithm_class_obj = hashlib.sha1()
        elif hash_algorithm_name == 'SHA224':
            algorithm_class_obj = hashlib.sha224()
        elif hash_algorithm_name == 'SHA256':
            algorithm_class_obj = hashlib.sha256()
        elif hash_algorithm_name == 'SHA384':
            algorithm_class_obj = hashlib.sha384()
        elif hash_algorithm_name == 'SHA512':
            algorithm_class_obj = hashlib.sha512()
        elif hash_algorithm_name == 'SHA3_256':
            algorithm_class_obj = hashlib.sha3_256()
        elif hash_algorithm_name == 'SHA3_512':
            algorithm_class_obj = hashlib.sha3_512()
        else:
            algorithm_class_obj = hashlib.md5()
        return algorithm_class_obj

    @staticmethod
    def calc_file_hash(hash_algorithm_name: str, file_path: str) -> str:
        BLOCK_SIZE = 1024 * 16
        algorithm_object = CheckFile.create_hash_algorithm_object(hash_algorithm_name)
        with open(file_path, "rb") as fp:
            while True:
                blocks = fp.read(BLOCK_SIZE)
                if len(blocks) != 0:
                    algorithm_object.update(blocks)
                else:
                    break
        hash_hex = algorithm_object.hexdigest().lower()
        return hash_hex


class CheckSumFile:

    @staticmethod
    def create_checksum_item(hash_algorithm_name: str, file_path: str) -> CheckFile:
        item = CheckFile()
        hash_hex = item.calc_file_hash(hash_algorithm_name, file_path)
        item.set_file_hash(hash_hex)
        item.set_file_path(file_path)
        return item

    @staticmethod
    def load_checksum_file(checksum_item_buffer: list, checksum_file_path: str) -> None:
        # lines = list()
        UTF8_BOM_LEN = len(codecs.BOM_UTF8)
        with open(checksum_file_path, "rb") as fp:
            raw_data = fp.read()
            # 如果存在BOM则跳过BOM
            if raw_data.startswith(codecs.BOM_UTF8):
                raw_data = raw_data[UTF8_BOM_LEN:]
            lines = raw_data.decode().splitlines(keepends=False)
        for line in lines:
            # 忽略开头为;的行
            if line.startswith(';') is True:
                continue
            # 忽略开头为#的行
            if line.startswith('#') is True:
                continue
            check_file_object = CheckFile()
            check_file_object.load_line(line.strip())
            checksum_item_buffer.append(check_file_object)
        pass

    @staticmethod
    def write_checksum_file(checksum_item_buffer: list, checksum_file_path: str) -> None:
        if len(checksum_item_buffer) == 0:
            return
        if len(checksum_file_path) == 0:
            return
        write_string = ''
        for item in checksum_item_buffer:
            write_string += item.create_line()
        with open(checksum_file_path, "wb") as fp:
            fp.write(codecs.BOM_UTF8)
            fp.write(write_string.encode())
        pass

    @staticmethod
    def is_checksum_file(file_path: str) -> bool:
        upper_file_path = file_path.upper()
        if upper_file_path.endswith('CHECKSUM') is True:
            return True
        elif upper_file_path.endswith('CHECKSUMS') is True:
            return True
        elif upper_file_path.endswith('.MD5') is True:
            return True
        elif upper_file_path.endswith('.SHA1') is True:
            return True
        elif upper_file_path.endswith('.SHA256') is True:
            return True
        elif upper_file_path.endswith('.SHA512') is True:
            return True
        elif upper_file_path.endswith('MD5SUMS') is True:
            return True
        elif upper_file_path.endswith('SHA1SUMS') is True:
            return True
        elif upper_file_path.endswith('SHA256SUMS') is True:
            return True
        elif upper_file_path.endswith('SHA512SUMS') is True:
            return True
        return False

    @staticmethod
    def expand_relative_path(base_path: str, filename: str):
        if os.path.isabs(filename) is True:
            return filename
        abs_path = os.path.join(base_path, filename)
        return abs_path

    @classmethod
    def display_path_checksum(
            cls,
            path: str,
            hash_algorithm_name: str = 'SHA1'
    ) -> None:
        if os.path.isfile(path):
            item_object = cls.create_checksum_item(hash_algorithm_name, path)
            print(item_object.checksum())
        pass

    @classmethod
    def display_dir_checksum(
            cls,
            dir_path: str,
            hash_algorithm_name: str = 'SHA1'
    ) -> None:
        file_path_list = list()
        enum_paths(
            file_path_list,
            dir_path,
            include_file=True,
            include_dir=False,
            recursion=False
        )
        for file_path in file_path_list:
            cls.display_path_checksum(file_path, hash_algorithm_name)
        pass

    @classmethod
    def verify_checksum_file(
            cls,
            checksum_file_path: str,
            hash_algorithm_name: str = 'SHA1'
    ) -> None:
        print('Verify CHECKSUM file: %s' % checksum_file_path)
        checksum_dir = os.path.dirname(checksum_file_path)
        checksum_item_list = list()
        cls.load_checksum_file(checksum_item_list, checksum_file_path)
        for item_object in checksum_item_list:
            file_name = item_object.get_file_name()
            file_path = item_object.get_file_path()
            hash_log = item_object.get_file_hash()
            if os.path.isabs(file_path) is True:
                full_path = file_path
            else:
                full_path = os.path.join(checksum_dir, file_path)
            if os.path.isfile(full_path) is False:
                print('MISSED : %s' % file_name)
                continue
            current_hash = CheckFile.calc_file_hash(hash_algorithm_name, full_path)
            if hash_log == current_hash:
                print('PASSED : %s' % file_name)
            else:
                print('ERROR  : %s' % file_name)
        print('Verify finish.')
        pass

    @classmethod
    def verify_checksum_file_for_dir(
            cls,
            dir_path: str,
            hash_algorithm_name: str = 'SHA1',
            checksum_file_name: str = 'CHECKSUM.SHA1',
            recursion=True
    ) -> None:
        dir_path_list = list()
        dir_path_list.append(dir_path)
        enum_paths(
            dir_path_list,
            dir_path,
            include_file=False,
            include_dir=True,
            recursion=recursion
        )
        for find_path in dir_path_list:
            checksum_file_path = cls.expand_relative_path(find_path, checksum_file_name)
            if os.path.exists(checksum_file_path) is True:
                if os.path.isfile(checksum_file_path) is True:
                    cls.verify_checksum_file(checksum_file_path, hash_algorithm_name)
                pass
            pass
        pass

    @classmethod
    def create_checksum_file_for_dir(
            cls,
            dir_path: str,
            hash_algorithm_name: str = 'SHA1',
            checksum_file_name: str = 'CHECKSUM.SHA1',
            recursion=False
    ) -> None:
        checksum_item_list = list()
        file_path_list = list()
        enum_paths(
            file_path_list,
            dir_path,
            include_file=True,
            include_dir=True,
            recursion=False
        )
        for path in file_path_list:
            # 跳过checksum文件
            if cls.is_checksum_file(path) is True:
                continue
            if os.path.isdir(path):
                if recursion is True:
                    cls.create_checksum_file_for_dir(path, hash_algorithm_name, checksum_file_name, recursion)
                else:
                    pass
            elif os.path.isfile(path):
                item_object = cls.create_checksum_item(hash_algorithm_name, path)
                checksum_item_list.append(item_object)
            else:
                pass
        checksum_file_path = cls.expand_relative_path(dir_path, checksum_file_name)
        if len(checksum_item_list) > 0:
            cls.write_checksum_file(checksum_item_list, checksum_file_path)
            print('Create CHECKSUM : %s' % checksum_file_path)
        pass

    @classmethod
    def select_file_from_dir(
            cls,
            src_dir_path: str,
            checksum_file_name: str = 'CHECKSUM.SHA1',
    ) -> None:
        src_base_path = os.path.abspath(src_dir_path)
        dst_base_path = os.path.join(src_base_path, 'selected')
        ensure_folder(dst_base_path)
        checksum_file_path = cls.expand_relative_path(src_base_path, checksum_file_name)
        checksum_item_list = list()
        cls.load_checksum_file(checksum_item_list, checksum_file_path)
        for item_object in checksum_item_list:
            file_name = item_object.get_file_name()
            file_path = item_object.get_file_path()
            # hash_log = item_object.get_file_hash()
            if os.path.isabs(file_path) is True:
                full_path = file_path
            else:
                full_path = os.path.join(src_base_path, file_path)
            if os.path.isfile(full_path) is False:
                print('File does not exist : %s' % file_name)
                continue
            new_file_path = os.path.join(dst_base_path, file_name)
            try:
                print('Select : %s' % file_name)
                os.rename(full_path, new_file_path)
            except OSError:
                print('Move failed : %s' % file_name)
            pass
        pass

    @classmethod
    def select_mismatch_from_dir(
            cls,
            src_dir_path: str,
            hash_algorithm_name: str = 'SHA1',
            checksum_file_name: str = 'CHECKSUM.SHA1',
    ) -> None:
        src_base_path = os.path.abspath(src_dir_path)
        dst_base_path = os.path.join(src_base_path, 'check_failed')
        ensure_folder(dst_base_path)
        checksum_file_path = cls.expand_relative_path(src_base_path, checksum_file_name)
        checksum_item_list = list()
        cls.load_checksum_file(checksum_item_list, checksum_file_path)
        for item_object in checksum_item_list:
            file_name = item_object.get_file_name()
            file_path = item_object.get_file_path()
            hash_log = item_object.get_file_hash()
            if os.path.isabs(file_path) is True:
                full_path = file_path
            else:
                full_path = os.path.join(src_base_path, file_path)
            if os.path.isfile(full_path) is False:
                print('File does not exist : %s' % file_name)
                continue
            current_hash = CheckFile.calc_file_hash(hash_algorithm_name, full_path)
            if current_hash == hash_log:
                continue
            new_file_path = os.path.join(dst_base_path, file_name)
            try:
                print('Select : %s' % file_name)
                os.rename(full_path, new_file_path)
            except OSError:
                print('Move failed : %s' % file_name)
            pass
        pass


def display_help():
    help_string = R'''
usage: pychecksum.py [optional] [paths ...]

positional arguments:
paths

optional arguments:
-h, --help                      Show this help message and exit
--create_checksum_for_dir       Create checksum for folders
--verify_checksum_for_dir       Verify checksum for folders
--verify_checksum_file          Verify checksum files
--select_file_from_dir          Select checksum files
--select_mismatch_from_dir      Select mismatch files
--recursion                     Recursive folder(default: True)
--algorithm                     Hash algorithm(default: SHA1)
--filename                      Checksum file name(default: CHECKSUM.SHA1)

example:
pychecksum.py --create_checksum_for_dir D:\test_data
pychecksum.py --create_checksum_for_dir --recursion=false D:\test_data
pychecksum.py --verify_checksum_for_dir D:\test_data
pychecksum.py --verify_checksum D:\test_data\CHECKSUM.SHA1
pychecksum.py --select_file_from_dir D:\test_data
pychecksum.py --select_mismatch_from_dir D:\test_data
    '''
    print(help_string)
    exit(0)


def main() -> None:
    parser = argparse.ArgumentParser(add_help=False)

    parser.add_argument("paths", type=str, nargs='*')
    parser.add_argument('--create_checksum_for_dir', default=False, action='store_true')
    parser.add_argument('--verify_checksum_for_dir', default=False, action='store_true')
    parser.add_argument('--verify_checksum', default=False, action='store_true')
    parser.add_argument('--select_file_from_dir', default=False, action='store_true')
    parser.add_argument('--select_mismatch_from_dir', default=False, action='store_true')
    parser.add_argument('--recursion', type=bool, default=True)
    parser.add_argument("--algorithm", type=str, default='SHA1')
    parser.add_argument("--filename", type=str, default='CHECKSUM.SHA1')
    parser.add_argument('-h', '--help', action='store_true')
    args = parser.parse_args()

    if args.help:
        display_help()

    if args.paths:
        if args.create_checksum_for_dir is True:
            for path in args.paths:
                if os.path.isdir(path) is True:
                    CheckSumFile.create_checksum_file_for_dir(path, args.algorithm, args.filename, args.recursion)
                else:
                    print('Invalid folder path : %s' % path)
        elif args.verify_checksum_for_dir is True:
            for path in args.paths:
                if os.path.isdir(path) is True:
                    CheckSumFile.verify_checksum_file_for_dir(path, args.algorithm, args.filename, args.recursion)
                else:
                    print('Invalid folder path : %s' % path)
        elif args.verify_checksum is True:
            for path in args.paths:
                if os.path.isfile(path) is True:
                    CheckSumFile.verify_checksum_file(path, args.algorithm)
                else:
                    print('Invalid file path : %s' % path)
        elif args.select_file_from_dir is True:
            for path in args.paths:
                if os.path.isdir(path) is True:
                    CheckSumFile.select_file_from_dir(path, args.filename)
                else:
                    print('Invalid folder path : %s' % path)
        elif args.select_mismatch_from_dir is True:
            for path in args.paths:
                if os.path.isdir(path) is True:
                    CheckSumFile.select_mismatch_from_dir(path, args.algorithm, args.filename)
                else:
                    print('Invalid folder path : %s' % path)
        else:
            for path in args.paths:
                if os.path.isfile(path) is True:
                    CheckSumFile.display_path_checksum(path, args.algorithm)
                elif os.path.isdir(path) is True:
                    CheckSumFile.display_dir_checksum(path, args.algorithm)
                else:
                    pass
        pass


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("User exit.")
    exit(0)
