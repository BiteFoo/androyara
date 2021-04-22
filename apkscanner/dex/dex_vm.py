# coding:utf8
'''
@File    :   dex_vm.py
@Author  :   Loopher 
@Version :   1.0
@License :   (C)Copyright 2020-2021,Loopher
@Desc    :   DexFile VM
'''


from apkscanner.utils.buffer import BuffHandle
from apkscanner.dex.dex_header import DexHeader


class DexFileVM(BuffHandle):

    def __init__(self, pkgname, buff):
        super(DexFileVM, self).__init__(buff)

        self.raw = buff

        #
        self.dex_header = DexHeader(buff)
        self.dex_header.read_all(pkgname)  # read all pkg class

    def build_map(self):
        """
        Build a search map for every class
        class contains class_name_idx, method_proto_idx,code_ins:[offset,size]
        """
        # for class_def in self.dex_header.class_defs:

        #     print("--> ", class_def)

        print("--"*10)
        for k, v in self.dex_header.string_table_map.items():
            try:
                if isinstance(v, bytes):
                    v = str(v, encoding="utf-8")
            except UnicodeDecodeError:
                continue
            if "://" in v:
                # check content:// or http(s)://
                print(k, v)

    def all_strings(self):
        """
        return all dex strings
        """
        strings = ""
        for _, v in self.dex_header.string_table_map.items():
            try:
                if isinstance(v, bytes):
                    v = str(v, encoding="utf-8")
            except UnicodeDecodeError:
                continue
            strings += v+"\n"
            # if "://" in v:
            #     print(k, v)
        return strings
