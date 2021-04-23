# coding:utf8
'''
@File    :   dex_vm.py
@Author  :   Loopher 
@Version :   1.0
@License :   (C)Copyright 2020-2021,Loopher
@Desc    :   DexFile VM
'''

from os import pardir
import re
from androyara.utils.buffer import BuffHandle
from androyara.dex.dex_header import DexHeader
from androyara.utils.utility import echo


class DexFileVM(BuffHandle):

    def __init__(self, pkgname, buff):
        super(DexFileVM, self).__init__(buff)

        self.raw = buff
        # need check apk
        self.dex_header = DexHeader(buff)
        self._ok = self.dex_header.is_dex()
        if not self._ok:
            echo("error", "is not dex file format", 'red')
            return
        self.dex_header.read_all(pkgname)  # read all pkg class

    def ok(self):
        return self._ok

    def all_class_defs(self):
        #
        # for class_def in self.dex_header.class_defs:

        #     print("--> ", class_def)
        #     print("")
        return self.dex_header.class_defs

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

    def print_ins(self, offset):
        for i, ins in enumerate(self.dex_header.read_code_item(offset)):
            print(i, "%s" % (hex(ins)))

    def all_strings(self, pattern_list: list):
        """
        return all dex strings
        """
        strings = []
        reobjs_exprs = []
        for pattern in pattern_list:
            if "," in pattern:
                for p in pattern.split(','):
                    expr = re.compile(p, re.IGNORECASE)
                    reobjs_exprs.append(expr)
            elif pattern is not None and pattern != '':
                reobjs_exprs.append(re.compile(pattern))

        for _, v in self.dex_header.string_table_map.items():
            try:
                if isinstance(v, bytes):
                    v = str(v, encoding="utf-8")
            except UnicodeDecodeError:
                continue

            if len(reobjs_exprs) == 0:
                # all string
                strings.append(v)
                continue

            for expr in reobjs_exprs:
                if expr.search(v):
                    strings.append(v)

        return strings
