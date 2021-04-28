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
        ins_ = ' '
        instrus = self.dex_header.read_code_instrs(offset)
        print("")
        #  red, green, yellow, blue, magenta, cyan, white.
        echo("info", "codeoff:%s codesize:%s" %
             (hex(instrus[0]), hex(instrus[1])), "magenta")
        print("")

        # 格式化输出
        print(""+" 0 "+" "+""+" 1 "+" "+" 2 "+" "+""+" 3 "
              + "  "+" 4 "+" "+""+" 5 "+" "+" 6 "+" "+""+" 7 "
              + "  "+" 8 "+" "+""+" 9 "+" "+" A "+" "+""+" B "
              + "  "+" C "+" "+""+" D "+" "+" E "+" "+""+" F ")

        print("-"*16 + " "+"-"*16+" "+"-"*16+" "+"-"*16)
        save = []
        for i, ins in enumerate(instrus[2:]):
            if i > 0 and i % 16 == 0:
                print("%s" % (ins_))
                print("")
                ins_ = ""

            if i > 0 and i % 4 == 0:
                ins_ += " "
            ins_ += "%.2x " % (ins)+" "
            save.append("%.2x " % (ins))
        print(ins_)
        # print("")
        echo("info", "all instructions ", )
        echo("warning", "\n"+" ".join(save), 'yellow')

    def all_strings(self, pattern_list: list):
        """
        return all dex strings
        """
        # echo("warning", "pattern list : %s" % (pattern_list), 'yellow')
        strings = []
        reobjs_exprs = []
        for pattern in pattern_list:
            if pattern is None:
                continue
            if "," in pattern:
                for p in pattern.split(','):
                    expr = re.compile(p)
                    reobjs_exprs.append(expr)
            elif pattern is not None and pattern != '':
                reobjs_exprs.append(re.compile(pattern))
                # echo("info", "pattern: %s" % (pattern), 'yellow')

        for _, v in self.dex_header.string_table_map.items():
            try:
                if isinstance(v, bytes):
                    v = str(v, encoding="utf-8")
                # echo("warning", "string: {}".format(v), 'yellow')
            except UnicodeDecodeError:
                continue

            if len(reobjs_exprs) == 0:
                # all string
                strings.append(v)
                continue

            for expr in reobjs_exprs:
                if expr.search(v):
                    # echo("debug", "v: %s" % (v), 'white')
                    strings.append(v)

        return strings
