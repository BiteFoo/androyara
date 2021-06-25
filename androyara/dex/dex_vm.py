# coding:utf8
'''
@File    :   dex_vm.py
@Author  :   Loopher 
@Version :   1.0
@License :   (C)Copyright 2020-2021,Loopher
@Desc    :   DexFile VM
'''

from androguard.core.bytecodes import dvm
import re
from androyara.utils.buffer import BuffHandle
from androyara.dex.dex_header import DexHeader
from androyara.utils.utility import byte2str, echo


class DexFileVM(BuffHandle):

    def __init__(self, pkgname, buff):
        super(DexFileVM, self).__init__(buff)

        self.raw = buff
        # need check apk
        self.dex_header = DexHeader(buff)
        self._ok = self.dex_header.is_dex()
        if not self._ok:
            # echo("error", "is not dex file format", 'red')
            return
        self.dex_header.read_all(pkgname)  # read all pkg class

    def ok(self):
        return self._ok

    def all_class_defs(self):
        """
        Return all class in classes\d.dex 
        default will return classes.dex 
        """

        return self.dex_header.class_defs

    def analysis_dex(self, clazz_name, method_name, show_ins=False):
        """
        Analyzer dex .This function mainly is  use to show dex class_defs

        eg.
        if clazz_name or method_name is None or empty, default show all 
        class->method
        else if method_name is not none ,show the matched method info ,include 

        class_name->method 
        method_instructions

        else if class_name and method are not none or empty ,this means to specific class_def's method info 

        """
        if clazz_name is None:
            # class_name = "com.demo.Test"
            clazz_name = ''
        if method_name is None:
            method_name = ''

        marker = '.java -> '
        query = clazz_name + marker + method_name

        for class_def in self.all_class_defs():
            clzz_name = byte2str(class_def['class_name'])

            clzz_name = clzz_name.replace(
                "L", '').replace("/", '.').replace(";", '')

            for method_ in class_def['code_item']:
                _method_name = byte2str(method_['method_name'])
                signature = byte2str(method_['signature'])

                _x = clzz_name+marker+_method_name+signature

                if clazz_name != marker and method_name != '' and query == _x:
                    # show class.method(signature)
                    print("**"*20)
                    echo("className", " %s" % (clzz_name), "blue")
                    echo("methodName", " %s" % (_method_name), "blue")
                    echo("signature", " %s" % (signature), "blue")
                    self.print_ins(method_['code_off'], show=show_ins)

                elif method_name == '':
                    echo("info", "-> %s" %
                         (_x), "blue")

                elif method_name == _method_name:
                    print("**"*20)
                    echo("className", "%s" % (clzz_name), "blue")
                    echo("methodName", "%s" % (_method_name), "blue")
                    echo("signature", " %s" % (signature), "blue")
                    self.print_ins(method_['code_off'], show=show_ins)

    def print_ins(self, offset, show=True):
        ins_ = ' '
        instrus = self.dex_header.read_code_instrs(offset)

        if show:

            echo("instructions", "--"*20, 'yellow')
            #  red, green, yellow, blue, magenta, cyan, white.
            echo("codeoff", " %s" %
                 (hex(instrus[0])), "yellow")
            echo("codesize", " %s" %
                 (hex(instrus[1])), "yellow")
            print("")

            # 格式化输出
            print(" "+" 0 "+" "+""+" 1 "+" "+" 2 "+" "+""+" 3 "
                  + "  "+" 4 "+" "+""+" 5 "+" "+" 6 "+" "+""+" 7 "
                  + "  "+" 8 "+" "+""+" 9 "+" "+" A "+" "+""+" B "
                  + "  "+" C "+" "+""+" D "+" "+" E "+" "+""+" F ")

            print("-"*16 + " "+"-"*16+" "+"-"*16+" "+"-"*16)
        save = []
        for i, ins in enumerate(instrus[2:]):
            if show:
                if i > 0 and i % 16 == 0:
                    print("%s" % (ins_))
                    print("")
                    ins_ = ""
                if i > 0 and i % 4 == 0:
                    ins_ += " "
                ins_ += "%.2x " % (ins)+" "
            save.append("%.2x " % (ins))
        if show:
            print(ins_)
            # print("")
            # echo("info", "all instructions ", )
            echo("shellcode", "\n"+" ".join(save), 'yellow')
        return " ".join(save)

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

        # 2021-06-24  fixme : Using androguard to parse strings instead myself
        d = dvm.DalvikVMFormat(self.raw)
        # for _, v in self.dex_header.string_table_map.items():
        for v in d.get_strings():
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
