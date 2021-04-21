# coding:utf8
'''
@File    :   dex_parser.py
@Author  :   Loopher 
@Version :   1.0
@License :   (C)Copyright 2020-2021,Loopher
@Desc    :   Dex文件解析
'''
"""
每一个dex都会经过这里的解析处理，目的是建立一个映射表能快速索引和比较
"""


from apkscanner.dex.dex_vm import DexFileVM
class DexParser(object):

    parser_info = {
        "name": "DexParser",
        "desc": "Parsing Dex file into bytecode"
    }

    def __init__(self, pkg, buff):


        self.vm = DexFileVM(pkg,buff)

        self.vm.build_map()
