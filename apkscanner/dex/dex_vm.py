# coding:utf8
'''
@File    :   dex_vm.py
@Author  :   Loopher 
@Version :   1.0
@License :   (C)Copyright 2020-2021,Loopher
@Desc    :   DexFile VM
'''


from apkscanner.utils.buffer import BuffHandle


class DexFileVM(BuffHandle):

    def __init__(self, buff):
        super(DexFileVM, self).__init__(buff)
