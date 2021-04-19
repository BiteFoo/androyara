# coding:utf8
'''
@File    :   test_dex.py
@Author  :   Loopher 
@Version :   1.0
@License :   (C)Copyright 2020-2021,Loopher
@Desc    :   None
'''

import unittest
import os


from apkscanner.dex.dex_header import DexHeader

root =os.path.abspath(os.path.dirname(__file__))
sample = root[:root.rfind(os.sep)]
print("--> root ",root,sample)

class DexTest(unittest.TestCase):

    def test_dex(self):
        # hidex
        for dex in [sample+os.sep+"samples"+os.sep+"classes.dex"]:
            pass
            with open(dex, 'rb') as fp:
                dex_header = DexHeader(fp.read())
                pkg =  "com.tencent.qqpimsecure"#"com.loopher.virus" classes_1.dex
                dex_header.read_all(pkg)