# coding:utf8
'''
@File    :   test_dex.py
@Author  :   Loopher 
@Version :   1.0
@License :   (C)Copyright 2020-2021,Loopher
@Desc    :   None
'''

import unittest

from apkscanner.dex.dex_header import DexHeader


class DexTes(unittest.TestCase):

    def test_dex(self):
        # hidex
        for dex in ["D:\\app_virus\\app\\release\\classes.dex"]:
            pass
            with open(dex, 'rb') as fp:
                dex_header = DexHeader(fp.read())
                pkg = "com.loopher.virus"
                dex_header.read_all(pkg)