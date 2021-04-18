# -*- encoding: utf-8 -*-
'''
@File    :   test_apk.py
@Time    :   2021/04/18 12:22:26
@Author  :   Loopher 
@Version :   1.0
@Contact :   2426607795@qq.com
@License :   (C)Copyright 2020-2021, Loopher
@Desc    :   None
'''

# Here put the import lib

import unittest

from apkscanner.core.apk_parser import ApkPaser

class ApkTester(unittest.TestCase):

    def test_apk(self):
        for f in ["F:\\CodeDocuments\pythonCode\\appsamples\\normal\\apk_avl_pro_unsign_sign_signed.apk"]:
            apk = ApkPaser(f)


