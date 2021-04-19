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
import os

from apkscanner.core.apk_parser import ApkPaser
from apkscanner.dex.dex_header import DexHeader

root =os.path.abspath(os.path.dirname(__file__))
sample = root[:root.rfind(os.sep)]
class ApkTester(unittest.TestCase):

    def test_apk(self):
        for f in [sample+os.sep+"samples"+os.sep+"app-release.apk"]:
            apk = ApkPaser(f)


