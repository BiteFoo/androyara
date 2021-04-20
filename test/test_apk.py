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
import json

from apkscanner.core.apk_parser import ApkPaser
from apkscanner.dex.dex_header import DexHeader

root =os.path.abspath(os.path.dirname(__file__))
sample = root[:root.rfind(os.sep)]
class ApkTester(unittest.TestCase):

    def test_apk(self):
        # app-release-v3-signed.apk : v1+v2+v3 signed app-release.apk v1+v2 signed
        # tencent apk aaa.apk v1+v2 signature
        # check signature command : /path/to/sdk/build-tools/30.0.2/apksinger verify --print-certs test.apk
        # signed with v3 : /path/to/sdk/build-tools/30.0.2/apksinger sign --ks my.jsk --v3-signed-enabled true test.apk
        for f in [sample+os.sep+"samples"+os.sep+"aaa.apk"]:
            apk = ApkPaser(f)
            print("--"*10+"apk info "+"--"*10)
            print(json.dumps(apk.apk_base_info(),indent=2))
            dex = DexHeader(apk.get_classe_dex())
            dex.read_all(apk.package)



