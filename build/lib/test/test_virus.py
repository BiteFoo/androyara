# coding:utf8
'''
@File    :   test_virus.py
@Author  :   Loopher 
@Version :   1.0
@License :   (C)Copyright 2020-2021,Loopher
@Desc    :   None
'''
import unittest
import os
import json
import sys
from androyara.core.apk_parser import ApkPaser
from androyara.dex.dex_vm import DexFileVM
path = "/tmp/androyara/allvirusSample"


class ViruApkTest(unittest.TestCase):

    def test_virus_scan(self):

        # for root, _, fs in os.walk(path):
        #     for f in fs:
        #         if f.endswith('.APK') or f.endswith('.apk'):
        #             apk_file = os.path.join(root, f)
        #             try:
        #                 apk_parser = ApkPaser(apk_file)
        #                 print(json.dumps(apk_parser.apk_base_info(), indent=2))
        #                 vm = DexFileVM(apk_parser.package,
        #                                apk_parser.get_classe_dex())
        #                 vm.build_map()
        #                 # break

        #             except Exception as e:
        #                 print("error {} file: {}".format(
        #                     e, apk_file), file=sys.stderr)
        pass

    def test_virus_file(self):
        # "/tmp/androyara/allvirusSample/MalwareSamples/TROJAN/5A51DC7F8ABB013758B8D2C9B9A29967D82C80A7C5CEC67E45E46C28A55AA84D.APK"
        apk_file = "/tmp/androyara/allvirusSample/virussample/virussamplevirus5.apk"
        if not os.path.isfile(apk_file):
            return
        apk_parser = ApkPaser(apk_file)
        print(json.dumps(apk_parser.apk_base_info(), indent=2))
