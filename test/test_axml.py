# -*- encoding: utf-8 -*-
'''
@File    :   test_axml.py
@Author  :   Loopher 
@Version :   1.0
@License :   (C)Copyright 2020-2021, Loopher
@Desc    :   None
'''

# Here put the import lib

import os
import unittest
from apkscanner.core.axml_parser import AndroidManifestXmlParser

root = os.path.abspath(os.path.dirname(__file__))
sample = root[:root.rfind(os.sep)]


class AxmlTesst(unittest.TestCase):

    def test_axml(self):

        for xml in [sample+os.sep+"samples"+os.sep+"AndroidManifest.xml"]:
            axml = AndroidManifestXmlParser(xml)
            # print(axml)
            # print(axml.get_all_export_components())

            print(axml.get_main_activity())
            # axml.get_main_activity()
            pass
