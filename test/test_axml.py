# -*- encoding: utf-8 -*-
'''
@File    :   test_axml.py
@Author  :   Loopher 
@Version :   1.0
@License :   (C)Copyright 2020-2021, Loopher
@Desc    :   None
'''

# Here put the import lib

import unittest
from apkscanner.core.axml_parser import AndroidManifestXmlParser

class AxmlTesst(unittest.TestCase):

    def test_axml(self):

        for xml in ["F:\\CodeDocuments\pythonCode\\appsamples\\normal\\AndroidManifest.xml"]:
            axml = AndroidManifestXmlParser(xml)
            # print(axml)

