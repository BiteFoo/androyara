# -*- encoding: utf-8 -*-
'''
@File    :   main.py
@Author  :   Loopher 
@Version :   1.0
@License :   (C)Copyright 2020-2021, Loopher
@Desc    :   None
'''

# Here put the import lib

from apkscanner.core.axml_parser import AndroidManifestXmlParser

def test_axml():
    path = "F:\\CodeDocuments\pythonCode\\appsamples\\normal\\AndroidManifest.xml"
    axml  = AndroidManifestXmlParser(path)
    print(axml)
    # for a in axml.get_all_activities():
    #     print("--> activity ",a)
    # print("--> service ------")
    # for s in axml.get_all_services():
    #     print("-> service ",s)
    # pass

if __name__ =='__main__':
    test_axml()