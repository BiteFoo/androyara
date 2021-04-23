# coding:utf8
'''
@File    :   test_vbox.py
@Author  :   Loopher 
@Version :   1.0
@License :   (C)Copyright 2020-2021,Loopher
@Desc    :   None
'''

import unittest
from androyara.vsbox.vt import VT
from androyara.vsbox.threatbook import ThreatbookSandbox
from androyara.vsbox.hybird import HybirdSanbox


class TestVsbox(unittest.TestCase):

    def test_vsbox(self):
        # VT("b87f2f3a927bf967736ed43ca2dbfb60").analysis()
        ThreatbookSandbox("b87f2f3a927bf967736ed43ca2dbfb60").analysis()
        HybirdSanbox(
            "d2ba9a60abf9eade2d2934c75bd8de945e93c53e8e06f790a19a25925e793092").analysis()
