# -*- encoding: utf-8 -*-
'''
@File    :   base_parser.py
@Author  :   Loopher 
@Version :   1.0
@License :   (C)Copyright 2020-2021, Loopher
@Desc    :   所有的解析器的父类
'''

# Here put the import lib

import os
import hashlib


class ReadApkError(BaseException):
    pass


class BaserParser(object):

    parser_info = {
        "name": "BaserParser",
        "desc": "FooParser"

    }

    def __init__(self, filename, buff):

        if filename is not None and os.path.isfile(filename):
            self.filename = filename
            with open(filename, 'rb') as out:
                self.buff = out.read()
        elif buff is not None:
            self.filename = hashlib.sha256(buff).hexdigest()
            self.buff = buff
        else:
            raise ReadApkError("filename or buff must not be None")
