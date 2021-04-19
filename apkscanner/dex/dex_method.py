# coding:utf8
'''
@File    :   dex_method.py
@Author  :   Loopher 
@Version :   1.0
@License :   (C)Copyright 2020-2021,Loopher
@Desc    :   DexMethod
'''


class DexMethodProto:

    def __init__(self):
        # DexMethod reference
        self.shorty_idx = None
        self.rturn_type_idx = None
        self.parameter_type_offset = None

    def __str__(self):

        return " shorty_idx: %s return_type_idx: %s parameter_type_offset: %s" % (hex(self.shorty_idx),
                                                                                  hex(
                                                                                      self.rturn_type_idx),
                                                                                  hex(self.parameter_type_offset))


class DexFieldIdx:

    def __init__(self) -> None:
        self.class_idx = None
        self.type_idx = None
        self.name_idx = None

    def __str__(self):

        return " class_idx: %s  type_idx: %s name_idx: %s" % (
            hex(self.class_idx),
            hex(self.type_idx),
            hex(self.name_idx)
        )


class DexMethodIdx:

    def __init__(self):
        self.class_idx = None
        self.proto_idx = None
        self.name_idx = None

    def __str__(self):

        return "DexMethodIdx: class_idx: %s proto_idx: %s name_idx: %s " % (
            hex(self.class_idx),
            hex(self.proto_idx),
            hex(self.name_idx)
        )


class DexMethod:

    def __init__(self):

        self.method_idx = None
        self.access_flag = None
        self.code_off = None

    def __str__(self):

        return "DexMethod: method_id : %s access_flag: %s code_off: %s" % (

            hex(self.method_idx),
            hex(self.access_flag),
            hex(self.code_off)
        )
