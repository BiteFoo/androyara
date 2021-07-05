# -*- encoding: utf-8 -*-
'''
@File    :   apk_packer.py
@Time    :   2021/06/17 16:43:41
@Author  :   Ghidra
@Version :   1.0
@Contact :   unknowatdotcom
@License :   (C)Copyright 2020-2021, Ghidra
@Desc    :   App packer's vendor info
'''

# here put the import lib


PACKED_STATUS = {"prime": "基础版加固", "pro": "企业版加固"}

AJM_PACKED = {
    "features": ["assets/ijm_lib/", " assets/ijiami"],
    "shell_application": ["com.shell.SuperApplication"],
    "status": PACKED_STATUS,
    "name": "ijm/爱加密加固"
}

VENDER_NAME = {"ijm": "爱加密", "digit": "360", "pengui": "腾讯", "others": "其他"}

JIAGU_360 = {
    "features": ["assets/libjiagu_x86.so"],
    "shell_application": ["com.stub.StubApp"],
    "status": PACKED_STATUS,
    "name": "360加固"
}

SECNEO = {
    "features": ["libDexHelper.so", "libDexHelper-x86.so"],
    "shell_application": ["com.secneo.apkwrapper.AW"],
    "status": PACKED_STATUS,
    "name": "secneo/梆梆加固"
}

packers = [AJM_PACKED, JIAGU_360, SECNEO]


class ApkPackInfo(object):

    def __init__(self, namelist):
        self.zipinfo = namelist

    def get_pack_info(self, application):
        """
        Get apk packer info 
        """
        # 校验application
        for p in packers:
            for ap in p['shell_application']:
                if ap == application:
                    return p['name']
        # 校验lib目录下的或者assets目录下的
        for n in self.zipinfo:
            for p in packers:

                for _p in p['features']:
                    if _p in n:
                        return p['name']
        return "N/A"
