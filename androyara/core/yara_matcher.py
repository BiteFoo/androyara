# coding:utf8
'''
@File    :   yara_matcher.py
@Author  :   Loopher
@Version :   1.0
@License :   (C)Copyright 2020-2021,Loopher
@Desc    :   Yara matcher
'''
import yara
import os
from androyara.utils.utility import echo
from androyara.core.apk_parser import ApkPaser
from androyara.dex.dex_vm import DexFileVM


class YaraMatcher(object):

    def __init__(self, rule, apk):
        self._rule = rule
        self._apk = apk
        self.yara_rule = yara.compile(filepath=rule)

    def yara_scan(self):

        if os.path.isfile(self._apk):
            try:
                match = self.match(self._apk)
                # if match is not None:
                #     echo("info", " %s" % (self._apk))
            except Exception as e:
                pass
        elif os.path.isdir(self._apk):
            for root, _, fs in os.walk(self._apk):
                for f in fs:
                    if f.endswith('.apk') or f.endswith('.APK'):
                        apk = os.path.join(root, f)
                        try:
                            self.match(apk)
                            # if match is not None:
                            #     echo("info", "%s  %s" %
                            #          (self.match[0].rule, apk))
                        except:
                            continue

    def match(self, apk):

        apk_parser = ApkPaser(apk)
        for dex in apk_parser.get_all_dexs():
            rsult = self.yara_rule.match(data=dex)
            if len(rsult) > 0:
                echo("rule", " %s  %s" %
                     (rsult[0].rule, apk), 'yellow')
                return rsult
        return None
