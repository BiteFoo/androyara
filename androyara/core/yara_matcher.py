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
                self.match(self._apk)
                # if match is not None:
                #     echo("info", " %s" % (self._apk))
            except:
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
                    elif f.endswith('.dex'):
                        clzz_dex = os.path.join(root, f)
                        self.match(clzz_dex, dex=True)

    def match(self, f, dex=False):

        if dex:
            with open(f, 'rb') as fp:
                result = self.yara_rule.match(data=fp.read())
                if len(result) > 0:
                    echo("rule", " %s  %s" %
                         (result[0].rule, f), 'yellow')
                return result

        apk_parser = ApkPaser(f)
        if not apk_parser.ok():
            return None
        for buff in apk_parser.get_all_dexs():
            rsult = self.yara_rule.match(data=buff)
            if len(rsult) > 0:
                echo("rule", " %s  %s" %
                     (rsult[0].rule, f), 'yellow')
                return rsult
        return None
