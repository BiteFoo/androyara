# coding:utf8
'''
@File    :   analysis_apk.py
@Author  :   Loopher 
@Version :   1.0
@License :   (C)Copyright 2020-2021,Loopher
@Desc    :   analyzer a apk file
'''

import os
import json
from androyara.vsbox.vt import VT
from androyara.utils.utility import echo
from androyara.core.apk_parser import ApkPaser, FileNotFound


class AnalyzerApk(object):

    def __init__(self, apk, rule=None, pattern=None):

        self.ok = True
        self.rule = rule  # rule file
        self.pattern = pattern  # string pattern
        self.filename = apk
        self.rules = None
        try:
            # echo("info", " analysis : {}".format(apk))
            self.apk_parser = ApkPaser(apk)
        except FileNotFound:
            self.ok = False
            return
        except Exception as e:
            # echo("error", " parser \"{}\" error ,exception: {}".format(apk, e), 'red')
            self.ok = False
            return

        self.vt = VT(self.apk_parser._app_sha256)

    def __analyzer_string(self):
        """
        need pattern or rule file
        """
        for rule in self.rules:
            ss = self.apk_parser.all_strings(rule['patters'])
            if len(ss) > 0:
                echo("info", "rule: {}  {} ".format(
                    rule['name'], self.filename))
                return True
        return False

    def __analyzer_method(self):
        """
        check method ,need rule file
        """
        # echo("info", "to be continue...")
        pass

    def __read_rule(self):

        with open(self.rule, 'r') as fp:
            config = json.load(fp)
        result = []
        for rule in config['rules']:

            item = {
                "name": rule['name'],
                "patters": [],
                "shell_s": [],
                "file_type": ""
            }
            for k, v in rule.items():
                if k.startswith("string"):
                    if v is None or v == '':
                        continue
                    item['patters'].append(v)
                elif k.startswith("shell_code"):
                    item['shell_s'].append(v)
                elif k == 'file_type':
                    item['file_type'] = v
            result.append(item)
        return result

    def _online_sandbox(self):
        result = self.vt.analysis()
        if result is None:
            return False
        echo("info", "VT query reult:")
        echo("positives", result['positives'], "magenta")
        echo("virusName", result['virusName'], "red")
        echo("link", result['link'], "green")
        echo("scanDate", result['scanDate'], "yellow")
        echo("path", self.filename, "white")
        return True

    def analyzer(self):
        if not self.ok:
            return False
        elif not os.path.isfile(self.rule):
            echo("error", "need rule file!!", 'red')
            return False
        elif not self.apk_parser.ok:
            echo("error", " {} is not a apk file !!!", 'red')
            return False
        self.rules = self.__read_rule()

        return self.__analyzer_string()\
            or self.__analyzer_method()\
            or self._online_sandbox()

        # if self.__analyzer_string():
        #     return True

        # elif self.__analyzer_method():
        #     return True
        # elif self._online_sandbox():
        #     return True
        # else:
        #     return False
