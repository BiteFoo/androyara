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
from concurrent.futures import ThreadPoolExecutor, as_completed
from androyara.utils.utility import echo
from androyara.core.apk_parser import ApkPaser


class YaraMatcher(object):

    def __init__(self, rule, apk):
        self._rule = rule
        self._apk = apk
        self.__precompile()
        self.executors = ThreadPoolExecutor(max_workers=5)

    def __precompile(self):
        """
        maybe use a directory as input yara rule file

        """
        self.yara_namespace = {}
        if os.path.isfile(self._rule):
            name = os.path.basename(self._rule)[:-4]
            self.yara_namespace[name] = self._rule
            #self.yara_rule = yara.compile(filepath=self._rule)
        elif os.path.isdir(self._rule):
            for root, _, fs in os.walk(self._rule):
                for f in fs:
                    if f.endswith(".yar"):
                        self.yara_namespace[f[:-4]] = os.path.join(root, f)
            self.yara_rule = yara.compile(filepaths=self.yara_namespace)

    def check_file(self, f):
        # .bin is support online sandbox donwload samples
        return [f.endswith('.apk'), f.endswith(
            '.APK'), f.endswith('.dex'), f.endswith('.bin')]

    def yara_scan(self):
        """
        applying yara rule scan input file 
        """

        def scan(file):
            try:
                self.match(file)
            except Exception as e:
                echo("yara_scan", "error {} ".format(e), 'red')

        # dex or apk file
        if os.path.isfile(self._apk) and any(self.check_file(self._apk)):
            scan(self._apk)
        # folder contains  suffix .dex or .apk or .bin files
        elif os.path.isdir(self._apk):
            workers = []
            for root, _, fs in os.walk(self._apk):
                for f in fs:
                    file = os.path.join(root, f)
                    if any(self.check_file(f)):
                        workers.append(
                            self.executors.submit(fn=scan, file=file))
            for _ in as_completed(workers):
                pass

    def match(self, f):
        """
        f: a  apk  or dex file or sample ,it must be dex or apk.
        """
        rsult = None
        dex = False
        if f.endswith(".dex"):
            dex = True

        def show_result(rsult, susp):

            for name in self.yara_namespace:
                if rsult.get(name, None) is None:
                    continue
                for r in rsult[name]:
                    tag = r['tags'][0]

                    if r['matches']:
                        echo("rule", " %s/%s %s\t%s" %
                             (tag, r['rule'], self.yara_namespace[name], susp), 'yellow')
                        return
        if dex:
            with open(f, 'rb') as fp:
                result = self.yara_rule.match(data=fp.read())
                show_result(result, f)

                # return result

        apk_parser = ApkPaser(f)
        if not apk_parser.ok():
            return
        for _, buff in apk_parser.get_all_dexs():

            rsult = self.yara_rule.match(data=buff)
            # print(rsult)  # {'main': [{'tags': ['Android'], 'meta': {'author': 'loopher'}, 'strings': [{'data': 'http://ksjajsxccb.com/api/index/information', 'offset': 2514313, 'identifier': '$str', 'flags': 19}], 'rule': 'BYL_bank_trojan', 'matches': True}]}
            show_result(rsult, f)
