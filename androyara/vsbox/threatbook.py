# coding:utf8
'''
@File    :   threatbook.py
@Author  :   Loopher 
@Version :   1.0
@License :   (C)Copyright 2020-2021,Loopher
@Desc    :   query threatbook report .
'''
from androyara.vsbox.vsbox import VSandbox
from androyara.utils.mcolor import *


class ThreatbookSandbox(VSandbox):

    def get_sbox_info(self, config, resource):

        threatbook_api_key = config.get("threatbook", "api_key")
        if threatbook_api_key is None or threatbook_api_key == '':
            self.echo("warning", " {} sanbox api_key is None or empty".format(
                self.sbox_name()), "yellow")
            return "", None
        params = {"apikey": threatbook_api_key, "sha256": resource}
        url = "https://api.threatbook.cn/v3/file/report/multiengines"
        return url, params

    def analysis(self):
        """
        Return analysis result
        """

        result = self.get_result()
        if result is None:
            return
        if result['response_code'] != 0:
            self.echo("error", result['verbose_msg'])
            return

        data = result['data']['multiengines']
        scans = result['data']['multiengines']['scans']  # get anti-vendor name

        print(reset)
        print("\t"+yellow+"--"*40, end='\n\n')
        print(white+"\tservice:\tThreatbook", end='\n')
        print(green + "\t%s" % ("result:"), end='')
        print(red+"\t\t%d" % (data['positives']), end='')
        print(reset+"/", end='')
        print("%d" % (data['total2']), end='\n')
        print(pink+"\tmalware_type:"+" %s" %
              (data['malware_type']), end='\n')
        print(reset, end="")
        print(yellow+"\tmalware_family: %s" %
              (data['malware_family']), end='\n')
        print(reset, end="")
        print("\tAntiProductEngine:\t%s " %
              ("Tencent"), end='\n')
        print("\tvirusName: ", end="")
        print(red+"%s" % (scans['Tencent']), end="\n")
        print(reset, end="")
        print("\tscan_date: %s" % (data['scan_date']))
        print("\tsha256: ", end="")
        print(yellow+"%s" % (self.resource), end="\n")
        print(reset)

    def sbox_name(self):

        return "Threatbook"
