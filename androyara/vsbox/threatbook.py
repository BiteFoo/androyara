# coding:utf8
'''
@File    :   threatbook.py
@Author  :   Loopher 
@Version :   1.0
@License :   (C)Copyright 2020-2021,Loopher
@Desc    :   query threatbook report .
'''
from androyara.vsbox.vsbox import VSandbox


class ThreatbookSandbox(VSandbox):

    def get_sbox_info(self, config, resource):

        threatbook_api_key = config.get("threatbook", "api_key")
        if threatbook_api_key is None or threatbook_api_key == '':
            self.echo("warning", " {} sanbox api_key is None or empty".format(
                self.sbox_name()), "yellow")
            return "", None
        params = {"apikey": threatbook_api_key, "md5": resource}
        url = "https://api.threatbook.cn/v3/file/report/multiengines"
        return url, params

    def analysis(self):
        """
        Return analysis result
        """

        result = self.get_result()
        if result is None:
            return
        self.echo("Info: sandbox : {}".format(self.sbox_name()), result)

    def sbox_name(self):

        return "threatbook"
