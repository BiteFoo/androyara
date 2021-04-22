# coding:utf8
'''
@File    :   vt.py
@Author  :   Loopher 
@Version :   1.0
@License :   (C)Copyright 2020-2021,Loopher
@Desc    :   reference https://developers.virustotal.com/v3.0/reference#key-concepts
'''

from apkscanner.vsbox.vsbox import VSandbox
import configparser


class VT(VSandbox):

    def get_sbox_info(self, config: configparser.ConfigParser, resource):
        vt_key = config.get("VT", "api_key")
        if vt_key is None or vt_key == '':
            self.echo("warning", "VT api_key is emtpy or None", "yellow")
            return "", None

        # self.echo("Info", "start querying VT analysis info... {}".format(
        #     vt_key), "green")
        # v3 api
        # https://www.virustotal.com/api/v3/{collection name}/{object id}
        # {collection name} = files / analyses
        # v2 api https://developers.virustotal.com/reference#file-report
        url = "https://www.virustotal.com/vtapi/v2/file/report"
        params = {'apikey': vt_key, 'resource': resource}
        return url, params

    def sbox_name(self):
        return "VT"

    def analysis(self):
        result = self.get_result()
        if result is None:
            return

        self.echo("Info: sandbox : {}".format(self.sbox_name()), result)
