# coding:utf8
'''
@File    :   vt.py
@Author  :   Loopher 
@Version :   1.0
@License :   (C)Copyright 2020-2021,Loopher
@Desc    :   reference https://developers.virustotal.com/v3.0/reference#key-concepts
'''
import json
from androyara.vsbox.vsbox import VSandbox
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

        # self.echo("info", json.dumps(result, indent=2))
        total = result['total']
        positives = result['positives']
        permalink = result['permalink']
        scan_data = result['scan_date']
        info = '\n\tscan_result: %d/%d\n\tscan_date: %s\n\tpermalink: %s\n\tsha256: %s\n\t' % (
            positives, total, scan_data, permalink, result['sha256']
        )

        self.echo("Info", "\n\t{} scan results: \n\t{}".format(
            self.sbox_name(), info))
