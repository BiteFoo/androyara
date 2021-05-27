# coding:utf8
'''
@File    :   vt.py
@Author  :   Loopher
@Version :   1.0
@License :   (C)Copyright 2020-2021,Loopher
@Desc    :   reference https://developers.virustotal.com/v3.0/reference#key-concepts
'''
from androyara.vsbox.vsbox import VSandbox
from androyara.utils.mcolor import *
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
            return None

        scan = {
            "positives": "%d/%d" % (result['positives'], result['total']),
            "virusName": "",
            "link": result['permalink'],
            "scanDate": result['scan_date'],
            "vendor": ""


        }
        if result['positives'] > 0:
            for vendor, v in result['scans'].items():

                if v['detected']:
                    scan['virusName'] = v['result']
                    scan['vendor'] = vendor
                    break

        print(reset)
        print("\t"+yellow+"-"*40, end='\n\n')
        print(white+"\tservice:\tVirusTotal", end='\n\n')
        print(green + "\t%s" % ("result:"), end='')
        print(red+"\t\t%d" % (result['positives']), end='')
        print(reset+"/", end='')
        print("%d" % (result['total']), end='\n\n')
        print(pink+"\tpermalink:"+"\t%s" %
              (result['permalink']), end='\n\n')
        print(reset)
        print("\tvirusName:\t%s  vendor: %s" %
              (scan['virusName'], scan['vendor']), end='\n\n')
        print("\tscan_date:\t%s" % (result['scan_date']), end='\n\n')

        return scan
