# coding:utf8
'''
@File    :   hybird.py
@Author  :   Loopher 
@Version :   1.0
@License :   (C)Copyright 2020-2021,Loopher
@Desc    :   query hybird sandbox report info
'''
import requests
from requests.api import head
from apkscanner.vsbox.vsbox import VSandbox


class HybirdSanbox(VSandbox):

    def get_sbox_info(self, config, resource):
        return "", None

    def query_report(self, config, resource):
        # hybird sandbox need query by user's,it's not http post method
        api_key = config.get("hybird", "api_key")
        if api_key is None or api_key == '':

            return None
        headers = {
            "api-key": api_key,
            "user-agent": "Falcon Sandbox",  # fixed header
            # "sha256": resource
        }
        url = "https://www.hybrid-analysis.com/api/v2/overview/"+resource
        res = requests.get(url=url, headers=headers)
        try:
            self.echo("info", " {} response code  {} ".format(
                self.sbox_name(), res.status_code))
            if res.status_code == 403:
                self.echo("error", " {} query 403 , due to {}".format(
                    self.sbox_name(), res.json()), "red")
                return None
            elif res.status_code == 200:
                return res.json()
            else:
                self.echo("error", " {}  query report failed ,{} ".format(
                    self.sbox_name(), res.json()))
                return None
        except Exception as e:
            self.echo("warning", "{} query report error : {}".format(
                self.sbox_name(), e), "yellow")
            return None

    def sbox_name(self):
        return "Hybird"

    def analysis(self):
        result = self.get_result()
        if result is None:
            return
        self.echo("Info:", " {} query report result.".format
                  (result))
