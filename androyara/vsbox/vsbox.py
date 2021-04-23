# coding:utf8
'''
@File    :   vsbox.py
@Author  :   Loopher 
@Version :   1.0
@License :   (C)Copyright 2020-2021,Loopher
@Desc    :   View Sandbox query samples fingerprint from online sandbox
'''

import configparser
import logging
import os
import requests
import json
from termcolor import colored

root = os.path.abspath(os.path.dirname(__file__))
root = root[:root.rfind(os.sep)]
user = root[:root.rfind(os.sep)]+os.sep+"user"

logger = logging.getLogger("androyara.vbox")
logger.setLevel(logging.INFO)


class ConfigError(BaseException):
    pass


class VSandbox(object):

    def __init__(self, finger_print):

        self.result = None
        self._init_conf(finger_print)

    def _init_conf(self, finger_print: str):

        config_path = user+os.sep+"user.conf"
        if not os.path.isfile(config_path):
            print(colored(
                "[error]: Read user.conf error  {} is not file !!! ".format(config_path), "red"))

            return
        if finger_print is None or finger_print == '':
            self.echo(
                "error", " query sanbox resource must be not None or empty!!!!")
            return None
        config = configparser.ConfigParser()
        config.read(config_path)
        url, params = self.get_sbox_info(
            config, finger_print)  # Get sanbox url,api_key,sanbox_name
        if url != '':
            result = self.query(url,  params)
            if result is None:
                self.echo("warning", " {} can't query anything from {} sandbox".format(
                    finger_print))
                return
        else:
            self.echo(
                "warning", " {} sandbox url is empty , your should call query_report method for query report ".format(self.sbox_name()), "yellow")
            result = self.query_report(config, finger_print)

        self.result = result

    def analysis(self):
        pass

    def get_result(self):

        return self.result

    def query_report(self, config, resource):
        """
        another query method  for user 
        return :  
        """
        return None

    def sbox_name(self):

        return "VSandbox"

    def query(self, url, params):

        try:
            res = requests.get(url=url, params=params)
            res.raise_for_status()
            result = res.json()
            return result
        except Exception as e:
            self.echo("warning", "request report error {}".format(e), "yellow")
            return None

    def echo(self, tag, msg, color="green"):
        print(colored("[{}]: {}".format(tag, msg), color))

    def get_sbox_info(self, config, resource):

        raise NotImplementedError
