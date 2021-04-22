# coding:utf8
'''
@File    :   apkscanner.py
@Author  :   Loopher 
@Version :   1.0
@License :   (C)Copyright 2020-2021,Loopher
@Desc    :   apkscanner main entry
'''
import os
import json
from termcolor import colored
from apkscanner.vsbox.vt import VT
import argparse
from apkscanner.core.apk_parser import ApkPaser


def echo(tag, msg, color="green"):
    # show info
    print(colored("[{}]: {}".format(tag, msg), color=color))


def query_report(resource):
    # default for vt
    if resource is None or resource == '':
        echo("error", "query_report resouroce must be empty or None", color="red")
        return
    vt = VT(resource)
    vt.analysis()


def apk_info(apk):
    # get_apk_info
    if apk is None or not os.path.isfile(apk):
        return
    apk_parser = ApkPaser(apk)
    echo("info", "{}".format(json.dumps(apk_parser, indent=2)))


def apk_strings(apk, save=None):
    if apk is None or not os.path.isfile(apk):
        return
    apk_parser = ApkPaser(apk)
    #  maybe too many ,
    echo("info", "{}".format(apk_parser.apk_strings()))
    if save is not None:
        with open(save, 'w') as fp:
            fp.write(apk_parser.apk_strings())
        echo("info", "string save at path : %s " % (save))


def analysis_apk(apk):
    # scan apk  include AVEngin and vt check

    pass


if __name__ == '__main__':

    parser = argparse.ArgumentParser(prog=None,

                                     description="Apkscanner is a tool for android apk to  retrieve some information written by Loopher")

    parser.add_argument("-f", "--file", metavar="/path/to/apkfile ",
                        type=str, default="", help="-s  Use local scan apk by AVEngine and query information from vt"
                        )
    parser.add_argument('-q', '--query', type=bool,
                        default=False, metavar='if true  will show online sandbox\'s report  result ',
                        help="-q or --query need to provide sha256 to query report from vt. You need to check user/user.conf ")

    parser.add_argument('-e', "--extract", type=bool, metavar=" if true will return all string in classes ",
                        default=False, help="-e or --etract will return apk's classes string")

    parser.add_argument('-r', '--rule', type=str, default='', metavar="/path/to/rule.json",
                        help='-r or --rule A rule to check apk ,just like yara\'s rule .')

    parser.add_argument('-i', '--info', type=bool, default=False, metavar="apk's base info",
                        help='-r or --info Read apk information ,AndroidManifest.xml\'s strings  and classes\'s methods ')

    args = parser.parse_args()

    echo("args ", args.file)
    echo("args ", args.info)
    echo("args ", args.rule)
    echo("args ", args.extract)
    echo("args ", args.query)
