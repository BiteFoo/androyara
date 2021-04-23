# coding:utf8
'''
@File    :   androyara.py
@Author  :   Loopher 
@Version :   1.0
@License :   (C)Copyright 2020-2021,Loopher
@Desc    :   androyara main entry
'''
import hashlib
import os
from androyara.dex.dex_vm import DexFileVM
import sys
import json
from androyara.utils.utility import echo
from androyara.vsbox.vt import VT
import argparse
from androyara.core.apk_parser import ApkPaser


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
    echo("info", "\n{}".format(json.dumps(apk_parser.apk_base_info(), indent=2)))


def apk_strings(apk, save=None):
    if apk is None or not os.path.isfile(apk):
        return
    apk_parser = ApkPaser(apk)
    #  maybe too many ,need to save into file ,save will specificate.
    echo("info", "{}".format(apk_parser.apk_strings()))
    if save is not None:
        with open(save, 'w') as fp:
            fp.write(apk_parser.apk_strings())
        echo("info", "strings save at path : %s " % (save))


def dex_info(pkg, dex, pattern):
    # check dex file header
    # with open(dex,'rb') as fp:
    #     buff =
    if pkg is None:
        echo("warning", "pkg is None and will use empty to retrive all methods in dex file.", 'yellow')
    if pattern is None:
        # retrive content:// and http(s)://
        pattern = '://'
        echo("warning", "pattern is None and will return all strings in dex file.")
    with open(dex, 'rb') as f:

        vm = DexFileVM(pkgname=pkg, buff=f.read())
        if not vm.ok:
            echo("error", "{} is not a dex format file.", 'red')
            return
        for i, s in enumerate(vm.all_strings(pattern)):
            echo("%d" % (i), "%s" % (s))


def analysis_apk(apk):
    # scan apk  include AVEngin and vt check

    pass


if __name__ == '__main__':

    parser = argparse.ArgumentParser(prog=None,

                                     description="Apkscanner is a tool for android apk to  retrieve some information and analysis android virus feature written by Loopher.Version:1.0")

    parser.add_argument("-f", "--file", metavar="/path/to/apkfile ",
                        type=str, default="", help="-s  Use local scan apk by AVEngine and query information from vt"
                        )
    parser.add_argument('-q', '--query', type=bool,
                        default=False, metavar='true/false',
                        help="-q or --query need to provide sha256 to query report from vt. You need to check user/user.conf ")

    parser.add_argument('-e', "--extract", type=bool, metavar=" true/false ",
                        default=False, help="-e or --extract will return apk's classes string")

    parser.add_argument('-r', '--rule', type=str, default=None, metavar="/path/to/rule.json",
                        help='-r or --rule A rule to check apk ,just like yara\'s rule .')

    parser.add_argument('-i', '--info', type=bool, default=False, metavar="true/false",
                        help='-r or --info read apk information ,AndroidManifest.xml\'s strings  and classes\'s methods ')
    parser.add_argument('-s', '--save', default=None, type=str,
                        metavar=" /path/to/save.txt", help="save strings into file,see -e option ,need a file path.")

    parser.add_argument('-d', '--dex', default=None, type=str,
                        metavar="/path/to/dexfile", help="A dex file for retriving methods and strings.")
    parser.add_argument("-p", '--pkg', default=None, type=str, metavar="packagename",
                        help="A package name for retriving dex file methods and strings.")
    parser.add_argument("-g", '--pattern', default=None, type=str, metavar="reg pattern",
                        help='A reg pattern for retriving apk\'s or dex\'s string content,use comma to split')

    args = parser.parse_args()

    if args.rule is not None:
        if not os.path.isfile(args.rule):
            echo("error", "a rule file need to specificate!!", 'red')
            parser.print_help()
            sys.exit(1)
    if args.info:
        if not os.path.isfile(args.file):
            echo("error", "apk need to specificate.", "red")
            parser.print_help()
            sys.exit(1)
        apk_info(apk=args.file)
    elif args.extract:
        if not os.path.isfile(args.file):
            echo("error", "apk need to specificate.", "red")
            parser.print_help()
            sys.exit(1)
        if args.save is None:
            echo(
                'warning', "specificate -e but no save file ,will not save strings result !", 'yellow')
        apk_strings(apk=args.file, save=args.save)
    elif args.query:
        if not os.path.isfile(args.file):
            echo("error", "apk need to specificate.", "red")
            parser.print_help()
            sys.exit(1)
        with open(args.file, 'rb') as fp:
            resource = hashlib.sha256(fp.read()).hexdigest()
            query_report(resource)
    elif args.dex:
        if not os.path.isfile(args.dex):
            echo("error", "{} is not file".format(args.dex))
            parser.print_help()
            sys.exit(1)

        dex_info(args.pkg, args.dex, pattern=args.pattern)

    else:
        parser.print_help()
