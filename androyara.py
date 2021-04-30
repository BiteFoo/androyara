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
import argparse
import sys
import json
from androyara.dex.dex_vm import DexFileVM
from androyara.utils.utility import echo
from androyara.vsbox.vt import VT
from androyara.core.apk_parser import ApkPaser
from androyara.core.axml_parser import AndroidManifestXmlParser
from androyara.core.yara_matcher import YaraMatcher
from androyara.utils.mcolor import *


pattern = None
save = None
rule = None
input_file = None
method_name_arg = None
pkg = None
fingerprint = None


def query_report(args):

    # default for vt
    resource = args.resource
    bsize = 65536
    buff = None
    if input_file is not None and os.path.isfile(resource):
        sha256 = hashlib.sha256()
        while True:
            with open(resource, 'rb') as fp:
                buff = fp.read(bsize)
                if buff is None:
                    break
                sha256.update(buff)

        resource = sha256.hexdigest()

    if resource is None or resource == '':
        echo("error", "query_report resouroce must be empty or None", color="red")
        return
    vt = VT(resource)
    vt.analysis()


def apk_info(args):
    """
    默认输出apk内的基本信息
    apk的指纹信息
    AndroidManifest.xml内的信息
    使用-z --zipinfo 读取apk内的所有文件名信息
    """
    # get_apk_info
    input_file = args.apk
    zip_info = args.zipinfo
    info = args.info
    print(input_file, zip_info, info)

    if input_file is None or not os.path.isfile(input_file):
        echo("error", "need apk.", "red")
        sys.exit(1)
    if not input_file.endswith('.apk') and not input_file.endswith('.APK'):
        echo("error", "need a apk file", 'red')
        return

    apk_parser = ApkPaser(input_file)
    if info:
        echo("apkInfo", "\n{}".format(
            json.dumps(apk_parser.apk_base_info(), indent=2)), "yellow")
        print("--"*20)

    if zip_info:
        for f in apk_parser.get_file_names():
            echo("info", "-> %s" % (f))


def extract_android_manifest_info(args):

    input_file = args.manifest
    entry = args.entry
    acs = args.activities
    rs = args.receivers
    ss = args.services
    ps = args.providers
    both = args.both
    exported = args.exported
    pm = args.permission

    if not os.path.isfile(input_file):
        echo("error", "need apk or AndroidManifest.xml as input file!!", 'red')
        return
    elif input_file.endswith('.xml'):
        axml = AndroidManifestXmlParser(input_file)
        axml.show_manifest(acs, rs, ss, ps, entry, both, exported, pm)
    elif input_file.endswith('apk'):
        apk_parser = ApkPaser(input_file)
        if apk_parser.ok():
            apk_parser.show_manifest(
                acs, rs, ss, ps, entry, both, exported, pm)
            # echo("info", "\n"+str(apk_parser.mainifest_info()))
    else:
        echo("error", "unknow {} filtyep ".format(input_file), 'red')


def extract_apk_info(args):
    input_file = args.apk
    pattern = args.string
    method_name_arg = args.method
    clazz_name = args.clazz
    dump = args.print_ins

    if input_file is None or not os.path.isfile(input_file):
        echo("error", "need a apk file", 'red')
        return
    if pattern is None:
        echo("warning", "no string specificed", 'yellow')
        # pattern = ''

    apk_parser = ApkPaser(input_file)
    if not apk_parser.ok():
        return

    if pattern is not None:
        for s in apk_parser.all_strings([pattern]):
            echo("string", "%s" % (s), 'yellow')
    if method_name_arg is None:
        #
        echo("warning", "no method name ", 'yellow')
        # method_name_arg = ""
        return

    apk_parser.analysis_dex(clazz_name, method_name_arg, dump)


def dex_info(args):

    input_file = args.dex
    pattern = args.string
    method_name_arg = args.method
    pkg = args.pkgname
    clazz_name = args.clazz
    dump = args.print_ins

    if input_file is None or not os.path.isfile(input_file):
        echo("error", "need a dex file!! ", "red")
        parser.print_help()
        sys.exit(1)

    patters = []
    if pkg is None:
        echo("warning", "pkg is None and will retrive all methods in dex file.", 'yellow')
    # if pattern is None or pattern == '':
    #     pattern = "://"

    patters.append(pattern)
    with open(input_file, 'rb') as f:

        vm = DexFileVM(pkgname=pkg, buff=f.read())
        if not vm.ok():
            echo("error", "{} is not a dex format file.".format(input_file), 'red')
            return
        if pattern is not None:
            # if pattern is not None will show string
            for i, s in enumerate(vm.all_strings(patters)):
                echo("%d" % (i), "%s" % (s))
        if method_name_arg is None:
            echo("warning", " methodName is empty ,show all methods", 'yellow')

        vm.analysis_dex(clazz_name, method_name_arg, dump)


def yara_scan(args):
    rule = args.rule
    f = args.file
    if rule is None or f is None:
        echo("error", "yara rule or apk file must be include", 'red')
        return
    if not os.path.isfile(rule):
        echo("error", "yara rule file not exists", 'red')
        return
    if not os.path.isfile(f) and not os.path.isdir(f):
        echo("error", "apk file or apk directory need", 'red')
        return
    echo("yara_scan", "------YARA SCAN -------", 'yellow')
    YaraMatcher(rule, f).yara_scan()


def show_info(args):

    print(white+'-'*40, end='\n')
    print(light_blue)
    print("\t%s" % ("author:")+"\t\t%s" % ("loopher"), end='\n')
    print("\t%s" % ("version:")+"\t%s" % ("1.0.0"), end='\n')
    print("\t%s" % ("updatedate:\t%s" % ("2021-04-30")))
    print(reset)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(usage="%(prog)s [options]")
    subparsers = parser.add_subparsers(title="options")

    version = subparsers.add_parser("version", help='show version')
    version.set_defaults(func=show_info)
    # query vt
    query_parser = subparsers.add_parser("query", help="query from VT")
    query_parser.set_defaults(func=query_report)
    query_parser.add_argument(
        "-s", "--resource", type=str, default=None, help="file path or  sh256 ")

    analysis_dex = subparsers.add_parser(
        "search_dex", help="search dex string or method all instructions from dex")
    analysis_dex.set_defaults(func=dex_info)
    analysis_dex.add_argument("-d", "--dex", type=str,
                              default=None, help="A dex file")
    analysis_dex.add_argument(
        "-s", "--string", type=str, default=None, help="A string eg: \"hello\" or  reg pattern,eg: \"^(aaa).+ or ^(aaa).+,^(bbb).?\"")
    analysis_dex.add_argument("-m", "--method", type=str,
                              default=None, help="A method Name in the dex file.")
    analysis_dex.add_argument("-pkg", "--pkgname", type=str,
                              default=None, help="class pkgname")
    analysis_dex.add_argument(
        "-c", "--clazz", type=str, default=None, help="specific class name ,default is None ")
    analysis_dex.add_argument(
        "-p", "--print_ins",  action="store_true", help="dump method instruction ")

    # analysis AndroidManifest.xml
    manifest_parser = subparsers.add_parser(
        "manifest", help=" Parsing Binary AndroidManifest.xml")
    manifest_parser.set_defaults(func=extract_android_manifest_info)
    manifest_parser.add_argument("-m", "--manifest", type=str, default=None,
                                 help="A binary AndroidManifest.xml or apk contain's AndroidManifest.xml")
    manifest_parser.add_argument(
        "-a", "--activities",  action="store_true", help="show all activities ")
    manifest_parser.add_argument(
        "-r", "--receivers",  action="store_true", help="show all receivers ")
    manifest_parser.add_argument(
        "-s", "--services",  action="store_true", help="show all services ")
    manifest_parser.add_argument(
        "-p", "--providers",  action="store_true", help="show all providers ")
    manifest_parser.add_argument(
        "-b", "--both",  action="store_true", help="show all componets ")
    manifest_parser.add_argument(
        "-e", "--entry",  action="store_true", help="show entry point , MainActivity pkgname Application ")

    manifest_parser.add_argument(
        "-et", "--exported",  action="store_true", help="show entry point , MainActivity pkgname Application ")
    manifest_parser.add_argument(
        "-pm", "--permission",  action="store_true", help="show permissions ")
    # apk base info
    apk_base = subparsers.add_parser("apkinfo",  help="Apk base  info")
    apk_base.set_defaults(func=apk_info)
    apk_base.add_argument("-a", "--apk", type=str,
                          default=None, help="path to apk")
    apk_base.add_argument(
        "-i", "--info", action="store_true", help="read apk base info ")
    # 获取所有的apk内的文件名
    apk_base.add_argument(
        "-z", "--zipinfo", action="store_true", help="read filename from apk,like zipinfo apk")

    # search infor  from apk
    search_from_apk = subparsers.add_parser(
        "search_apk", help="search string or method instructions from apk")
    search_from_apk.set_defaults(func=extract_apk_info)
    search_from_apk.add_argument(
        "-a", "--apk", type=str, default=None, help="path to apk")
    # 使用,分隔开
    search_from_apk.add_argument(
        "-s", "--string", type=str, default=None, help="A string eg: \"hello\" or  reg pattern,eg: \"^(aaa).+ or ^(aaa).+,^(bbb).?\"")
    # 使用method name 输出指令
    search_from_apk.add_argument(
        "-m", "--method", type=str, default=None, help="specific method name default is None")
    search_from_apk.add_argument(
        "-c", "--clazz", type=str, default=None, help="specific class name ,default is None ")
    search_from_apk.add_argument(
        "-p", "--print_ins",  action="store_true", help="dump method instruction ")

    # 使用yara扫描
    yara_parser = subparsers.add_parser(
        "yara_scan", help="Using yara rule to scan")
    yara_parser.set_defaults(func=yara_scan)
    yara_parser.add_argument("-r", '--rule', default=None,
                             type=str, help="Yara rule file")
    yara_parser.add_argument("-f", '--file', default=None,
                             type=str, help="apk file or directory contains .apk/.APK or .dex")

    #
    args = parser.parse_args()
    if len(vars(args)) == 0:
        parser.print_help()
    else:
        args.func(args)
