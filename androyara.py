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
from androyara.utils.utility import byte2str
from androyara.dex.dex_vm import DexFileVM
from androyara.utils.utility import echo
from androyara.vsbox.vt import VT
from androyara.core.apk_parser import ApkPaser
from androyara.core.analysis_apk import AnalyzerApk
from androyara.core.axml_parser import AndroidManifestXmlParser


pattern = None
save = None
rule = None
input_file = None
method_name_arg = None
pkg = None
fingerprint = None


def query_report(args):

    # default for vt
    print("fp ", args.fingerprint)
    resource = args.fingerprint
    if resource is None and input_file is not None and os.path.isfile(input_file):
        with open(input_file, 'rb') as fp:
            resource = hashlib.sha256(fp.read()).hexdigest()

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
        echo("info", "\napkInfo:\n{}".format(
            json.dumps(apk_parser.apk_base_info(), indent=2)))
        print("--"*20)

    # zipinfo
    if zip_info:
        for f in apk_parser.get_file_names():
            echo("info", "-> %s" % (f))

    # method


def extract_android_manifest_info():

    if not os.path.isfile(input_file):
        echo("error", "need apk or AndroidManifest.xml as input file!!", 'red')
        return
    elif input_file.endswith('.xml'):
        axml = AndroidManifestXmlParser(input_file)
        echo("info", "\n"+str(axml))
        pass
    elif input_file.endswith('apk'):
        apk_parser = ApkPaser(input_file)
        echo("info", "\n"+str(apk_parser.mainifest_info()))
    else:
        echo("error", "unknow {} filtyep ".format(input_file), 'red')


def extract_apk_info(args):
    input_file = args.apk
    pattern = args.pattern
    method_name_arg = args.method

    if input_file is None or not os.path.isfile(input_file):
        echo("error", "need a apk file", 'red')
        return
    if pattern is None:
        pattern = "://"
    # echo("info", "pattern :%s" % (pattern))
    apk_parser = ApkPaser(input_file)

    for s in apk_parser.all_strings([pattern]):
        echo("info", "%s" % (s))
    # if method_name_arg is None or method_name_arg == '':
    #     #
    #     echo("warning", "no method name ", 'yellow')
    #     return

    echo("info", "--"*10+"show method info: %s " % (method_name_arg)+"--"*10)
    for class_def in apk_parser.all_class_defs():
        clzz_name = byte2str(class_def['class_name'])
        # echo("info", "%s" % (clzz_name))

        for method_ in class_def['code_item']:

            method_name = byte2str(method_['method_name'])
            signature = byte2str(method_['signature'])

            if method_name_arg is None:
                echo("info", "-> %s-->%s%s" %
                     (clzz_name, method_name, signature))

            elif method_name_arg == method_name:
                echo("info", "className: %s" % (clzz_name))
                echo("info", "methodName: %s" % (method_name))
                echo("info", "signature: %s" % (signature))
                echo("instructions", "--"*10, 'yellow')

                # echo("warning", "got method :%s" %
                #      (method_name_arg), 'yellow')
                apk_parser.print_ins(method_['code_off'])


def dex_info(args):
    # check dex file header
    # with open(dex,'rb') as fp:
    #     buff =
    input_file = args.dex
    pattern = args.pattern
    method_name_arg = args.method
    pkg = args.pkgname

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
        if not vm.ok:
            echo("error", "{} is not a dex format file.", 'red')
            return
        if pattern is not None:
            # if pattern is not None will show string
            for i, s in enumerate(vm.all_strings(patters)):
                echo("%d" % (i), "%s" % (s))
        if method_name_arg is None:
            echo("warning", " methodName 为空，默认输出全部方法信息", 'yellow')
        for class_def in vm.all_class_defs():
            class_name = byte2str(class_def['class_name'])

            for method in class_def['code_item']:
                method_name = byte2str(method['method_name'])
                signature = byte2str(method['signature'])

                if method_name_arg is not None and method_name == method_name_arg:
                    print("")
                    echo("info", " Got target -> %s-->%s%s" %
                         (class_name, method_name, signature))
                    vm.print_ins(method['code_off'])
                elif method_name_arg is None:
                    echo("info", " -> %s-->%s%s" %
                         (class_name, method_name, signature))


def analysis_apk(args):

    input_file = args.input_file
    pattern = args.pattern
    rule = args.rule

    if not os.path.isfile(input_file) and not os.path.isdir(input_file):
        echo("error", "need file or directory!!.", "red")
        parser.print_help()
        sys.exit(1)

    if rule is None or not os.path.isfile(rule):
        echo("error", "need rule.json", 'red')
        sys.exit(1)

    if os.path.isfile(input_file):
        if not input_file.endswith('.apk') and not input_file.endswith('.APK'):
            echo("error", "need a apk file !!", 'red')
            sys.exit(1)

        analyzer = AnalyzerApk(input_file, rule, pattern)
        analyzer.analyzer()

    elif os.path.isdir(input_file):
        cnt = 0
        shot = 0
        # echo("info", "scan dir : %s" % (apk), 'magenta')
        for root, _, fs in os.walk(input_file):
            for f in fs:
                if f.endswith('.apk') or f.endswith('.APK'):
                    cnt += 1
                    infile = os.path.join(root, f)
                    # echo("debug", "find target : %s" % (infile), 'blue')
                    analyzer = AnalyzerApk(infile, rule, pattern)
                    if analyzer.analyzer():
                        shot += 1
        echo("warning", "total scan: %d positive:%d" % (cnt, shot), 'yellow')


if __name__ == '__main__':

    parser = argparse.ArgumentParser(usage="%(prog)s [options]")
    subparsers = parser.add_subparsers(title="options")

    # query vt
    query_parser = subparsers.add_parser("query", help="query from VT")
    query_parser.set_defaults(func=query_report)
    query_parser.add_argument(
        "-fp", "--fingerprint", type=str, default=None, help="-fp|--fingerprint sh256.")

    # analysis apk
    analysis_parser = subparsers.add_parser("analysis", help=" analysis apk.")
    analysis_parser.set_defaults(func=analysis_apk)
    analysis_parser.add_argument(
        "-f", "--file", type=str, default=None, help="apk file or directory ,default None.")
    analysis_parser.add_argument(
        "-r", "--rule", type=str, default=None, help="A rule's file,like demo.json.")
    analysis_parser.add_argument(
        "-p", "--pattern", type=str, default=None, help="A reg pattern use to search string ,default None. ")
    # search infor from  dex
    analysis_dex = subparsers.add_parser(
        "search_dex", help="search dex string or method all instructions from dex")
    analysis_dex.set_defaults(func=dex_info)
    analysis_dex.add_argument("-d", "--dex", type=str,
                              default=None, help="A dex file")
    analysis_dex.add_argument(
        "-p", "--pattern", type=str, default=None, help="A reg pattern,eg: ^(aaa).+ or ^(aaa).+,^(bbb).?")
    analysis_dex.add_argument("-m", "--method", type=str,
                              default=None, help="A method Name in the dex file.")
    analysis_dex.add_argument("-pkg", "--pkgname", type=str,
                              default=None, help="class pkgname")
    # analysis AndroidManifest.xml
    manifest_parser = subparsers.add_parser(
        "manifest", help=" Parsing Binary AndroidManifest.xml")
    manifest_parser.set_defaults(func=extract_android_manifest_info)
    manifest_parser.add_argument("-m", "--manifest", type=str, default=None,
                                 help="A binary AndroidManifest.xml or apk contain's AndroidManifest.xml")

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
        "-p", "--pattern", type=str, default=None, help="A string eg: \"hello\" or  reg pattern,eg: \"^(aaa).+ or ^(aaa).+,^(bbb).?\"")
    # 使用method name 输出指令
    search_from_apk.add_argument(
        "-m", "--method", type=str, default=None, help="a method name in apk ")

    #
    args = parser.parse_args()
    if len(vars(args)) == 0:
        parser.print_help()
    else:
        args.func(args)
