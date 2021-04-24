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
from androyara.core.analysis_apk import AnalyzerApk
from androyara.core.axml_parser import AndroidManifestXmlParser


pattern = None
save = None
rule = None
input_file = None
method_name_arg = None


def query_report(resource):
    # default for vt
    if resource is None or resource == '':
        echo("error", "query_report resouroce must be empty or None", color="red")
        return
    vt = VT(resource)
    vt.analysis()


def apk_info(apk):
    # get_apk_info
    if not apk.endswith('.apk') and  apk.endswith('.APK'):
        echo("error", "need a apk file", 'red')
        return
    apk_parser = ApkPaser(apk)
    echo("info", "\n{}".format(json.dumps(apk_parser.apk_base_info(), indent=2)))

    # method


def extract_android_manifest_info():

    if not os.path.isfile(input_file):
        echo("error","need apk or AndroidManifest.xml as input file!!",'red')
        return 
    elif input_file.endswith('.xml'):
        axml = AndroidManifestXmlParser(input_file)
        echo("info","\n"+str(axml))
        pass
    elif input_file.endswith('apk'):
        apk_parser = ApkPaser(input_file)
        echo("info","\n"+str(apk_parser.mainifest_info()))
        pass
    else:
        echo("error","unknow {} filtyep ".format(input_file),'red')

def extract_apk_info(apk):
    if apk is None or not os.path.isfile(apk):
        return
    # echo("info", "pattern :%s" % (pattern))
    apk_parser = ApkPaser(apk)

    for s in apk_parser.all_strings([pattern]):
        echo("info", "%s" % (s))
    if method is None or method == '':
        #
        echo("warning", "no method name ", 'yellow')
        return
    echo("info", "--"*10+"show method : %s " % (method)+"--"*10)
    for class_def in apk_parser.all_class_defs():
        for method_ in class_def['code_item']:
            method_name = method_['method_name']
            try:
                if isinstance(method_name, bytes):
                    method_name = str(method_name, encoding="utf-8")
                    # echo("info", "method name: %s" % (method_name))
                if method_name_arg is None and method_name_arg == method_name:
                    echo("warning", "got method :%s" % (method), 'yellow')
                    apk_parser.print_ins(method_['code_off'])

            except UnicodeDecodeError:
                continue
    # for method in apk_parser.all_class_defs():
    #     echo("info", method)
    #  maybe too many ,need to save into file ,save will specificate.
    #echo("info", "{}".format(apk_parser.apk_strings(pattern)))
    # for s in apk_parser.all_class_defs(pattern):
    #     echo("info", s)

    # if save is not None:
    #     with open(save, 'w') as fp:
    #         fp.write(apk_parser.apk_strings(pattern))
    #     echo("info", "strings save at path : %s " % (save))


def dex_info(pkg, dex):
    # check dex file header
    # with open(dex,'rb') as fp:
    #     buff =
    patters = []
    if pkg is None:
        echo("warning", "pkg is None and will use empty to retrive all methods in dex file.", 'yellow')
    # if pattern is None:
    #     # retrive content:// and http(s)://
    #     # pattern = '://'
    #     patters.append("://")  # 默认
    #     echo("warning", "pattern is None,use :// to search string .", 'yellow')
    patters.append(pattern)
    with open(dex, 'rb') as f:

        vm = DexFileVM(pkgname=pkg, buff=f.read())
        if not vm.ok:
            echo("error", "{} is not a dex format file.", 'red')
            return
        for i, s in enumerate(vm.all_strings(patters)):
            echo("%d" % (i), "%s" % (s))
        echo("info","method_name_arg: %s"%(method_name_arg))
        for class_def in vm.all_class_defs():
            # echo("info","%s"%(class_def['class_name']))
            class_name = class_def['class_name']
            if isinstance(class_name,bytes):
                class_name = str(class_name,encoding="utf-8")
            for method in class_def['code_item']:
                method_name = method['method_name']

                try:
                    if isinstance(method_name, bytes):
                        method_name = str(method_name, encoding="utf-8")
                    if method_name_arg is not  None and method_name == method_name_arg:
                        echo("info"," -> %s/%s"%(class_name,method_name))
                        vm.print_ins(method['code_off'])
                    elif method_name_arg is None:
                        echo("info"," -> %s/%s"%(class_name,method_name))


                except UnicodeDecodeError:
                    continue


def analysis_apk(apk):
    # scan apk  include AVEngin and vt check
    # 检测
    echo("info", "analysis apk {} ".format(apk))
    if os.path.isfile(apk):
        if not apk.endswith('.apk') or not apk.endswith('.APK'):
            echo("error", "need a apk file !!", 'red')
            return
        analyzer = AnalyzerApk(apk, rule, pattern)
        analyzer.analyzer()

    elif os.path.isdir(apk):
        for root, _, fs in os.walk(apk):
            for f in fs:
                if f.endswith('.apk') or not f.endswith('.APK'):
                    infile = os.path.join(root, f)
                    # analysis 1
                    analyzer = AnalyzerApk(infile, rule, pattern)
                    analyzer.analyzer()


if __name__ == '__main__':

    parser = argparse.ArgumentParser(prog=None,

                                     description="Apkscanner is a tool for android apk to  retrieve some information and analysis android virus feature written by Loopher.Version:1.0")

    parser.add_argument("-f", "--file", metavar="apk|dex|AndroidManifest.xml",
                        type=str, default="", help="--file   apk|dex|AndroidManifest.xml "
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

    parser.add_argument('-d', '--dex', default=False, type=bool,
                        metavar="true/false", help="A dex file for retriving methods and strings,default False give.")
    parser.add_argument("-p", '--pkg', default=None, type=str, metavar="packagename",
                        help="A package name for retriving dex file methods and strings.")
    parser.add_argument("-g", '--pattern', default=None, type=str, metavar="reg pattern",
                        help='A reg pattern for retriving apk\'s or dex\'s string content,use comma to split')
    parser.add_argument("-a", '--analysis', default=False, type=bool,
                        metavar="true/false", help="--analysis if true will analysis apk ,need -f is apkfile")

    parser.add_argument('-m', '--method_name', default=None, type=str,
                        metavar="method_name ", help="A method name in dex file.")
    parser.add_argument('-x','--xml',default=False,metavar="true/false",type=bool,help='--xml read AndroidManifest.xml or apk\' AndroidManifest.xml information')
    args = parser.parse_args()

    pattern = args.pattern
    save = args.save
    rule = args.rule
    input_file = args.file
    method_name_arg = args.method_name

    echo("info","dex: {} info: {} extract: {}  analysis: {}".format(args.dex,args.info,args.extract,args.analysis))

    if rule is not None:
        if not os.path.isfile(rule):
            echo("error", "a rule file need to specificate!!", 'red')
            parser.print_help()
            sys.exit(1)
    if not os.path.isfile(input_file) and not os.path.isdir(input_file):
        echo("error", "need file or directory!!.", "red")
        parser.print_help()
        sys.exit(1)

    
    if args.info:
        if not os.path.isfile(input_file):
            echo("error", "apk need to specificate.", "red")
            parser.print_help()
            sys.exit(1)
        apk_info(apk=input_file)
    
    elif args.extract:
        if save is None:
            echo(
                'warning', "specificate -e but no save file ,will not save strings result !", 'yellow')
        extract_apk_info(apk=input_file)
    elif args.query:
        with open(input_file, 'rb') as fp:
            resource = hashlib.sha256(fp.read()).hexdigest()
            query_report(resource)
    elif args.dex:
        dex_info(args.pkg, args.file)

    elif args.xml:
        extract_android_manifest_info()
    elif args.analysis:
        analysis_apk(input_file)

    else:
        parser.print_help()
