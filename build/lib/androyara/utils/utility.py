# coding:utf8
'''
@File    :   utility.py
@Author  :   Loopher 
@Version :   1.0
@License :   (C)Copyright 2020-2021,Loopher
@Desc    :   common utility
'''


from termcolor import colored


def echo(tag, msg, color="green"):
    # show info
    try:
        print(colored("[{}]: {}".format(tag, msg), color=color))
    except UnicodeDecodeError as e:
        print("--> type : {}".format(type(msg)))
        raise e


def byte2str(s):
    if isinstance(s, bytes):
        s = str(s, encoding="utf-8")
    return s
