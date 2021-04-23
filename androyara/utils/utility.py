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
    print(colored("[{}]: {}".format(tag, msg), color=color))
