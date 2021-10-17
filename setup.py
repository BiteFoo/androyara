# -*- encoding: utf-8 -*-
'''
@File    :   setup.py
@Author  :   Loopher 
@Version :   1.0
@License :   (C)Copyright 2020-2021, Loopher
@Desc    :   None
'''

# Here put the import lib
import codecs
import setuptools

with codecs.open("readme.md", "r",encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="androyara",
    version="2.0",
    author="BiteFoo",
    author_email="1653946112@qq.com",
    description="A tool is use to analyzer Android malware",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/BiteFoo/androyara",
    packages=setuptools.find_packages(),
    #data_files=[('androyara/typeinfo/public.xml', ['androyara/typeinfo/public.xml']), ],
    package_data={
        # 引入任何包下面的 *.txt、*.rst 文件

        "": ["*.xml"],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache-2.0",
        "Operating System :: OS Independent",
    ],
     install_requires=[               # 该库需要的依赖库
        'termcolor >= 1.1.0',
        'lxml >= 4.6.2',
        'requests >= 2.25.1',
        'yara >= 1.7.7',
        'asn1crypto >=1.4.0',
        "androguard>=3.3.5"
        # exapmle
    ],
    python_requires='>=3.7',
)