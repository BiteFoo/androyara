# -*- encoding: utf-8 -*-
'''
@File    :   axml.py
@Author  :   Loopher
@Version :   1.0
@License :   (C)Copyright 2020-2021, Loopher
@Desc    :   AndroidManifest.xml parser
'''

# Here put the import lib

import os

from apkscanner.parser.base_parser import BaserParser
from apkscanner.types.types import*


NS_ANDROID_URI = 'http://schemas.android.com/apk/res/android'
NS_ANDROID = '{{{}}}'.format(NS_ANDROID_URI)  # Namespace as used by etree


class AxmlExcetion(BaseException):
    pass


class ElementNotFound(BaseException):
    pass


class AndroidManifestXmlParser(BaserParser):
    parser_info = {
        "name": "AndroidManifestXmlParser",
        "desc": "AndroidManifest.xml parser"

    }

    def __init__(self, manifest, buff=None):
        super(AndroidManifestXmlParser, self).__init__(manifest, buff)

        xml_file = AXMLPrinter(self.buff)  # 在这里解析出所有的xml信息
        self.axml = {}
        if not xml_file.is_valid():
            raise AxmlExcetion("while parsing AndroidManifest.xml error ")
        self.axml['AndroidManifest.xml'] = xml_file.get_xml_obj()
        # self.show_xml()

        if self.axml['AndroidManifest.xml'].tag != 'manifest':
            raise AxmlExcetion("parse Android mnifest erro r")
        self.android_version = {}
        self.package = ""
        self.permissions = []

        self.user_permission = []  # app内申请的权限

        self.package = self.get_attribute_value("manifest", "package")

        self.android_version['Code'] = self.get_attribute_value(
            "manifest", "versionCode")
        self.android_version['Name'] = self.get_attribute_value(
            "manifest", "versionName")

        # Get ALl Permission
        permisions = list(self.get_all_attribute_value(
            "uses-permission", "name"))
        self.permissions = list(set(permisions))

    def get_all_export_components(self):

        export_keys = ["activity", "service", "provider", "receiver"]
        result = {}
        for k in export_keys:

            result[k] = list(self.get_all_attribute_value(
                k, "name", {"exported": "true"}))
        return result

    def find_tags(self, tag_name, **attribute_filter):
        all_tags = [
            self.find_tag_from_xml(i, tag_name, **attribute_filter)
            for i in self.axml
        ]
        return [tag for tag_list in all_tags for tag in tag_list]

    def find_tag_from_xml(self, xml_name, tag_name, **attribute_filter):

        xml = self.axml[xml_name]
        if xml is None:
            return []
        if xml.tag == tag_name:
            if self.is_tag_matched(xml.tag, **attribute_filter):
                return [xml]
            return []
        tags = xml.findall(".//" + tag_name)
        return [
            tag for tag in tags if self.is_tag_matched(tag, **attribute_filter)

        ]

    def is_tag_matched(self, tag, **attribute_filter):
        if len(attribute_filter) <= 0:
            return True
        for attr, value in attribute_filter.items():
            _value = self.get_value_from_tag(tag, attr)
            if _value == value:
                return True
        return False

    def get_value_from_tag(self, tag, attribute):

        value = tag.get(self._ns(attribute))
        if value is None:
            # 如果不是通过namespace获取，则这个不是一个标准的AndroidManifest.xml的文件格式
            value = tag.get(attribute)
            if value:
                log.warning(
                    "--> Failed to get attribute {}  ,due to it is not AndroidManifest.xml data".format(attribute))
        return value

    def _ns(self, name):
        return NS_ANDROID+name

    def get_attribute_value(self, tag_name, attribute, format_value=True, **attributes_filter):
        for value in self.get_all_attribute_value(tag_name, attribute, format_value, **attributes_filter):
            if value is not None:
                return value

    def get_all_attribute_value(self, tag_name, attribute, format_value=True, **attribute_filter):

        tags = self.find_tags(tag_name, **attribute_filter)
        for tag in tags:
            value = tag.get(attribute) or tag.get(self._ns(attribute))
            if value is not None:
                if format_value:
                    yield self._format_value(value)
                else:
                    yield value

    def _format_value(self, value):
        if value in self.package:
            dot = value.find('.')
            if dot == 0:
                value = self.package + value
            elif dot == -1:
                value = self.package+'.'+value
        return value

    def get_all_activities(self):

        return list(self.get_all_attribute_value("activity", "name"))

    def get_all_services(self):

        return list(self.get_all_attribute_value("service", "name"))

    def get_permissions(self):

        return self.permissions

    def get_main_activities(self):

        x = set()
        y = set()

        for i in self.axml:
            if self.axml[i] is None:
                continue
            manifest = self.axml[i]
            activities_aliases = manifest.findall(".//activity") + \
                manifest.findall(".//activity-alias")
            for item in activities_aliases:
                activity_enable = item.get(self._ns("enabled"))
                if activity_enable == 'false':
                    continue

                for sitem in item.findall(".//action"):
                    val = sitem.get(self._ns("name"))
                    if val == 'android.intent.action.MAIN':
                        x.add(item.get(self._ns("name")))

                for sitem in item.findall(".//category"):
                    val = sitem.get(self._ns("name"))
                    if val == "android.intent.category.LAUNCHER":
                        y.add(item.get(self._ns("name")))

                # 有些app的MainActivity的属性表情中含有VIEW DEFAULT BROWSABLE 的，这里再次判断是否包含在了y内
        return y.intersection(x)

    def get_main_activity(self):
        """
        For some application:  category maybe more than one ,so I will pick on one for MAIN. 
        """

        x = set()
        y = set()
        for i in self.axml:
            if self.axml[i] is None:
                continue
            manifest = self.axml[i]
            activities_aliases = manifest.findall(".//activity") + \
                manifest.findall(".//activity-alias")
            for item in activities_aliases:
                activity_enable = item.get(self._ns("enabled"))
                if activity_enable == 'false':
                    continue

                for sitem in item.findall(".//action"):
                    val = sitem.get(self._ns("name"))
                    if val == 'android.intent.action.MAIN':
                        x.add(item.get(self._ns("name")))

                category = item.findall(".//category")

                if len(category) >= 2 or len(category) >= 3:
                    continue
                for sitem in item.findall(".//category"):
                    val = sitem.get(self._ns("name"))
                    if val == "android.intent.category.LAUNCHER":
                        y.add(item.get(self._ns("name")))

        activities = y.intersection(x)

        if len(activities) > 0:
            main_activity = self._format_value(activities.pop())
            if main_activity.startswith("."):
                # maybe need add package to .MainActivity
                main_activity = self.package + main_activity
            return main_activity
        return "Not Found MainActivity"

    def get_package_name(self):
        return self.package

    def get_application(self):

        try:
            return self.get_attribute_value("application", "name")
        except ElementNotFound:
            # for some application Not
            return ""

    def get_providers(self):

        return list(self.get_all_attribute_value("provider", "name"))

    def get_receivers(self):

        return list(self.get_all_attribute_value("receiver", "name"))

    def get_thrid_sdk_metas(self):
        """
        Return Thrid part sdk info
        """

        pass

    def get_export_components(self):
        """
        Return All export components info
        """

        pass

    def get_app_name(self):
        """
        Androguard read this value from AndroidManifest or resource.asrc file ,but I'll not read it too complicate
        """

        app_name = self.get_attribute_value('application', 'label')
        if app_name is None:
            return ""
        return app_name

    def __str__(self):

        info = "--"*10+self.get_app_name()+" pkgname:"+self.package+"--"*10+"  \n"

        info += "--> activity info: \n"
        activities = self.get_all_activities()
        for activity in activities:
            info += activity+"\n"

        info += '--> permission info: \n'
        permissions = self.permissions
        for per in permissions:
            info += per+'\n'

        info += '--> receivers info: \n'
        receivers = self.get_receivers()
        for per in receivers:
            info += per+'\n'

        info += '--> providers info: \n'
        providers = self.get_providers()
        for per in providers:
            info += per+'\n'
        return info
