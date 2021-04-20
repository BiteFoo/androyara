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
    parser_info={
        "name" :"AndroidManifestXmlParser",
        "desc":"AndroidManifest.xml parser"

    }
    def __init__(self,manifest,buff=None):
        super(AndroidManifestXmlParser,self).__init__(manifest,buff)
        # if manifest is not None and os.path.isfile(manifest):
        #     self.buff = open(manifest,'rb').read()
        # elif buff is not None:
        #     self.buff = buff
        # else:
        #     raise AxmlExcetion("Need AndroidManifest.xml or buff data")
        xml_file  =  AXMLPrinter(self.buff) # 在这里解析出所有的xml信息
        self.axml ={}
        if not xml_file.is_valid():
            raise AxmlExcetion("while parsing AndroidManifest.xml error ")
        self.axml['AndroidManifest.xml'] = xml_file.get_xml_obj()
        # self.show_xml()

        if self.axml['AndroidManifest.xml'].tag !='manifest':
            raise AxmlExcetion("parse Android mnifest erro r")
        self.android_version ={}
        self.package = ""
        self.permissions =[]

        self.user_permission = [] # app内申请的权限

        self.package = self.get_attribute_value("manifest","package")

        self.android_version['Code'] = self.get_attribute_value("manifest","versionCode")
        self.android_version['Name'] = self.get_attribute_value("manifest","versionName")

        # Get ALl Permission 
        permisions = list(self.get_all_attribute_value("uses-permission","name"))
        self.permissions = list(set(permisions))



    def show_xml(self):

        for i,tag in enumerate(self.axml):
            
            # print("--> ",self.axml[i].tag)
            pass

    def find_tags(self,tag_name,**attribute_filter):
        all_tags = [
            self.find_tag_from_xml(i,tag_name,**attribute_filter) 
            for i  in self.axml
        ]
        return [tag for tag_list in all_tags for tag in tag_list]


    def find_tag_from_xml(self,xml_name ,tag_name,**attribute_filter):

        xml = self.axml[xml_name]
        if xml is None:
            return []
        if xml.tag == tag_name:
            if self.is_tag_matched(xml.tag,**attribute_filter):
                return [xml]
            return []
        tags =xml.findall(".//" + tag_name)
        return [
            tag for tag in tags if self.is_tag_matched(tag,**attribute_filter)

        ]

    def is_tag_matched(self,tag,**attribute_filter):
        if len(attribute_filter) <=0:
            return True
        for attr,value in attribute_filter.items():
            _value = self.get_value_from_tag(tag,attr)
            if _value != value:
                return False
        return True 
    
    def get_value_from_tag(self,tag,attribute):

        value = tag.get(self._ns(attribute))
        if value is None:
            # 如果不是通过namespace获取，则这个不是一个标准的AndroidManifest.xml的文件格式
            value = tag.get(attribute)
            if value:
                log.warning("--> Failed to get attribute {}  ,due to it is not AndroidManifest.xml data".format(attribute))
        return value 

    def _ns(self,name):
        return NS_ANDROID+name

    def get_attribute_value(self,tag_name,attribute,format_value=True,**attributes_filter):
        for value in self.get_all_attribute_value(tag_name,attribute,format_value,**attributes_filter):
            if value is not None:
                return value 
    def  get_all_attribute_value(self,tag_name,attribute,format_value=True,**attribute_filter):

        tags = self.find_tags(tag_name,**attribute_filter)
        for tag in tags:
            value = tag.get(attribute)  or tag.get(self._ns(attribute))
            if value is not None:
                if format_value:
                    yield self._format_value(value)
                else:
                    yield value 

    def _format_value(self,value):
        if value in self.package:
            dot = value.find('.')
            if dot ==0:
                value = self.package + value
            elif dot == -1:
                value = self.package+'.'+value 
        return value 

    def get_all_activities(self):

        return list(self.get_all_attribute_value("activity","name"))

    def get_all_services(self):

        return list(self.get_all_attribute_value("service", "name"))

    def get_permissions(self):

        return self.permissions
    
    def get_main_activity(self):

        log.warning("---> Get MainActivity maybe error ,due to pop first one activity from the list")
        activities =self.get_all_activities()
        if len(activities)>0:
            return self._format_value(activities.pop())
        return "Not Found MainActivity"

    def get_package_name(self):
        return self.package

    def get_application(self):

        try:
            return self.get_attribute_value("application","name")
        except ElementNotFound:
            return ""

    def get_providers(self):

        return list(self.get_all_attribute_value("provider","name"))
    
    def get_receivers(self):

        return list(self.get_all_attribute_value("receiver","name"))
        

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

        info+="--> activity info: \n"
        activities = self.get_all_activities()
        for activity in activities:
            info+=activity+"\n"
        
        info+='--> permission info: \n'
        permissions = self.permissions
        for per in permissions:
            info+=per+'\n'

        info+='--> receivers info: \n'
        receivers = self.get_receivers()
        for per in receivers:
            info+=per+'\n'

        info+='--> providers info: \n'
        providers = self.get_providers()
        for per in providers:
            info+=per+'\n'   
        return info 