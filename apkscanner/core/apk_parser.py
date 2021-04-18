# -*- encoding: utf-8 -*-
'''
@File    :   apk_parser.py
@Author  :   Loopher 
@Version :   1.0
@License :   (C)Copyright 2020-2021, Loopher
@Desc    :   APk Information
'''

# 在这里将会读取处APK内的信息，包括 classes.dex 签名信息，签名版本v1 v2 v3 AndroidManifest.xml 包括app的指纹信息
# Here put the import lib
import os 
import io
import zipfile
import hashlib
import re
import logging 
from struct import unpack
from zlib import crc32

from apkscanner.parser.base_parser import BaserParser
from apkscanner.core.axml_parser import AndroidManifestXmlParser


log = logging.getLogger("apkscanner.apk")
class ApkReadException(BaseException):

    pass
class FileNotFound(BaseException):
    pass

class ApkPaser(BaserParser):

    parser_info={
        "name" :"ApkPaser",
        "desc":"Parse apk file "

    }
     # Constants in ZipFile
    _PK_END_OF_CENTRAL_DIR = b"\x50\x4b\x05\x06"
    _PK_CENTRAL_DIR = b"\x50\x4b\x01\x02"

    # Constants in the APK Signature Block
    _APK_SIG_MAGIC = b"APK Sig Block 42"
    _APK_SIG_KEY_V2_SIGNATURE = 0x7109871a
    _APK_SIG_KEY_V3_SIGNATURE = 0xf05368c0
    _APK_SIG_ATTR_V2_STRIPPING_PROTECTION = 0xbeeff00d

    _APK_SIG_ALGO_IDS = {
        0x0101 : "RSASSA-PSS with SHA2-256 digest, SHA2-256 MGF1, 32 bytes of salt, trailer: 0xbc",
        0x0102 : "RSASSA-PSS with SHA2-512 digest, SHA2-512 MGF1, 64 bytes of salt, trailer: 0xbc",
        0x0103 : "RSASSA-PKCS1-v1_5 with SHA2-256 digest.", # This is for build systems which require deterministic signatures.
        0x0104 : "RSASSA-PKCS1-v1_5 with SHA2-512 digest.", # This is for build systems which require deterministic signatures.
        0x0201 : "ECDSA with SHA2-256 digest",
        0x0202 : "ECDSA with SHA2-512 digest",
        0x0301 : "DSA with SHA2-256 digest",
    }


    def __init__(self,apk,buff=None):
        
        if apk is not None and  os.path.isfile(apk):
            print("--> apk ",apk )
            self.buff = open(apk,'rb').read()
        elif buff is not None:
            self.buff = buff
        else:
            raise ApkReadException("apk info read eror ,apk or buff must not be None")
        # 在这里统一读取出apk信息
        default_meta_info ={
            "classes":"classes",
            "AndroidManifest_xml":"AndroidManifest.xml",
            "Signature":""
        }
        self.zip_buff = zipfile.ZipFile(io.BytesIO(self.buff),mode='r')
        self._v2_blocks ={}

        self._is_signed_v2 = False
        self._is_signed_v3 = False
        # read AndroidManifestxml info 
        axml_buff = self.get_buff(default_meta_info['AndroidManifest_xml'])
        self.axml = AndroidManifestXmlParser(None,buff=axml_buff)
        # Read APK's fingerprint 
        self._app_md5 = hashlib.md5(self.buff).hexdigest()
        self._app_sha256 = hashlib.sha256(self.buff).hexdigest()
        self._app_crc32 = crc32(self.buff)
        #  eb5d886abb2f01efa0de268de38a1ee7 app_sha256:c924023051836aecffb9c302de440477e6a529573f1586a3312c42a17c818015 app_crc32:1318333930
        # print("--> app_md5: {} app_sha256:{} app_crc32:{} ".format(self._app_md5,self._app_sha256,self._app_crc32))
        # Read signature info 
        signatures_name  = self.get_v1_signature_names(v1=False)
        print("--> signtuares" ,signatures_name)
        print("Is V1 signed ",self.is_v1_signed())
        print("Is V2 signed ",self.is_signed_v2())
        print("Is V3 signed ",self.is_signed_v3())
        # Read 
        # print("--> AndoridManifest.xml info ",self.axml)

    def is_signed_v2(self):

        if self._is_signed_v2 is False:
            self.__parse_v2_v3_signature()
        return self._is_signed_v2

    def is_signed_v3(self):

        if self._is_signed_v3 is False:
            self.__parse_v2_v3_signature()
        return self._is_signed_v3
    

    def __parse_v2_v3_signature(self):
        # Read apk signature v2 v3 info 

        fp = io.BytesIO(self.buff)

        fp.seek(-1,io.SEEK_END)
        fp.seek(-20,io.SEEK_CUR)
        
        offset_central = 0

        while fp.tell()>0:
            fp.seek(-1,io.SEEK_CUR)
            r, = unpack('<4s',fp.read(4))
            if r == self._PK_END_OF_CENTRAL_DIR:
                this_disk,disk_central,this_entries,total_entries, \
                    size_central,offset_central = unpack('<HHHHII',fp.read(16))
                if this_disk !=0:
                    raise Exception("Read APK signture Info error,this_dist !=0  ,value: {}".format(this_disk))
                if disk_central !=0:
                    raise Exception("-> Read apk  signature info error ,disk_central !=0 ,value: {}".format(disk_central))
                break
            fp.seek(-1,io.SEEK_CUR)
        if not offset_central:
            return 
        fp.seek(offset_central)

        r,= unpack("<4s",fp.read(4))
        if r!=self._PK_CENTRAL_DIR:
            raise Exception("--> Not Found apk's central dir at {}".format(offset_central))

        end_off = fp.tell()

        fp.seek(-24,io.SEEK_CUR)

        size_of_block ,magic = unpack("<Q16s",fp.read(24))

     
        if magic != self._APK_SIG_MAGIC:
            log.warning("cant' Read apk v2 or v3 signature info ")
            return 

        
        fp.seek(-(size_of_block+8),io.SEEK_CUR)

        size_of_block_start,= unpack("<Q",fp.read(8))
        if size_of_block_start != size_of_block:
            raise Exception("Read apk's signature error ,size_of_block != size_of_block_start")

        # reach signature's block

        while fp.tell() > end_off -24:
            size,key = unpack("<QI",fp.read(12))
            value = fp.read(size-4)
            self._v2_blocks[key] = value 
        
        if self._APK_SIG_KEY_V2_SIGNATURE in self._v2_blocks:
            self._is_signed_v2 = True
        if self._APK_SIG_KEY_V3_SIGNATURE in self._blocks:
            self._is_signed_v3 = True



        

    def parse_v3_signing_block(self):

        self._v3_siging_data =[]
        if not self.is_signed_v3():
            return 
        
        block_bytes = self._v2_blocks[self._APK_SIG_KEY_V3_SIGNATURE]

        block = io.BytesIO(block_bytes)

        view = block.getvalue()

        size_sequence = self.read_uint32_le(block)

        # 等再补充读取签名信息 方法
        if size_sequence +4 != len(block_bytes):
            raise Exception("can't read v3 signature block")
            


    def get_certificate_der_v3(self):

        if self._v3_siging_data == None:
            self.parse_v3_signing_block()
        certs =[]
        for signed_data in [signer.data for signer in self._v3_siging_data]:
            for cert in signed_data.certificates:
                certs.append(cert)
        return certs

    
    def get_v1_signature_names(self,v1=True):
        """
        Read META-INF V1 signature file name
        """
        signature_xpr=re.compile(r"^(META-INF/)(.*)(\.RSA|\.EC|\.DSA)$")
        signature_names =[]
        for i in self.get_file_names():
            if signature_xpr.search(i):
                if v1 and "{}.SF".format(i.rsplit('.',1)[0]) in self.get_file_names():
                    signature_names.append(i)
                elif v1 is False:
                    # read all signature files 
                    signature_names.append(i)
                else:
                    log.warning("V1 signture file {} missing .SF file ".format(i))


        return signature_names

    
    def get_signatures(self):
        # Read all signature file data -> bytes buffer
        
        signatures =self.get_v1_signature_names(v1=False)
        signature_data = []
        for s in signatures:
            signature_data.append(self.get_buff(s))
        return signature_data


    def is_v1_signed(self):
        # If we read ,it will not be empty list 
        return len(self.get_v1_signature_names() ) >0

    def app_type(self):
        # Return file type 
        return "apk"

    def get_buff(self,name):
        """
        Read zipinfo from apk's internal file buff with name 
        """
        try:
            return self.zip_buff.read(name)
        except KeyError :
            raise FileNotFound(name)
    
    def get_classe_dex(self):

        return self.get_buff("classes.dex")

    def get_file_names(self):
        """
        Read zipinfo File 
        """

        return self.zip_buff.namelist()

    def __parse(self):
        """
        Read APK information
        """

        pass


