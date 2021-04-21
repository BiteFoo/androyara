# -*- encoding: utf-8 -*-
'''
@File    :   apk_parser.py
@Author  :   Loopher 
@Version :   1.0
@License :   (C)Copyright 2020-2021, Loopher
@Desc    :   APk Information

Here's all code are from androgurad.
'''

# 在这里将会读取处APK内的信息，包括 classes.dex 签名信息，签名版本v1 v2 v3 AndroidManifest.xml 包括app的指纹信息
# Here put the import lib

import io
import json
import codecs
import zipfile
import hashlib
import re
import logging
from struct import unpack
from zlib import crc32
import binascii
import asn1crypto
from asn1crypto import cms, x509, keys
from apkscanner.parser.base_parser import BaserParser
from apkscanner.core.axml_parser import AndroidManifestXmlParser, ARSCParser, ARSCResTableConfig

log = logging.getLogger("apkscanner.apk")


class ApkReadException(BaseException):

    pass


class FileNotFound(BaseException):
    pass


def get_certificate_name_string(name, short=False, delimiter=', '):
    """
    Format the Name type of a X509 Certificate in a human readable form.

    :param name: Name object to return the DN from
    :param short: Use short form (default: False)
    :param delimiter: Delimiter string or character between two parts (default: ', ')

    :type name: dict or :class:`asn1crypto.x509.Name`
    :type short: boolean
    :type delimiter: str

    :rtype: str
    """
    if isinstance(name, asn1crypto.x509.Name):
        name = name.native

    # For the shortform, we have a lookup table
    # See RFC4514 for more details
    _ = {
        'business_category': ("businessCategory", "businessCategory"),
        'serial_number': ("serialNumber", "serialNumber"),
        'country_name': ("C", "countryName"),
        'postal_code': ("postalCode", "postalCode"),
        'state_or_province_name': ("ST", "stateOrProvinceName"),
        'locality_name': ("L", "localityName"),
        'street_address': ("street", "streetAddress"),
        'organization_name': ("O", "organizationName"),
        'organizational_unit_name': ("OU", "organizationalUnitName"),
        'title': ("title", "title"),
        'common_name': ("CN", "commonName"),
        'initials': ("initials", "initials"),
        'generation_qualifier': ("generationQualifier", "generationQualifier"),
        'surname': ("SN", "surname"),
        'given_name': ("GN", "givenName"),
        'name': ("name", "name"),
        'pseudonym': ("pseudonym", "pseudonym"),
        'dn_qualifier': ("dnQualifier", "dnQualifier"),
        'telephone_number': ("telephoneNumber", "telephoneNumber"),
        'email_address': ("E", "emailAddress"),
        'domain_component': ("DC", "domainComponent"),
        'name_distinguisher': ("nameDistinguisher", "nameDistinguisher"),
        'organization_identifier': ("organizationIdentifier", "organizationIdentifier"),
    }
    return delimiter.join(["{}={}".format(_.get(attr, (attr, attr))[0 if short else 1], name[attr]) for attr in name])

# -------------------------


def _dump_additional_attributes(additional_attributes):
    """ try to parse additional attributes, but ends up to hexdump if the scheme is unknown """

    attributes_raw = io.BytesIO(additional_attributes)
    attributes_hex = binascii.hexlify(additional_attributes)

    if not len(additional_attributes):
        return attributes_hex

    len_attribute, = unpack('<I', attributes_raw.read(4))
    if len_attribute != 8:
        return attributes_hex

    attr_id, = unpack('<I', attributes_raw.read(4))
    if attr_id != ApkPaser._APK_SIG_ATTR_V2_STRIPPING_PROTECTION:
        return attributes_hex

    scheme_id, = unpack('<I', attributes_raw.read(4))

    return "stripping protection set, scheme %d" % scheme_id


def _dump_digests_or_signatures(digests_or_sigs):

    infos = ""
    for i, dos in enumerate(digests_or_sigs):

        infos += "\n"
        infos += " [%d]\n" % i
        infos += "  - Signature Id : %s\n" % ApkPaser._APK_SIG_ALGO_IDS.get(
            dos[0], hex(dos[0]))
        infos += "  - Digest: %s" % binascii.hexlify(dos[1])

    return infos


class APKV2SignedData:
    """
    This class holds all data associated with an APK V3 SigningBlock signed data.
    source : https://source.android.com/security/apksigning/v2.html
    """

    def __init__(self):
        self._bytes = None
        self.digests = None
        self.certificates = None
        self.additional_attributes = None

    def __str__(self):

        certs_infos = ""

        for i, cert in enumerate(self.certificates):
            x509_cert = x509.Certificate.load(cert)

            certs_infos += "\n"
            certs_infos += " [%d]\n" % i
            certs_infos += "  - Issuer: %s\n" % get_certificate_name_string(
                x509_cert.issuer, short=True)
            certs_infos += "  - Subject: %s\n" % get_certificate_name_string(
                x509_cert.subject, short=True)
            certs_infos += "  - Serial Number: %s\n" % hex(
                x509_cert.serial_number)
            certs_infos += "  - Hash Algorithm: %s\n" % x509_cert.hash_algo
            certs_infos += "  - Signature Algorithm: %s\n" % x509_cert.signature_algo
            certs_infos += "  - Valid not before: %s\n" % x509_cert['tbs_certificate']['validity']['not_before'].native
            certs_infos += "  - Valid not after: %s" % x509_cert['tbs_certificate']['validity']['not_after'].native

        return "\n".join([
            'additional_attributes : {}'.format(
                _dump_additional_attributes(self.additional_attributes)),
            'digests : {}'.format(_dump_digests_or_signatures(self.digests)),
            'certificates : {}'.format(certs_infos),
        ])


class APKV3SignedData(APKV2SignedData):
    """
    This class holds all data associated with an APK V3 SigningBlock signed data.
    source : https://source.android.com/security/apksigning/v3.html
    """

    def __init__(self):
        super().__init__()
        self.minSDK = None
        self.maxSDK = None

    def __str__(self):

        base_str = super().__str__()

        # maxSDK is set to a negative value if there is no upper bound on the sdk targeted
        max_sdk_str = "%d" % self.maxSDK
        if self.maxSDK >= 0x7fffffff:
            max_sdk_str = "0x%x" % self.maxSDK

        return "\n".join([
            'signer minSDK : {:d}'.format(self.minSDK),
            'signer maxSDK : {:s}'.format(max_sdk_str),
            base_str
        ])


class APKV2Signer:
    """
    This class holds all data associated with an APK V2 SigningBlock signer.
    source : https://source.android.com/security/apksigning/v2.html
    """

    def __init__(self):
        self._bytes = None
        self.signed_data = None
        self.signatures = None
        self.public_key = None

    def __str__(self):
        return "\n".join([
            '{:s}'.format(str(self.signed_data)),
            'signatures : {}'.format(
                _dump_digests_or_signatures(self.signatures)),
            'public key : {}'.format(binascii.hexlify(self.public_key)),
        ])


class APKV3Signer(APKV2Signer):
    """
    This class holds all data associated with an APK V3 SigningBlock signer.
    source : https://source.android.com/security/apksigning/v3.html
    """

    def __init__(self):
        super().__init__()
        self.minSDK = None
        self.maxSDK = None

    def __str__(self):

        base_str = super().__str__()

        # maxSDK is set to a negative value if there is no upper bound on the sdk targeted
        max_sdk_str = "%d" % self.maxSDK
        if self.maxSDK >= 0x7fffffff:
            max_sdk_str = "0x%x" % self.maxSDK

        return "\n".join([
            'signer minSDK : {:d}'.format(self.minSDK),
            'signer maxSDK : {:s}'.format(max_sdk_str),
            base_str
        ])


# -------------------

class ApkPaser(BaserParser):

    parser_info = {
        "name": "ApkPaser",
        "desc": "Parse apk file "

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
        0x0101: "RSASSA-PSS with SHA2-256 digest, SHA2-256 MGF1, 32 bytes of salt, trailer: 0xbc",
        0x0102: "RSASSA-PSS with SHA2-512 digest, SHA2-512 MGF1, 64 bytes of salt, trailer: 0xbc",
        # This is for build systems which require deterministic signatures.
        0x0103: "RSASSA-PKCS1-v1_5 with SHA2-256 digest.",
        # This is for build systems which require deterministic signatures.
        0x0104: "RSASSA-PKCS1-v1_5 with SHA2-512 digest.",
        0x0201: "ECDSA with SHA2-256 digest",
        0x0202: "ECDSA with SHA2-512 digest",
        0x0301: "DSA with SHA2-256 digest",
    }

    def __init__(self, apk, buff=None):

        super(ApkPaser, self).__init__(apk, buff)

        # 在这里统一读取出apk信息
        default_meta_info = {
            "classes": "classes",
            "AndroidManifest_xml": "AndroidManifest.xml",
            "arsc": "resources.arsc"
        }

        self.raw = self.buff

        self.zip_buff = zipfile.ZipFile(io.BytesIO(self.buff), mode='r')
        self._v2_blocks = {}

        self._is_signed_v2 = False
        self._is_signed_v3 = False

        self._v3_siging_data = None
        self._v2_signing_data = None
        # read AndroidManifestxml info
        arsc_buff = self.get_buff(default_meta_info['arsc'])
        self.asrc = ARSCParser(arsc_buff)

        axml_buff = self.get_buff(default_meta_info['AndroidManifest_xml'])
        self.axml = AndroidManifestXmlParser(None, buff=axml_buff)
        # Read APK's fingerprint
        self._app_md5 = hashlib.md5(self.buff).hexdigest()
        self._app_sha256 = hashlib.sha256(self.buff).hexdigest()
        self._app_crc32 = crc32(self.buff)

        # len(self.buff)  # len(self.buff) / 1024
        self.filesize = int(len(self.buff) / 1024)
        #  eb5d886abb2f01efa0de268de38a1ee7 app_sha256:c924023051836aecffb9c302de440477e6a529573f1586a3312c42a17c818015 app_crc32:1318333930
        # print("--> app_md5: {} app_sha256:{} app_crc32:{} ".format(self._app_md5,self._app_sha256,self._app_crc32))
        # Read signature info
        # signatures_name  = self.get_v1_signature_names(v1=False)
        # print("--> signtuares" ,signatures_name)
        # print("Is V1 signed ",self.is_v1_signed())
        # print("Is V2 signed ",self.is_signed_v2())
        # print("Is V3 signed ",self.is_signed_v3())

        self.package = self.axml.package
        # Read
        # print("--> AndoridManifest.xml info ",self.axml)

    def apk_base_info(self):
        apk_info = {
            "appName":self.get_app_name(),
            "signed": {
                "v1": self.is_signed_v1(),
                "v2": self.is_signed_v2(),
                "v3": self.is_signed_v3()
            },
            "certifacte": self.certification_info(),
            "package": self.package,
            "versionCode": self.axml.android_version['Code'],
            "versionName": self.axml.android_version['Name'],
            "Application": self.axml.get_application(),
            "sha256": self._app_sha256,
            "md5": self._app_md5,
            "crc32": hex(self._app_crc32),
            "file": self.filename,
            "filetype": self.get_type(),
            "filesize": self.filesize,
            "mainActivity": self.axml.get_main_activity()
            # "manifest":str(self.axml)
        }
        return apk_info

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

        fp = io.BytesIO(self.raw)

        fp.seek(-1, io.SEEK_END)
        fp.seek(-20, io.SEEK_CUR)

        offset_central = 0

        while fp.tell() > 0:
            fp.seek(-1, io.SEEK_CUR)
            r, = unpack('<4s', fp.read(4))
            if r == self._PK_END_OF_CENTRAL_DIR:
                this_disk, disk_central, this_entries, total_entries, \
                    size_central, offset_central = unpack(
                        '<HHHHII', fp.read(16))
                if this_disk != 0:
                    raise Exception(
                        "Read APK signture Info error,this_dist !=0  ,value: {}".format(this_disk))
                if disk_central != 0:
                    raise Exception(
                        "-> Read apk  signature info error ,disk_central !=0 ,value: {}".format(disk_central))
                break
            fp.seek(-1, io.SEEK_CUR)

        if not offset_central:
            return

        fp.seek(offset_central)
        r, = unpack("<4s", fp.read(4))
        fp.seek(-4, io.SEEK_CUR)

        if r != self._PK_CENTRAL_DIR:
            raise Exception(
                "--> Not Found apk's central dir at {}".format(offset_central))

        end_off = fp.tell()
        fp.seek(-24, io.SEEK_CUR)
        size_of_block, magic = unpack("<Q16s", fp.read(24))

        self._is_signed_v2 = False
        self._is_signed_v3 = False

        if magic != self._APK_SIG_MAGIC:
            log.warning("cant' Read apk v2 or v3 signature info ")
            return

        fp.seek(-(size_of_block+8), io.SEEK_CUR)

        size_of_block_start, = unpack("<Q", fp.read(8))
        # print("--> size_of_block_start ",size_of_block_start ," size_of_block ",size_of_block)
        if size_of_block_start != size_of_block:
            raise Exception(
                "Read apk's signature error ,size_of_block != size_of_block_start")

        # reach signature's block
        while fp.tell() < end_off - 24:
            size, key = unpack("<QI", fp.read(12))
            value = fp.read(size-4)
            self._v2_blocks[key] = value
        # print("--> ",self._v2_blocks)
        if self._APK_SIG_KEY_V2_SIGNATURE in self._v2_blocks:
            self._is_signed_v2 = True
        if self._APK_SIG_KEY_V3_SIGNATURE in self._v2_blocks:
            self._is_signed_v3 = True

    def parse_v3_signing_block(self):

        # print("-> read v3 signature ")
        self._v3_siging_data = []
        if not self.is_signed_v3():
            return

        block_bytes = self._v2_blocks[self._APK_SIG_KEY_V3_SIGNATURE]

        block = io.BytesIO(block_bytes)

        # view = block.getvalue()

        size_sequence = self.read_uint32_le(block)

        # 等再补充读取签名信息 方法
        if size_sequence + 4 != len(block_bytes):
            raise Exception("can't read v3 signature block")

    def read_uint32_le(self, buff):

        return unpack("<I", buff.read(4))[0]

    def get_certificate_der_v3(self):

        if self._v3_siging_data == None:
            self.parse_v3_signing_block()
        certs = []
        for signed_data in [signer.data for signer in self._v3_siging_data]:
            for cert in signed_data.certificates:
                certs.append(cert)
        return certs

    def get_v1_signature_names(self, v1=True):
        """
        Read META-INF V1 signature file name
        """
        signature_xpr = re.compile(r"^(META-INF/)(.*)(\.RSA|\.EC|\.DSA)$")
        signature_names = []
        for i in self.get_file_names():
            if signature_xpr.search(i):
                if v1 and "{}.SF".format(i.rsplit('.', 1)[0]) in self.get_file_names():
                    signature_names.append(i)
                elif v1 is False:
                    # read all signature files
                    signature_names.append(i)
                else:
                    log.warning(
                        "V1 signture file {} missing .SF file ".format(i))

        return signature_names

    def get_app_name(self):
        if "resources.arsc" not in self.get_file_names():
            return ""
        app_name_id = self.axml.get_app_name()
        app_name = ''
        if app_name_id is None or app_name_id == '':
            return app_name
        if app_name_id.startswith("@"):
            try:
                app_name_res_id = int(app_name_id[1:],16)

                app_name = self.asrc.get_resolved_res_configs(app_name_res_id,ARSCResTableConfig.default_config())[0][1]
                # print("-->> ",type(app_name))
                # if isinstance(app_name,str):
                #     app_name = codecs.decode()
            except:
                return ""
        return app_name




    def get_signatures(self):
        # Read all signature file data -> bytes buffer

        signatures = self.get_v1_signature_names(v1=False)
        signature_data = []
        for s in signatures:
            signature_data.append(self.get_buff(s))
        return signature_data

    def is_signed_v1(self):
        # If we read ,it will not be empty list
        return len(self.get_v1_signature_names()) > 0

    def get_type(self):
        # Return file type
        return "apk"

    def get_buff(self, name):
        """
        Read zipinfo from apk's internal file buff with name 
        """
        try:
            return self.zip_buff.read(name)
        except KeyError:
            raise FileNotFound(name)

    def get_classe_dex(self):

        return self.get_buff("classes.dex")

    def get_file_names(self):
        """
        Read zipinfo File 
        """

        return self.zip_buff.namelist()

    def get_signature_names(self):
        return self.get_v1_signature_names(v1=False)

    def certification_info(self):
        """
        show Certifications
        """
        info = "**" * 10 + "Apk Certification Info " + "**" * 10 + "\n"
        info += "filename:{}".format(self.filename) + \
                " ,package: {}" + self.package + "\n"
        info += " Signed V1:{}".format(self.is_signed_v1()) + "\n"
        info += " Signed V2:{}".format(self.is_signed_v2()) + "\n"
        info += " Signed V3:{}".format(self.is_signed_v3()) + "\n"

        certs = set(self.get_certificates_der_v3(
        ) + self.get_certificates_der_v2() + [self.get_certificate_der(x) for x in
                                              self.get_signature_names()])
        pass

        certification = {}

        pkeys = set(self.get_public_keys_der_v3() +
                    self.get_public_keys_der_v2())
        if len(certs) > 0:
            print("Found {} unique certificates".format(len(certs)))

        info += "--" * 10 + "Ceritification Info:" + "--" * 10+"\n"
        for cert in certs:
            x509_cert = x509.Certificate.load(cert)
            issuer = get_certificate_name_string(x509_cert.issuer, short=True)
            certification['Issuer'] = issuer
            info += "Issuer: " + issuer + "\n"
            subjuect = get_certificate_name_string(
                x509_cert.subject, short=True)
            info += "Subject: " + subjuect + "\n"
            certification['Subject'] = subjuect

            serial_number = hex(x509_cert.serial_number)
            info += "Serial Number: " + serial_number + "\n"

            certification['Serial Number'] = serial_number

            hash_algorithm = x509_cert.hash_algo
            info += "Hash Algorithm: " + hash_algorithm + "\n"
            certification['Hash Algorithm'] = hash_algorithm

            signature_algorithm = x509_cert.signature_algo
            info += "Signatue Algorithm: " + signature_algorithm + "\n"
            certification['Signature Algorithm'] = signature_algorithm

            valide_not_before = x509_cert['tbs_certificate']['validity']['not_before'].native
            certification['Validate  not before'] = self.date_time(
                valide_not_before)

            info += "Valide not before: " + \
                self.date_time(valide_not_before) + "\n"

            valid_not_after = x509_cert['tbs_certificate']['validity']['not_after'].native
            certification['Validate  not after'] = self.date_time(
                valid_not_after)

            info += "Valide not after: " + \
                self.date_time(valid_not_after) + "\n"
        # info += "**" * 10 + "Public keys info " + '**' * 10 + "\n"
        # for public_key in pkeys:
        #     x509_public_key = keys.PublicKeyInfo(public_key)
        #     public_algorithm = x509_public_key.algorithm
        #     info += "Public Algorithm: " + public_algorithm + "\n"
        #     bit_size = x509_public_key.bit_size
        #     info += "Bit Size: " + bit_size + "\n"
        #     finger_print = binascii.hexlify(x509_public_key.fingerprint)
        #     info += "Finger print: " + finger_print + "\n"
        #     try:
        #         hash_algorithm = x509_public_key.hash_algo
        #     except ValueError as e:
        #         print("--> Not found pubic key hash algorithm ")
        #         hash_algorithm = "unknow"
        #     info += "Hash algorithm: " + hash_algorithm + "\n"

        return certification

    def get_certificate_der(self, filename):
        """
        Return the DER coded X.509 certificate from the signature file.

        :param filename: Signature filename in APK
        :returns: DER coded X.509 certificate as binary
        """
        pkcs7message = self.get_buff(filename)

        pkcs7obj = cms.ContentInfo.load(pkcs7message)
        cert = pkcs7obj['content']['certificates'][0].chosen.dump()
        return cert

    def get_public_keys_der_v2(self):
        """
        Return a list of DER coded X.509 public keys from the v3 signature block
        """

        if self._v2_signing_data == None:
            self.parse_v2_signing_block()

        public_keys = []

        for signer in self._v2_signing_data:
            public_keys.append(signer.public_key)

        return public_keys

    def get_certificates_der_v3(self):
        """
        Return a list of DER coded X.509 certificates from the v3 signature block
        """

        if self._v3_siging_data is None:
            self.parse_v3_signing_block()

        certs = []
        for signed_data in [signer.signed_data for signer in self._v3_siging_data]:
            for cert in signed_data.certificates:
                certs.append(cert)

        return certs

    def get_public_keys_der_v3(self):
        """
        Return a list of DER coded X.509 public keys from the v3 signature block
        """

        if self._v3_siging_data is None:
            self.parse_v3_signing_block()

        public_keys = []

        for signer in self._v3_siging_data:
            public_keys.append(signer.public_key)

        return public_keys

    def get_certificates_der_v2(self):
        """
        Return a list of DER coded X.509 certificates from the v3 signature block
        """

        if self._v2_signing_data is None:
            self.parse_v2_signing_block()

        certs = []
        for signed_data in [signer.signed_data for signer in self._v2_signing_data]:
            for cert in signed_data.certificates:
                certs.append(cert)

        return certs

    def parse_v2_signing_block(self):
        """
        Parse the V2 signing block and extract all features
        """

        self._v2_signing_data = []

        # calling is_signed_v2 should also load the signature
        if not self.is_signed_v2():
            return

        block_bytes = self._v2_blocks[self._APK_SIG_KEY_V2_SIGNATURE]
        block = io.BytesIO(block_bytes)
        view = block.getvalue()

        # V2 signature Block data format:
        #
        # * signer:
        #    * signed data:
        #        * digests:
        #            * signature algorithm ID (uint32)
        #            * digest (length-prefixed)
        #        * certificates
        #        * additional attributes
        #    * signatures
        #    * publickey

        size_sequence = self.read_uint32_le(block)
        # print("--. len(block) : {} size_sequence + 4 :{} ".format(len(block_bytes), size_sequence + 4))
        if size_sequence + 4 != len(block_bytes):
            raise ApkReadException(
                "size of sequence and blocksize does not match")

        while block.tell() < len(block_bytes):
            off_signer = block.tell()
            size_signer = self.read_uint32_le(block)

            # read whole signed data, since we might to parse
            # content within the signed data, and mess up offset
            len_signed_data = self.read_uint32_le(block)
            signed_data_bytes = block.read(len_signed_data)
            signed_data = io.BytesIO(signed_data_bytes)

            # Digests
            len_digests = self.read_uint32_le(signed_data)
            raw_digests = signed_data.read(len_digests)
            digests = self.parse_signatures_or_digests(raw_digests)

            # Certs
            certs = []
            len_certs = self.read_uint32_le(signed_data)
            start_certs = signed_data.tell()
            while signed_data.tell() < start_certs + len_certs:
                len_cert = self.read_uint32_le(signed_data)
                cert = signed_data.read(len_cert)
                certs.append(cert)

            # Additional attributes
            len_attr = self.read_uint32_le(signed_data)
            attributes = signed_data.read(len_attr)

            signed_data_object = APKV2SignedData()
            signed_data_object._bytes = signed_data_bytes
            signed_data_object.digests = digests
            signed_data_object.certificates = certs
            signed_data_object.additional_attributes = attributes

            # Signatures
            len_sigs = self.read_uint32_le(block)
            raw_sigs = block.read(len_sigs)
            sigs = self.parse_signatures_or_digests(raw_sigs)

            # PublicKey
            len_publickey = self.read_uint32_le(block)
            publickey = block.read(len_publickey)

            signer = APKV2Signer()
            signer._bytes = view[off_signer:off_signer + size_signer]
            signer.signed_data = signed_data_object
            signer.signatures = sigs
            signer.public_key = publickey

            self._v2_signing_data.append(signer)

    def parse_signatures_or_digests(self, digest_bytes):
        """ Parse digests """

        if not len(digest_bytes):
            return []

        digests = []
        block = io.BytesIO(digest_bytes)

        data_len = self.read_uint32_le(block)
        while block.tell() < data_len:
            algorithm_id = self.read_uint32_le(block)
            digest_len = self.read_uint32_le(block)
            digest = block.read(digest_len)

            digests.append((algorithm_id, digest))

        return digests

    def date_time(self, dt):

        return dt.strftime("%Y/%m/%d %H:%M:%S")
