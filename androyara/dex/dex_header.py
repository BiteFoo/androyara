# coding:utf8
'''
@File    :   dex_header.py
@Author  :   Loopher
@Version :   1.0
@License :   (C)Copyright 2020-2021,Loopher
@Desc    :   DexFileHeader
'''

import io
import hashlib
import binascii
import sys
from struct import unpack, calcsize


from androyara.dex.dex_method import *
import re


class DexHeaderError(BaseException):
    pass


class DexClassDefsError(BaseException):
    pass


class DexHeader(object):

    def __init__(self, buff):

        fp = io.BytesIO(buff)

        self.magic, = unpack("<4s", fp.read(4))
        if not self.is_dex():
            return
        self.version, = unpack("<4s", fp.read(4))

        self.checksum, = unpack("<I", fp.read(4))
        self.signature, = unpack("<20s", fp.read(20))

        fmt_I = "<I"
        self.filesize, = unpack(fmt_I, fp.read(4))
        self.header_size, = unpack(fmt_I, fp.read(4))
        self.endian_tag, = unpack(fmt_I, fp.read(4))

        self.linke_size, = unpack(fmt_I, fp.read(4))
        self.linke_offset, = unpack(fmt_I, fp.read(4))

        self.map_offset, = unpack(fmt_I, fp.read(4))

        self.string_idx_size, = unpack(fmt_I, fp.read(4))
        self.string_idx_offset, = unpack(fmt_I, fp.read(4))

        self.type_idx_size, = unpack(fmt_I, fp.read(4))
        self.type_idx_offset, = unpack(fmt_I, fp.read(4))

        self.proto_idx_size, = self.read(fp, fmt_I)
        self.proto_idx_offset, = self.read(fp, fmt_I)

        self.field_idx_size, = self.read(fp, fmt_I)
        self.field_idx_offset, = self.read(fp, fmt_I)

        self.method_idx_size, = self.read(fp, fmt_I)
        self.method_idx_offset, = self.read(fp, fmt_I)

        self.class_defs_idx_size, = self.read(fp, fmt_I)
        self.class_defs_idx_offset, = self.read(fp, fmt_I)

        self.data_size, = self.read(fp, fmt_I)
        self.data_offset, = self.read(fp, fmt_I)

        self.buff = fp
        self.__raw = buff

        self.class_defs = None

    def is_dex(self):
        # return hex(self.magic) == 0xa786564
        dex = self.magic
        if isinstance(dex, bytes):
            dex = str(dex, encoding="utf-8")
        return "dex" in dex

    def read_all(self, pkg):
        self.pkg = pkg

        self.read_string_idx_datas()
        self.read_type_idx_datas()
        self.read_dex_method_proto_idx_datas()
        self.read_field_idx_datas()
        self.read_method_idx_datas()
        self.read_class_defs_datas()
        # for offset,s in  self.string_table_map.items():
        #     print("%s  %s"%(hex(offset),s))

    def read(self, buff, fmt):
        return unpack(fmt, buff.read(4))

    def read_string_idx_datas(self):

        if self.string_idx_size <= 0 or self.string_idx_offset <= 0:
            print("read_string_idx_datas error string_idx_size = %d < 0 or string_idx_offset = %d <0 " % (
                self.string_idx_size, self.string_idx_offset), file=sys.stderr)
            return
        assert isinstance(self.buff, io.BytesIO)

        # reach to the strings table
        self.string_item_offset_list = []
        self.buff.seek(self.string_idx_offset, io.SEEK_SET)

        index = 0
        while index < self.string_idx_size:
            string_item_offset, = unpack("<I", self.buff.read(4))
            self.string_item_offset_list.append(string_item_offset)
            index += 1

        # print("Info: , string_idx_size: %d,read total: %d ," % (
        #     self.string_idx_size, len(self.string_item_offset_list)))

        # Right here read all string
        self.string_table_map = {
        }
        for str_offset in self.string_item_offset_list:
            self.buff.seek(str_offset, io.SEEK_SET)

            size = self.read_uleb128(self.buff, str_offset)
            if size == '\x00':
                raise DexHeaderError(
                    "While reading string_idx_data occurred an error , read_uleb128 error ,size = %s" % (size))

            string_data = self.buff.read(size)
            fmt = str(size)+"s"
            string, = unpack(fmt, string_data)
            # store string data bytes like
            self.string_table_map[str_offset] = string

            # print("--> offset: %s string: %s" %
            #       (hex(str_offset), string))

    def read_type_idx_datas(self):

        self.type_item_offset_list = []

        self.buff.seek(self.type_idx_offset, io.SEEK_SET)

        index = 0
        while index < self.type_idx_size:
            type_item_offset, = unpack("I", self.buff.read(4))
            self.type_item_offset_list.append(type_item_offset)
            index += 1
        # read type

        # print(":--<  type item size :%d  total read: %d" %
        #       (self.type_idx_size, len(self.type_item_offset_list)))
        #
        # for offset in self.type_item_offset_list:
        #
        #     for idx, str_offset in enumerate(self.string_item_offset_list):
        #         if idx == offset:
        #             print("-----> read type item :%s" %
        #                   (hex(offset)), self.string_table_map[str_offset])

    def read_dex_method_proto_idx_datas(self):

        self.buff.seek(self.proto_idx_offset, io.SEEK_SET)
        index = 0
        fmt = "I"

        self.dex_method_obj_list = []
        self.dex_method_obj_index = {}
        while index < self.proto_idx_size:
            dex_method_proto = DexMethodProto()

            dex_method_proto.shorty_idx, = unpack(
                fmt, self.buff.read(4))  # point to string_idx_list
            dex_method_proto.rturn_type_idx, = unpack(
                fmt, self.buff.read(4))  # point to type_idx_list
            dex_method_proto.parameter_type_offset, = unpack(
                fmt, self.buff.read(4))

            # save
            self.dex_method_obj_list.append(dex_method_proto)
            self.dex_method_obj_index[index] = dex_method_proto

            index += 1
        # debugging show
        # for dex_method_proto in self.dex_method_obj_list:
        #     print(dex_method_proto)

    def read_field_idx_datas(self):

        self.buff.seek(self.field_idx_offset, io.SEEK_SET)

        index = 0

        self.field_idx_list = []
        self.field_idx_index = {}

        # print("--. field_idx_size: %d" % (self.field_idx_size))
        while index < self.field_idx_size:

            field_idx_obj = DexFieldIdx()

            field_idx_obj.class_idx, = unpack("H", self.buff.read(2))
            field_idx_obj.type_idx, = unpack("H", self.buff.read(2))
            field_idx_obj.name_idx, = unpack("I", self.buff.read(4))

            self.field_idx_list.append(field_idx_obj)
            self.field_idx_index[index] = field_idx_obj

            index += 1
        # print("--> field info ")
        # for field in self.field_idx_list:
        #     print(field)

    def read_method_idx_datas(self):

        self.buff.seek(self.method_idx_offset, io.SEEK_SET)

        self.method_idx_list = []
        self.method_idx_index = {}

        index = 0
        while index < self.method_idx_size:
            method_idx_obj = DexMethodIdx()

            method_idx_obj.class_idx, = unpack("H", self.buff.read(2))
            method_idx_obj.proto_idx, = unpack("H", self.buff.read(2))
            method_idx_obj.name_idx, = unpack("I", self.buff.read(4))

            self.method_idx_list.append(method_idx_obj)
            self.method_idx_index[index] = method_idx_obj

            index += 1
        # print("--> DexMethodIdx Info ")
        # for method_idx in self.method_idx_list:
        #     print(method_idx)

    def read_class_defs_datas(self):

        if self.class_defs_idx_size <= 0:
            raise DexClassDefsError("class_defs_idx_size <0")
        index = 0
        self.class_defs = []
        while index < self.class_defs_idx_size:
            class_def_item_off = self.class_defs_idx_offset + index * 32
            self.buff.seek(class_def_item_off, io.SEEK_SET)

            class_idx, access_flags, superclass_idx,\
                interface_off, source_file_idx,\
                annotations_off, clazz_data_off,\
                static_values_off = unpack("IIIIIIII", self.buff.read(32))

            clzz_name = self.get_class_name_by_idx(class_idx)
            index += 1
            # Find target classes info
            target_pkg = self.pkg
            if not self.is_target_clazz(target_pkg, clzz_name):
                continue
            # target class
            if clazz_data_off <= 0:
                # print("error class_data_off error ",file=sys.stderr)
                continue

            class_def = {
                "class_name": clzz_name,
                "class_idx": class_idx,
                "code_item": []
            }

            self.buff.seek(clazz_data_off, io.SEEK_SET)
            static_field_size = self.read_uleb128(self.buff)
            instance_field_size = self.read_uleb128(self.buff)
            direct_method_size = self.read_uleb128(self.buff)
            virtual_method_size = self.read_uleb128(self.buff)

            class_def['virtual_method_size'] = virtual_method_size
            class_def['direct_method_size'] = direct_method_size

            # for now we will rebuild entity of class info

            static_field_cnt = 0
            # print("--" * 10 + "StaticField" + "--" * 10)
            while static_field_size > 0:
                static_field_idx_ = self.read_uleb128(self.buff)

                static_field_cnt = static_field_idx_ + static_field_cnt
                access_flags = self.read_uleb128(self.buff)
                # 不处理属性变量的情况，可直接忽略掉
                # print(" static field  : %s  access_flags: %s" %
                #       (self.field_idx_list[static_field_cnt],hex(access_flags))) # every item is FieldIdx

                static_field_cnt += static_field_idx_
                static_field_size -= 1

            instance_field_idx_cnt = 0
            # print("--" * 10 + "InstanceField" + "--" * 10)
            while instance_field_size > 0:
                instance_idx = self.read_uleb128(self.buff)
                instance_field_idx_cnt = instance_field_idx_cnt + instance_idx
                access_flags = self.read_uleb128(self.buff)
                # print("Instance field: %s  access_flags: %s"%(self.field_idx_list[instance_field_idx_cnt],hex(access_flags)))
                instance_field_size -= 1

            direct_method_idx = 0
            # print("--" * 10 + "DirectMethod" + "--" * 10)
            while direct_method_size > 0:
                direct_method_ = self.read_uleb128(self.buff)
                direct_method_idx += direct_method_
                method_name = self.get_method_name_by_idx(direct_method_idx)
                access_flags = self.read_uleb128(self.buff)
                code_off = self.read_uleb128(self.buff)
                # code_inss = self.read_code_item(code_off)

                direct_method_size -= 1
                all_codes = {
                    "direct_method_idx": direct_method_idx,
                    "method_name": method_name,
                    "access_flags": access_flags,
                    "code_off": code_off
                }
                class_def['code_item'].append(all_codes)

            #     print("direct  Method : %s  method_name: %s access_flag: %s code_off: %s code_ins len: %s" %
            #           (self.method_idx_list[direct_method_idx], method_name, hex(access_flags), hex(code_off),
            #            len(code_inss)))
            #     for i,ins in enumerate(code_inss):
            #         print("code[%d]: %s"%(i,hex(ins)))
            #
            # print("--"*10+"VirtualMethod"+"--"*10)

            virtual_method_idx = 0
            while virtual_method_size > 0:
                virtual_method_ = self.read_uleb128(self.buff)
                virtual_method_idx += virtual_method_
                method_name = self.get_method_name_by_idx(virtual_method_idx)
                access_flags = self.read_uleb128(self.buff)
                code_off = self.read_uleb128(self.buff)
                # code_inss = self.read_code_item(code_off)
                virtual_method_size -= 1
                all_codes = {
                    "virtual_method_idx": virtual_method_idx,
                    "method_name": method_name,
                    "access_flags": access_flags,
                    "code_off": code_off
                }
                class_def['code_item'].append(all_codes)
                # print("virtual Method : %s  method_name: %s access_flag: %s code_off: %s code_ins len: %s" %
                #       (self.method_idx_list[direct_method_idx],method_name,hex(access_flags),hex(code_off),len(code_inss)))
                # for i, ins in enumerate(code_inss):
                #     print("code[%d]: %s" % (i, hex(ins)))
            # self.class_defs['']

            self.class_defs.append(class_def)

    def read_code_item(self, code_off):

        if code_off == 0x0:
            return []

        _buff = io.BytesIO(self.__raw)
        _buff.seek(code_off, io.SEEK_SET)

        method_register_size, = unpack("H", _buff.read(2))
        method_ins_size, = unpack("H", _buff.read(2))
        method_outs_size, = unpack("H", _buff.read(2))
        method_tries_size, = unpack("H", _buff.read(2))
        method_debug_info_off, = unpack("I", _buff.read(4))

        method_instructions_size, = unpack("I", _buff.read(4))
        # record codeitem's offset and size
        code_instructions = [code_off, method_instructions_size]

        # print("--> code_off :%s method_instructions_size:%s"%(hex(code_off),hex(method_instructions_size)))
        while method_instructions_size > 0:
            ins_code, = unpack("H", _buff.read(2))
            code_instructions.append(ins_code)
            method_instructions_size -= 1

        return code_instructions

    def is_target_clazz(self, pkg, clazz):

        # return True if pkg in clazz else False
        need_filter_classes = [
            '.R$attr',
            '.R$drawable',
            '.R$id',
            '.R$layout',
            '.R$string',
            '.R',
            '.BuildConfig'
        ]
        if pkg is None or pkg == '':
            # default all
            return True

        if isinstance(clazz, bytes):
            clazz = str(clazz, encoding="utf-8")
        if pkg == '' or clazz == '':
            return False
        clazz = clazz.replace("L", "").replace("/", '.').replace(";", "")

        # filter thridpart class ,like google's code etc
        suffix = clazz[clazz.rfind('.'):]
        if suffix in need_filter_classes:
            return False
        #
        target = re.compile(pkg)
        if target.match(clazz):
            return True
        return False

    def get_method_name_by_idx(self, idx):

        dex_method_idx = self.method_idx_list[idx]

        short_class_idx = dex_method_idx.class_idx
        name_idx = dex_method_idx.name_idx
        proto_idx = dex_method_idx.proto_idx

        method_name = self.get_string_by_idx(name_idx)

        clazz_name = self.get_class_name_by_idx(short_class_idx)
        method_proto_name = self.get_method_proto_name_by_idx(proto_idx)

        # print("--> class_name: %s , method_proto_name:%s method_name:%s"%(clazz_name,method_proto_name,method_name))
        return method_name

    def get_class_name_by_idx(self, idx):
        """
        Return bytes like strings
        """
        off = self.string_item_offset_list[self.type_item_offset_list[idx]]
        return self.string_table_map[off]

    def get_method_proto_name_by_idx(self, idx):

        dexmethod_proto = self.dex_method_obj_index[idx]
        method_proto_name = self.get_string_by_idx(dexmethod_proto.shorty_idx)
        rtvalue = self.get_string_by_idx(
            self.type_item_offset_list[dexmethod_proto.rturn_type_idx])

        # print("rtvalue: %s"%(rtvalue))
        return method_proto_name

    def get_string_by_idx(self, idx):
        off = self.string_item_offset_list[idx]
        return self.string_table_map[off]

    def read_uleb128(self, buff, offset=0):
        '''
        ULEB128
        '''
        result, = unpack('B', buff.read(1))
        if result > 0x7f:
            cur, = unpack('B', buff.read(1))
            result = (result & 0x7f) | ((cur & 0x7f) << 7)
            if cur > 0x7f:
                cur, = unpack('B', buff.read(1))
                result |= (cur & 0x7f) << 14
                if cur > 0x7f:
                    cur, = unpack('B', buff.read(1))
                    result |= (cur & 0x7f) << 21
                    if cur > 0x7f:
                        cur, = unpack('B', buff.read(1))
                        if cur > 0x0f:
                            print(" warning possible error while decoding number")
                        result |= cur << 28
        return result
