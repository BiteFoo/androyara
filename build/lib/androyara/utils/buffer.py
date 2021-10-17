# -*- encoding: utf-8 -*-
'''
@File    :   buffer.py
@Author  :   Loopher 
@Version :   1.0
@License :   (C)Copyright 2020-2021, Loopher
@Desc    :   None
'''

# Here put the import lib

class BuffHandle:
    """
    BuffHandle is a wrapper around bytes.
    It gives the ability to jump in the byte stream, just like with BytesIO.
    """

    def __init__(self, buff):
        self.__buff = bytearray(buff)
        self.__idx = 0

    def __getitem__(self, item):
        """
        Get the byte at the position `item`

        :param int item: offset in the buffer
        :returns: byte at the position
        :rtype: int
        """
        return self.__buff[item]

    def __len__(self):
        return self.size()

    def size(self):
        """
        Get the total size of the buffer

        :rtype: int
        """
        return len(self.__buff)

    def length_buff(self):
        """
        Alias for :meth:`size`
        """
        return self.size()

    def set_idx(self, idx):
        """
        Set the current offset in the buffer

        :param int idx: offset to set
        """
        self.__idx = idx

    def get_idx(self):
        """
        Get the current offset in the buffer

        :rtype: int
        """
        return self.__idx

    def add_idx(self, idx):
        """
        Advance the current offset by `idx`

        :param int idx: number of bytes to advance
        """
        self.__idx += idx

    def tell(self):
        """
        Alias for :meth:`get_idx`.

        :rtype: int
        """
        return self.__idx

    def readNullString(self, size):
        """
        Read a String with length `size` at the current offset

        :param int size: length of the string
        :rtype: bytearray
        """
        data = self.read(size)
        return data

    def read_b(self, size):
        """
        Read bytes with length `size` without incrementing the current offset

        :param int size: length to read in bytes
        :rtype: bytearray
        """
        return self.__buff[self.__idx:self.__idx + size]

    def peek(self, size):
        """
        Alias for :meth:`read_b`
        """
        return self.read_b(size)

    def read_at(self, offset, size):
        """
        Read bytes from the given offset with length `size` without incrementing
        the current offset

        :param int offset: offset to start reading
        :param int size: length of bytes to read
        :rtype: bytearray
        """
        return self.__buff[offset:offset + size]

    def readat(self, off):
        """
        Read all bytes from the start of `off` until the end of the buffer

        This method can be used to determine a checksum of a buffer from a given
        point on.

        :param int off: starting offset
        :rtype: bytearray
        """
        return self.__buff[off:]

    def read(self, size):
        """
        Read from the current offset a total number of `size` bytes
        and increment the offset by `size`

        :param int size: length of bytes to read
        :rtype: bytearray
        """
        buff = self.__buff[self.__idx:self.__idx + size]
        self.__idx += size

        return buff

    def end(self):
        """
        Test if the current offset is at the end or over the buffer boundary

        :rtype: bool
        """
        return self.__idx >= len(self.__buff)

    def get_buff(self):
        """
        Return the whole buffer

        :rtype: bytearray
        """
        return self.__buff

    def set_buff(self, buff):
        """
        Overwrite the current buffer with the content of `buff`

        :param bytearray buff: the new buffer
        """
        self.__buff = buff

    def save(self, filename):
        """
        Save the current buffer to `filename`

        Exisiting files with the same name will be overwritten.

        :param str filename: the name of the file to save to
        """
        with open(filename, "wb") as fd:
            fd.write(self.__buff)
