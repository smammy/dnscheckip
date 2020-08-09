#!/usr/bin/env python3

#import binascii
import bitstruct
import codecs
from collections import namedtuple
from datetime import datetime
#from enum import Enum
from io import BytesIO
import socket
import socketserver
import struct
import sys

Message = namedtuple('Message', ['header', 'questions', 'answers'])
Header = namedtuple('Header', ['id', 'qr', 'opcode', 'aa', 'tc', 'rd', 'ra',
                               'z', 'rcode', 'qdcount', 'ancount', 'nscount',
                               'arcount'])
Question = namedtuple('Question', ['rawqname', 'qname', 'qtype', 'qclass'])
ResourceRecord = namedtuple('ResourceRecord', ['rawname', 'type', 'class_',
                                               'ttl', 'rdlength', 'rdata'])

class DNSNotImplementedError(Exception):
    pass

def readbytes(fmt, msg_io):
    raw = msg_io.read(struct.calcsize(fmt))
    val = struct.unpack(fmt, raw)
    return (raw, *val)

def readbits(fmt, msg_io):
    raw = msg_io.read(bitstruct.calcsize(fmt) // 8)
    val = bitstruct.unpack(fmt, raw)
    return (raw, *val)

def writebytes(fmt, data):
    return struct.pack(fmt, *data)

def writebits(fmt, data):
    return bitstruct.pack(fmt, *data)

def parse_question(msg_io):
    qname = b''
    rawqname = b''
    while True:
        raw, size = readbytes('B', msg_io)
        rawqname += raw
        if size == 0:
            break
        raw, label = readbytes(f'{size}s', msg_io)
        rawqname += raw
        qname += label + b'.'
    _, qtype, qclass = readbytes('!HH', msg_io)
    return Question(rawqname, qname, qtype, qclass)

def parse_msg(msg_io):
    _, *val = readbits('u16 b1u4b1b1b1b1 u3u4 u16 u16 u16 u16', msg_io)
    header = Header(*val)
    questions = []
    for qcurr in range(header.qdcount):
        question = parse_question(msg_io)
        questions.append(question)
    return Message(header, questions, [])

def not_impl_resp(msg):
    return Message(
        header=Header(
            id=msg.header.id,
            qr=True,
            opcode=msg.header.opcode,
            aa=False,
            tc=False,
            rd=msg.header.rd,
            ra=False,
            z=0,
            rcode=0, # Not Implemented
            qdcount=0,
            ancount=0,
            nscount=0,
            arcount=0),
        questions=[],
        answers=[])

def fmt_err_resp(msg):
    return Message(
        header=Header(
            id=msg.header.id,
            qr=True,
            opcode=msg.header.opcode,
            aa=False,
            tc=False,
            rd=msg.header.rd,
            ra=False,
            z=0,
            rcode=1, # Format error
            qdcount=0,
            ancount=0,
            nscount=0,
            arcount=0),
        questions=[],
        answers=[])

def refused_resp(msg):
    return Message(
        header=Header(
            id=msg.header.id,
            qr=True,
            opcode=msg.header.opcode,
            aa=False,
            tc=False,
            rd=msg.header.rd,
            ra=False,
            z=0,
            rcode=5, # Refused
            qdcount=0,
            ancount=0,
            nscount=0,
            arcount=0),
        questions=[],
        answers=[])

def no_recs_resp(msg):
    return Message(
        header=Header(
            id=msg.header.id,
            qr=True,
            opcode=msg.header.opcode,
            aa=False,
            tc=False,
            rd=msg.header.rd,
            ra=False,
            z=0,
            rcode=0,
            qdcount=0,
            ancount=0,
            nscount=0,
            arcount=0),
        questions=[],
        answers=[])

def client_ip_resp(msg, client):
    return Message(
        header=Header(
            id=msg.header.id,
            qr=True,
            opcode=msg.header.opcode,
            aa=True,
            tc=False,
            rd=msg.header.rd,
            ra=False,
            z=0,
            rcode=0,
            qdcount=0,
            ancount=1,
            nscount=0,
            arcount=0),
        questions=[],
        answers=[ResourceRecord(
            rawname=msg.questions[0].rawqname,
            type=1, # A, a host address
            class_=1, # IN, the Internet
            ttl=1,
            rdlength=4,
            rdata=socket.inet_aton(client[0]))],
    )

class DNSCheckIPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        now = datetime.utcnow()
        client = self.client_address
        msg_buf = self.request[0]
        msg_hex = codecs.encode(msg_buf, 'hex')
        msg_io = BytesIO(msg_buf)
        print(f'{now} {client[0]} {client[1]} {msg_hex}')
        msg = parse_msg(msg_io)
        print(f'• msg={msg}')
        if msg.header.qr or msg.header.opcode != 0:
            resp = not_impl_resp(msg)
        elif msg.header.tc:
            resp = fmt_err_resp(msg)
        elif msg.header.qdcount < 1:
            resp = not_impl_resp(msg)
        elif msg.questions[0].qtype not in (1, 255):
            resp = no_recs_resp(msg)
        elif msg.questions[0].qclass != 1:
            resp = not_impl_resp(msg)
        elif msg.questions[0].qname != b'my.ip4.live.':
            resp = refused_resp(msg)
        else:
            resp = client_ip_resp(msg, client)
        print(f'• resp={resp}')
        resp_buf = b''
        resp_buf += writebits('u16 b1u4b1b1b1b1 u3u4 u16 u16 u16 u16',
                              resp.header)
        if len(resp.answers):
            resp_buf += writebytes(f'!{len(resp.answers[0].rawname)}B',
                                   resp.answers[0].rawname)
            resp_buf += writebytes('!HHIH4B', (resp.answers[0].type,
                                   resp.answers[0].class_,  resp.answers[0].ttl,
                                   resp.answers[0].rdlength, *resp.answers[0].rdata))
        resp_hex = codecs.encode(resp_buf, 'hex')
        print(f'• resp_hex={resp_hex}')
        self.request[1].sendto(resp_buf, client)

if __name__ == '__main__':
    socketserver.UDPServer((sys.argv[1], int(sys.argv[2])),
        DNSCheckIPHandler).serve_forever()
