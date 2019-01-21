# -*- coding:utf-8 -*-
__author__ = 'achelics'

import re as _re
from IPy import IP

if __name__ == '__main__':
    IP_RE = _re.compile(r"(?<!\d\.)(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d|(?:\.\d))")
    IP_CIDR_RE = _re.compile(r"(?<!\d\.)(?<!\d)(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}(?!\d|(?:\.\d))")
    ip = '192..12.1'
    if ip in IP_RE.findall(ip):
        print ip
    hello = '192.168.0/24'
    if hello in IP_CIDR_RE.findall(hello):
        cidr = IP(hello)
        for ip in cidr:
            ip = str(ip)
            print ip