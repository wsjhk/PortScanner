# -*- coding:utf-8 -*-

import socket
import gevent
from gevent import monkey;monkey.patch_all()
socket.setdefaulttimeout(3) #设置默认超时时间

ports = []
tasks = []

def socket_port(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = s.connect_ex((ip, port))
    if result == 0:
        ports.append(port)
    else:
        pass

def get_ports(port):
    if port.find("-") != -1:
        return range(int(port.split('-')[0]), int(port.split('-')[1]))
    elif port.find(",") != -1:
        return port.split(',')
    else:
        return [port]

def ip_scan(ip, portlist):
    for n in get_ports(portlist):
        tasks.append(gevent.spawn(socket_port, ip, int(n)))

    gevent.joinall(tasks)
    return ports

# ip = 'xxx.xxx.xxx.xxx'
# print ip_scan(ip, '1-65535')
