# -*- coding:utf-8 -*-
import os
import platform
import re
import socket
from urlparse import urlparse

import chardet
import requests
from lxml import etree

from common.db.sqlite3_db import sqlite3_db
from constants import default_ports, fingerprint

portdb = os.path.join(os.path.join(os.path.dirname(__file__), '../datas'), 'ports.db')

LINUX = "unix"
WINDOWS = "windows"

class OsType(object):
    WINDOWS_PORTS = [3389]
    LINUX_PORTS = []
    @classmethod
    def get_ostype(cls, port=None, server=None, server_app=None, res=None):
        ostype = "unknown"
        only_windows_ports = list(set(cls.WINDOWS_PORTS)-set(cls.LINUX_PORTS))
        only_linux_ports = list(set(cls.LINUX_PORTS)-set(cls.WINDOWS_PORTS))
        if port:
            if isinstance(port,int):
                if port and (port in only_windows_ports):
                    ostype = WINDOWS
                elif port in only_linux_ports:
                    ostype = LINUX

            elif isinstance(port,list):
                counts = len(set(cls.WINDOWS_PORTS+cls.LINUX_PORTS))
                win_num = len(set(port) & set(cls.WINDOWS_PORTS))
                lin_num = len(set(port) & set(cls.LINUX_PORTS))
                diff = abs(win_num-lin_num)/counts
                if diff > 0.7:
                    if win_num > lin_num:
                        ostype = WINDOWS
                    else:
                        ostype = LINUX
        if server:
            if isinstance(server,list):
                server = ",".join(server)
            regx = re.compile(r"Microsof|iis",re.I)
            if regx.findall(server):
                ostype = WINDOWS

        if server_app:
            if any(["asp" in server_app,"aspx" in server_app]):
                ostype = WINDOWS

        if res and res.status_code == 500:
            regx = re.compile(r"[a-zA-Z]:(?:\\(?:[a-zA-Z0-9_]+.[a-zA-Z0-9_]{1,16}))+", re.I)
            if regx.findall(res.content):
                ostype = "windows"

        return ostype

def biying_find(ip):
    position,domain,banner = "","",""
    url = "https://www.bing.com/search?q=ip%3A{ip}&qs=n".format(ip=ip)
    try:
        res = requests.get(url, verify=False, allow_redirects=True, timeout=1)
        content = res.content
        page = etree.HTML(content.decode('utf-8'))
        divnodes = page.xpath(u"//div[@class='b_xlText']")
        for divnode in divnodes:
            position = divnode.text

        divnodes = page.xpath(u"//li[@class='b_algo']")
        for divnode in divnodes:
            bnode = divnode.xpath(u"div[@class='b_title']")
            if bnode:
                alink = bnode[0].xpath(u"h2/a")
            else:
                alink = divnode.xpath(u"h2/a")
            banner = alink[0].text
            href = alink[0].attrib.get("href")
            domain = urlparse(href).netloc
            if domain and banner:
                break
    except:
        pass
    return position, domain, banner

def get_banner_by_content(content):
    for k,cues in fingerprint.items():
        for cue in cues:
            preg = re.compile(cue)
            ret = re.search(preg,content)
            if ret:
                return k
    return ""

def get_server_profile(headers):
    resp_headers = {}
    for k, v in headers.items():
        resp_headers.update({k.lower(): v})

    os, server, server_app = None, [], []

    server_in_header = resp_headers.get('server', '')
    server_in_header = server_in_header.lower()

    win_signatures = ['win', 'iis']
    unix_signatures = ['unix', 'centos', 'fedora', 'ubuntu', 'redhat']

    for signature in win_signatures:
        if signature in server_in_header:
            os = 'windows'
            break
    for signature in unix_signatures:
        if signature in server_in_header:
            os = 'unix'
            break

    if 'apache' in server_in_header:
        server.append('apache')
    if 'iis' in server_in_header:
        server.append('iis')
    if 'glassfish' in server_in_header:
        server.append('glassfish')
    if len(server) == 0 and server_in_header:
        server.append(server_in_header)

    powerd_by = resp_headers.get('x-powered-by', '')
    powerd_by = powerd_by.lower()
    if 'php' in server_in_header or 'php' in powerd_by:
        server_app.append('php')
    if 'jsp' in server or 'jsp' in powerd_by or 'tomcat' in powerd_by:
        server_app.append('jsp')
    if 'asp' in server or 'asp' in powerd_by:
        server_app.append('asp')

    return (os, server, server_app)

def get_socket_banner(ip, port,ref_banner=""):
    try:
        regex = re.compile(r"\w{3,}",re.I)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        s.connect((ip, port))
        s.send('HELLO\r\n')
        rs = s.recv(1024).split('\r\n')[0].strip('\r\n')
        if re.search(regex, rs):
            return rs
        else:
            return ref_banner
    except Exception as e:
        pass
    finally:
        s.close()
    return ref_banner

def UsePlatform():
    sysstr = platform.system()
    if(sysstr =="Windows"):
        return WINDOWS
    else:
        return LINUX

def is_domain(domain):
    domain_regex = re.compile(
        r'(?:[A-Z0-9_](?:[A-Z0-9-_]{0,247}[A-Z0-9])?\.)+(?:[A-Z]{2,6}|[A-Z0-9-]{2,}(?<!-))\Z',
        re.IGNORECASE)
    return True if domain_regex.match(domain) else False

def is_ipv4(address):
    ipv4_regex = re.compile(
        r'(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}',
        re.IGNORECASE)
    return True if ipv4_regex.match(address) else False

def query_service_and_banner(port,protocol):
    db = sqlite3_db(portdb)
    rs = db.queryrow("select * from portdb where PORT='{0}' and PROTOCOL='{1}'".format(port,protocol))
    if rs:
        service = rs[1] if rs[1] else "unknown"
        banner = rs[4] if rs[4] else ""
    else:
        service = "unknown"
        banner = ""
    return service,banner

def char_convert(content, in_enc=["ASCII", "GB2312", "GBK", "gb18030"], out_enc="UTF-8"):
    rs_content = ""
    try:
        result = chardet.detect(content)
        coding = result.get("encoding")
        for k in in_enc:
            if k and coding and k.upper() == coding.upper():
                rs_content = content.decode(coding).encode(out_enc)
        rs_content = content if not rs_content else rs_content
    except IOError, e:
        pass
    return rs_content

def computing_ports(ports):
    rs_list = []
    if isinstance(ports,list):
        return ports
    if ports in default_ports.keys():
        rs_list = default_ports.get(ports)
    else:
        ports = str(ports)
        ports_lev1 = ports.split(",")
        for p in ports_lev1:
            if "-" in p:
                port_lev2 = [int(x) for x in p.split("-")]
                rs_list = rs_list + range(port_lev2[0], port_lev2[1] + 1)
            else:
                rs_list.append(p)
    rs_list = sorted(rs_list)
    rs_list = [str(x) for x in rs_list]
    return rs_list

def is_default_ports(ports):
    return (ports in default_ports.keys())
