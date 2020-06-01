# -*- coding:utf-8 -*-
import os
import platform
import re
import socket
from thirdparty import chardet

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

def get_banner_by_content(res):
    ret = []
    for k,cues in fingerprint.items():
        rs = []
        for cue in cues:
            if cue.get("content"):
                if cue.get("type") == "regex":
                    preg = re.compile(cue.get("content"))
                    rs.append(True if re.search(preg,res.content) else False)
                elif cue.get("type") == "string":
                    rs.append(cue.get("content") in res.content)
            if cue.get("resheader"):
                resp_headers = str(dict(res.resp_headers))
                if cue.get("type") == "regex":
                    preg = re.compile(cue.get("resheader"))
                    rs.append(True if re.search(preg, resp_headers) else False)
                elif cue.get("type") == "string":
                    rs.append(cue.get("resheader") in resp_headers)
        if rs and all(rs):
            ret.append(k)
    return ",".join(ret)

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

def update_file_content(file,old_str,new_str):
  file_data = ""
  with open(file, "r") as f:
    for line in f:
      if old_str in line:
        line = line.replace(old_str,new_str)
      file_data += line
  with open(file,"w") as f:
    f.write(file_data)

class CommonUtils(object):
    @classmethod
    def ListTrim(cls, StringList, char=[]):
        rs_list = []
        if not char:
            for s in StringList:
                if s.strip() == "":
                    continue
                else:
                    rs_list.append(s.strip())
        else:
            for s in StringList:
                if s.strip() in char:
                    continue
                else:
                    rs_list.append(s.strip())
        return rs_list

    @classmethod
    def getIp(cls, domain):
        try:
            myaddr = socket.getaddrinfo(domain, 'http')[0][4][0]
            return myaddr
        except:
            return None

    @classmethod
    def package_ipscope_c_net(cls, ipscope):
        rs_list = []
        retlist = cls.package_ipscope(ipscope, retType="list")
        for ip in retlist:
            ipcues = ip.split(".")
            newip = "{0}.{1}.{2}.0/24".format(ipcues[0], ipcues[1], ipcues[2])
            rs_list.append(newip)
        rs_list = list(set(rs_list))
        return rs_list

    @classmethod
    def package_ipscope_mid(cls,ipscope):
        regex = re.compile("(?P<subfix>(?:\d+\.){3})(?P<start>\d+)-(?:\d+\.){3}(?P<end>\d+)")
        ret = re.match(regex,ipscope)
        if ret:
            start = int(ret.group('start'))
            end = int(ret.group('end'))
            subfix = ret.group('subfix')
            if end > start:
                return ["{0}{1}".format(subfix,x) for x in range(start,end+1)]
        return ipscope

    @classmethod
    def package_ipscope(cls, ipscope, handle_ip=True, retType="string"):
        rs_list = []
        ret_list = []
        ipscope_list = cls.ListTrim(ipscope.split("\n"))
        for cues in ipscope_list:
            dir = cls.package_ipscope_mid(cues)
            if isinstance(dir,list):
                rs_list = rs_list + cls.ListTrim(dir)
            else:
                if "," in cues:
                    rs_list = rs_list + cls.ListTrim(cues.split(","))
                elif ";" in cues:
                    rs_list = rs_list + cls.ListTrim(cues.split(";"))
                else:
                    rs_list.append(cues)

        rs_list = list(set(rs_list))
        if handle_ip:
            for tar in rs_list:
                if is_domain(tar):
                    ip = cls.getIp(tar)
                    if ip:
                        ret_list.append(ip)
                else:
                    ret_list.append(tar)
            ret_list = list(set(ret_list))
        else:
            ret_list = rs_list

        if retType is "string":
            return ",".join(ret_list)
        else:
            return ret_list

    @classmethod
    def div_list(cls, ls, n):
        if not isinstance(ls, list) or not isinstance(n, int):
            return [ls]
        ls_len = len(ls)
        if n <= 0 or 0 == ls_len:
            return [ls]
        if n > ls_len:
            return [ls]
        elif n == ls_len:
            return [[i] for i in ls]
        else:
            j = ls_len / n
            k = ls_len % n
            ls_return = []
            for i in xrange(0, (n - 1) * j, j):
                ls_return.append(ls[i:i + j])
            ls_return.append(ls[(n - 1) * j:])
            return ls_return

    @classmethod
    def create_command(cls,scanmode, ipscope, ports, pseudo_ip, pseudo_port,rate):
        if scanmode == "fast":
            if UsePlatform() == WINDOWS:
                command = ["cmd.exe", "/c", "masscan", ipscope, "-p", str(ports), "--max-rate", str(rate)]
            else:
                command = ["masscan", ipscope, "-p", str(ports), "--max-rate", str(rate)]
            if pseudo_ip:
                command = command + [" --source-ip ", str(pseudo_ip)]
            if pseudo_port:
                command = command + [" --source-port ", str(pseudo_port)]
        else:
            if UsePlatform() == WINDOWS:
                command = ["cmd.exe", "/c", "main", "-p", str(ports), "-h",ipscope, "-r", str(rate)]
            else:
                command = ["main", "-p", str(ports), ipscope, "-r", str(rate)]
        return command