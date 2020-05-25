# -*- coding:utf-8 -*-
from __future__ import division
import re
from urlparse import urlparse
from lxml import etree
from common.qqwry import IPInfo
from common.utils import get_server_profile, get_banner_by_content
from constants import finger2https
from thirdparty.connection.http_urllib3 import HttpUtil

class HttpWeb(object):
    NOT_DETECT_PORTS = [22,21,3389]

    @classmethod
    def is_ssl_request(cls,content):
        for x in finger2https:
            if len(content) < 2000 and x.lower() in content.lower():
                return True
        return False

    @classmethod
    def detect(cls,ip,port,httpclient=None):
        assettype = 0
        port = int(port)
        if httpclient is None:
            httpclient = HttpUtil()
        banner,service,ostype,proext,domain,position= "","","","","",""
        if not port in cls.NOT_DETECT_PORTS:
            if port == 80:
                schemas = ["http"]
            elif port == 443 or port == 8443:
                schemas = ["https"]
            else:
                schemas = ["http", "https"]
            pregx = re.compile(r"<title>(.*?)</title>", re.I)
            for schema in schemas:
                url = "{schema}://{ip}:{port}".format(schema=schema, ip=ip if not domain else domain, port=port)
                try:
                    res = httpclient.request(url,timeout=1,redirect=True)
                    content = res.content
                    if cls.is_ssl_request(content):
                        continue
                    headers = res.headers
                    ostype, server, server_app = get_server_profile(headers)
                    ostype = OsType.get_ostype(port=port,server=server,server_app=server_app,res=res)
                    service = "{0} web application ".format(schema)
                    if server:
                        service = service + " server: {0}".format(server)
                    if server_app:
                        service = service + " application: {0}".format(server_app)

                    if content:
                        rs = re.findall(pregx, content)
                        if rs and len(rs) > 0:
                            banner = rs[0] if not get_banner_by_content(content) else rs[0]+" ["+get_banner_by_content(content)+"]"
                        else:
                            banner = content[0:100] if not get_banner_by_content(content) else content[0:100]+" ["+get_banner_by_content(content)+"]"
                    assettype = 1
                    proext = schema
                    break
                except:
                    banner = ""
                    assettype = 0
        return banner,service,ostype,assettype,domain,position,proext

class OsType(object):
    WINDOWS_PORTS = [3389]
    LINUX_PORTS = []
    LINUX = "unix"
    WINDOWS = "windows"
    @classmethod
    def get_ostype(cls, port=None, server=None, server_app=None, res=None):
        ostype = "unknown"
        only_windows_ports = list(set(cls.WINDOWS_PORTS)-set(cls.LINUX_PORTS))
        only_linux_ports = list(set(cls.LINUX_PORTS)-set(cls.WINDOWS_PORTS))
        if port:
            if isinstance(port,int):
                if port and (port in only_windows_ports):
                    ostype = cls.WINDOWS
                elif port in only_linux_ports:
                    ostype = cls.LINUX

            elif isinstance(port,list):
                counts = len(set(cls.WINDOWS_PORTS+cls.LINUX_PORTS))
                win_num = len(set(port) & set(cls.WINDOWS_PORTS))
                lin_num = len(set(port) & set(cls.LINUX_PORTS))
                diff = abs(win_num-lin_num)/counts
                if diff > 0.7:
                    if win_num > lin_num:
                        ostype = cls.WINDOWS
                    else:
                        ostype = cls.LINUX
        if server:
            if isinstance(server,list):
                server = ",".join(server)
            regx = re.compile(r"Microsof|iis",re.I)
            if regx.findall(server):
                ostype = cls.WINDOWS

        if server_app:
            if any(["asp" in server_app,"aspx" in server_app]):
                ostype = cls.WINDOWS

        if res and res.status_code == 500:
            regx = re.compile(r"[a-zA-Z]:(?:\\(?:[a-zA-Z0-9_]+.[a-zA-Z0-9_]{1,16}))+", re.I)
            if regx.findall(res.content):
                ostype = "windows"

        return ostype

if __name__ == "__main__":
    banner, service, ostype, assettype, domain,position,proext =  HttpWeb.detect('42.48.85.15',8082)
    print banner
    print service
    print ostype
    print assettype
    print position
    print domain
    print proext

