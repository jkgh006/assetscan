# -*- coding:utf-8 -*-
from __future__ import division
import base64
import socket
import dns.resolver
import re
from urlparse import urlparse
from lxml import etree
import requests
from common.qqwry import IPInfo
from common.utils import get_server_profile, get_banner_by_content

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

class HttpWeb(object):
    NOT_DETECT_PORTS = [22,21,3389]
    @classmethod
    def detect(cls,ip,port,checkdomain=True):
        assettype = 0
        port = int(port)
        banner,service,ostype,proext = "","","",""
        position, domain, banner = biying_find(ip)
        if not port in cls.NOT_DETECT_PORTS:
            if port == 80:
                schemas = ["http"]
            elif port == 443:
                schemas = ["https"]
            else:
                schemas = ["http", "https"]
            pregx = re.compile(r"<title>(.*?)</title>", re.I)
            for schema in schemas:
                url = "{schema}://{ip}:{port}".format(schema=schema, ip=ip if not domain else domain, port=port)
                try:
                    res = requests.get(url, verify=False, allow_redirects=True, timeout=1)
                    content = res.content
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
                    break
                except:
                    banner = ""
                    assettype = 0
        return banner,service,ostype,assettype,domain,position,schema

    @classmethod
    def check_cdn(self,target):
        # 目标域名cdn检测
        result = []
        myResolver = dns.resolver.Resolver()
        myResolver.lifetime = myResolver.timeout = 2.0
        dnsserver = [['114.114.114.114'], ['8.8.8.8'], ['223.6.6.6']]
        try:
            for i in dnsserver:
                myResolver.nameservers = i
                record = myResolver.query(target)
                result.append(record[0].address)
        except Exception as e:
            pass
        finally:
            return True if len(set(list(result))) > 1 else False

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
        position = IPInfo.position_info(ip) if not position.strip() else position
    except:
        pass
    return position, domain, banner

if __name__ == "__main__":
    banner, service, ostype, assettype, domain,position,proext =  HttpWeb.detect('111.205.207.140',443)
    print banner
    print service
    print ostype
    print assettype
    print position
    print domain
    print proext

