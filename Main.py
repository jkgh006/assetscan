# -*- coding:utf-8 -*-
import base64
import md5
import os
import sys
import uuid
import subprocess
import time
import re
import cgi
from optparse import OptionParser, OptionGroup

from Report import Report
from common.initsql import SQL
from common.db.sqlite3_db import sqlite3_db
from common.utils import query_service_and_banner, get_socket_banner, char_convert
from ProbeTool import HttpWeb
from constants import computing_ports, default_ports
from pool.thread_pool import ThreadPool
from IPlugin import IPlugin

from common.logger.log_util import LogUtil as logging
logger = logging.getLogger(__name__)
class Plugin(IPlugin):
    def __init__(self):
        super(Plugin, self).__init__()
        self._id = 10000
        self._name = "PortScan"
        self._level = 10
        self.rate = 300
        self.uuid_hash = md5.md5(str(uuid.uuid4())).hexdigest()
        self.finished = False
        self.db = None
        self.portdb = None

    def init_db(self):
        self.portdb = os.path.join(os.path.dirname(__file__), 'repertory',time.strftime("%Y-%m-%d_%H_%M_%S", time.localtime()),"rs.db")
        if not os.path.exists(os.path.dirname(self.portdb)):
            os.makedirs(os.path.dirname(self.portdb))
        self.db = sqlite3_db(self.portdb)
        self.db.create_table(SQL)
        logger.info("database initialization completed")

    def create_command(self,ipscope,ports,pseudo_ip,pseudo_port):
        command = ["cmd.exe","/c","masscan",ipscope,"-p",str(ports),"--max-rate",str(self.rate)]
        if pseudo_ip:
            command = command + [" --source-ip ",str(pseudo_ip)]
        if pseudo_port:
            command = command + [" --source-port ",str(pseudo_port)]
        return command

    def ListTrim(cls,StringList, char=[]):
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

    def package_ipscope(self,ipscope):
        rs_list = []
        ipscope_list = self.ListTrim(ipscope.split("\n"))
        for cues in ipscope_list:
            if "," in cues:
                rs_list = rs_list + self.ListTrim(cues.split(","))
            elif ";" in cues:
                rs_list = rs_list + self.ListTrim(cues.split(";"))
            else:
                rs_list.append(cues)

        return ",".join(rs_list)

    def report(self,ip,port,protocol):
        package = (ip,port,protocol,)
        self._report(package)

    def start_masscan(self,command):
        preg = re.compile(r".*Discovered open port (?P<port>\d+)/(?P<protocol>\w+) on (?P<ip>((25[0-5]|2[0-4]\d|[01]?\d\d?)($|(?!\.$)\.)){4}).*",re.I)
        cmddir = os.path.join(os.path.join(os.path.dirname(__file__), 'bin'))
        process = subprocess.Popen(command, cwd=cmddir, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        while True:
            time.sleep(0.1)
            returncode = process.poll()
            line = process.stdout.readline()
            line = line.strip()
            if line:
                rs = re.match(preg,line)
                if rs:
                    self.report(rs.group("ip"),rs.group("port"),rs.group("protocol"))
            pid = process.pid
            if returncode is None:
                continue
            else:
                break
    @classmethod
    def div_list(cls,ls, n):
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

    def _run(self, *args,**kwargs):
        self.init_db()
        logger.info("tasks start running")
        if any([not kwargs.get("ipscope",None),not kwargs.get("ports",None)]):
            return
        ipscope = self.package_ipscope(kwargs.get("ipscope"))
        ports = computing_ports(kwargs.get("ports"))
        pseudo_ip = kwargs.get("pseudo_ip","")
        pseudo_port = kwargs.get("pseudo_port","")
        sps = len(ports) / 1000
        if (sps <= 1):
            ports_list = [ports]
        else:
            ports_list = self.div_list(ports, sps)

        if len(ports_list) <= 1:
            for plist in ports_list:
                pl = ",".join([str(x) for x in plist])
                command = self.create_command(ipscope,pl,pseudo_ip,pseudo_port)
                self.start_masscan(command)
        else:
            pool = ThreadPool(4)
            for plist in ports_list:
                pl = ",".join([str(x) for x in plist])
                command = self.create_command(ipscope,pl,pseudo_ip,pseudo_port)
                pool.add_task(self.start_masscan,command)
            pool.wait_all_complete()
        self.finished = True
        logger.info("task is finished")

    def _store(self):
        logger.info("start collecting results information.........")
        while not self.finished:
            if self.result_manage.output_queue.empty():
                continue
            else:
                ip, port, protocol = self.result_manage.output_queue.get(timeout=0.1)
                ref_service, ref_banner = query_service_and_banner(port, protocol)
                web_banner, web_service, ostype, assettype, domain, position, proext = HttpWeb.detect(ip, port)
                banner = web_banner if web_banner else get_socket_banner(ip, port, ref_banner)
                banner = char_convert(banner)
                banner = base64.b64encode(banner)
                service = web_service if web_service else ref_service
                banner = cgi.escape(banner)
                rs_one = {"ip": ip,"domain": domain, "port": str(port), "service": service, "banner": banner, "protocol": protocol,"assettype": assettype, "position": position, "proext": proext}
                self.db.insert('asset',rs_one,filter=False)

    def _create_report(self):
        logger.info("start creating reports.........")
        rt = Report(self.portdb)
        rt.report_html()
        logger.info("report completion [{0}]".format(rt.filename))

def cmdLineParser():
    optparser = OptionParser()
    optparser.add_option("-i", "--ipscope", dest="ipscope", type="string", help="Specify IP scan range,eg: 127.0.0.1/24 or 10.65.10.3-10.65.10.255")
    optparser.add_option("-p", "--portscope", dest="portscope", type="string",default="web_ports",help="Specify Port scan range,eg: 80,443,8080 or web_ports or top_100 or top_1000")
    try:
        (options, args) = optparser.parse_args()
    except Exception, err:
        sys.exit(0)

    if len(sys.argv) < 2:
        optparser.print_help()
        sys.exit(0)

    ipscope = options.ipscope
    portscope = options.portscope
    portscope = default_ports.get(portscope,portscope)
    test = Plugin()
    test.cmd_run(ipscope=ipscope, ports=portscope)

if __name__ == "__main__":
    cmdLineParser()