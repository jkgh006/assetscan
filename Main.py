# -*- coding:utf-8 -*-
import base64
import md5
import os
import socket
import sys
import uuid
import subprocess
import time
import re
import cgi
from optparse import OptionParser
from multiprocessing import Process, Queue
from Report import Report
from TaskCenter import TaskCenter, TaskStatus
from common.initsql import SQL1,SQL2
from common.db.sqlite3_db import sqlite3_db
from common.utils import query_service_and_banner, get_socket_banner, char_convert, computing_ports, WINDOWS, UsePlatform, is_domain
from ProbeTool import HttpWeb
from constants import default_ports
from fuzzdir.dirfuzz import DirFuzz
from pool.thread_pool import ThreadPool
from IPlugin import IPlugin

from common.logger.log_util import LogUtil as logging
logger = logging.getLogger(__name__)
class Plugin(IPlugin):
    def __init__(self,msgqueue=None,taskstatus=None,statusqueue=None):
        super(Plugin, self).__init__()
        self.msgqueue = msgqueue
        self.statusqueue = statusqueue
        self.taskstatus = taskstatus
        self._id = 10000
        self._name = "PortScan"
        self._level = 10
        self.rate = 500
        self.uuid_hash = md5.md5(str(uuid.uuid4())).hexdigest()
        self.finished = False
        self.db = None
        self.taskid = 0

    def init_db(self):
        self.portdb = os.path.join(os.path.dirname(__file__), 'repertory',format(time.strftime("%Y-%m-%d", time.localtime())),"{0}.port.db".format(time.strftime("%H_%M_%S", time.localtime())))
        if not os.path.exists(os.path.dirname(self.portdb)):
            os.makedirs(os.path.dirname(self.portdb))
        self.db = sqlite3_db(self.portdb)
        self.db.create_table(SQL1)
        self.db.create_table(SQL2)
        logger.info("database (port.db) initialization completed")
        name = "assetscan_task_{0}".format(self.uuid_hash)
        self.db.insert('porttask', {"name":name,"status":1}, filter=False)
        rs = self.db.query_row("select id from porttask where name='{0}'".format(name))
        self.taskid = rs[0]

    def create_command(self,ipscope,ports,pseudo_ip,pseudo_port):
        if UsePlatform() == WINDOWS:
            command = ["cmd.exe","/c","masscan",ipscope,"-p",str(ports),"--max-rate",str(self.rate)]
        else:
            command = ["masscan", ipscope, "-p", str(ports), "--max-rate", str(self.rate)]
        if pseudo_ip:
            command = command + [" --source-ip ",str(pseudo_ip)]
        if pseudo_port:
            command = command + [" --source-port ",str(pseudo_port)]
        return command

    @classmethod
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

    @classmethod
    def getIp(cls,domain):
        try:
            myaddr = socket.getaddrinfo(domain, 'http')[0][4][0]
            return myaddr
        except:
            return None

    @classmethod
    def package_ipscope_c_net(cls,ipscope):
        rs_list = []
        retlist = cls.package_ipscope(ipscope,retType="list")
        for ip in retlist:
            ipcues = ip.split(".")
            newip = "{0}.{1}.{2}.0/24".format(ipcues[0],ipcues[1],ipcues[2])
            rs_list.append(newip)
        rs_list = list(set(rs_list))
        return rs_list

    @classmethod
    def package_ipscope(cls,ipscope,handle_ip=True,retType="string"):
        rs_list = []
        ret_list = []
        ipscope_list = cls.ListTrim(ipscope.split("\n"))
        for cues in ipscope_list:
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
            pool = ThreadPool(5)
            for plist in ports_list:
                pl = ",".join([str(x) for x in plist])
                command = self.create_command(ipscope,pl,pseudo_ip,pseudo_port)
                pool.add_task(self.start_masscan,command)
            pool.wait_all_complete()
        self.finished = True
        TaskCenter.update_task_status(self.statusqueue,"portscan",TaskStatus.FINISHED) if self.statusqueue else None
        logger.info("portscan_task is finished")

    def _store(self):
        logger.info("start collecting results information.........")
        self.product = 0
        while not self.finished:
            time.sleep(0.2)
            if not self.result_manage.output_queue:
                continue
            else:
                ip, port, protocol = self.result_manage.output_queue.pop()
                ref_service, ref_banner = query_service_and_banner(port, protocol)
                web_banner, web_service, ostype, assettype, domain, position, proext = HttpWeb.detect(ip, port)
                banner = web_banner if web_banner else get_socket_banner(ip, port, ref_banner)
                banner = char_convert(banner)
                banner = base64.b64encode(banner)
                service = web_service if web_service else ref_service
                banner = cgi.escape(banner)
                rs_one = {"ip": ip,"taskid":self.taskid,"domain": domain,"port": str(port), "service": service, "banner": banner, "protocol": protocol,"assettype": assettype, "position": position, "proext": proext}
                self.db.insert('asset',rs_one,filter=False)
                if self.msgqueue:
                    rs = self.db.query_row("select id from asset where ip='{0}' and port='{1}' and taskid='{2}'".format(ip, port,self.taskid))
                    rs_one.update({"assetid":rs[0]})
                    self.product = self.product + 1
                    self.msgqueue.put(rs_one)

    def _create_report(self):
        logger.info("start creating reports.........")
        rt = Report(self.portdb)
        rt.report_html()
        logger.info("report completion [{0}]".format(rt.filename))

def cmdLineParser():
    optparser = OptionParser()
    optparser.add_option("-i", "--ipscope", dest="ipscope", type="string", help="Specify IP scan range,eg: 127.0.0.1/24 or 10.65.10.3-10.65.10.255")
    optparser.add_option("-p", "--portscope", dest="portscope", type="string",default="web_ports",help="Specify Port scan range,eg: 80,443,8080 or web_ports or top_100 or top_1000")
    optparser.add_option("-f", "--file", dest="file", type="string",default="",help="asset's file")
    optparser.add_option("-t", "--task-run",action="store_true", dest="taskstart", default=False,help="Start in task mode,default cmd run")
    try:
        (options, args) = optparser.parse_args()
    except Exception, err:
        sys.exit(0)

    if len(sys.argv) < 2:
        optparser.print_help()
        sys.exit(0)

    ipscope = options.ipscope
    portscope = options.portscope
    assetfile = options.file
    taskstart = options.taskstart
    if assetfile:
        with open(assetfile,"rb+") as file:
            ipscope = file.read()
    portscope = default_ports.get(portscope,portscope)
    if taskstart:
        msgqueue = Queue()
        statusqueue = Queue()
        mainscan = Plugin(msgqueue,statusqueue=statusqueue)
        dirfuzz = DirFuzz(statusqueue=statusqueue)
        TaskCenter.register(statusqueue,["portscan","dirscan"])
        mainprocess = Process(target=mainscan.cmd_run, kwargs={"ipscope":ipscope, "ports":portscope})
        dirfuzzprocess = Process(target=dirfuzz.funzz,args=(msgqueue,))
        taskcenterprocess = Process(target=TaskCenter.run,args=(statusqueue,))
        mainprocess.start()
        dirfuzzprocess.start()
        taskcenterprocess.start()
        mainprocess.join()
        dirfuzzprocess.join()
        taskcenterprocess.join()
        mainprocess.terminate()
        dirfuzzprocess.terminate()
        taskcenterprocess.terminate()
    else:
        test = Plugin()
        test.cmd_run(ipscope=ipscope, ports=portscope)

if __name__ == "__main__":
    cmdLineParser()