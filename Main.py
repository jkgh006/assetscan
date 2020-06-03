# -*- coding:utf-8 -*-
import base64
import os
import sys
import uuid
import subprocess
import time
import re
import cgi
from optparse import OptionParser
from multiprocessing import Process, Queue
from TaskCenter import TaskCenter, TaskStatus
from common.initsql import SQL1,SQL2
from common.db.sqlite3_db import sqlite3_db
from common.utils import query_service_and_banner, get_socket_banner, char_convert, computing_ports, WINDOWS, \
    UsePlatform, CommonUtils, md5_string
from ProbeTool import HttpWeb
from constants import default_ports
from fuzzdir.dirfuzz import DirFuzz
from pool.thread_pool import ThreadPool
from IPlugin import IPlugin

from common.logger.log_util import LogUtil as logging
from report.ReportCenter import Report
from thirdparty.connection.http_urllib3 import HttpUtil

logger = logging.getLogger(__name__)
class PortScan(IPlugin):
    def __init__(self,msgqueue=None,taskstatus=None,statusqueue=None):
        super(PortScan, self).__init__()
        self.msgqueue = msgqueue
        self.statusqueue = statusqueue
        self.taskstatus = taskstatus
        self._id = 10000
        self._name = "portscan"
        self._level = 10
        self.rate = 500
        self.uuid_hash = md5_string(str(uuid.uuid4()))
        self.finished = False
        self.db = None
        self.taskid = 0
        self.portdb = os.path.join(os.path.dirname(__file__), 'repertory',format(time.strftime("%Y-%m-%d", time.localtime())),"{0}.port.db".format(time.strftime("%H_%M_%S", time.localtime())))
        if not os.path.exists(os.path.dirname(self.portdb)):
            os.makedirs(os.path.dirname(self.portdb))

    def init_db(self):
        self.db = sqlite3_db(self.portdb)
        self.db.create_table(SQL1)
        self.db.create_table(SQL2)
        logger.info("database (port.db) initialization completed")
        name = "assetscan_task_{0}".format(self.uuid_hash)
        self.db.insert('porttask', {"name":name,"status":1}, filter=False)
        rs = self.db.query_row("select id from porttask where name='{0}'".format(name))
        self.taskid = rs[0]

    def report(self,ip,port,protocol):
        package = (ip,port,protocol,)
        self._report(package)

    def start_scanning(self,scanmode,command):

        if scanmode == "fast":
            preg = re.compile(r".*Discovered open port (?P<port>\d+)/(?P<protocol>\w+) on (?P<ip>((25[0-5]|2[0-4]\d|[01]?\d\d?)($|(?!\.$)\.)){4}).*",re.I)
        else:
            if UsePlatform() == WINDOWS:
                preg = re.compile(r".*\d+/\d+/\d+ \d+:\d+:\d+ (?P<protocol>\w+)://(?P<ip>((25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})):(?P<port>\d+).*",re.I)
            else:
                preg = re.compile(r".*INFO\\[\d+\\] (?P<protocol>\w+)://(?P<ip>((25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})):(?P<port>\d+).*",re.I)

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

    def _run(self, *args,**kwargs):
        self.init_db()
        logger.info("tasks start running")
        if any([not kwargs.get("ipscope",None),not kwargs.get("ports",None)]):
            return
        ipscope = CommonUtils.package_ipscope(kwargs.get("ipscope"))
        ports = computing_ports(kwargs.get("ports"))
        scanmode = kwargs.get("scanmode","fast")
        pseudo_ip = kwargs.get("pseudo_ip","")
        pseudo_port = kwargs.get("pseudo_port","")
        sps = len(ports) / 1000
        if (sps <= 1):
            ports_list = [ports]
        else:
            ports_list = CommonUtils.div_list(ports, sps)

        if len(ports_list) <= 1:
            for plist in ports_list:
                pl = ",".join([str(x) for x in plist])
                command = CommonUtils.create_command(scanmode,ipscope=ipscope,ports=pl,pseudo_ip=pseudo_ip,pseudo_port=pseudo_port,rate=self.rate)
                self.start_scanning(scanmode,command)
        else:
            pool = ThreadPool(5)
            for plist in ports_list:
                pl = ",".join([str(x) for x in plist])
                command = CommonUtils.create_command(scanmode,ipscope=ipscope,ports=pl,pseudo_ip=pseudo_ip,pseudo_port=pseudo_port,rate=self.rate)
                pool.add_task(self.start_scanning,scanmode,command)
            pool.wait_all_complete()
        self.finished = True
        TaskCenter.update_task_status(self.statusqueue,"portscan",TaskStatus.FINISHED) if self.statusqueue else None

    def _store(self):
        logger.info("start collecting results information.........")
        self.product = 0
        httpclient = HttpUtil()
        while not self.finished:
            time.sleep(0.2)
            if not self.result_manage.output_queue:
                continue
            else:
                ip, port, protocol = self.result_manage.output_queue.pop()
                ref_service, ref_banner = query_service_and_banner(port, protocol)
                web_banner, web_service, ostype, assettype, domain, position, proext = HttpWeb.detect(ip, port,httpclient)
                banner = web_banner if web_banner else get_socket_banner(ip, port, ref_banner)
                banner = banner.replace("\n", "").replace("\r", "")
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

def cmdLineParser():
    optparser = OptionParser()
    optparser.add_option("-i", "--ipscope", dest="ipscope", type="string", help="Specify IP scan range,eg: 127.0.0.1/24 or 10.65.10.3-10.65.10.255")
    optparser.add_option("-p", "--portscope", dest="portscope", type="string",default="web_ports",help="Specify Port scan range,eg: 80,443,8080 or web_ports or top_100 or top_1000")
    optparser.add_option("-m", "--scanmode", dest="scanmode", type="string", default="fast", help="Scan mode[fast,low],default:fast")
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
    scanmode = options.scanmode
    taskstart = options.taskstart
    if assetfile:
        with open(assetfile,"rb+") as file:
            ipscope = file.read()
    portscope = default_ports.get(portscope,portscope)
    if taskstart:
        msgqueue = Queue()
        statusqueue = Queue()
        mainscan = PortScan(msgqueue,statusqueue=statusqueue)
        dirfuzz = DirFuzz(statusqueue=statusqueue)
        TaskCenter.register(statusqueue,[mainscan.name,dirfuzz.name])
        dirdb = dirfuzz.fuzzdb
        portdb = mainscan.portdb
        rpt_tools = Report(portdb, dirdb)
        mainprocess = Process(target=mainscan.cmd_run, kwargs={"ipscope":ipscope,"ports":portscope,"scanmode":scanmode})
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
        rpt_tools.report_html()

    else:
        test = PortScan()
        test.cmd_run(ipscope=ipscope, ports=portscope,scanmode=scanmode)
        rpt_tools = Report(test.portdb)
        rpt_tools.report_html()

if __name__ == "__main__":
    cmdLineParser()