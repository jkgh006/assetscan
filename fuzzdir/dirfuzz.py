# -*- coding:utf-8 -*-
import base64
import cgi
import os
import random
import sys
import threading
import time
from optparse import OptionParser
from thirdparty.connection.http_urllib3 import HttpUtil

from TaskCenter import TaskStatus, TaskCenter
from common.initsql import SQL3
from common.utils import char_convert, get_banner_by_content
from pool.thread_pool import ThreadPool
from ProbeTool import HttpWeb
from common.db.sqlite3_db import sqlite3_db
from common.logger.log_util import LogUtil as logging
from urlparse import urljoin
logger = logging.getLogger(__name__)
mu = threading.Lock()

class DirFuzz(object):

    def __init__(self,dbname=None,url=None,statusqueue=None):
        self.dbname = dbname
        self.filename = []
        self.taskid = None
        self.fuzzdb = None
        self.url = url
        self.statusqueue = statusqueue
        self.taskrun = False
        self.finished = False
        self.single = False if not self.url else True
        self.name = "dirscan"
        if not self.taskrun:
            if self.single:
                self.fuzzdb = os.path.join(os.path.dirname(__file__),'..','repertory','tmp',"{0}.fuzz.db".format(time.strftime("%Y-%m-%d_%H_%M_%S", time.localtime())))
            else:
                self.fuzzdb = os.path.join(os.path.dirname(__file__),'..','repertory',format(time.strftime("%Y-%m-%d", time.localtime())),"{0}.fuzz.db".format(time.strftime("%H_%M_%S", time.localtime())))
        else:
            self.fuzzdb = os.path.join(os.path.dirname(__file__), '..', 'repertory',format(time.strftime("%Y-%m-%d", time.localtime())),"{0}.fuzz.db".format(time.strftime("%H_%M_%S", time.localtime())))

        if not os.path.exists(os.path.dirname(self.fuzzdb)):
            os.makedirs(os.path.dirname(self.fuzzdb))

    def init_db(self):
        self.fuzzdb = sqlite3_db(self.fuzzdb)
        self.fuzzdb.create_table(SQL3)
        logger.info("database (fuzz.db) initialization completed")

    def init_dir_dict(self):
        filename = os.path.join(os.path.join(os.path.dirname(__file__), 'dict'),"directory.lst")
        with open(filename,"rb+") as file:
            self.filename = [x.strip() for x in file.readlines()]

    def cache_content(self,taskid,assetid,url):
        try:
            filename = "".join(random.sample('abcdefghijklmnopqrstuvwxyz0123456789', 6)) + ".css"
            dirname = "".join(random.sample('abcdefghijklmnopqrstuvwxyz0123456789', 6)) + "/"
            res1 = self.httpclient.request(urljoin(url,filename), timeout=3,redirect=True)
            res2 = self.httpclient.request(urljoin(url, dirname), timeout=3,redirect=True)
            res3 = self.httpclient.request(url,timeout=3,redirect=True)
            content = res3.content
            rs_one = {"taskid": taskid, "assetid": assetid, "url": url,"banner": base64.b64encode(content[0:100]), "reslength": len(content), "status": 1}
            self.fuzzdb.insert('fuzztask', rs_one, filter=False)
            rs = [res1.content,res2.content,res3.content]
        except:
            rs = None
        return rs

    def req_ad_file(self,taskid,assetid,url,filename,cache):
        newurl = urljoin(url,filename)
        try:
            res = self.httpclient.request(newurl,timeout=3,redirect=True)
            condition1 = (abs(len(res.content)-len(cache[0])) <=20) or (abs(len(res.content)-len(cache[1])) <= 20) or (abs(len(res.content.replace(filename,"").replace(newurl,""))-len(cache[2].replace(filename,"").replace(newurl,""))) <= 20)
            condition2 = (res.status_code not in [401,405]) and ((res.status_code >= 400 and res.status_code < 500) or (res.status_code > 500) or (res.status_code < 200))
            if condition2:
                pass
            else:
                if not condition1:
                    if mu.acquire():
                        content = res.content[0:100] if not get_banner_by_content(res) else "["+get_banner_by_content(res)+"] ==" + res.content[0:100]
                        content = content.replace("\n","").replace("\r","")
                        rs_one = {"taskid":taskid,"assetid":assetid,"url":newurl,"path":filename,"reqcode":res.status_code,"banner":cgi.escape(base64.b64encode(char_convert(content))),"reslength":len(res.content),"status":1}
                        self.fuzzdb.insert('fuzztask', rs_one, filter=False)
                        mu.release()
        except:
            pass

    def result_unique(self):
        sql = "select * from (select *,count(reslength) as flag from fuzztask where taskid={0} group by reslength)".format(self.taskid)
        rs = self.fuzzdb.queryall(sql)
        sql_1 = "delete from fuzztask"
        sql_2 = "update sqlite_sequence SET seq = 0 where name ='fuzztask'"
        self.fuzzdb.query(sql_1)
        self.fuzzdb.query(sql_2)
        for id,taskid,assetid,url,path,reqcode,banner,reslength,status,count in rs:
            rs_one = {"taskid": taskid, "assetid": assetid, "url": url,"path":path,"reqcode":reqcode,"banner": banner, "reslength": reslength, "status": 1}
            self.fuzzdb.insert('fuzztask', rs_one, filter=False)
            logger.info("url:{0} ".format(url))

    def funzz(self,msgqueue=None):
        if msgqueue:
            self.taskrun = True
        self.init_db()
        self.init_dir_dict()
        tp = ThreadPool(10)
        self.httpclient = HttpUtil()
        if msgqueue is None:
            if not self.single:
                rs = self.assetdb.query_all("select * from asset")
                for id, taskid,ip, port, domain, banner, protocol, service, assettype, position, schema in rs:
                    if self.taskid is None:
                        self.taskid = taskid
                    web_banner, web_service, ostype, assettype, domain, position, proext = HttpWeb.detect(ip, port,self.httpclient)
                    if proext:
                        url = "{schema}://{ip}:{port}".format(schema=proext,ip=ip,port=port)
                        rs = self.cache_content(taskid,id,url)
                        if rs:
                            for x in self.filename:
                                tp.add_task(self.req_ad_file,taskid,id,url,x,rs)
            else:
                self.taskid = -100
                rs = self.cache_content(self.taskid,-100,self.url)
                for x in self.filename:
                    tp.add_task(self.req_ad_file, self.taskid,-100,self.url, x, rs)
        else:
            task_null_count = 0
            while not self.finished:
                time.sleep(0.2)
                if  task_null_count >= 5:
                    TaskCenter.update_task_status(self.statusqueue, "dirscan", TaskStatus.FINISHED)
                    self.finished = True
                    continue
                if not msgqueue.empty():
                    rs_one = msgqueue.get(True)
                    self.taskid = rs_one.get("taskid")
                    web_banner, web_service, ostype, assettype, domain, position, proext = HttpWeb.detect(rs_one.get("ip"), rs_one.get("port"),self.httpclient)
                    if proext:
                        url = "{schema}://{ip}:{port}".format(schema=proext, ip=rs_one.get("ip"), port=rs_one.get("port"))
                        rs = self.cache_content(self.taskid,rs_one.get("assetid"),url)
                        if rs:
                            for x in self.filename:
                                tp.add_task(self.req_ad_file,self.taskid,rs_one.get("assetid"), url, x, rs)
                else:
                    if TaskCenter.task_is_finished(self.statusqueue,"portscan"):
                        task_null_count = task_null_count+1
                        time.sleep(0.5)

        tp.wait_all_complete()
        self.result_unique()

if __name__ == "__main__":
    optparser = OptionParser()
    optparser.add_option("-d", "--dbname", dest="dbname", type="string", default="", help="port scan result's db")
    optparser.add_option("-u", "--url", dest="url", type="string", default="", help="url cues")
    try:
        (options, args) = optparser.parse_args()
    except Exception, err:
        sys.exit(0)
    if len(sys.argv) < 2:
        optparser.print_help()
        sys.exit(0)
    dbname = options.dbname
    url = options.url
    test = DirFuzz(dbname=dbname,url=url)
    test.funzz()
