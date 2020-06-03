# -*- coding:utf-8 -*-
import base64
import json
import os
import shutil
import time

from common.db.sqlite3_db import sqlite3_db
from common.utils import update_file_content
from common.logger.log_util import LogUtil as logging
logger = logging.getLogger(__name__)

class Report(object):
    def __init__(self,portdb,dirdb=None):
        self.portdb = portdb
        self.dirdb = dirdb
        self.report_dir = os.path.dirname(self.portdb)
        self.report_tpl_dir = os.path.join(os.path.dirname(__file__),"template")
        self.port_db = sqlite3_db(self.portdb)
        self.dir_db = sqlite3_db(self.dirdb) if self.dirdb else None


    def create_scan_datajson(self):
        port_rs = self.port_db.queryall("select * from asset")
        ip_port_map = {}
        ip_children = []
        for id, taskid, ip, port, domain, banner, protocol, service, assettype, position, schema in port_rs:
            if self.dir_db:
                dir_rs = self.dir_db.queryall("select * from fuzztask where taskid={0} and assetid={1}".format(taskid,id))
                if dir_rs:
                    path_children = []
                    for id,taskid,assetid,url,path,reqcode,banner,reslength,status in dir_rs:
                        path_children.append({"name": "/{0} (code:{1})".format(path, reqcode),"children": [{"name": banner, "type": "path", "value": url}]})
                else:
                    if schema:
                        path_children = [{"name": "/","children": [{"name": banner, "type": "path", "value":"{schema}://{ip}:{port}".format(schema=schema, ip=ip, port=port)}]}]
                    else:
                        path_children = [{"name": "Unknown", "children": [{"name": base64.b64decode(banner)}]}]
            else:
                if schema:
                    path_children = [{"name": "/", "children": [{"name": banner, "type": "path","value": "{schema}://{ip}:{port}".format(schema=schema,ip=ip,port=port)}]}]
                else:
                    path_children = [{"name": "Unknown", "children": [{"name": base64.b64decode(banner)}]}]

            if ip_port_map.has_key(ip):
                if port not in ip_port_map.get(ip):
                    ip_port_map.get(ip).append(port)
                    for x in ip_children:
                        if x.get("name") == ip:
                            x.get("children").append({"name": port, "children": path_children})
                            break
            else:
                ip_port_map.update({ip:[port]})
                ip_children.append({"name": ip, "children": [{"name": port, "children": path_children}]})
        datajson = json.dumps({"name":u"结果","children":ip_children})
        return datajson

    def report_html(self):
        files = ["index.html","inspector.css","package.json","utils.js"]
        report_files = os.path.join(self.report_dir,"{0}_files".format(time.strftime("%H_%M_%S", time.localtime())))
        if not os.path.exists(report_files):
            os.makedirs(report_files)
        for f in files:
            shutil.copy(os.path.join(self.report_tpl_dir,f),report_files)

        jsondata = self.create_scan_datajson()
        update_file_content(os.path.join(report_files,"index.html"),"$$$JSONDATA$$$",jsondata)
        logger.info("scan result: {0}".format(os.path.join(report_files,"index.html")))

if __name__ == "__main__":
    dirdb = r"D:\gitproject\assetscan\repertory\2020-06-01\13_49_47.fuzz.db"
    portdb = r"D:\gitproject\assetscan\repertory\2020-06-01\13_49_47.port.db"
    test = Report(portdb,dirdb)
    print test.create_scan_datajson()