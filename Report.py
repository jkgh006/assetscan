# -*- coding:utf-8 -*-
import base64
import cgi
import os

from common.db.sqlite3_db import sqlite3_db


class Report(object):
    """
    filename
    portdb 项目的db文件
    """
    def __init__(self,portdb):
        self.portdb = portdb
        self.filename = os.path.join(os.path.dirname(self.portdb),"report.html")
        self.tplfile = os.path.join(os.path.dirname(__file__), 'datas','tpl.html')

    def get_scan_result(self):
        results = {}
        db = sqlite3_db(self.portdb)
        rs = db.queryall("select * from asset")
        for id, ip, port, domain, banner, protocol, service, assettype, position, schema in rs:
            if results.get(ip, None):
                results.get(ip).append({"port": port, "domain": domain, "banner": base64.b64decode(banner),
                                             "protocol": protocol, "service": service, "assettype": assettype,
                                             "position": position, "schema": schema})
            else:
                results.update({ip: [{"port": port, "domain": domain, "banner": base64.b64decode(banner),
                                             "protocol": protocol, "service": service, "assettype": assettype,
                                             "position": position, "schema": schema}]})
        return results

    def report_html(self):
        tpl = """
            <div class="panel panel-default">
                <div class="panel-heading">
                    <h4 class="panel-title">
                        <a data-toggle="collapse" data-parent="#accordion" href="#{index}">
                            {title}
                        </a>
                    </h4>
                </div>
                <div id="{index}" class="panel-collapse collapse">
                    <div class="panel-body">
                        <table class="table">
                           <thead>
                              <tr>
                                 <th>ip</th>
                                 <th>port</th>
                                 <th>banner</th>
                                 <th>service</th>
                                 <th>protocol</th>
                                 <th>position</th>
                                 <th>domain</th>
                              </tr>
                           </thead>
                           <tbody>
                               {cues}
                           </tbody>
                        </table>
                    </div>
                </div>
            </div>
        """
        tpl2 = """
        <tr>
            <td>
                {ip}
            </td>
            <td>
                {port}
            </td>
            <td>
                {banner}
            </td>
            <td>
                {service}
            </td>
            <td>
                {protocol}
            </td>
            <td>
                {position}
            </td>
            <td>
                {domain}
            </td>
        </tr>
        """
        table_start = []
        count = 1
        for ip,cues in self.get_scan_result().items():
            count = count+1
            urls = []
            trs = []
            for c in cues:
                port = c.get("port")
                schema = c.get("schema")
                go = '<a href="{schema}://{ip}:{port}" target="_blank">{port}</a>'.format(schema=schema, port=port,ip=ip)
                urls.append(go)
                trs.append(tpl2.format(ip=ip,port=go,banner=cgi.escape(c.get("banner")),service=c.get("service"),position=c.get("position"),protocol=c.get("protocol"),domain=c.get("domain")))
            title = "{ip}------------------------------------[{ports}]".format(ip=ip,ports=",".join(urls))
            table_start.append(tpl.format(index="collapseOne{0}".format(count),title=title,cues="\n".join(trs)))
        f1 = open(self.tplfile,"rb+")
        content = f1.read()
        f1.close()
        f2 = open(self.filename,"wb+")
        f2.write(content.replace("[BODY]","\n".join(table_start)))
        f2.close()

if __name__ == "__main__":
    test = Report(r"E:\Penetration\Assert_Scan\repertory\2019-03-22_22_02_02\rs.db")
    test.report_html()