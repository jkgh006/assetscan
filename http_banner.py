import threading
from ProbeTool import HttpWeb
from common.utils import query_service_and_banner, get_socket_banner, CommonUtils
from constants import default_ports
from pool.thread_pool import ThreadPool
mu = threading.Lock()
ports = default_ports.get("web_ports")
with open("hosts.txt", "rb+") as file:
    ipscope = file.read()

domains = CommonUtils.package_ipscope(ipscope,handle_ip=False,retType="list")
def scanner(ip,port):
    ref_service, ref_banner = query_service_and_banner(port, "tcp")
    web_banner, web_service, ostype, assettype, domain, position, proext = HttpWeb.detect(ip, port)
    banner = web_banner if web_banner else get_socket_banner(domain, port, ref_banner)
    if mu.acquire(True):
        if proext:
            msg = "{proext}://{domain}:{port}      {banner}\n".format(proext=proext,domain=ip,port=port,banner=banner)
            f = open("result.txt","ab+")
            f.write(msg)
            f.close()
        mu.release()

f = open("result.txt","wb+")
f.truncate()
f.close()
pool = ThreadPool(30)
for domain in domains:
    for port in ports:
        pool.add_task(scanner,domain,port)
pool.wait_all_complete()