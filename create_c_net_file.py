from common.utils import CommonUtils

with open("hosts.txt", "rb+") as file:
    ipscope = file.read()

domains = CommonUtils.package_ipscope_c_net(ipscope)

flag = 0
for ipc in domains:
    with open("rhosts.txt","ab+") as file1:
        if flag == 0:
            file1.truncate()
            flag=1
        file1.write(ipc+"\n")