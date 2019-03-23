# assetscan
资产扫描工具

python Main.py -i 10.0.0.1/24
python Main.py -i 10.0.0.1-255

默认是系统自动提供的web端口

也可以指定端口范围

python Main.py -i 10.0.0.1/24 -p 80,443,8080
python Main.py -i 10.0.0.1-255 -p 1-65535
