import os
import re
import socket

app_path = '/home/yangs/Bigdata/BigDataBackend/cmd'
work_load = '$HIBENCH_WORKLOADS/ml/bayes/spark/run.sh'


def get_slaves_name():#Todo:检测slave是否正常
    slaves = []
    f = os.popen("cat $SPARK_HOME/conf/slaves")
    lines = f.read().split('\n')
    for line in lines:
        if not('#'in line or len(line) == 0):
            slaves.append(line)
    f.close()
    return slaves

def  get_slaves_ip():
    slaves_ip = []
    slaves_name = get_slaves_name()
    slaves_ip = []
    f = os.popen("cat /etc/hosts")
    hosts = f.read().split('\n')
    pattern = re.compile(r'((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3}')
    for slave_name in slaves_name:
        for host in hosts:
            if re.search(slave_name,host):
                slaves_ip.append(pattern.search(host).group())
    f.close()
    return slaves_ip

def get_user():
    f = os.popen("whoami")
    name = f.read()[:-1]
    f.close()
    return name

def get_master_name():
    return socket.gethostname()

def get_master_ip():
    return socket.gethostbyname(get_master_name())
