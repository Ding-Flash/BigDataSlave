import sys
import time
import os
import threading
import time
import logging
import argparse
import subprocess
sys.path.append('lib')
from decoder import *
from env_conf import *
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
prefix = app_path
benchmark_prefix = work_load
master_ip = get_master_ip()
slaves_name = get_slaves_name()

def start_samp_slave(slave):
    os.system('ssh '+slave+' python3 '+prefix+'lib/samp_run.py')
# 去掉异常生成器的调用
# def start_anomaly_slave(slave,last,t,ip):
#     os.system('ssh '+slave+' python3 '+prefix+'anomaly_generator.py -t '+t+' -last '+str(last)+' -tnum '+str(res.tnum)+' ')

def start_iostat_local():
    os.system("python "+prefix+"/samp_run.py")
    time.sleep(100)

# def start_anomaly_local():
#     os.system("python "+prefix+"anomaly_generator.py -disable -ip "+master_ip)
#     time.sleep(100)

def start_benchmark(cmd):
    ### luice modified
    '''
    检查是否存在 spark 程序，如果存在，运行 spark 程序，否则运行 hadoop 程序
    '''
    # workload_path = benchmark_prefix+name
    # if os.path.exists(workload_path + '/spark'):
    #     os.system(workload_path + '/spark/run.sh')
    # elif os.path.exists(workload_path + '/hadoop'):
    #     os.system(workload_path + '/hadoop/run.sh')
    while True:
        try:
            print(cmd)
            subprocess.check_call(cmd, shell=True)
            break
        except subprocess.CalledProcessError:
            logging.info("命令执行失败,请重新输入")
            cmd = input()
            continue


#    os.system('ssh slave5 \'' + workload_path + '/hadoop/run.sh\'')

def start(res):
    print('请输入执行任务的命令')
    cmd = input()
    while True:
        # benchmark=res.name
        pin_ano_start_time=time.time()
        ### luice comment

        for slave in slaves_name:
            t = threading.Thread(target = start_samp_slave,args=(slave,))
            t.start()

        slaves=res.slaves
        ano_slaves=[]
        if slaves=='all':
            ano_slaves=slaves_name
        elif slaves=='':
            pass
        else:
            ano_slaves.extend(slaves.split())
        # 去掉异常生成器的调用
        # for i in ano_slaves:
        #     t = threading.Thread(target = start_anomaly_slave,args=(i,res.last,res.ano,res.ip))
        #     t.start()
        print('ready to start workload,timestamp=',time.time())
        pin_benchmark_start_time=time.time()
        try:
            subprocess.check_call(cmd, shell=True)
            break
        except subprocess.CalledProcessError:
            logging.info("命令执行失败,请重新输入")
            cmd = input()
            continue
    # start_benchmark(cmd)
    print('benchmark done! timestamp=',time.time())
    print('ready to collect logs')
    pin_benmark_end_time=time.time()
    collect_logs()
    pin_collect_log_time=time.time()
    kill()
    decode()

    pin_end_time=time.time()
    with open('experiment/overhead','a') as d:
        d.write('%.3f %.3f %.3f %.3f %.3f %.3f'%(pin_global_init_time-pin_global_start_time,pin_ano_start_time-pin_global_init_time,
            pin_benchmark_start_time-pin_ano_start_time,pin_benmark_end_time-pin_benchmark_start_time,pin_collect_log_time-pin_benmark_end_time,
            pin_end_time-pin_collect_log_time)+'\n')
    # get application duration
    for file in os.listdir('out'):
        if file.startswith('app'):
            app='out/'+file
    # luice comment
    '''
    import job_time
    print('spark log file:',app)
    start_time,end_time=job_time.job_time(app)
    print('\n+---------------------------------------------------------------+')
    print('\tjob time:',end_time-start_time,'delay:',start_time-pin_ano_start_time)
    print('+---------------------------------------------------------------+\n')
    with open(res.job_time_file,'a') as f:
        f.write(str(end_time-start_time)+'\n')
    with open('out/delay','w') as f:
        f.write(str(start_time-pin_ano_start_time))
    time.sleep(5)
    os.system("ps aux|grep \"anomaly_generator.py\"|awk \'{print $2}\'|xargs kill $1")
    print('\033[32m[INFO] Application analysis...\033[0m')
    os.system('python3 root_cause.py')
    '''

def collect_logs():
    os.system("cp $SPARK_HOME/tsee_log/* ./logs")
    os.system("cp ./logs/app* ./out")
    for slave in slaves_name:
        os.system("scp "+slave+":"+prefix+"/logs/iostat_log_master ./logs/iostat_log_"+slave)

    for slave in slaves_name:
        os.system("scp "+slave+":"+prefix+"/logs/vmstat_log_master ./logs/vmstat_log_"+slave)

    for slave in slaves_name:
        os.system("scp "+slave+":"+prefix+"/logs/mpstat_log_master ./logs/mpstat_log_"+slave)

    for slave in slaves_name:
        os.system("scp "+slave+":"+prefix+"/logs/sar_log_master ./logs/sar_log_"+slave)

    for slave in slaves_name:
        os.system("scp "+slave+":"+prefix+"/logs/anomaly_log.txt ./logs/anomaly_"+slave)
# def collect_logs():
#     os.system("cp $SPARK_HOME/tsee_log/* temp/bigroot/logs")
#     os.system("cp temp/bigroot/logs/app* temp/bigroot/out")
#     for slave in slaves_name:
#         os.system("scp "+slave+":"+prefix+"/temp/bigroot/logs/iostat_log_master temp/bigroot/logs/iostat_log_"+slave)
#
#     for slave in slaves_name:
#         os.system("scp "+slave+":"+prefix+"/temp/bigroot/logs/vmstat_log_master temp/bigroot/logs/vmstat_log_"+slave)
#
#     for slave in slaves_name:
#         os.system("scp "+slave+":"+prefix+"/temp/bigroot/logs/mpstat_log_master temp/bigroot/logs/mpstat_log_"+slave)
#
#     for slave in slaves_name:
#         os.system("scp "+slave+":"+prefix+"/temp/bigroot/logs/sar_log_master temp/bigroot/logs/sar_log_"+slave)
#
#     for slave in slaves_name:
#         os.system("scp "+slave+":"+prefix+"/temp/bigroot/logs/anomaly_log.txt temp/bigroot/logs/anomaly_"+slave)

def init():
    os.system("rm ./logs/* ./out/* experiment/*")
    for slave in slaves_name:
        os.system("ssh "+slave+" python "+prefix+"lib/kill_samp.py")

    os.system("rm /home/zhg/spark/tsee_log/*")
    print('clear old logs in salves')
    for slave in slaves_name:
        os.system('ssh '+slave+' "rm %slogs/*"'%(prefix))

def decode():
    os.system("cp logs/anomaly* out")
    for slave in slaves_name:
        decode_sar(slave)
    for slave in slaves_name:
        decode_mpstat(slave)
    for slave in slaves_name:
        decode_iostat(slave)

def kill():
    for slave in slaves_name:
        os.system("ssh "+slave+" python "+prefix+"lib/kill_samp.py")


parser=argparse.ArgumentParser()
parser.add_argument('-run',action='store_true',help='run the whole system')
# parser.add_argument('-name',type=str,default='micro/wordcount',help='specify benchmark name')
parser.add_argument('-collect',action='store_true',help='collect logs from slaves')
parser.add_argument('-decode',action='store_true',help='decode logs')
parser.add_argument('-last',type=int,default=30,help='specify anomaly last time')
parser.add_argument('-ano',type=str,default='cpu',help='choices are cpu, io, net, all')
parser.add_argument('-slaves',type=str,default='5',help='slaves to generate anomaly')
parser.add_argument('-ip',type=str,default='10.254.13.16',help='connect particular ip address')
parser.add_argument('-job_time_file',type=str,default='info',help='dump job duration info to this file')
parser.add_argument('-tnum',type=int,default='32',help='thread num to start')
res=parser.parse_args()
if res.run:
    ### luice comment
    pin_global_start_time=time.time()
    print('[INFO]init system status')
    init()
    pin_global_init_time=time.time()
    start(res)

# luice comment
'''
if res.collect:
    collect_logs()
    decode()
    kill()
if res.decode:
    decode()
'''
