import os

os.system("ps aux|grep \"sar\"|awk \'{print $2}\'|xargs kill $1")
os.system("ps aux|grep \"iostat\"|awk \'{print $2}\'|xargs kill $1")
os.system("ps aux|grep \"mpstat\"|awk \'{print $2}\'|xargs kill $1")
os.system("ps aux|grep \"vmstat\"|awk \'{print $2}\'|xargs kill $1")
os.system("ps aux|grep \"anomaly_generator.py\"|awk \'{print $2}\'|xargs kill $1")
#os.system("ps aux|grep \"iostat\"|awk \'{print $2}\'|xargs kill $1 ; ps aux|grep \"mpstat\"|awk \'{print $2}\'|xargs kill $1 ; ps aux|grep \"vmstat\"|awk \'{print $2}\'|xargs kill $1 ; ps aux|grep \"sar\"|awk \'{print $2}\'|xargs kill $1")
