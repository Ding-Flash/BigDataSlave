import re
import os
from IPython import embed
from bigroot.env_conf import *
slaves_name = get_slaves_name()
prefix=app_path

def decode_vmstat(slave,log_dir):
    if slave == 0:
        vmpath = log_dir+"/logs/vmstat_log_master"
        outpath = log_dir+"/out/vmstat_out_master"
    else:
        vmpath = log_dir+"/logs/vmstat_log_"+slave
        outpath = log_dir+"/out/vmstat_out_"+slave
    if not os.path.exists(vmpath):
        return
    vmfile=open(vmpath)
    outfile=open(outpath,'w')
    time_stp_all = []
    r = []
    b = []
    swdp = []
    free = []
    buff = []
    cache = []
    si = []
    so = []
    bi = []
    bo = []
    iin = []
    cs = []
    us = []
    sy = []
    iid = []
    wa = []
    st = []
    line = vmfile.readline()
    line_num = 1
    count=0
    while line:
        if line_num % 23 < 3:
            line_num = line_num + 1
        else:
            line_list = line.split()
            time_stp_all.append(str(count))
            r.append(line_list[0])
            b.append(line_list[1])
            swdp.append(line_list[2])
            free.append(line_list[3])
            buff.append(line_list[4])
            cache.append(line_list[5])
            si.append(line_list[6])
            so.append(line_list[7])
            bi.append(line_list[8])
            bo.append(line_list[9])
            iin.append(line_list[10])
            cs.append(line_list[11])
            us.append(line_list[12])
            sy.append(line_list[13])
            iid.append(line_list[14])
            wa.append(line_list[15])
            st.append(line_list[16])
            count = count + 1
            line_num = line_num + 1
        line = vmfile.readline()
    for i in range(0, count - 1):
        outline = [time_stp_all[i], ' ', r[i], ' ', b[i], ' ', swdp[i], ' ', free[i], ' ', buff[i], ' ', cache[i], ' ',
                   si[i], ' ', so[i], ' ', bo[i], ' ', iin[i], ' ', cs[i], ' ', us[i], ' ', sy[i], ' ', iid[i], ' ',
                   wa[i], ' ', st[i], '\n']
        outfile.writelines(outline)
    outfile.close()
    vmfile.close()


def decode_sar(slave, log_dir):
    if slave == 0:
        sapath = log_dir+"/logs/sar_log_master"
        outpath = log_dir+"/out/sar_out_master"
    else:
        sapath = log_dir+"/logs/sar_log_"+slave
        outpath = log_dir+"/out/sar_out_"+slave
    if not os.path.exists(sapath):
        return 
    safile=open(sapath)
    outfile=open(outpath,'w')
    time_stp_all = []
    rxkb_all = []
    txkb_all = []
    ifutil_all = []
    line = safile.readline()
    line = safile.readline()
    line = safile.readline()
    line_num = 0
    count = 0
    period=7;pos=2;
    while line:
        if 'em1' in line:  # eth0
            line_list = line.split()
            if len(line_list)<9:
                break
            time_stp_all.append(str(count))
            rxkb_all.append(line_list[4])
            txkb_all.append(line_list[5])
            ifutil_all.append(line_list[8])
            count = count + 1
        line_num = line_num + 1
        line = safile.readline()
    for i in range(0, count - 1):
        outline = [time_stp_all[i], ' ', rxkb_all[i], ' ', txkb_all[i], ' ', ifutil_all[i], '\n']
        outfile.writelines(outline)
    outfile.close()
    safile.close()

def decode_mpstat(slave, log_dir):
    if slave==0:
        mppath = log_dir+"/logs/mpstat_log_master"
        outpath = log_dir+"/out/mpstat_out_master"
    else:
        mppath = log_dir+"/logs/mpstat_log_"+slave
        outpath = log_dir+"/out/mpstat_out_"+slave
    if not os.path.exists(mppath):
        return
    mpfile=open(mppath)
    outfile=open(outpath,'w')
    time_stp_all = []
    user_all = []
    nice_all = []
    sys_all = []
    iowait_all = []
    steal_all = []
    guest_all = []
    gnice_all = []
    idle_all = []
    irq_all=[]
    soft_all=[]

    line = mpfile.readline()

    line_num = 1
    count = 0
    while line:
        if 'all' in line and  line_num < 10000:  # ALL
            line_list = line.split()
            time_stp_all.append(str(count))
            try:
                user_all.append(line_list[2])
                nice_all.append(line_list[3])
                sys_all.append(line_list[4])
                iowait_all.append(line_list[5])
                irq_all.append(line_list[6])
                soft_all.append(line_list[7])
                steal_all.append(line_list[8])
                guest_all.append(line_list[9])
                #gnice_all.append(line_list[10])
                idle_all.append(line_list[10])
            except:
                print('embed because mpstat decode error',count,line_list);embed();exit()
            count = count + 1
        line_num = line_num + 1
        line = mpfile.readline()
    for i in range(0, count - 1):
        outline = [time_stp_all[i], ' ', user_all[i], ' ', nice_all[i], ' ', sys_all[i], ' ', iowait_all[i], ' ',
                   irq_all[i], ' ', soft_all[i], ' ', steal_all[i], ' ', guest_all[i], ' ', '0', ' ',
                   idle_all[i], '\n']
        outfile.writelines(outline)
    outfile.close()
    mpfile.close()

def decode_iostat(slave, log_dir):
    if slave == 0:
        iostatpath = log_dir+"/logs/iostat_log_master"
        # rrqm/s   wrqm/s     r/s     w/s    rkB/s    wkB/s avgrq-sz avgqu-sz   await r_await w_await  svctm  %util
        outpath = log_dir+"/out/iostat_out_master"
    else:
        iostatpath = log_dir+"/logs/iostat_log_"+slave
        outpath = log_dir+"/out/iostat_out_"+slave
    if not os.path.exists(iostatpath):
        return
    iostatfile=open(iostatpath)
    outfile=open(outpath,'w')
    time_count = []
    rrgm = []
    wrgm = []
    rs = []
    ws = []
    rkb = []
    wkb = []
    avgrq = []
    avgqu = []
    await = []
    rawait = []
    wawait = []
    svctm = []
    util = []
    line = iostatfile.readline()
    count = 0
    while line:
        linedata = re.findall(r'[0-9]+\.?[0-9]*', line)
        if 'sda' in line and len(linedata) == 13:
            count = count + 1
            time_count.append(str(count))
            rrgm.append(linedata[0])
            wrgm.append(linedata[1])
            rs.append(linedata[2])
            ws.append(linedata[3])
            rkb.append(linedata[4])
            wkb.append(linedata[5])
            avgrq.append(linedata[6])
            avgqu.append(linedata[7])
            await.append(linedata[8])
            rawait.append(linedata[9])
            wawait.append(linedata[10])
            svctm.append(linedata[11])
            util.append(linedata[12])
        elif 'sda' in line and len(linedata) == 11:

            count = count + 1
            time_count.append(str(count))
            rrgm.append(linedata[0])
            wrgm.append(linedata[1])
            rs.append(linedata[2])
            ws.append(linedata[3])
            rkb.append(linedata[4])
            wkb.append(linedata[5])
            avgrq.append(linedata[6])
            avgqu.append(linedata[7])
            await.append(linedata[8])
            rawait.append(linedata[9])
            wawait.append('0')
            svctm.append('0')
            util.append(linedata[10])

        line = iostatfile.readline()
    for i in range(0, count):
        outline = [time_count[i], ' ', rrgm[i], ' ', wrgm[i], ' ', rs[i], ' ', ws[i], ' ', rkb[i], ' ', wkb[i], ' ',
                   avgrq[i], ' ', avgqu[i], ' ', await[i], ' ', rawait[i], ' ', wawait[i], ' ', svctm[i], ' ', util[i],
                   '\n']
        outfile.writelines(outline)
    outfile.close()
    iostatfile.close()

def decode(slaves_name,log_dir):
    os.system("cp "+log_dir+"/logs/anomaly* "+log_dir+"/out")
    for slave in slaves_name:
        decode_sar(slave, log_dir)
    for slave in slaves_name:
        decode_mpstat(slave, log_dir)
    for slave in slaves_name:
        decode_iostat(slave, log_dir)


