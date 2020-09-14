#-*- encoding=utf8 -*-
import os
import math
import argparse
import pickle
import sys
import time
import prettytable as pt
from IPython import embed
from bigroot.env_conf import *
import json
''' Root cause detection
2017/10/31:
1.加入相关性分析
2.加入资源占用边缘检测
3.加入全局分位点检测
'''
############### Config #############
prefix = app_path
slaves_name = get_slaves_name()
slaves_ip = get_slaves_ip()
####################################
def correlation(feature, label, thresh=0.8,returnValue=False):
    assert len(feature) == len(label)
    # Person correlation coefficient
    EXY = 0
    EX = 0
    EY = 0
    EX2 = 0
    EY2 = 0
    thetaX = 0
    thetaY = 0
    for i in range(len(feature)):
        EXY += feature[i] * label[i]
        EX += feature[i]
        EY += label[i]
        EX2 += feature[i] * feature[i]
        EY2 += label[i] * label[i]
    EXY /= len(feature)
    EX /= len(feature)
    EY /= len(feature)
    EX2 /= len(feature)
    EY2 /= len(feature)
    # Calculate standard deviation
    for i in range(len(feature)):
        thetaX += (feature[i] - EX) ** 2
        thetaY += (label[i] - EY) ** 2
    thetaX /= (len(feature) - 1)
    thetaY /= (len(feature) - 1)
    thetaX = math.sqrt(thetaX)
    thetaY = math.sqrt(thetaY)
    try:
        rho = (EXY - EX * EY) / thetaY / thetaX
    except:
        rho=0
    if returnValue:
        return rho
    return abs(rho) > thresh

class Feature:
    def __init__(self,name):
        self.name=name

    def anomaty(self,cur,data,method,assist_data=None,pearson=False,straggler_scale=0,quantile=None):
        raise NotImplementedError

class BytesFeature(Feature):
    def __init__(self, name):
        Feature.__init__(self, name)

    def anomaty(self,cur,data,method='plain',thresh=0.9,assist_data=None,pearson=False,straggler_scale=0,quantile=None,**args):
        if len(data)==0:
            return False
        if pearson:
            # Implement pearson judgement
            data.append(cur)
            assist_data.append(straggler_scale)
            if correlation(data,assist_data,returnValue=True)>pearson_thresh and cur>correlation_thresh*max(data):
                #print('found correlation')
                return True
            return False
        else:
            # My algorithm
            if use_median:
                #print(root_detect_thresh);embed();time.sleep(2)
                data=sorted(data)
                medean=data[int(len(data)/2)]
                if cur>medean*root_detect_thresh and cur>quantile:
                    return True
                else: return False
            else:
                max_=0
                min_=1<<30
                mean_=0
                for item in data:
                    mean_+=item
                    if item>max_: max_=item
                    if item<min_: min_=item
                mean_/=len(data)
                #if cur>max_*thresh and cur>mean_*2:
                if cur > mean_ * root_detect_thresh and cur>quantile:
                    if self.name=='bytes_read':
                        print('Found bytes_read root:',cur,data)
                    return True
                return False
            # # Round 2: cal variation.
            # var=0
            # for item in data:
            #     var+=(item-mean_)*(item-mean_)
            # var/=len(data)

class DiscreteFeature(Feature):
    def __init__(self, name):
        Feature.__init__(self, name)

    def anomaty(self,cur,data,method='plain',thresh=0.9,assist_data=None,pearson=False,quantile=None,straggler_scale=0):
        pass

class LocalityFeature(Feature):
    def __init__(self,name):
        Feature.__init__(self,name)

    def anomaty(self,cur,data,method='plain',assist_data=None,pearson=False,straggler_scale=0,quantile=None):
        if cur==1: return False
        s_0,s_1,s_2,n_0,n_1,n_2=[0]*6
        count_n=0
        for i in range(len(data)):
            if assist_data[i]>straggler_thresh:
                # straggler
                if data[i]==0: s_0+=1
                if data[i]==1: s_1+=1
                if data[i]==2: s_2+=1
            else:
                count_n+=1
                if data[i]==0: n_0+=1
                if data[i]==1: n_1+=1
                if data[i]==2: n_2+=1
        #if cur==1 and count1<len(data)*0.2: return True
        if cur==2 and n_0+n_1+n_2<count_n/2: return True

class TimeFeature(BytesFeature):
    def anomaty(self,cur,data,method='plain',thresh=0.9,assist_data=None,pearson=False,straggler_scale=0,quantile=None):
        #assert False,'This block has BUG!!!'
        if cur<0.2:
            return False
        super().anomaty(cur,data,method=method,thresh=thresh,assist_data=assist_data,pearson=pearson,
                        straggler_scale=straggler_scale,quantile=quantile)

class Engine:
    def __init__(self,log_dir='out',embed_debug=False,sample_start=None,delay=7.75,straggler_thresh=1.5):
        print('Initialize decode engine')
        self.sample_start=sample_start
        self.DELAY=delay
        # auto get delay
        self.LOG_DIR = log_dir
        ############################################
        # 初始化统计信息
        self.TN=0 # true negative
        self.TP=0 # true positive
        self.FP=0 # false positive
        self.FN=0 # false negative
        self.PN_detail=dict()
        self.corre_TN=0
        self.corre_TP=0
        self.corre_FP=0
        self.corre_FN=0
        self.corre_PN_detail=dict()
        self.filter_edge=0 # how many stragglers filtered out because edge detection
        self.filter_detail=[] # record filtered anos
        ###########################################
        if os.path.exists(self.LOG_DIR+'delay'):
            with open(self.LOG_DIR+'delay') as f:
                self.DELAY=float(f.readline())
                print('Calibration delay:',self.DELAY)
        self.host_list=slaves_ip
        self.anomaly_ids=[]
        self.embed_debug=embed_debug
        # make anomaly file more readable
        self.decode_anomaly_file()
        self.application_start_timestamp=-1
        self.application_finish_timestamp=-1
        self.clock2task=[]
        self.straggler_thresh=straggler_thresh
        print('解析慢任务')
        if os.path.exists('cmd/binary/stragglers.dat'):
            self.node_features, self.features, self.stragglers, self.tasks, self.stages = pickle.load(open('cmd/binary/stragglers.dat', 'rb'))
        else:
            start_time, self.tasks, self.stages = self.load_dicts()
            # Note: stragglers -> task_id : task
            self.features, self.node_features, self.stragglers = self.analysis_features(self.tasks, self.stages)
            self.wraper(self.tasks, start_time, self.features)
            pickle.dump([self.node_features,self.features,self.stragglers,self.tasks,self.stages],open('cmd/binary/stragglers.dat','wb'))
        # 分析root
        print('分析根原因')
        self.run()

    def summary(self):
        root_dict=dict()
        correlation_dict=dict()
        rets_dict = self.draw()
        for id in self.root:
            for feature in self.root[id]:
                if feature not in root_dict:
                    root_dict[feature]=0
                root_dict[feature]+=1
        for id in self.correlation_root:
            for feature in self.correlation_root[id]:
                if feature not in correlation_dict:
                    correlation_dict[feature]=0
                correlation_dict[feature]+=1
        result_dict = {}
        result_dict['root'] = root_dict
        result_dict['correlation'] = correlation_dict
        result_dict['rest'] = rets_dict
        # print(self.root)
        # print('root_dict:',root_dict)
        # print('correlation_dict:',correlation_dict)
        return result_dict
        # with open('../../data/bigroot/report.json','w') as f:
        #     json.dump(result_dict, f)
        # '''
        # print('TP,TN,FP,FN,fpr,tpr,acc:',self.TP,self.TN,self.FP,self.FN,self.FP/(self.FP+self.TN),self.TP/(self.TP+self.FN),(self.TP+self.TN)/(self.TP+self.TN+self.FP+self.FN))
        # print('corre_TN,corre_TP,corre_FN,corre_FP,corre_fpr,corre_tpr,corre_acc:', self.corre_TN, self.corre_TP,
        #       self.corre_FN, self.corre_FP, self.corre_FP / (self.corre_FP + self.corre_TN),
        #       self.corre_TP / (self.corre_TP + self.corre_FN),
        #       (self.corre_TP+self.corre_TN)/(self.corre_TN+self.corre_TP+self.corre_FP+self.corre_FN)
        #       )
        # '''

    def dump(self,filename):
        with open(filename,'a') as d:
            d.write('TP=%d,TN=%d,FP=%d,FN=%d,detail=%s\n'%(self.TP,self.TN,self.FP,self.FN,str(self.PN_detail)))
            d.write('corre_TP=%d,corre_TN=%d,corre_FP=%d,corre_FN=%d,corre_detail=%s\n'%(self.corre_TP,self.corre_TN,self.corre_FP,self.corre_FN,str(self.corre_PN_detail)))
            d.write('duration %.4f\n'%(self.application_finish_timestamp-self.application_start_timestamp))

    def compare(self,slave=5):
        ''' 比较correlation and root'''
        root_ids=list(self.root.keys())
        correlation_ids=list(self.correlation_root.keys())
        all_ids=set(root_ids+correlation_ids)
        table=pt.PrettyTable(['task id','task duration','straggler scale','cpu','io','net','AG','BigRoots','Correlation Roots'])
        print('task id','task duration','straggler scale','cpu','io','net','AG','BigRoots','Correlation Roots','\\\\\\hline',sep='&')
        for id in all_ids:
            # ID为straggler id
            task=self.tasks[id]
            feature=self.features[id]
            host=task['host']
            # 过滤不需要考虑的straggler
            if host!=slave: continue
            task_duration=task['finish_id']-task['start_id']
            straggler_scale=feature['straggler']
            cpu=feature['cpu']
            io=feature['io']
            net=feature['net']
            if 'anomaly' in feature:
                AG=set(feature['anomaly'])
                _t=''
                for item in AG:
                    _t+=item+', '
                #embed()
                AG=_t[:-2]
            else: AG='-'
            if id in self.root:
                BigRoots=self.root[id]
                s_big_roots = ''
                for item in BigRoots:
                    s_big_roots += item.replace('_', '\\_')+', '
                s_big_roots = s_big_roots[:-2]
            else:
                s_big_roots='-'
            if id in self.correlation_root:
                CorrelationRoots=self.correlation_root.get(id)
                s_correlation_roots=''
                for item in CorrelationRoots:
                    s_correlation_roots+=item.replace('_','\\_')+', '
                s_correlation_roots=s_correlation_roots[:-2]
            else:
                s_correlation_roots='-'
            table.add_row([id,round(task_duration,2),round(straggler_scale,2),round(cpu,2),round(io,2),round(net,2),
                           AG,s_big_roots,s_correlation_roots])
            print(round(task_duration,2),round(straggler_scale,2),round(cpu,2),round(io,2),round(net,2),
                  AG,s_big_roots,s_correlation_roots,sep='&',end='')
            print('\\\\\\hline')
        print(table)

    def draw(self):
        '''
        画出不同节点的资源监控和瓶颈分析的示意图
        '''
        rets = {}
        for slave in slaves_name:
            ret = self.export(slave)
            rets[slave] = ret
        #print(rets)
        return rets

    def export(self,slave=5):
        ''' Export data for visualization.
        Trace data in slave.
        NOTE that slave is slave name not index.
        '''
        # get root cause
        root=self.root
        # decode anomaly trace
        anomaly_trace=[]
        anomaly_file_name=self.LOG_DIR+'anomaly_'+slave+'_decoded'
        if os.path.exists(anomaly_file_name):
            pre=None
            with open(anomaly_file_name) as file:
                _f_first=True
                for line in file:
                    _t=line.strip().split('->')
                    if _f_first:
                        pre=_t
                        _f_first=False
                    else:
                        if abs(int(_t[1])-int(pre[1]))<=2:
                            pre[0]+=', '+_t[0]
                            #embed()
                        else:
                            anomaly_trace.append(pre)
                            pre=_t
                if pre!=None:
                    anomaly_trace.append(pre)
        # tasks trace
        straggler_trace=[]
        for straggler in self.stragglers:
            if self.tasks[straggler]['host'] == slave:
                t_trace=[]
                t_trace.append(self.tasks[straggler]['Task Info']['Launch Time'] / 1000 - self.application_start_timestamp+self.DELAY)
                t_trace.append(self.tasks[straggler]['Task Info']['Finish Time'] / 1000 - self.application_start_timestamp+self.DELAY)
                if self.tasks[straggler]['start_id']==self.tasks[straggler]['finish_id']:
                    pass
                stage = self.stages[self.tasks[straggler]['Stage ID']]
                t_trace.append(self.features[straggler]['straggler'])
                if straggler not in root:
                    t_trace.append('{unkown}')
                else:
                    t_trace.append(root[straggler])
                straggler_trace.append(t_trace)
        #print(straggler_trace);embed()
        # cpu, io, net trace: index -> value
        ret=dict()
        slave_ind=slaves_name.index(slave)
        ret['cpu']=self.cpu_features[slave_ind]
        ret['io']=self.io_features[slave_ind]
        ret['net']=self.net_features[slave_ind]
        # name -> start id -> finish id
        ret['anomaly']=anomaly_trace
        # start id -> finish id -> stage_avg_duration
        ret['tasks']=straggler_trace
        # invoke visualize block
        return ret

    def draw_task_duration(self):
        ''' Draw all tasks duration distribution'''
        ret=[]
        for task_id in self.tasks:
            task_duration=self.tasks[task_id]['finish_id']-self.tasks[task_id]['start_id']
            ret.append(task_duration)
        #visualizer.draw_distribution(ret)

    def decode_anomaly_file(self):
        out_dir=self.LOG_DIR
        for i in os.listdir(out_dir):
            if i.startswith('anomaly') and (not i.endswith('decoded')):
                print('decoding',i,'...')
                with open(out_dir+i+'_decoded','w') as dump:
                    with open(out_dir+i,'r') as file:
                        start_time = float(file.readline())
                        while True:
                            line1 = file.readline()
                            if line1 == '':
                                break
                            line2 = file.readline()
                            if line2 == '':
                                break
                            assert line1.split()[-1] == 'begin' and line2.split()[-1] == 'end'
                            start_id = float(line1.split()[0]) - start_time
                            end_id = float(line2.split()[0]) - start_time
                            ano_str=''
                            for i in line1.strip().split(','):
                                ano_str+=i.split('_')[1]+', '
                            ano_str=ano_str[:-2]
                            dump.write(ano_str+'->'+str(int(start_id)) + '->' + str(int(end_id)) + '\n')

    def cal_correlation(self):
        if os.path.exists('cmd/binary/stragglers.dat'):
            node_features, features, stragglers, tasks, stages = pickle.load(open('cmd/binary/stragglers.dat', 'rb'))
        else:
            start_time, tasks, stages = self.load_dicts()
            # Note: stragglers -> task_id : task
            features, node_features, stragglers = self.analysis_features(tasks, stages)
            self.wraper(tasks, start_time, features)
            pickle.dump([node_features,features,stragglers,tasks,stages],open('cmd/binary/stragglers.dat','wb'))
        considered_features = [LocalityFeature('locality'), BytesFeature('bytes_read'),
                               BytesFeature('shuffle_read_bytes'),
                               BytesFeature('shuffle_write_bytes'), BytesFeature('JVM_time'), BytesFeature('cpu'),
                               BytesFeature('net'), BytesFeature('io')]
        for feature in considered_features:
            feature_name=feature.name
            x=[]
            y=[]
            for task_id in tasks:
                task=features[task_id]
                x.append(task[feature_name])
                y.append(task['straggler'])
            if feature_name=='locality':
                pass
            if False and feature_name=='shuffle_write_bytes':
                sum_straggler=sum([x[i] for i in range(len(x)) if y[i]==1])
                sum_normal=sum([x[i] for i in range(len(x)) if y[i]==0])
                print('shuffle write bytes: sum_straggler:',sum_straggler,'sum_normal:',sum_normal)
            print(feature_name,':',correlation(x,y,returnValue=True))

    def verify_anomaly(self):
        if os.path.exists('cmd/binary/stragglers.dat'):
            node_features, features, stragglers, tasks, stages = pickle.load(open('cmd/binary/stragglers.dat', 'rb'))
        else:
            start_time, tasks, stages = self.load_dicts()
            # Note: stragglers -> task_id : task
            features, node_features, stragglers = self.analysis_features(tasks, stages)
            self.wraper(tasks, start_time, features)
            pickle.dump([node_features,features,stragglers,tasks,stages],open('cmd/binary/stragglers.dat','wb'))
        print('anomalies:',len(self.anomaly_ids))
        count_straggler=0
        count_anomaly=0
        for task_id in stragglers:
            count_straggler+=1
            task=tasks[task_id]
            if 'anomaly' in task:
                count_anomaly+=1
        print('count_straggler',count_straggler,'count_anomaly',count_anomaly)

    def run(self):
        '''
        Find root cause of stragglers.
        Algorithm:
            1. Compare the straggler features with features in other nodes.
            2. Compare the straggler features with features in the same node.
            3. Node level history comparison.
        '''
        debug_embed=self.embed_debug
        root=dict()
        correlation_root=dict()
        considered_features=[LocalityFeature('locality'),BytesFeature('bytes_read'),BytesFeature('shuffle_read_bytes'),
                             BytesFeature('shuffle_write_bytes'),TimeFeature('JVM_time'),BytesFeature('cpu'),
                             BytesFeature('net'),BytesFeature('io'),TimeFeature('deserialize'),TimeFeature('serialize'),
                             BytesFeature('memory_bytes_spilled'),BytesFeature('disk_bytes_spilled')]
        # 加入全局分位点检测
        # 算法： 统计每个任务的特征大小，并进行分位点探测，定位的时候进行边缘探测
        print('正在获取全局特征信息...')
        global_features=dict()
        for task_id in self.tasks:
            for feature in considered_features:
                name=feature.name
                if name not in global_features:
                    global_features[name]=[]
                global_features[name].append(self.features[task_id][name])
        print('正在获取分位点...')
        global_quantile=dict()
        # 数据结构: feature name -> quantile name -> value
        for feature_name in global_features:
            feature_data=global_features[feature_name]
            sorted_data=sorted(feature_data)
            if feature_name not in global_quantile:
                global_quantile[feature_name]=dict()
            global_quantile[feature_name]['high']=sorted_data[int(len(sorted_data)*quantile_thresh)]
            #print('分位点为：',feature_name,'->',global_quantile[feature_name])
        split_feature='task_type'
        revert_node_features=dict()
        for feature in considered_features:
            revert_node_features[feature.name] = dict()
            for node in self.node_features:
                if node not in revert_node_features[feature.name]:
                    revert_node_features[feature.name][node]=[]
                node_tasks=self.node_features[node]
                for _task_id in node_tasks:
                    revert_node_features[feature.name][node].append(self.features[_task_id][feature.name])
        strag_host=[0]*len(slaves_name)
        for task_id in self.stragglers:
            # cal strag host info
            cur_task=self.tasks[task_id]
            cur_feature=self.features[task_id]
            current_host=self.tasks[task_id]['host']
            strag_host[self.host_list.index(self.tasks[task_id]['Task Info']['Host'])]+=1
            stage_id=self.stragglers[task_id]['Stage ID']
            stage_tasks=self.stages[stage_id]['tasks']
            inter_node_tasks=[]
            iner_node_tasks=[]
            straggler_scale=self.features[task_id]['straggler']
            for _task_id in stage_tasks:
                if _task_id==task_id:
                    continue
                if self.tasks[_task_id]['Task Info']['Host']==self.tasks[task_id]['Task Info']['Host']:
                    iner_node_tasks.append(_task_id)
                else:
                    inter_node_tasks.append(_task_id)
            # 获取边缘资源占用信息
            edge_resource={'cpu':[],'io':[],'net':[]}
            for resource_name in edge_resource:
                start_id=self.tasks[task_id]['start_id']
                end_id=self.tasks[task_id]['finish_id']
                head_edge=int(start_id+self.DELAY)
                tail_edge=int(end_id+self.DELAY)
                head_mean=0
                tail_mean=0
                for clk in range(head_edge-edge_width,head_edge):
                    try:
                        if resource_name=='cpu': head_mean+=self.cpu_features[current_host][clk][1]
                        elif resource_name=='io':head_mean+=self.io_features[current_host][clk][1]
                        elif resource_name=='net':head_mean+=self.net_features[current_host][clk][1]
                        else:
                            raise NotImplementedError
                    except:
                        break
                        #print('embed because getting edge data error');embed()
                for clk in range(tail_edge+1,tail_edge+edge_width+1):
                    try:
                        if resource_name=='cpu': tail_mean+=self.cpu_features[current_host][clk][1]
                        elif resource_name=='io':tail_mean+=self.io_features[current_host][clk][1]
                        elif resource_name=='net':tail_mean+=self.net_features[current_host][clk][1]
                        else: raise NotImplementedError
                    except:
                        break
                        print('embed because rearange resource into edge info')
                        embed()
                edge_resource[resource_name].append(head_mean/edge_width)
                edge_resource[resource_name].append(tail_mean/edge_width)
            # Algo.1
            for feature in considered_features:
                # 过滤数值过低的特征
                data=[]
                assist_data=[]
                for _task_id in inter_node_tasks:
                    data.append(self.features[_task_id][feature.name])
                    assist_data.append(self.features[_task_id]['straggler'])
                # 采用相关性分析
                if feature.anomaty(self.features[task_id][feature.name],data,assist_data=assist_data,straggler_scale=straggler_scale,pearson=True):
                    if task_id not in correlation_root:
                        correlation_root[task_id]=set()
                    correlation_root[task_id].add(feature.name)

                if not disable_edge and feature.name in edge_resource:
                    if edge_resource[feature.name][0]<edge_scale*self.features[task_id][feature.name] and \
                        edge_resource[feature.name][1] < edge_scale * self.features[task_id][feature.name]:
                        # 如果前后资源占用都出现了大幅下降，则资源占用率不是瓶颈
                        #print('filter out feature because of edge drop,',feature.name)
                        #embed()
                        self.filter_edge+=1
                        self.filter_detail.append(feature.name)
                        continue
                bingo=False
                if feature.anomaty(self.features[task_id][feature.name],data,assist_data=assist_data,straggler_scale=straggler_scale,
                                   quantile=global_quantile[feature.name]['high']):
                    if feature.name=='bytes_read':
                        print('task_id=',task_id,',stage_id=',self.tasks[task_id]['Stage ID'])

                    bingo=True
                    if task_id not in root:
                        root[task_id]=set()
                    root[task_id].add(feature.name)
                    if feature.name=='io' and True and self.features[task_id].get('anomaly')=='io':
                        print('algo.1 detect io anomaly, please check anomaly feature')
                        embed()
                    if debug_embed:
                        print('agorithm 1 ->',feature.name,'->',self.features[task_id][feature.name],'->',data)
                        embed()
                # 过滤人为造成异常的异常任务，便于检查准确率
                if filter_anomaly and 'anomaly' in cur_feature and feature.name in cur_feature['anomaly'] and not bingo :
                #if filter_anomaly and 'anomaly' in cur_feature
                    print('embed because met anomaly')
                    print('feature.anomaly:',cur_feature['anomaly'])
                    print('data:',data)
                    print('cur:',cur_feature[feature.name])
                    print('duration %.2f -> %.2f'%(cur_task['start_id']+self.DELAY,cur_task['finish_id']+self.DELAY))
                    print('bingo:',bingo)
                    embed();exit()
                # filter these damn stragglers
                #if abs(cur_task['start_id']-86)<2:print('embed because those damn straggler');embed()

                if feature.name=='net' and False and self.tasks[task_id]['host']==4 and self.tasks[task_id]['finish_id']-self.tasks[task_id]['start_id']>5:
                    print('stop because met ',feature.name)
                    print('anomaly:',self.features[task_id].get('anomaly'))
                    print('straggler scale:',self.features[task_id].get('straggler'))
                    print('start id:',self.tasks[task_id].get('start_id')+self.DELAY)
                    print('feature val:',self.features[task_id][feature.name])
                    print('feature data:',data)
                    print('host:',self.tasks[task_id]['host'])
                    embed()
            # Algo.2
            for feature in considered_features:
                if not disable_edge and feature.name in edge_resource:
                    if edge_resource[feature.name][0]<edge_scale*self.features[task_id][feature.name] and \
                        edge_resource[feature.name][1] < edge_scale * self.features[task_id][feature.name]:
                        # 如果前后资源占用都出现了大幅下降，则资源占用率不是瓶颈
                        #print('filter out feature because of edge drop,',feature.name)
                        self.filter_edge+=1
                        self.filter_detail.append({'name':feature.name,'edge0':edge_resource[feature.name][0],
                            'edge1':edge_resource[feature.name][1],'center':self.features[task_id][feature.name]})
                        continue
                data=[]
                assist_data=[]
                for _task_id in iner_node_tasks:
                    data.append(self.features[_task_id][feature.name])
                    assist_data.append(self.features[_task_id]['straggler'])
                # 采用相关性分析
                if feature.anomaty(self.features[task_id][feature.name], data, assist_data=assist_data,
                                   straggler_scale=straggler_scale, pearson=True):
                    if task_id not in correlation_root:
                        correlation_root[task_id] = set()
                    correlation_root[task_id].add(feature.name)
                # 我的算法
                if feature.anomaty(self.features[task_id][feature.name],data,assist_data=assist_data,straggler_scale=straggler_scale,
                                   quantile=global_quantile[feature.name]['high']):
                    if feature.name=='bytes_read':
                        print('task_id=',task_id,',stage_id=',self.tasks[task_id]['Stage ID'])
                    if task_id not in root:
                        root[task_id]=set()
                    root[task_id].add(feature.name)
                    if debug_embed:
                        print('algo 2 find strag')
                        embed()
            # Algo.3
            # Note: we need to distinguish two kinds of tasks.
            # Algo.3 is troublesome, currently disable it
            if False:
                for feature in considered_features:
                    data=revert_node_features[feature.name][self.features[task_id]['node_id']]
                    if feature.anomaty(self.features[task_id][feature.name],data):
                        if task_id not in root:
                            root[task_id]=set()
                        root[task_id].add(feature.name)
                        if debug_embed:
                            print('algo 3 find strag')
                            embed()
            # 搜集统计信息
            # 搜集统计信息
            resource_features=['cpu','net','io']
            task_anos=cur_task.get('anomaly',[])
            if len(task_anos)>0: task_anos=task_anos[0]
            #if len(task_anos)>0: embed()
            '''
            print(task_anos_str);embed()
            task_anos=[]
            for ano in task_anos_str.split(','):
                task_anos.append(ano.strip())
            '''
            task_roots=root.get(task_id,[])
            task_correlation_roots=correlation_root.get(task_id,[])
            #if task_anos!='' :print(task_anos,resource_features,task_roots);embed();exit();
            for resource in resource_features:
                #raise NotImplementedError
                if resource in task_anos and resource in task_roots:
                    # there is an ano and algo catch it
                    self.TP+=1
                elif resource in task_anos and resource not in task_roots:
                    self.FN+=1
                elif resource not in task_anos and resource in task_roots:
                    self.FP+=1
                elif resource not in task_anos and resource not in task_roots:
                    self.TN+=1
                else:
                    pass
                self.PN_detail[task_id]={'resource:':resource,'ano':task_anos}
                if resource in task_anos and resource in task_correlation_roots:
                    # there is an ano and algo catch it
                    self.corre_TP+=1
                elif resource in task_anos and resource not in task_correlation_roots:
                    self.corre_FN+=1
                elif resource not in task_anos and resource in task_correlation_roots:
                    self.corre_FP+=1
                elif resource not in task_anos and resource not in task_correlation_roots:
                    self.corre_TN+=1
                else:
                    pass
                self.corre_PN_detail[task_id]={'resource:':resource,'ano':task_anos}

        # print('strag host',strag_host)
        # Dump root
        #print('###### ROOT ##############')
        #for id in sorted(root.keys()): print('task id:',id,'host:',self.features[id]['host'],'start_id:',self.tasks[id]['start_id'],'root:',root[id])
        #print('########## CORRELATION ROOT ##########')
        #for id in sorted(correlation_root.keys()):print('task id:',id,'host:',self.features[id]['host'],'start_id:',self.tasks[id]['start_id'],'root:',correlation_root[id])
        #print(root)
        self.root=root
        self.correlation_root=correlation_root
        return root

    def feed(self,filename='data/log'):
        # tasks: task_id -> task
        tasks = {}
        stages = {}
        # this param is to prevent multiple `SparkListenerApplicationStart`
        application_start_flag = True
        with open(filename) as file:
            line_num=0
            while True:
                line = file.readline()
                # delete improper '\'
                line = line.replace('\"', '"')
                # change `false` to 'False', 'true' to 'True'
                line = line.replace('false', 'False')
                line = line.replace('true', 'True')

                if not line:
                    break
                try:
                    event = eval(line)
                except:
                    print('event resolution error,event:\n\t', line)
                    continue
                if event['Event'] == 'SparkListenerTaskEnd':
                    event['host']=event['Task Info']['Host']
                    tasks[event['Task Info']['Task ID']] = event

                elif event['Event'] == 'SparkListenerStageCompleted':
                    stages[event['Stage Info']['Stage ID']] = event
                elif event['Event'] == 'SparkListenerJobStart' and application_start_flag:
                    application_start_flag = False
                    # note that start_time_stamp is int variable
                    #start_time_stamp = event['Submission Time']
                elif event['Event']=='SparkListenerApplicationStart':
                    start_time_stamp=event["Timestamp"]
                    self.application_start_timestamp=float(start_time_stamp)/1000
                elif event['Event']=='SparkListenerApplicationEnd':
                    self.application_finish_timestamp=float(event['Timestamp'])/1000
                line_num+=1
        print('log analysis finished!\n\tfind %d tasks, %d stages, application started at %d' % (
            len(tasks), len(stages), self.application_start_timestamp))
        return self.application_start_timestamp, tasks, stages

    def catch_exception(self,expression, default=0):
        try:
            return eval(expression)
        except:
            return default

    def load_dicts(self,dump_file_name='saved_raw_features'):
        #log_file=None
        #for i in os.listdir(self.LOG_DIR):
        #    if os.path.isfile(self.LOG_DIR + i):
        #        log_file = self.LOG_DIR + i
        #if log_file==None:
        if not self.LOG_DIR.endswith('/'): self.LOG_DIR+='/'
        for i in os.listdir(self.LOG_DIR):
            if i.startswith('app'):
                log_file=self.LOG_DIR+i
        start_time_stamp, tasks, stages = self.feed(log_file)
        return start_time_stamp, tasks, stages

    def analysis_features(self,tasks, stages):
        host_list=self.host_list
        assert self.application_start_timestamp!=-1 and self.application_finish_timestamp!=-1
        print('application duration=',self.application_finish_timestamp-self.application_start_timestamp)
        if self.sample_start!=None:
            self.DELAY=self.application_start_timestamp-self.sample_start
        self.clock2task=[0]*(int((self.application_finish_timestamp-self.application_start_timestamp))+10)
        def cal_stage_data_read(tasks, stages):
            for stage_id in stages.keys():
                stages[stage_id]['task_duration_sum'] = 0
                stages[stage_id]['bytes_read'] = 0
                stages[stage_id]['records_read'] = 0
                stages[stage_id]['shuffle_read'] = 0
                stages[stage_id]['shuffle_records'] = 0
                stages[stage_id]['tasks'] = []
                stages[stage_id]['bytes_per_record_sum'] = 0
                stages[stage_id]['write_bytes_per_record_sum'] = 0
                stages[stage_id]['bytes_wrote'] = 0
                stages[stage_id]['records_wrote'] = 0
                stages[stage_id]['partition'] = stages[stage_id]['Stage Info']['RDD Info'][0]['Number of Partitions']
                stages[stage_id]['duration'] = stages[stage_id]['Stage Info']['Completion Time'] - \
                                               stages[stage_id]['Stage Info']['Submission Time']
                stages[stage_id]['remote_fetch'] = 0
            for task_id in tasks:
                task = tasks[task_id]
                ########################## encode clock2task ####################################
                task_start_clock=task['Task Info']['Launch Time']/1000-self.application_start_timestamp
                task_finish_clock=task['Task Info']['Finish Time']/1000-self.application_start_timestamp
                task['start_id']=task_start_clock
                task['finish_id']=task_finish_clock
                for clk in range(int(task_start_clock),int(task_finish_clock+1)):
                    if self.clock2task[clk]==0:
                        self.clock2task[clk]=[task_id]
                    else:
                        self.clock2task[clk].append(task_id)
                ##############################################################
                # get task ids of one stage
                stages[task['Stage ID']]['tasks'].append(task_id)
                # WARN: I change time unit from mili-second to second
                stages[task['Stage ID']]['task_duration_sum'] += (task['Task Info']['Finish Time'] - task['Task Info'][
                    'Launch Time'])/1000
                if 'Input Metrics' in task['Task Metrics'].keys():
                    stages[task['Stage ID']]['bytes_read'] += task['Task Metrics']['Input Metrics']['Bytes Read']
                    stages[task['Stage ID']]['records_read'] += task['Task Metrics']['Input Metrics']['Records Read']
                if 'Shuffle Read Metrics' in task['Task Metrics'].keys():
                    stages[task['Stage ID']]['shuffle_read'] += task['Task Metrics']['Shuffle Read Metrics'][
                        'Remote Bytes Read']
                    stages[task['Stage ID']]['shuffle_records'] += task['Task Metrics']['Shuffle Read Metrics'][
                        'Total Records Read']
                    try:
                        stages[task['Stage ID']]['bytes_per_record_sum'] += \
                        task['Task Metrics']['Shuffle Read Metrics'][
                            'Remote Bytes Read'] / \
                        task['Task Metrics']['Shuffle Read Metrics'][
                            'Total Records Read']
                    except:
                        pass
                if 'Shuffle Write Metrics' in task['Task Metrics'].keys():
                    try:
                        stages[task['Stage ID']]['bytes_wrote'] += task['Task Metrics']['Shuffle Write Metrics'][
                            'Shuffle Bytes Written']
                        stages[task['Stage ID']]['records_wrote'] += task['Task Metrics']['Shuffle Write Metrics'][
                            'Shuffle Records Written']
                        stages[task['Stage ID']]['write_bytes_per_record_sum'] += \
                        task['Task Metrics']['Shuffle Write Metrics'][
                            'Shuffle Bytes Written'] / \
                        task['Task Metrics']['Shuffle Write Metrics'][
                            'Shuffle Records Written']
                    except:
                        continue

        def find_straggler(tasks, stages, features, threshold=1.5):
            # straggler->task_duration/stage_duration>threshold
            # TODO: we need to change definition of stragglers.
            stragglers = {}
            for stage_id in stages:
                stage = stages[stage_id]
                # stage_duration=stage['duration']
                stage_avg_duration = stage['task_duration_sum'] / len(stage['tasks'])
                # round 1
                stage_task_durations=[]
                for task_id in stage['tasks']:
                    task=tasks[task_id]
                    stage_task_durations.append((task['Task Info']['Finish Time'] - task['Task Info']['Launch Time'])/1000)
                median=sorted(stage_task_durations)[int(len(stage_task_durations)/2)]
                for task_id in stage['tasks']:
                    task=tasks[task_id]
                    task_duration = (task['Task Info']['Finish Time'] - task['Task Info']['Launch Time'])/1000
                    # if task_duration/stage_duration>=threshold:
                    if task_duration / median >= self.straggler_thresh:
                        #print('times:',task_duration / stage_avg_duration)
                        stragglers[task_id] = tasks[task_id]
                        features[task_id]['straggler'] = task_duration / median
            print('find %d stragglers' % (len(stragglers)))
            # for k in stragglers:
            #     print('straggler:',stragglers[k])
            #     break
            return stragglers

        def init_feature(feature):
            feature['shuffle_read'] = 0
            feature['shuffle_records'] = 0
            feature['bytes_per_record'] = 0
            feature['remote_fetch'] = 0
            feature['remote_fetch_rate'] = 0
            feature['shuffle_write'] = 0
            feature['shuffle_write_bytes'] = 0
            feature['stage_id'] = 0
            feature['read_from_hdfs'] = 0
            feature['data_read_method'] = 0
            feature['bytes_read'] = 0
            feature['records_read'] = 0
            feature['input_bytes/result_bytes'] = 0
            feature['shuffle_write'] = 0
            feature['shuffle_write_bytes'] = 0
            feature['remote_fetch'] = 0
            feature['remote_fetch_rate'] = 0
            feature['fetch_wait_time'] = 0
            feature['data_read_method'] = 0
            feature['input_bytes/result_bytes'] = 0
            feature['shuffle_write_records'] = 0
            feature['straggler'] = 0
            feature['node_id'] = 0
            feature['task_type'] = 0
            feature['task_duration'] = 0
            feature['shuffle_read_bytes'] = 0
            feature['write_bytes_per_record'] = 0
            feature['write_bytes/read_bytes'] = 0
            feature['deserialize'] = 0
            feature['executor_run_ime'] = 0
            feature['JVM_time'] = 0
            feature['serialize'] = 0
            feature['memory_bytes_spilled'] = 0
            feature['disk_bytes_spilled'] = 0
            feature['locality'] = 0

        def value2bit(value, border=1):
            if value > border:
                return 1
            return 0

        def locality(value):
            if value == 'PROCESS_LOCAL':
                return 0
            if value == 'NODE_LOCAL':
                return 1
            return 2

        def cal_nodes(stragglers):
            nodes = {}
            for task_id in stragglers:
                task = stragglers[task_id]
                #node_id = int(task['Task Metrics']['Host Name'][-1])%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
                node_id=host_list.index(task['Task Info']['Host'])
                if node_id in nodes.keys():
                    nodes[node_id].append(task_id)
                else:
                    nodes[node_id] = [task_id]
            return nodes

        features = {}
        cal_stage_data_read(tasks, stages)
        for task_id in tasks:
            task = tasks[task_id]
            feature = {}
            # init feature
            init_feature(feature)
            # todo: this expression is not scalable
            #feature['node_id'] = int(task['Task Metrics']['Host Name'][-1])%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
            feature['node_id']=host_list.index(task['Task Info']['Host'])
            feature['host']=feature['node_id']
            if task['Task Type'] == 'ResultTask':
                feature['task_type'] = 1
            elif task['Task Type'] == 'ShuffleMapTask':
                feature['task_type'] = 0
            feature['task_duration'] = task['Task Info']['Finish Time'] - \
                                       task['Task Info']['Launch Time']
            # todo: note that if read_from_hdfs is 0, then other features
            # may not exist and should be set properly
            if 'Input Metrics' in task['Task Metrics'].keys():
                feature['read_from_hdfs'] = 1
                # Hadoop -> 1, Memory -> 0, Not Exist -> -1
                if 'Data Read Method' in task['Task Metrics']['Input Metrics'] and task['Task Metrics']['Input Metrics']['Data Read Method'] == 'Hadoop':
                    feature['data_read_method'] = 1
                try:
                    feature['bytes_read'] = len(stages[task['Stage ID']]['tasks']) * task['Task Metrics']['Input Metrics'][
                        'Bytes Read'] / \
                                            stages[task['Stage ID']]['bytes_read']
                    feature['records_read'] = len(stages[task['Stage ID']]['tasks']) * \
                                              task['Task Metrics']['Input Metrics'][
                                                  'Records Read'] / \
                                              stages[task['Stage ID']]['records_read']
                except:
                    pass
                if task['Task Metrics']['Result Size'] > 0 and task['Task Metrics']['Input Metrics']['Bytes Read'] / \
                        task['Task Metrics']['Result Size'] > 1:
                    feature['input_bytes/result_bytes'] = 1
            if 'Shuffle Read Metrics' in task['Task Metrics'].keys():
                feature['shuffle_read'] = 1
                try:
                    feature['shuffle_read_bytes'] = len(stages[task['Stage ID']]['tasks']) * (
                        task['Task Metrics']['Shuffle Read Metrics']['Remote Bytes Read'] +
                        task['Task Metrics']['Shuffle Read Metrics']['Local Bytes Read']) / \
                                                    stages[task['Stage ID']]['shuffle_read']
                except:
                    feature['shuffle_read_bytes'] = 0
                try:
                    feature['shuffle_records'] = len(stages[task['Stage ID']]['tasks']) * \
                                                 task['Task Metrics']['Shuffle Read Metrics']['Total Records Read'] / \
                                                 stages[task['Stage ID']]['shuffle_records']
                except:
                    feature['shuffle_records'] = 0
                try:
                    feature['bytes_per_record'] = feature['shuffle_read_bytes'] / feature['shuffle_records'] / \
                                                  stages[task['Stage ID']]['bytes_per_record_sum'] / \
                                                  len(stages[task['Stage ID']]['tasks'])
                except:
                    feature['bytes_per_record'] = 0
                if 'Reote Blocks Fetched' in task['Task Metrics']['Shuffle Read Metrics'].keys():
                    feature['remote_fetch'] = 1
                    # todo: maybe errors
                    feature['remote_fetch_rate'] = task['Task Metrics']['Shuffle Read Metrics'][
                                                       'Remote Bytes Fetched'] / \
                                                   feature['bytes_read']
                    feature['fetch_wait_time'] = task['Task Metrics']['Shuffle Read Metrics']['Fetch Wait Time'] / \
                                                 feature['task_duration']

            if 'Shuffle Write Metrics' in task['Task Metrics'].keys():
                feature['shuffle_write'] = 1
                try:
                    feature['shuffle_write_bytes'] = task['Task Metrics']['Shuffle Write Metrics'][
                                                         'Shuffle Bytes Written'] / \
                                                     stages[task['Stage ID']]['bytes_wrote']
                    feature['shuffle_write_records'] = task['Task Metrics']['Shuffle Write Metrics'][
                                                           'Shuffle Records Written'] / \
                                                       stages[task['Stage ID']]['records_wrote']
                    feature['write_bytes_per_record'] = feature['shuffle_write_bytes'] / feature[
                        'shuffle_write_records'] / \
                                                        stages[task['Stage ID']]['write_bytes_per_record_sum'] / \
                                                        len(stages[task['Stage ID']]['tasks'])
                except:
                    feature['write_bytes_per_record'] = 0
            try:
                feature['write_bytes/read_bytes'] = value2bit(feature['shuffle_write_bytes'] / feature['bytes_read'])
            except:
                feature['write_bytes/read_bytes'] = 0
            feature['locality'] = locality(task['Task Info']['Locality'])
            try:
                feature['deserialize'] = task['Task Metrics']['Executor Deserialize Time'] / feature['task_duration']
                feature['executor_run_ime'] = task['Task Metrics']['Executor Run Time'] / feature['task_duration']
                feature['JVM_time'] = task['Task Metrics']['JVM GC Time'] / feature['task_duration']
                feature['serialize'] = task['Task Metrics']['Result Serialization Time'] / feature['task_duration']
                feature['memory_bytes_spilled'] = task['Task Metrics']['Memory Bytes Spilled'] / feature['bytes_read']
                feature['disk_bytes_spilled'] = task['Task Metrics']['Disk Bytes Spilled'] / feature['bytes_read']
            except:
                pass
            features[task_id] = feature
        node_features = {}
        stragglers = find_straggler(tasks, stages, features)
        nodes = cal_nodes(stragglers)
        node_tasks=cal_nodes(tasks)
        for node_id in nodes:
            ids = nodes[node_id]
            node_feature = {}
            # mean input bytes of all stragglers in a node
            input_bytes = 0
            input_records = 0
            remote_fetch = 0
            fetch_wait_time = 0
            bytes_write = 0
            records_write = 0
            locality = 0
            deserialize = 0
            executor_run_ime = 0
            JVM_time = 0
            serialize = 0
            memory_bytes_spilled = 0
            disk_bytes_spilled = 0
            for id in ids:
                try:
                    input_bytes += tasks[id]['Task Metrics']['Input Metrics']['Bytes Read']
                except:
                    pass
                try:
                    input_records += tasks[id]['Task Metrics']['Input Metrics']['Records Read']
                except:
                    pass
                try:
                    remote_fetch += tasks[id]['Task Metrics']['Shuffle Read Metrics']['Remote Bytes Fetched']
                except:
                    pass
                try:
                    fetch_wait_time += tasks[id]['Task Metrics']['Shuffle Read Metrics']['Fetch Wait Time']
                except:
                    pass
                try:
                    bytes_write += tasks[id]['Task Metrics']['Shuffle Write Metrics']['Shuffle Bytes Written']
                except:
                    pass
                try:
                    records_write += tasks[id]['Task Metrics']['Shuffle Write Metrics']['Shuffle Records Written']
                except:
                    pass
                try:
                    locality += locality(tasks[id]['Task Info']['Locality'])
                except:
                    pass
                try:
                    deserialize += task['Task Metrics']['Executor Deserialize Time'] / feature['task_duration']
                except:
                    pass
                try:
                    executor_run_ime += task['Task Metrics']['Executor Run Time'] / feature['task_duration']
                except:
                    pass
                try:
                    JVM_time += task['Task Metrics']['JVM GC Time'] / feature['task_duration']
                except:
                    pass
                try:
                    serialize += task['Task Metrics']['Result Serialization Time'] / feature['task_duration']
                except:
                    pass
                try:
                    memory_bytes_spilled += task['Task Metrics']['Memory Bytes Spilled'] / feature['bytes_read']
                except:
                    pass
                try:
                    disk_bytes_spilled += task['Task Metrics']['Disk Bytes Spilled'] / feature['bytes_read']
                except:
                    pass
            node_feature['input_bytes'] = input_bytes
            node_feature['input_records'] = input_records
            node_feature['remote_fetch'] = remote_fetch
            node_feature['fetch_wait_time'] = fetch_wait_time
            node_feature['bytes_write'] = bytes_write
            node_feature['records_write'] = records_write
            node_feature['locality'] = locality
            node_feature['deserialize'] = deserialize
            node_feature['executor_run_ime'] = executor_run_ime
            node_feature['JVM_time'] = JVM_time
            node_feature['serialize'] = serialize
            node_feature['memory_bytes_spilled'] = memory_bytes_spilled
            node_feature['disk_bytes_spilled'] = disk_bytes_spilled
            node_feature['tasks']=ids
            node_features[node_id] = node_feature
        #return features, node_features, stragglers
        return features,node_tasks,stragglers

    def read_hardware_log(self,filename, timestamp=0, features=[]):
        with open(filename) as log:
            rt = []
            line = log.readline()
            while line:
                try:
                    values = line.split()
                except:
                    break
                rt.append([float(values[index]) for index in [timestamp, *features]])
                line = log.readline()
        if len(rt)==0:
            print('rt:',rt,'filename=',filename)
            embed()
        return rt

    def expand_tasks(self,tasks, features, name, timestamp, extracted_features,anomaly=False):
        # Note: features is refered to hardware features
        for task_id in tasks:
            if anomaly:
                task=tasks[task_id]
                task_start = task['Task Info']['Launch Time']
                task_finish = task['Task Info']['Finish Time']
                slave_index = self.host_list.index(task['Task Info']['Host'])
                if slave_index>2:
                    slave_index=slave_index-1
                if features[slave_index]==[]:
                    continue
                start_id = task['start_id'] + self.DELAY
                end_id = task['finish_id'] + self.DELAY
                if start_id<0:
                    embed()
                    #print('start_id',start_id)
                flag_ano=False
                for feature in features[slave_index]:
                    if min(end_id,feature[2])-max(start_id,feature[1])>0:
                        if 'anomaly' not in tasks[task_id]:
                            tasks[task_id]['anomaly']=[]
                        tasks[task_id]['anomaly'].append(feature[0])
                        if 'anomaly' not in extracted_features[task_id]:
                            extracted_features[task_id]['anomaly']=[]
                        #print('appending anomaly:',feature[0]);embed()
                        extracted_features[task_id]['anomaly'].append(feature[0])
                        self.anomaly_ids.append(task_id)
                    #break
            else:
                task = tasks[task_id]
                slave_index = self.host_list.index(task['Task Info']['Host'])
                temp_sum = 0
                # NOTE: here I include start point and end point
                start_id = int(task['start_id'] + self.DELAY)
                end_id = int(task['finish_id'] + self.DELAY)
                assert end_id >= start_id
                for i in range(start_id, end_id + 1):
                    try:
                        temp_sum += features[slave_index][i][1]
                        #if name=='io' :embed()
                    except:
                        continue
                #if task_id==471 : print('embed 471');embed()
                avg = temp_sum / (end_id - start_id + 1)
                task[name] = avg
                extracted_features[task_id][name] = avg
                if name in extracted_features[task_id]:
                    pass
                    #print(task_id,name)
                if False and name=='cpu' and task_id==8:
                    print('after expand cpu features:',task_id,name);embed();exit()
                #if name=='cpu':print('avg=',avg,'task_id=',task_id);embed();exit()

    def wraper(self,tasks, start_time, extracted_features):
        # WARN: tasks need to be raw tasks
        # '''
        # get iostat
        io_files = []
        for slave in slaves_name:
            io_files.append(self.LOG_DIR + 'iostat_out_'+slave)
        # io_features: [slave_id [[timestamp,value] ... ] ...]
        self.io_features = []
        for file_id in range(len(io_files)):
            self.io_features.append(self.read_hardware_log(io_files[file_id], features=[-1]))
        self.expand_tasks(tasks, self.io_features, 'io', start_time, extracted_features)
        # '''
        # cpu_features
        cpu_files = []
        for slave in slaves_name:
            cpu_files.append(self.LOG_DIR + 'mpstat_out_' + slave)
        self.cpu_features = []
        for file_id in range(len(cpu_files)):
            self.cpu_features.append(self.read_hardware_log(cpu_files[file_id], features=[2]))
            #print('decode cpu info,',self.cpu_features[-1]);embed()
            # io_t=[]
            # cpu_t=[]
            # for item in rt:
            #     io_t.append([item[0],item[1]])
            #     cpu_t.append([item[0],item[1]])
            # io_features.append(io_t)
            # cpu_features.append(cpu_t)
        self.expand_tasks(tasks, self.cpu_features, 'cpu', start_time, extracted_features)
        # net_features
        net_files = []
        for slave in slaves_name:
            net_files.append(self.LOG_DIR + 'sar_out_' + slave)
        self.net_features = []
        for file_id in range(len(net_files)):
            raw = self.read_hardware_log(net_files[file_id], features=[1, 2])
            self.net_features.append([[row[0], (row[1] + row[2]) / 1000] for row in raw])
        self.expand_tasks(tasks, self.net_features, 'net', start_time, extracted_features)

        # deal with anomaly files
        anomaly_files = []
        for slave in slaves_name:
            anomaly_files.append(self.LOG_DIR + 'anomaly_' + slave)
        anomaly_feature=[]
        for file_id in range(len(anomaly_files)):
            raw=self.decode_anomaly(anomaly_files[file_id])
            anomaly_feature.append(raw)
        #print(anomaly_feature)
        self.expand_tasks(tasks,anomaly_feature,'anomaly',start_time,extracted_features,anomaly=True)

    def decode_anomaly(self,file_name):
        if not os.path.exists(file_name):
            return []
        count=0
        ret=[]
        with open(file_name) as file:
            for line in file:
                if count==0:
                    begining=float(line.strip())
                elif count%2==1:
                    # start
                    start,ano_type,_=line.strip().split()
                    start=int(float(start)-begining)
                    t_anos=ano_type.split(',')
                    str_ano=''
                    for t in t_anos:
                        str_ano+=t.split('_')[1]+', '
                    str_ano=str_ano[:-2]
                    ret.append([str_ano,start])
                else:
                    end,_,_=line.strip().split()
                    end=int(float(end)-begining)
                    ret[-1].append(end)
                    assert len(ret[-1])==3, 'decode anomaly error'
                count+=1
        #print('anomaly:');print(ret)
        return ret

    def visualize(self,features):
        for task_id in features:
            feature = features[task_id]
            for k in feature:
                v = feature[k]
                print(k, '->', v)
            break

    def regulize(self,mat):
        # WARN: mat is a 2-d list
        row_num = len(mat)
        col_num = len(mat[0])
        #    sum_list=[0]*col_num
        min_list = [0] * col_num
        max_list = [0] * col_num
        flag = True
        for row in mat:
            for i in range(col_num):
                # sum_list[i]+=row[i]/row_num
                if flag:
                    min_list[i] = row[i]
                    max_list[i] = row[i]
                else:
                    if row[i] < min_list[i]:
                        min_list[i] = row[i]
                    if row[i] > max_list[i]:
                        max_list[i] = row[i]
            flag = False
        for i in range(row_num):
            for j in range(col_num):
                try:
                    mat[i][j] = (mat[i][j] - min_list[j]) / (max_list[j] - min_list[j])
                except:
                    mat[i][j] = 0

def init(log_dir):
    parser=argparse.ArgumentParser()
    parser.add_argument('-dir',type=str,default=log_dir+'/out/',help='specify your log dir')
    parser.add_argument('-disable_edge',action='store_true',help='disable edge detection')
    parser.add_argument('-pearson_thresh',type=float,default=1.5)
    parser.add_argument('-edge_width',type=int,default=5)
    parser.add_argument('-edge_scale',type=float,default=0.7)
    parser.add_argument('-correlation_thresh',type=float,default=0.8)
    parser.add_argument('-root_detect_thresh',type=float,default=1.5)
    parser.add_argument('-dump',type=str,default='cmd/experiment/basic_info')
    parser.add_argument('-quantile_thresh',type=float,default=0.5)
    return parser.parse_args()

def roc():
    flag_optimize=False #统计最优配置下模型评估
    if flag_optimize:
        optimized_data=dict()
        optimized_data['root_with_edge']=dict()
        optimized_data['correlation_root']=dict()
        optimized_data['root_no_edge']=dict()
        # no-edge && ca
        disable_edge=True
        root_detect_thresh=11*0.2
        quantile_thresh=9*0.1
        pearson_thresh=6*0.05
        correlation_thresh=9*0.1
        if os.path.exists('cmd/binary/stragglers.dat'):
            os.remove('cmd/binary/stragglers.dat')
        engine=Engine(args.dir,embed_debug=False,delay=8.62,straggler_thresh=straggler_thresh)
        optimized_data['root_no_edge']['TN']=engine.TN
        optimized_data['root_no_edge']['TP']=engine.TP
        optimized_data['root_no_edge']['FN']=engine.FN
        optimized_data['root_no_edge']['FP']=engine.FP
        optimized_data['correlation_root']['TN']=engine.corre_TN
        optimized_data['correlation_root']['TP']=engine.corre_TP
        optimized_data['correlation_root']['FN']=engine.corre_FN
        optimized_data['correlation_root']['FP']=engine.corre_FP
        # root with edge
        disable_edge=False
        root_detect_thresh=8*0.2
        quantile_thresh=9*0.1
        if os.path.exists('cmd/binary/stragglers.dat'):
            os.remove('cmd/binary/stragglers.dat')
        engine=Engine(args.dir,embed_debug=False,delay=8.62,straggler_thresh=straggler_thresh)
        optimized_data['root_with_edge']['TN']=engine.TN
        optimized_data['root_with_edge']['TP']=engine.TP
        optimized_data['root_with_edge']['FN']=engine.FN
        optimized_data['root_with_edge']['FP']=engine.FP
        optimized_data['root_with_edge']['filter_num']=engine.filter_edge
        # dump data
        with open('cmd/experiment/optimized_data','a') as d:
            d.write(str(optimized_data)+'\n')
        exit()
    flag_ROC=False
    #arg_opt=open('argopt','w')
    if flag_ROC:
        #------------------------------------------------------------------------#
        # Calculate ROC
        ROC=dict()
        # disable edge detection
        disable_edge=True
        ROC['root_no_edge']={'TN':[],'TP':[],'FN':[],'FP':[]}
        # change root_detection_thresh,1, 0.1 ,3
        for i in range(20):
            #break
            root_detect_thresh=i*0.2
            for j in range(10):
                quantile_thresh=j*0.1
                if os.path.exists('cmd/binary/stragglers.dat'):
                    os.remove('cmd/binary/stragglers.dat')
                engine=Engine(args.dir,embed_debug=False,delay=8.62,straggler_thresh=straggler_thresh)
                ROC['root_no_edge']['TN'].append(engine.TN)
                ROC['root_no_edge']['TP'].append(engine.TP)
                ROC['root_no_edge']['FN'].append(engine.FN)
                ROC['root_no_edge']['FP'].append(engine.FP)
                arg_opt.write('no-edge,i=%d,j=%d,fpr=%.4f,tpr=%.4f\n'%(i,j,engine.FP/(engine.FP+engine.TN),engine.TP/(engine.TP+engine.FN)))
        disable_edge=False
        ROC['root_with_edge']={'TN':[],'TP':[],'FN':[],'FP':[]}
        # change root_detection_thresh,1, 0.1 ,3
        for i in range(20):
            #break
            root_detect_thresh=i*0.2
            for j in range(10):
                quantile_thresh=j*0.1
                if os.path.exists('cmd/binary/stragglers.dat'):
                    os.remove('cmd/binary/stragglers.dat')

                engine=Engine(args.dir,embed_debug=False,delay=8.62,straggler_thresh=straggler_thresh)
                ROC['root_with_edge']['TN'].append(engine.TN)
                ROC['root_with_edge']['TP'].append(engine.TP)
                ROC['root_with_edge']['FN'].append(engine.FN)
                ROC['root_with_edge']['FP'].append(engine.FP)
                arg_opt.write('with-edge,i=%d,j=%d,fpr=%.4f,tpr=%.4f\n'%(i,j,engine.FP/(engine.FP+engine.TN),engine.TP/(engine.TP+engine.FN)))
        # Correlation Root ROC
        ROC['correlation_root']={'TN':[],'TP':[],'FN':[],'FP':[]}
        # change root_detection_thresh,1, 0.1 ,3
        for i in range(20):
            #break
            #correlation_thresh=i*0.05
            pearson_thresh=i*0.05
            for j in range(11):
                correlation_thresh=i*0.1
                if os.path.exists('cmd/binary/stragglers.dat'):
                    os.remove('cmd/binary/stragglers.dat')
                engine=Engine(args.dir,embed_debug=False,delay=8.62,straggler_thresh=straggler_thresh)
                ROC['correlation_root']['TN'].append(engine.corre_TN)
                ROC['correlation_root']['TP'].append(engine.corre_TP)
                ROC['correlation_root']['FN'].append(engine.corre_FN)
                ROC['correlation_root']['FP'].append(engine.corre_FP)
                arg_opt.write('ca,i=%d,j=%d,fpr=%.4f,tpr=%.4f\n'%(i,j,engine.corre_FP/(engine.corre_FP+engine.corre_TN),engine.corre_TP/(engine.corre_TP+engine.corre_FN)))

        print('ROC analysis done! dumping to experiment ROC.')
        with open('cmd/experiment/ROC','a') as d:
            d.write(str(ROC)+'\n')
        arg_opt.close()
        exit()
        #------------------------------------------------------------------------#
    if os.path.exists('cmd/binary/stragglers.dat'):
        os.remove('cmd/binary/stragglers.dat')
    engine=Engine(args.dir,embed_debug=False,delay=8.62,straggler_thresh=straggler_thresh)
    print('Stage num:',len(engine.stages))
    print(engine.root)

def analysis(log_dir):
    args=init(log_dir)
    filter_anomaly=False # 是否过滤异常产生和straggler产生的任务
    straggler_thresh=1.5
    pearson_thresh=args.pearson_thresh
    edge_width=args.edge_width
    edge_scale=args.edge_scale
    correlation_thresh=args.correlation_thresh
    disable_edge=args.disable_edge
    disable_edge=True
    use_median=True
    root_detect_thresh=args.root_detect_thresh # 算法检测root cause时的阈值
    quantile_thresh=args.quantile_thresh
    flag_summary=True
    if flag_summary:
        if os.path.exists('cmd/binary/stragglers.dat'):
            os.remove('cmd/binary/stragglers.dat')
        disable_edge=True
        engine=Engine(args.dir,embed_debug=False,delay=8.62,straggler_thresh=straggler_thresh)
        #print('Stage num:',len(engine.stages))
        result = engine.summary()
        print('完成分析！')
        return result
