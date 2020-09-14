import os
import matplotlib.pyplot as plt
import numpy as np
import matplotlib.gridspec as gridspec
from IPython import embed

root_prefix='/'.join(os.path.abspath(__file__).split('/')[:-2])+'/'

def regularize_name(names):
    ret=''
    for name in names:
        if name == 'cpu': ret+='CPU '
        elif name == 'io': ret+= 'I/O '
        elif name == 'net': ret+= 'Network '
    return ret[:-1]


def draw_anomaly_with_tasks(package,slave='slave1'):
    ''' Draw package.
    Args:
        package: key->val format, possible keys are `cpu`, `net`, 'io`, `anomaly`, ` tasks`
    '''
    print('Drawing '+slave)
    if slave=='4':
        print(package['tasks'])
    print(package['anomaly'])
    offset = 2
    word_offset = 35
    root_head = 'Roots:'
    arrow_head_width = 0.1
    arrow_head_length = 0.4
    arrow_end_offset = 1
    arrow_head_y_offset = 0.07
    arrow_width = 0.0001
    # =========================
    fig1 = plt.figure()
    ax1 = fig1.add_subplot(111)
    ax1.set_xlabel('Timeline')
    ax1.set_ylabel('Feature Scale')
    ax1.set_ylim(0, 1.2)
    color = {'cpu': 'b', 'io': 'g', 'net': 'c'}
    keys = package.keys()
    flag_straggler_label = True
    legends = dict()
    after_transfor = ['CPU', 'I/O', 'Network']
    before_transfor = ['cpu', 'io', 'net']
    has_ag=False
    for key in sorted(keys):
        obj = package[key]
        if key in ['cpu', 'net', 'io']:
            #if key=='cpu':print(key,'->',obj)
            plot_x = []
            plot_y = []
            # we need to normalize these features
            max_y = max(obj, key=lambda x: x[1])
            if max_y[1] == 0: max_y = 1
            else:max_y=max_y[1]
            for x, y in obj:
                plot_x.append(float(x))
                plot_y.append(float(y / max_y))
            # cpu, net, io is wrapped in the same format
            # revert format
            temp = ax1.plot(plot_x, plot_y, color[key])
            if key not in legends:
                legends[key] = temp[0]
        if key == 'anomaly':
            if len(obj) == 0:
                continue
            has_ag=True
            max_len = int(obj[-1][2])
            # draw rectangle
            for name, start, end in obj:
                start = int(start)
                end = int(end)
                print('Draw anomaly',start,end)
                temp = ax1.plot([float(start), float(end)], [1.1, 1.1], 'k-.')
                if 'AG' not in legends:
                    legends['AG'] = temp[0]
                name = after_transfor[before_transfor.index(name)]
                ax1.annotate(name, xy=((start + end) / 2, 1.1), xytext=(start, 1.12))
        if key == 'tasks':
            ax2 = ax1.twinx()
            # ax2.set_ylim(0,4)
            ax2.set_ylabel('Straggler Scale')
            # ax2=ax1
            strides = []
            for start, end, avg, root in obj:
                temp = ax2.plot([float(start), float(end)], [avg, avg], 'k-', linewidth=2)
                if 'straggler' not in legends:
                    legends['straggler'] = temp[0]
                if 'unkown' in str(root): continue
                ax2.text(start-offset, avg+0.003, root_head + regularize_name(root))
                '''
                ax2.arrow(start ,avg,
                              start-offset, avg,
                              length_includes_head=True, head_width=arrow_head_width, head_length=arrow_head_length,
                              fc='k', ec='k', width=arrow_width)
                strides.append([start, end, root, avg])
                '''
            '''
            # sort strides
            strides = sorted(strides, key=lambda x: int(x[0]))
            pre_start = -1
            pre_root = ''
            sum_y = 0
            num_y = 0
            pre_points = []
            for stride in strides:
                if abs(float(stride[0]) - float(pre_start)) > 0.5 and pre_start != -1:
                    # ready to write text
                    mean_y = sum_y / num_y
                    center_x = pre_start - word_offset
                    center_y = mean_y
                    ax2.text(center_x, center_y, root_head + regularize_name(pre_root))
                    print('Draw text '+root_head + regularize_name(pre_root))
                    for p_x, p_y in pre_points:
                        ax2.arrow(center_x + offset, center_y + arrow_head_y_offset,
                                  p_x - center_x - offset - arrow_end_offset, p_y - center_y - arrow_head_y_offset,
                                  length_includes_head=True, head_width=arrow_head_width, head_length=arrow_head_length,
                                  fc='k', ec='k', width=arrow_width)
                    num_y = 0
                    sum_y = 0
                    pre_points = []
                sum_y += stride[3]
                num_y += 1
                pre_root = stride[2]
                #print('pre_root:',pre_root)
                pre_start = stride[0]
                pre_points.append([float(stride[0]), float(stride[-1])])
            if num_y==0:
                mean_y=0
            else:
                mean_y = sum_y / num_y
            center_x = pre_start - word_offset
            center_y = mean_y
            if pre_root!='':
                ax2.text(center_x, center_y, root_head + regularize_name(pre_root))
                for p_x, p_y in pre_points:
                    ax2.arrow(center_x + offset, center_y + arrow_head_y_offset, p_x - center_x - offset - arrow_end_offset,
                              p_y - center_y - arrow_head_y_offset,
                              length_includes_head=True, head_width=arrow_head_width, head_length=arrow_head_length,
                              fc='k', ec='k', width=arrow_width)
            '''
    #if int(slave)==4:embed();exit()
    # ax1.legend(loc=2)
    # ax2.legend(loc=2)
    # print(legends.keys())
    vals = []
    raw_keys = ['straggler', 'AG', 'cpu', 'io', 'net']
    keys = ['straggler', 'AG', 'CPU', 'I/O', 'Network']
    if not has_ag:
        keys.remove('AG')
        raw_keys.remove('AG')
    for k in raw_keys:
        if k in legends:
            vals.append(legends[k])
    plt.xlim([-15, 105])
    plt.legend(vals, keys)
    # plt.legend(loc=2)
    # plt.ylim(0,4)
    plt.title(slave)
    fig_path=root_prefix+'server/webshell/static/imgs/application_%s.svg'%(slave)
    print('Saving figure to',fig_path)
    plt.savefig(fig_path)


def draw_distribution(data, bucket=10, ):
    ''' Draw different data occurrence.
    Args:
        data: list format, [x1, x2, ...]
        bucket: divide value into these buckets
    '''
    max_val = max(data)
    bucket_size = (max_val + 0.1) / bucket
    plot_y = [0] * bucket
    bins = []
    for i in range(bucket):
        bins.append(i * bucket_size)
    plt.hist(data, bins=bins)
    plt.xlabel('task duration/s')
    plt.ylabel('task count')
    plt.show()


def draw_box_duration():
    data = dict()
    # read info
    name = ''
    with open('info') as f:
        for line in f:
            if line.strip() == '': continue
            if line.strip().startswith('#'):
                name = line.split('=')[1].strip()
                data[name] = []
            else:
                data[name].append(float(line))
    names = ('Baseline', 'CPU', 'I/O', 'Network', 'Mixed')
    raw_names = ('baseline', 'cpu', 'io', 'net', 'mixture')
    food = []
    for name in raw_names:
        food.append(data[name])
    plt.ylabel('Duration (s)')
    plt.boxplot(food, labels=names)
    plt.show()


def draw_errer_bar(data=None, names=('baseline', 'cpu', 'io', 'net', 'mixture')):
    if data == None:
        data = dict()
        # read info
        name = ''
        with open('info') as f:
            for line in f:
                if line.strip() == '': continue
                if line.strip().startswith('#'):
                    name = line.split('=')[1].strip()
                    data[name] = []
                else:
                    data[name].append(float(line))
    # calculate
    # print('data:',data)
    mean = []
    err = [[], []]
    ind = list(range(len(data)))
    for name in names:
        mean.append(sum(data[name]) / len(data[name]))
        err[0].append(-min(data[name]) + mean[-1])
        err[1].append(max(data[name]) - mean[-1])
    print(mean)
    # ready to plot
    # plt.style.use('seaborn-whitegrid')
    plt.errorbar(ind, mean, yerr=err, marker='o', fmt='.k--')
    plt.xticks(ind, names)
    plt.ylabel('duration/s')
    plt.title('Job duration when different AG is injected.')
    # print('err:',err)
    # print('mean:',mean)
    plt.show()


def draw_group_bars(ax, names, subnames, data, tag='None'):
    ind = np.arange(len(names) - 1)
    # fig,ax=plt.subplots()
    group_len = len(subnames)
    width = (1 - 0.2) / group_len
    rects = []
    for i, subname in enumerate(subnames):
        flag = True
        mean_data = []
        err_data = []
        for j, name in enumerate(names):
            if name == 'PCC':
                continue
            sub_data = data[i][j]
            sub_mean = np.mean(sub_data)
            sub_err = np.std(sub_data)
            mean_data.append(sub_mean)
            err_data.append(sub_err)
        curbar = ax.bar(ind + width * i, mean_data, width, yerr=err_data)
        if flag:
            rects.append(curbar)
            flag = False
    names.remove('PCC')
    ax.set_ylabel('Rate(%)')
    ax.set_xticks(ind + width / 2, )
    ax.set_xticklabels(names)
    ax.set_title(tag)
    ax.legend(rects, (subnames), loc=2)
    # plt.show()


def draw_overhead():
    names = ['init status', 'start sampling tools', 'collect logs', 'decode logs']
    data = []
    with open('overhead') as f:
        for line in f:
            for ind, d in enumerate(line.strip().split()):
                if ind + 1 > len(data):
                    data.append([])
                data[ind].append(float(d))
    data = np.array(data).transpose()
    mean = data.mean(0)
    err = data.std(0)
    print(mean, err)
    plt.ylabel('duration/s')
    ind = np.arange(len(names))
    plt.bar(ind, mean, yerr=err)
    plt.xticks(ind, names)
    plt.show()


def draw_optimization():
    tpr_global = []
    fpr_global = []
    acc_global = []
    names_global = []
    package = []
    fig, axes = plt.subplots(nrows=1, ncols=4, sharey=True)
    ax_index = 0
    with open('optimized_data') as f:
        for line in f:
            if line.startswith('#'):
                if len(tpr_global) > 0:
                    package.append([names_global, ['TPR', 'FPR', 'ACC'], [tpr_global, fpr_global, acc_global], tag])
                    draw_group_bars(axes[ax_index], names_global, ['TPR', 'FPR', 'ACC'],
                                    [tpr_global, fpr_global, acc_global], tag=tag)
                    ax_index += 1
                tag = line.strip()[1:]  # 实验配置
                tpr_global = []
                fpr_global = []
                acc_global = []
                names_global = []
            else:
                data = eval(line.strip())
                print('dealing with', tag)
                sks = sorted(data.keys())
                for name in sks:
                    # name是不同的参数配置
                    names_global.append(name)
                    pn_data = data[name]
                    data_len = len(pn_data['TP'])
                    # fpr=fp/(fp+tn)
                    # tpr=tp/(tp+fn)
                    # 遍历每次参数配置时的数据
                    tpr_temp = []
                    fpr_temp = []
                    acc_temp = []
                    for i in range(data_len):
                        tpr_temp.append(pn_data['TP'][i] / (pn_data['TP'][i] + pn_data['FN'][i]))
                        fpr_temp.append(pn_data['FP'][i] / (pn_data['FP'][i] + pn_data['TN'][i]))
                        acc_temp.append((pn_data['TP'][i] + pn_data['TN'][i]) / (pn_data['TP'][i] + pn_data['TN'][i] +
                                                                                 pn_data['FP'][i] + pn_data['FN'][i]))
                    tpr_global.append(tpr_temp)
                    fpr_global.append(fpr_temp)
                    acc_global.append(acc_temp)
    if len(tpr_global) > 0:
        package.append([names_global, ['TPR', 'FPR', 'ACC'], [tpr_global, fpr_global, acc_global], tag])
        draw_group_bars(axes[ax_index], names_global, ['TPR', 'FPR', 'ACC'], [tpr_global, fpr_global, acc_global],
                        tag=tag)
    # plt.tight_layout()
    plt.show()
    # draw_package(package)


def draw_ROC(data, key, axes):
    # print(data.keys())
    plot_index = 0
    print(data.keys())
    for k in data:
        if k == 'use edge detection': continue
        # print(plot_index)
        v = data[k]
        tn = v['TN']
        tp = v['TP']
        fn = v['FN']
        fp = v['FP']
        fpr = []  # fpr=fp/(fp+tn)
        tpr = []  # tpr=tp/(tp+fn)
        data_len = len(tn) + 2
        for i in range(data_len - 2):
            if fp[i] + tn[i] == 0 or tp[i] + fn[i] == 0:
                continue
            fpr.append(fp[i] / (fp[i] + tn[i]))
            tpr.append(tp[i] / (tp[i] + fn[i]))
        fpr.append(0)
        tpr.append(0)
        fpr.append(1)
        tpr.append(1)
        # calculate AUC
        auc_data = []
        for i in range(data_len):
            auc_data.append([fpr[i], tpr[i]])
        auc_data = sorted(auc_data, key=lambda x: x[0])
        auc = 0
        pre_p = auc_data[0]
        fpr = [pre_p[0]]
        tpr = [pre_p[1]]
        for i in range(1, data_len):
            cur_p = auc_data[i]
            stride = cur_p[0] - pre_p[0]
            auc += stride * (pre_p[1] + cur_p[1]) / 2
            pre_p = cur_p
            fpr.append(cur_p[0])
            tpr.append(cur_p[1])
        axes[plot_index].text(0.7, 0.05, 'AUC=' + str(round(auc, 4)))
        axes[plot_index].plot(fpr, tpr)
        # print(k)
        if k == 'root_no_edge':
            cond = 'BigRoots'
        else:
            cond = 'PCC'
        # axes[plot_index].set_title('ROC of '+cond+' when '+key+' AG injected')
        axes[plot_index].set_title('ROC of ' + cond)
        # print('name=',k,'auc=',auc)
        axes[plot_index].set_xlabel('FPR')
        axes[plot_index].set_ylabel('TPR')
        # plt.show()
        plot_index += 1


def draw_ROC_all(all):
    keys = ['CPU', 'I/O', 'network', 'mixture']
    # fig,axes=plt.subplots(nrows=2,ncols=4,sharey=True,sharex=True)
    fig = plt.figure(figsize=(18, 8))
    outer = gridspec.GridSpec(2, 2, wspace=0.3, hspace=0.5)
    inners = []
    for i in range(4):
        inner = gridspec.GridSpecFromSubplotSpec(1, 2, subplot_spec=outer[i], wspace=0.15, hspace=0.15)
        inners.append(inner)
    for ind, key in enumerate(keys):
        # print(axes.shape,ind/2,ind%2)
        data = all[key]
        # draw_ROC(data,key,[axes[int(ind/2),(2*ind)%4],axes[int(ind/2),(2*ind+1)%4]])
        ax1 = plt.Subplot(fig, inners[ind][0])
        ax2 = plt.Subplot(fig, inners[ind][1])
        if ind % 2 == 1:
            ax1.set_yticklabels([])
        ax2.set_yticklabels([])
        if ind < 2:
            ax1.set_xticklabels([])
            ax2.set_xticklabels([])
        fig.add_subplot(ax1)
        fig.add_subplot(ax2)
        draw_ROC(data, key, [ax1, ax2])
    # fig.tight_layout()
    plt.show()


def load_ROC_data():
    all = dict()
    with open('sumROC') as f:
        for line in f:
            if line.strip() == '': continue
            if line.startswith('#'):
                name = line.strip()[1:]
            else:
                # print('name=',name)
                data = eval(line.strip())
                all[name] = data
                # draw_ROC(data)
    draw_ROC_all(all)


if __name__ == '__main__':
    #draw_optimization()
    draw_anomaly_with_tasks()
