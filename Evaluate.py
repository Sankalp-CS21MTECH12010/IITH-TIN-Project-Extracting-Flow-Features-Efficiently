import pandas as pd
df_sys = pd.read_csv("/home/c310/p4-learning/examples/read_write_registers_cli/P4-classified-flows2.csv")
df2 = pd.DataFrame()

import matplotlib.pyplot as plt
import pandas as pd
from pathlib import Path
import socket
import struct
from datetime import datetime
import numpy as np

def ip2int(addr_list):
    return [struct.unpack("!I", socket.inet_aton(addr))[0] for addr in addr_list]



#Append all files and create a dataset
folder = Path('/home/c310/Downloads/GeneratedLabelledFlows').rglob('*.csv')
files = []
for x in folder:
    file = pd.read_csv(x,low_memory=False,encoding='cp1252')
    file.columns = [c.strip() for c in file.columns]
    files.append(file)
dataset = pd.concat(files, axis=0)
dataset.columns = [c.strip() for c in dataset.columns]
dataset = dataset[dataset["Label"].notna()]
dataset =dataset[~dataset.isin([np.nan, np.inf, -np.inf]).any(1)]
dataset = dataset[['Source IP',  'Destination IP', 'Source Port','Destination Port', 'Protocol', 'Label']]
print(dataset.columns)

df_sys = df_sys[['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protos', 'Labels']]
df_sys.columns = ['Source IP',  'Destination IP', 'Source Port','Destination Port', 'Protocol', 'Label']

flow_ids1 =  []
flow_ids2 =  []

for i in range(len(df_sys)):
    sip = df_sys['Source IP'][i]
    dip = df_sys['Destination IP'][i]
    sp = df_sys['Source Port'][i]
    dp = df_sys['Destination Port'][i]
    pr = df_sys['Protocol'][i]
    l = ','.join(sorted([str(sip),str(dip)]) + sorted([str(sp),str(dp)]) + [str(pr)])
    flow_ids1.append(l)

df_sys["Flow ID"] = flow_ids1

for i in range(len(dataset)):
    sip = dataset['Source IP'][i]
    dip = dataset['Destination IP'][i]
    sp = dataset['Source Port'][i]
    dp = dataset['Destination Port'][i]
    pr = dataset['Protocol'][i]
    l = ','.join(sorted([str(sip),str(dip)]) + sorted([str(sp),str(dp)]) + [str(pr)])
    flow_ids2.append(l)

dataset["Flow ID"] = flow_ids2

dict1 = {}

fids = list(dataset["Flow ID"])
labs = list(dataset["Label"])

for i in range(len(fids)):
    if(fids[i] not in dict1):
        dict1[fids[i]] = 0
    dict1[fids[i]] = labs[i]

acc = 0
fids2 = list(df_sys["Flow ID"])
labs2 = list(df_sys["Label"])
for i in range(len(fids2)):
    acc = acc + (labs2[i] == dict1[fids2[i]])

print(acc/len(df_sys))
