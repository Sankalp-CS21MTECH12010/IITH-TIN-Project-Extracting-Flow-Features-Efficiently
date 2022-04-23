import os
import subprocess
import pandas as pd
import socket
import struct
import ipaddress
import time
import pickle
import numpy as np
from sklearn.preprocessing import MinMaxScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn import datasets
from sklearn.model_selection import train_test_split
from sklearn.feature_selection import SelectFromModel
from sklearn.metrics import accuracy_score

clf = ""
with open('/home/c310/Downloads/RF_Model.pkl', 'rb') as f:
    clf = pickle.load(f)

t0 = time.time()
eviction_time = 300 #in seconds
files = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protos', 'tos_register', 'syn_counter', 'psh_counter', 'ack_counter', 'flow_total_length', 'forward_total_length', 'fw_win_byt', 'flow_duration', 'flow_min_duration', 'flow_total_active_duration', 'flow_active_segments', 'flow_total_inactive_duration', 'subflow_fwd_bytes', 'is_inactive', 'flow_start_time_stamp']
df_curr = pd.DataFrame(columns = files)

def format_df(df):
    df['Average_Packet_Length'] = df['flow_total_length']/df['tos_register']
    df['Active Mean'] = df['flow_total_active_duration']/df['flow_active_segments']
    return df

def ip_format(df):
    df['src_ip'] = [ipaddress.ip_address(int(i)) for i in df['src_ip']]
    df['dst_ip'] = [ipaddress.ip_address(int(i)) for i in df['dst_ip']]
    return df

def to_labels(y):
    y = np.argmax(y, axis = 1)
    labs = []
    map1 = {'BENIGN': 0, 'Bot': 1, 'DDoS': 2, 'DoS GoldenEye': 3, 'DoS Hulk': 4, 'DoS Slowhttptest': 5, 'DoS slowloris': 6, 'FTP-Patator': 7, 'Heartbleed': 8, 'Infiltration': 9, 'PortScan': 10, 'SSH-Patator': 11, 'Web Attack - Brute Force': 12, 'Web Attack - Sql Injection': 13, 'Web Attack - XSS': 14}
    inv_map = {v: k for k, v in map1.items()}
    for i in range(len(y)):
        labs.append(inv_map[y[i]])
    return labs

def create_dataset(df):
    df = format_df(df)
    selected_features =  ['src_ip',	 'src_port',	 'dst_ip',	 'dst_port',	 'protos', 'flow_duration', 'forward_total_length', 'syn_counter', 'psh_counter',	 'ack_counter', 'Active Mean', 'flow_min_duration',  'subflow_fwd_bytes', 'fw_win_byt', 'flow_total_inactive_duration', 'Average_Packet_Length']
    df = df[selected_features]
    X = df.values.tolist()
    scaler = MinMaxScaler()
    model=scaler.fit(X)
    X=model.transform(X)
    X = np.array(X)
    y_pred = clf.predict(np.nan_to_num(X))
    
    df["Labels"] = to_labels(y_pred)
    df = ip_format(df)
    return df

while(True):
    start_time = time.time()
    subprocess.call(['sh', '/home/c310/p4-learning/examples/read_write_registers_cli/reg_copy.sh'])
    df = pd.DataFrame()
    for fls in files:
        with open(fls+".txt") as f:
            lines = f.readlines()
            s = lines[0].split(",")
            df[fls] = s
    df = df.apply(pd.to_numeric)
    # df = df.loc[~(df==0).all(axis=1)] 
    # print("Reading Time = {}".format(time.time() - start_time))

    start_time = time.time()
    # df[df.columns[:-1]] = df[df.columns[:-1]].loc[~(df[df.columns[:-1]]==0.0).all(axis=1)]
    df = df[(df["tos_register"]>0)]
    df = df[(df["is_inactive"] != -1)]
    df1 = df[(df["is_inactive"] == 1)]
    # print(df1)
    if not df1.empty:
        df1 = create_dataset(df1)
        df_curr = df_curr.append(df1)
    # print("Saving Time = {}".format(time.time() - start_time))

    start_time = time.time()
    # print(len(df_curr))
    indices = list(df1.index)
    # print(indices)
    #Evict all the inactive flows
    for i in indices:
        cmd = "echo register_write '{} {} {}' | simple_switch_CLI --thrift-port 9090".format("is_inactive",i,-1)
        os.system(cmd)

    #Evict all the active flows that have been there for long time
    df2 = df[(df["is_inactive"] == 0)]
    df2["Time Gap"] = time.time() - t0 - (df2["flow_start_time_stamp"]/(10**6))
    df2 = df2[df2["Time Gap"] >= 300]
    if not df2.empty:
        df2 = create_dataset(df2)
        df_curr = df_curr.append(df2)
    indices = list(df2.index)
    # print(len(indices))
    for i in indices:
        cmd = "echo register_write '{} {} {}' | simple_switch_CLI --thrift-port 9090".format("is_inactive",i,-1)
        os.system(cmd)
    # print(df_curr)
    df_curr.to_csv('/home/c310/p4-learning/examples/read_write_registers_cli/P4-classified-flows2.csv')
