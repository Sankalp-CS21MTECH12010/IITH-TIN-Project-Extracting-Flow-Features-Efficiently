# Importing the required libraries
import matplotlib.pyplot as plt
import pandas as pd
from pathlib import Path
import socket
import struct
from datetime import datetime
import numpy as np
from sklearn.svm import SVC

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
X_temp = dataset[dataset.columns[1:-1]]
y_temp = dataset[dataset.columns[-1]]
X_temp["Source IP"] = ip2int(list(X_temp["Source IP"]))
X_temp["Destination IP"] = ip2int(list(X_temp["Destination IP"]))
X_temp['Timestamp'] = pd.to_datetime(X_temp["Timestamp"])

z = sorted(list(set(y_temp)))
index_dict = {}
i = 0
for z1 in z:
    index_dict[z1] = i
    i = i + 1
print(index_dict)

selected_features =  ['Source IP',	 'Source Port',	 'Destination IP',	 'Destination Port',	 'Protocol', 'Flow Duration', 'Total Length of Fwd Packets', 'SYN Flag Count',		 'PSH Flag Count',	 'ACK Flag Count', 'Active Mean', 'Active Min',  'Subflow Fwd Bytes', 'Init_Win_bytes_forward', 'Flow IAT Min', 'Packet Length Mean']
print(X_temp.columns)
X_temp = X_temp[selected_features]

print(X_temp)

print(X_temp.shape)
print(y_temp.shape)

import numpy as np
from sklearn.preprocessing import MinMaxScaler

# y_vec = [0]*15
# y = []
# for y_ins in list(y_temp):
#     temp = y_vec.copy()
#     temp[index_dict[y_ins]] = 1
#     temp = np.array(temp)
#     y.append(temp)
    
#Do Min-Max scaling
X = X_temp.values.tolist()
X
scaler = MinMaxScaler()
model=scaler.fit(X)
X=model.transform(X)
X = np.array(X)
y = np.array(y_temp)

print(X.shape)
print(y.shape)


import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn import datasets
from sklearn.model_selection import train_test_split
from sklearn.feature_selection import SelectFromModel
from sklearn.metrics import accuracy_score

print(X.shape,y.shape)
from sklearn.utils import shuffle

X_train, y_train = shuffle(X, y)

import numpy as np
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
clf = make_pipeline(StandardScaler(), SVC(gamma='auto'))

# Train the classifier
clf.fit(X_train, y_train)

#Train Accuracy
# Apply The Full Featured Classifier To The Test Data
y_pred = clf.predict(X_train)

# View The Accuracy Of Our Full Feature (4 Features) Model
print(accuracy_score(y_train, y_pred))

import pickle

with open('/home/c310/Downloads/RF_Model.pkl', 'wb') as f:
    pickle.dump(clf, f)

