#################
#### imports ####
#################

# Standard
import pandas as pd
import numpy as np
import os
import sys
import subprocess
# Isolation Forest
from sklearn.pipeline import Pipeline
from sklearn.ensemble import IsolationForest

# SQLite
from sqlalchemy import create_engine
import datetime as dt
import time

################
#### CONFIG ####
################


###################
#### FUNCTIONS ####
###################
local_ip='127.0.0.1'
if_contamination='0.01'
def is_public_ip(ip):
    ip = list(map(int, ip.strip().split('.')[:2]))
    if ip[0] == 10: return False
    if ip[0] == 172 and ip[1] in range(16, 32): return False
    if ip[0] == 192 and ip[1] == 168: return False
    return True

def isolation_forest(filename,local_ip,if_contamination):
    # Convert data
    print('Converting data..')


    # Import data
    
    command="tshark -r app/mods/mod_scan/uploads/"+filename + " -T fields -e frame.number -e frame.time -e ip.src -e ip.dst -e _ws.col.Protocol -e frame.len -e _ws.col.Info -E header=y -E separator=, -E quote=d -E occurrence=f > app/mods/mod_scan/uploads/test.csv"
    #t=os.system("tshark -r app/mods/mod_scan/uploads/"+filename + " -T fields -e frame.number -e frame.time -e ip.src -e ip.dst -e _ws.col.Protocol -e frame.len -e _ws.col.Info -E header=y -E separator=, -E quote=d -E occurrence=f > app/mods/mod_scan/uploads/test.csv")
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    process.wait()
    df = pd.read_csv('app/mods/mod_scan/uploads/test.csv')
     
    #df = pd.read_csv(os.path.join('app/mods/mod_scan/uploads', filename)) 
    df.columns = ['no', 'time', 'ipsrc', 'ipdst', 'proto','length', 'info']
    df['info'] = "null"
    df.parse_dates=["time"]
    df['time'] = pd.to_datetime(df['time'])
    df['count'] = 1

    # Group
    dataGroup2 = df.groupby(['ipsrc','proto']).resample('5S', on='time').sum().reset_index().dropna()
    pd.options.display.float_format = '{:,.0f}'.format

    # Drop row with IP
    dataGroup2 = dataGroup2[['ipsrc','proto','time','count']]
    dataGroup2 = dataGroup2[dataGroup2.ipsrc != local_ip]

    # Normalize
    dataNorm = dataGroup2.copy()
    dataNorm['count_n'] = (dataGroup2['count'] - dataGroup2['count'].min()) / (dataGroup2['count'].max() - dataGroup2['count'].min())
    dataNorm = dataNorm
    dataNorm = dataNorm[['count','count_n']]

    # Isolation Forest
    dataTrain = dataNorm.iloc[0:100000]

    if not if_contamination:
        iforest = IsolationForest(n_estimators=100, contamination=0.01)

    else:
        if_contamination = float(if_contamination)
        iforest = IsolationForest(n_estimators=100, contamination=if_contamination)

    iforest.fit(dataTrain)
    clf = iforest.fit(dataTrain)
    prediction = iforest.predict(dataNorm)
    dataGroup2['prediction'] = prediction

    # Save the anomalies in a new var
    dataGroup3 = dataGroup2[(dataGroup2['prediction'] == -1)]

    # Save the anomalies ipdst in a new var
    anomalies = dataGroup2[(dataGroup2['prediction'] == -1)]['ipsrc'].values

    # Check anomalies IP type
    ips = anomalies
    type = []
    for ip in ips:
        if is_public_ip(ip):
            type.append('public')
        else:
            type.append('private')
    dataGroup3['type'] = type

    disk_engine = create_engine('sqlite:///app/mods/mod_scan/isolation_forest.db')

    # Save all data included anomalies in a new table
    dataGroup2.to_sql('data', disk_engine, if_exists='replace')

    # Save anomalies + IP type in a new table
    dataGroup3.to_sql('anomalies', disk_engine, if_exists='replace')
    return "DONE"
