import numpy as np
import pandas as pd
import pickle
import xgboost as xgb

model = pickle.load(open('xgboost_model.pkl', 'rb'))
scaler = pickle.load(open('scaler1.pkl', 'rb'))

dummy_data = pd.DataFrame([{
    'Header_Length': 100,
    'Protocol Type': 1,
    'Duration': 10,
    'Rate': 5,
    'Srate': 3,
    'Drate': 2,
    'fin_flag_number': 0,
    'syn_flag_number': 1,
    'rst_flag_number': 0,
    'psh_flag_number': 0,
    'ack_flag_number': 1,
    'ece_flag_number': 0,
    'cwr_flag_number': 0,
    'ack_count': 5,
    'syn_count': 1,
    'fin_count': 0,
    'rst_count': 0,
    'HTTP': 1,
    'HTTPS': 0,
    'DNS': 0,
    'Telnet': 0,
    'SMTP': 0,
    'SSH': 0,
    'IRC': 0,
    'TCP': 10,
    'UDP': 5,
    'DHCP': 0,
    'ARP': 0,
    'ICMP': 0,
    'IGMP': 0,
    'IPv': 1,
    'LLC': 0,
    'Tot sum': 500,
    'Min': 50,
    'Max': 200,
    'AVG': 100,
    'Std': 30,
    'Tot size': 500,
    'IAT': 2,
    'Number': 10,
    'Magnitue': 5,
    'Radius': 3,
    'Covariance': 1.2,
    'Variance': 2.5,
    'Weight': 0.8
}])

dummy_scaled = scaler.transform(dummy_data)

dmatrix_data = xgb.DMatrix(dummy_scaled)

prediction = model.predict(dmatrix_data)

status = "Normal" if prediction[0] == 0 else "Attack"
print(f"Prediction: {status} {prediction}")
