import numpy as np
import pandas as pd
import pickle
import xgboost as xgb

model = pickle.load(open('xgboost_model.pkl', 'rb'))
scaler = pickle.load(open('scaler1.pkl', 'rb'))

dummy_data = pd.DataFrame([{
    'Header_Length': 0,
    'Protocol Type': 1,
    'Duration': 0,
    'Rate': 0,
    'Srate': 0,
    'Drate': 0,
    'fin_flag_number': 0,
    'syn_flag_number': 0,
    'rst_flag_number': 0,
    'psh_flag_number': 0,
    'ack_flag_number': 0,
    'ece_flag_number': 0,
    'cwr_flag_number': 0,
    'ack_count': 0,
    'syn_count': 0,
    'fin_count': 0,
    'rst_count': 0,
    'HTTP': 0,
    'HTTPS': 0,
    'DNS': 0,
    'Telnet': 0,
    'SMTP': 0,
    'SSH': 0,
    'IRC': 0,
    'TCP': 0,
    'UDP': 0,
    'DHCP': 0,
    'ARP': 0,
    'ICMP': 0,
    'IGMP': 0,
    'IPv': 0,
    'LLC': 0,
    'Tot sum': 0,
    'Min': 0,
    'Max': 0,
    'AVG': 0,
    'Std': 0,
    'Tot size': 0,
    'IAT': 0,
    'Number': 0,
    'Magnitue': 0,
    'Radius': 0,
    'Covariance': 0,
    'Variance': 0,
    'Weight': 0
}])

dummy_scaled = scaler.transform(dummy_data)

dmatrix_data = xgb.DMatrix(dummy_scaled)

prediction = model.predict(dmatrix_data)

status = "Normal" if prediction[0] == 0 else "Attack"
print(f"Prediction: {status} {prediction}")
