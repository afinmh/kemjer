from flask import Flask, jsonify
import pandas as pd
import numpy as np
import pickle
import xgboost as xgb
from scapy.all import sniff
import threading
import time

app = Flask(__name__)

# Load model dan scaler
model = pickle.load(open('xgboost_model.pkl', 'rb'))
scaler = pickle.load(open('scaler1.pkl', 'rb'))

# Variabel untuk menyimpan informasi
header_lengths = []
packet_lengths = []
protocol_counts = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'IGMP': 0}
flag_counts = {'FIN': 0, 'SYN': 0, 'RST': 0, 'PSH': 0, 'ACK': 0, 'ECE': 0, 'CWR': 0}
service_counts = {'HTTP': 0, 'HTTPS': 0, 'DNS': 0, 'Telnet': 0, 'SMTP': 0, 'SSH': 0, 'IRC': 0}
other_features = {'Duration': 0, 'Rate': 0, 'Srate': 0, 'Drate': 0, 
                  'ack_count': 0, 'syn_count': 0, 'fin_count': 0, 'rst_count': 0, 
                  'DHCP': 0, 'ARP': 0, 'IPv': 0, 'LLC': 0, 'IAT': 0, 'Number': 0, 
                  'Magnitue': 0, 'Radius': 0, 'Covariance': 0, 'Variance': 0, 'Weight': 0}

# Variable to store prediction results
latest_prediction = {"prediction": "Unknown", "features": []}

# Variabel untuk melacak apakah ada paket pada port 5000
packets_received = False

FLASK_PORT = 5000

def process_packet(packet):
    global header_lengths, packet_lengths, protocol_counts, flag_counts, service_counts, other_features, packets_received
    
    if packet.haslayer('IP') and (packet.haslayer('TCP') or packet.haslayer('UDP')):
        sport = packet.sport
        dport = packet.dport
        
        if sport == FLASK_PORT or dport == FLASK_PORT:
            packets_received = True  # Tandai bahwa ada paket yang diterima
            
            ip_layer = packet.getlayer('IP')
            header_lengths.append(len(packet))
            packet_lengths.append(ip_layer.len)
            
            if packet.haslayer('TCP'):
                protocol_counts['TCP'] += 1
                tcp_layer = packet.getlayer('TCP')
                flag_counts['FIN'] += tcp_layer.flags.F
                flag_counts['SYN'] += tcp_layer.flags.S
                flag_counts['RST'] += tcp_layer.flags.R
                flag_counts['PSH'] += tcp_layer.flags.P
                flag_counts['ACK'] += tcp_layer.flags.A
                flag_counts['ECE'] += tcp_layer.flags.E
                flag_counts['CWR'] += tcp_layer.flags.C
                other_features['ack_count'] += 1
                other_features['syn_count'] += tcp_layer.flags.S
                other_features['fin_count'] += tcp_layer.flags.F
                other_features['rst_count'] += tcp_layer.flags.R
            elif packet.haslayer('UDP'):
                protocol_counts['UDP'] += 1
            
            if packet.haslayer('TCP') or packet.haslayer('UDP'):
                if sport == 80 or dport == 80:
                    service_counts['HTTP'] += 1
                elif sport == 443 or dport == 443:
                    service_counts['HTTPS'] += 1
                elif sport == 53 or dport == 53:
                    service_counts['DNS'] += 1
                elif sport == 23 or dport == 23:
                    service_counts['Telnet'] += 1
                elif sport == 25 or dport == 25:
                    service_counts['SMTP'] += 1
                elif sport == 22 or dport == 22:
                    service_counts['SSH'] += 1
                elif sport == 6667 or dport == 6667:
                    service_counts['IRC'] += 1

def calculate_features():
    protocol_mapping = {'TCP': 1, 'UDP': 2, 'ICMP': 3, 'IGMP': 4}
    protocol_type = max(protocol_counts, key=protocol_counts.get)
    protocol_num = protocol_mapping.get(protocol_type, 0)

    features = {
        'Header_Length': np.mean(header_lengths) if header_lengths else 0,
        'Protocol Type': protocol_num,
        'Duration': other_features['Duration'],
        'Rate': other_features['Rate'],
        'Srate': other_features['Srate'],
        'Drate': other_features['Drate'],
        'fin_flag_number': flag_counts['FIN'],
        'syn_flag_number': flag_counts['SYN'],
        'rst_flag_number': flag_counts['RST'],
        'psh_flag_number': flag_counts['PSH'],
        'ack_flag_number': flag_counts['ACK'],
        'ece_flag_number': flag_counts['ECE'],
        'cwr_flag_number': flag_counts['CWR'],
        'ack_count': other_features['ack_count'],
        'syn_count': other_features['syn_count'],
        'fin_count': other_features['fin_count'],
        'rst_count': other_features['rst_count'],
        'HTTP': service_counts['HTTP'],
        'HTTPS': service_counts['HTTPS'],
        'DNS': service_counts['DNS'],
        'Telnet': service_counts['Telnet'],
        'SMTP': service_counts['SMTP'],
        'SSH': service_counts['SSH'],
        'IRC': service_counts['IRC'],
        'TCP': protocol_counts['TCP'],
        'UDP': protocol_counts['UDP'],
        'DHCP': other_features['DHCP'],
        'ARP': other_features['ARP'],
        'ICMP': protocol_counts['ICMP'],
        'IGMP': protocol_counts['IGMP'],
        'IPv': other_features['IPv'],
        'LLC': other_features['LLC'],
        'Tot sum': np.sum(packet_lengths),
        'Min': np.min(packet_lengths) if packet_lengths else 0,
        'Max': np.max(packet_lengths) if packet_lengths else 0,
        'AVG': np.mean(packet_lengths) if packet_lengths else 0,
        'Std': np.std(packet_lengths) if packet_lengths else 0,
        'Tot size': np.sum(packet_lengths),
        'IAT': other_features['IAT'],
        'Number': other_features['Number'],
        'Magnitue': other_features['Magnitue'],
        'Radius': other_features['Radius'],
        'Covariance': other_features['Covariance'],
        'Variance': other_features['Variance'],
        'Weight': other_features['Weight']
    }
    return pd.DataFrame([features])

def reset_counts():
    global header_lengths, packet_lengths, protocol_counts, flag_counts, service_counts, other_features
    header_lengths.clear()
    packet_lengths.clear()
    for key in protocol_counts:
        protocol_counts[key] = 0
    for key in flag_counts:
        flag_counts[key] = 0
    for key in service_counts:
        service_counts[key] = 0
    for key in other_features:
        other_features[key] = 0

def detect_traffic():
    global latest_prediction, packets_received
    while True:
        time.sleep(10)  # Periksa setiap 10 detik
        if not packets_received:
            # Jika tidak ada paket yang diterima, tentukan status Normal
            latest_prediction = {"prediction": "Normal", "features": []}
            print("Prediction: Normal (No packets received)")  # Optional: Print to console
        else:
            features_df = calculate_features()
        
            # Scale and predict
            features_scaled = scaler.transform(features_df)
            dmatrix_data = xgb.DMatrix(features_scaled)
            prediction = model.predict(dmatrix_data)
        
            # Tentukan status
            status = "Normal" if prediction[0] == 0 else "Attack"
            latest_prediction = {"prediction": status, "features": features_df.to_dict('records')}
        
            print(f"Prediction: {status}")  # Optional: Print to console
        
        # Reset setelah setiap deteksi
        reset_counts()
        packets_received = False  # Reset setelah deteksi

@app.route('/predict', methods=['GET'])
def get_prediction():
    return latest_prediction

def run_sniffer():
    sniff(prn=process_packet, store=False)

if __name__ == '__main__':
    # Start packet sniffer in a separate thread
    sniffer_thread = threading.Thread(target=run_sniffer)
    sniffer_thread.start()
    
    # Start detection thread
    detection_thread = threading.Thread(target=detect_traffic)
    detection_thread.start()
    
    # Start Flask app
    app.run(debug=True, use_reloader=False)
