from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
import eventlet
eventlet.monkey_patch()
import numpy as np
import pandas as pd
import pickle
import xgboost as xgb
from scapy.all import sniff, IP, TCP, UDP, conf
import threading
import time
from collections import deque
import warnings
import logging
warnings.filterwarnings('ignore')

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
socketio = SocketIO(app, async_mode='eventlet', logger=True, engineio_logger=True)

# Load model dan scaler dengan penanganan error
try:
    model = pickle.load(open('xgboost_model.pkl', 'rb'))
    scaler = pickle.load(open('scaler1.pkl', 'rb'))
    logger.info("Model and scaler loaded successfully")
except Exception as e:
    logger.error(f"Error loading model or scaler: {e}")
    model = None
    scaler = None

# Variabel global untuk menyimpan data
traffic_data = {
    "count": 0,
    "packet_features": deque(maxlen=100),
    "predictions": deque(maxlen=100),
    "timestamps": deque(maxlen=100)
}

def extract_features(packet):
    """Ekstrak fitur dari paket jaringan"""
    features = {
        'Header_Length': 0,
        'Protocol Type': 0,
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
    }

    try:
        if IP in packet:
            features['Header_Length'] = len(packet[IP])
            features['Protocol Type'] = packet[IP].proto
            
            if TCP in packet:
                features['TCP'] = 1
                features['syn_flag_number'] = 1 if packet[TCP].flags & 0x02 else 0
                features['ack_flag_number'] = 1 if packet[TCP].flags & 0x10 else 0
                features['fin_flag_number'] = 1 if packet[TCP].flags & 0x01 else 0
                features['rst_flag_number'] = 1 if packet[TCP].flags & 0x04 else 0
                features['psh_flag_number'] = 1 if packet[TCP].flags & 0x08 else 0
                
                # Deteksi protokol aplikasi
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    features['HTTP'] = 1
                elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                    features['HTTPS'] = 1
                elif packet[TCP].dport == 22 or packet[TCP].sport == 22:
                    features['SSH'] = 1
                elif packet[TCP].dport == 25 or packet[TCP].sport == 25:
                    features['SMTP'] = 1
                elif packet[TCP].dport == 23 or packet[TCP].sport == 23:
                    features['Telnet'] = 1
                    
            elif UDP in packet:
                features['UDP'] = 1
                if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                    features['DNS'] = 1
                elif packet[UDP].dport == 67 or packet[UDP].sport == 67:
                    features['DHCP'] = 1
    except Exception as e:
        logger.error(f"Error extracting features: {e}")

    return features

def predict_attack(features):
    """Prediksi serangan menggunakan model XGBoost"""
    try:
        if model is None or scaler is None:
            return 0.0
            
        features_df = pd.DataFrame([features])
        features_scaled = scaler.transform(features_df)
        dmatrix_data = xgb.DMatrix(features_scaled)
        prediction = model.predict(dmatrix_data)
        return prediction[0]
    except Exception as e:
        logger.error(f"Error in prediction: {e}")
        return 0.0

def packet_callback(packet):
    """Callback untuk setiap paket yang ditangkap"""
    try:
        features = extract_features(packet)
        prediction = predict_attack(features)
        
        traffic_data["count"] += 1
        traffic_data["packet_features"].append(features)
        traffic_data["predictions"].append(prediction)
        traffic_data["timestamps"].append(time.time())
        
        # Kirim update ke client
        data = {
            'count': traffic_data["count"],
            'prediction': float(prediction),
            'timestamp': time.time()
        }
        logger.info(f"Sending data to client: {data}")
        socketio.emit('update_traffic', data)
    except Exception as e:
        logger.error(f"Error processing packet: {e}")

def start_sniffing():
    """Mulai sniffing paket"""
    try:
        # Gunakan L3socket untuk Windows
        conf.L3socket = conf.L3socket
        logger.info("Starting packet sniffing...")
        sniff(prn=packet_callback, store=False)
    except Exception as e:
        logger.error(f"Error in sniffing: {e}")

@app.route('/')
def index():
    logger.info("Serving index page")
    return render_template('index.html')

@app.route('/api/stats')
def get_stats():
    """Endpoint untuk mendapatkan statistik terbaru"""
    return jsonify({
        'total_packets': traffic_data["count"],
        'recent_predictions': list(traffic_data["predictions"]),
        'timestamps': list(traffic_data["timestamps"])
    })

@socketio.on('connect')
def handle_connect():
    logger.info('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    logger.info('Client disconnected')

if __name__ == '__main__':
    logger.info("Starting application...")
    # Jalankan sniffing dalam thread terpisah
    eventlet.spawn(start_sniffing)
    socketio.run(app, host='0.0.0.0', port=5000, debug=True) 