from flask import Flask, render_template, request, jsonify
import pickle
import pandas as pd
import xgboost as xgb
import numpy as np

app = Flask(__name__)

# Load model dan scaler
try:
    model = pickle.load(open('model/xgboost_model.pkl', 'rb'))
    scaler = pickle.load(open('model/scaler1.pkl', 'rb'))
except Exception as e:
    print(f"Error loading model: {e}")
    model = None
    scaler = None

def predict_attack(features):
    """Prediksi serangan menggunakan model"""
    try:
        if model is None or scaler is None:
            return None
            
        features_df = pd.DataFrame([features])
        features_scaled = scaler.transform(features_df)
        dmatrix_data = xgb.DMatrix(features_scaled)
        prediction = model.predict(dmatrix_data)
        return prediction[0]
    except Exception as e:
        print(f"Error in prediction: {e}")
        return None

@app.route('/')
def index():
    return render_template('detection_form.html')

@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Get form data
        features = {
            'Header_Length': int(request.form['header_length']),
            'Protocol Type': int(request.form['protocol_type']),
            'Duration': float(request.form['duration']),
            'Rate': float(request.form['rate']),
            'Srate': float(request.form['srate']),
            'Drate': float(request.form['drate']),
            'fin_flag_number': int(request.form['fin_flag']),
            'syn_flag_number': int(request.form['syn_flag']),
            'rst_flag_number': int(request.form['rst_flag']),
            'psh_flag_number': int(request.form['psh_flag']),
            'ack_flag_number': int(request.form['ack_flag']),
            'ece_flag_number': int(request.form['ece_flag']),
            'cwr_flag_number': int(request.form['cwr_flag']),
            'ack_count': int(request.form['ack_count']),
            'syn_count': int(request.form['syn_count']),
            'fin_count': int(request.form['fin_count']),
            'rst_count': int(request.form['rst_count']),
            'HTTP': int(request.form['http']),
            'HTTPS': int(request.form['https']),
            'DNS': int(request.form['dns']),
            'Telnet': int(request.form['telnet']),
            'SMTP': int(request.form['smtp']),
            'SSH': int(request.form['ssh']),
            'IRC': int(request.form['irc']),
            'TCP': int(request.form['tcp']),
            'UDP': int(request.form['udp']),
            'DHCP': int(request.form['dhcp']),
            'ARP': int(request.form['arp']),
            'ICMP': int(request.form['icmp']),
            'IGMP': int(request.form['igmp']),
            'IPv': int(request.form['ipv']),
            'LLC': int(request.form['llc']),
            'Tot sum': float(request.form['tot_sum']),
            'Min': float(request.form['min']),
            'Max': float(request.form['max']),
            'AVG': float(request.form['avg']),
            'Std': float(request.form['std']),
            'Tot size': float(request.form['tot_size']),
            'IAT': float(request.form['iat']),
            'Number': int(request.form['number']),
            'Magnitue': float(request.form['magnitude']),
            'Radius': float(request.form['radius']),
            'Covariance': float(request.form['covariance']),
            'Variance': float(request.form['variance']),
            'Weight': float(request.form['weight'])
        }
        
        # Make prediction
        prediction = predict_attack(features)
        
        if prediction is not None:
            threat_level = prediction
            status = "Attack Detected" if threat_level > 0.7 else "Normal"
            warning = ""
            
            if threat_level > 0.7:
                warning = "WARNING: High probability of network attack!"
            elif threat_level > 0.3:
                warning = "CAUTION: Suspicious network activity detected"
            else:
                warning = "Network traffic appears normal"
            
            return jsonify({
                'success': True,
                'threat_level': float(threat_level),
                'status': status,
                'warning': warning
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Prediction failed'
            })
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

if __name__ == '__main__':
    app.run(debug=True) 