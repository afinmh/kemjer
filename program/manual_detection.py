import pickle
import pandas as pd
import xgboost as xgb
import numpy as np

def load_model():
    """Load model dan scaler"""
    try:
        model = pickle.load(open('model/xgboost_model.pkl', 'rb'))
        scaler = pickle.load(open('model/scaler1.pkl', 'rb'))
        return model, scaler
    except Exception as e:
        print(f"Error loading model: {e}")
        return None, None

def get_user_input():
    """Dapatkan input dari user"""
    print("\n=== Network Traffic Feature Input ===")
    print("Enter 0 for No, 1 for Yes for binary features")
    print("Enter numeric values for other features\n")
    
    features = {
        'Header_Length': int(input("Header Length: ")),
        'Protocol Type': int(input("Protocol Type (1-255): ")),
        'Duration': float(input("Duration (seconds): ")),
        'Rate': float(input("Rate (packets/second): ")),
        'Srate': float(input("Source Rate (packets/second): ")),
        'Drate': float(input("Destination Rate (packets/second): ")),
        'fin_flag_number': int(input("FIN Flag (0/1): ")),
        'syn_flag_number': int(input("SYN Flag (0/1): ")),
        'rst_flag_number': int(input("RST Flag (0/1): ")),
        'psh_flag_number': int(input("PSH Flag (0/1): ")),
        'ack_flag_number': int(input("ACK Flag (0/1): ")),
        'ece_flag_number': int(input("ECE Flag (0/1): ")),
        'cwr_flag_number': int(input("CWR Flag (0/1): ")),
        'ack_count': int(input("ACK Count: ")),
        'syn_count': int(input("SYN Count: ")),
        'fin_count': int(input("FIN Count: ")),
        'rst_count': int(input("RST Count: ")),
        'HTTP': int(input("HTTP Protocol (0/1): ")),
        'HTTPS': int(input("HTTPS Protocol (0/1): ")),
        'DNS': int(input("DNS Protocol (0/1): ")),
        'Telnet': int(input("Telnet Protocol (0/1): ")),
        'SMTP': int(input("SMTP Protocol (0/1): ")),
        'SSH': int(input("SSH Protocol (0/1): ")),
        'IRC': int(input("IRC Protocol (0/1): ")),
        'TCP': int(input("TCP Protocol (0/1): ")),
        'UDP': int(input("UDP Protocol (0/1): ")),
        'DHCP': int(input("DHCP Protocol (0/1): ")),
        'ARP': int(input("ARP Protocol (0/1): ")),
        'ICMP': int(input("ICMP Protocol (0/1): ")),
        'IGMP': int(input("IGMP Protocol (0/1): ")),
        'IPv': int(input("IPv Protocol (0/1): ")),
        'LLC': int(input("LLC Protocol (0/1): ")),
        'Tot sum': float(input("Total Sum: ")),
        'Min': float(input("Minimum Value: ")),
        'Max': float(input("Maximum Value: ")),
        'AVG': float(input("Average Value: ")),
        'Std': float(input("Standard Deviation: ")),
        'Tot size': float(input("Total Size: ")),
        'IAT': float(input("Inter-Arrival Time: ")),
        'Number': int(input("Packet Number: ")),
        'Magnitue': float(input("Magnitude: ")),
        'Radius': float(input("Radius: ")),
        'Covariance': float(input("Covariance: ")),
        'Variance': float(input("Variance: ")),
        'Weight': float(input("Weight: "))
    }
    
    return features

def predict_attack(model, scaler, features):
    """Prediksi serangan menggunakan model"""
    try:
        features_df = pd.DataFrame([features])
        features_scaled = scaler.transform(features_df)
        dmatrix_data = xgb.DMatrix(features_scaled)
        prediction = model.predict(dmatrix_data)
        return prediction[0]
    except Exception as e:
        print(f"Error in prediction: {e}")
        return None

def main():
    # Load model
    model, scaler = load_model()
    if model is None or scaler is None:
        print("Error: Could not load model. Exiting...")
        return

    while True:
        print("\n=== Network Attack Detection System ===")
        print("1. Enter new traffic features")
        print("2. Exit")
        
        choice = input("\nEnter your choice (1-2): ")
        
        if choice == '1':
            # Get user input
            features = get_user_input()
            
            # Make prediction
            prediction = predict_attack(model, scaler, features)
            
            if prediction is not None:
                # Interpret prediction
                threat_level = prediction
                status = "Attack Detected" if threat_level > 0.7 else "Normal"
                
                print("\n=== Detection Results ===")
                print(f"Threat Level: {threat_level:.4f}")
                print(f"Status: {status}")
                
                if threat_level > 0.7:
                    print("WARNING: High probability of network attack!")
                elif threat_level > 0.3:
                    print("CAUTION: Suspicious network activity detected")
                else:
                    print("Network traffic appears normal")
            
        elif choice == '2':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main() 