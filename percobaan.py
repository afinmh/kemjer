from scapy.all import sniff, IP, TCP, UDP, ICMP
import pandas as pd
import numpy as np
import pickle
import xgboost as xgb

model = pickle.load(open('xgboost_model.pkl', 'rb'))
scaler = pickle.load(open('scaler1.pkl', 'rb'))

target_ip = "127.0.0.1"
target_port = 5000

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

# Variabel untuk melacak apakah ada paket yang diterima
packets_received = False

# Fungsi untuk menentukan protocol type
def get_protocol_type(packet):
    if TCP in packet:
        return 6   # TCP
    elif UDP in packet:
        return 17  # UDP
    elif ICMP in packet:
        return 1   # ICMP
    else:
        return 0   # Unknown

# Fungsi untuk menangkap dan menganalisis paket
def packet_callback(packet):
    global dummy_data, packets_received
    
    if IP in packet:  # Pastikan paket memiliki layer IP
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if TCP in packet or UDP in packet:  # Pastikan ada protokol transport
            sport = packet[TCP].sport if TCP in packet else packet[UDP].sport
            dport = packet[TCP].dport if TCP in packet else packet[UDP].dport
            
            # Filter berdasarkan IP dan port
            if src_ip == target_ip or dst_ip == target_ip:
                if sport == target_port or dport == target_port:
                    # Menghitung fitur tambahan untuk deteksi
                    flags = packet[TCP].flags if TCP in packet else 0
                    fin_flag = 1 if "F" in flags else 0
                    syn_flag = 1 if "S" in flags else 0
                    rst_flag = 1 if "R" in flags else 0
                    ack_flag = 1 if "A" in flags else 0
                    psh_flag = 1 if "P" in flags else 0
                    ece_flag = 1 if "E" in flags else 0
                    cwr_flag = 1 if "C" in flags else 0
                    
                    # Ambil informasi lebih lanjut dari sniffed packet
                    duration = packet.time
                    rate = len(packet)
                    tot_size = len(packet)
                    iat = packet.time  # Inter-arrival time
                    number = 1  # Jumlah paket

                    # Cek apakah ada TCP/UDP/ICMP yang terkait
                    tcp_flag = int(TCP in packet)
                    udp_flag = int(UDP in packet)
                    icmp_flag = int(ICMP in packet)

                    # Update nilai dalam DataFrame dengan fitur-fitur yang relevan
                    new_data = {
                        'Header_Length': len(packet),
                        'Protocol Type': get_protocol_type(packet),
                        'Duration': duration,
                        'Rate': rate,  # Ukuran paket
                        'Srate': sport,
                        'Drate': dport,
                        'fin_flag_number': fin_flag,
                        'syn_flag_number': syn_flag,
                        'rst_flag_number': rst_flag,
                        'psh_flag_number': psh_flag,
                        'ack_flag_number': ack_flag,
                        'ece_flag_number': ece_flag,
                        'cwr_flag_number': cwr_flag,
                        'ack_count': 0,  # Jika tidak ada data, bisa diupdate sesuai kebutuhan
                        'syn_count': 0,  # Jika tidak ada data, bisa diupdate sesuai kebutuhan
                        'fin_count': 0,  # Jika tidak ada data, bisa diupdate sesuai kebutuhan
                        'rst_count': 0,  # Jika tidak ada data, bisa diupdate sesuai kebutuhan
                        'HTTP': 0,  # Ambil dari trafik HTTP jika perlu
                        'HTTPS': 0,  # Ambil dari trafik HTTPS jika perlu
                        'DNS': 0,  # Ambil dari trafik DNS jika perlu
                        'Telnet': 0,  # Ambil dari trafik Telnet jika perlu
                        'SMTP': 0,  # Ambil dari trafik SMTP jika perlu
                        'SSH': 0,  # Ambil dari trafik SSH jika perlu
                        'IRC': 0,  # Ambil dari trafik IRC jika perlu
                        'TCP': tcp_flag,
                        'UDP': udp_flag,
                        'DHCP': 0,  # Ambil dari trafik DHCP jika perlu
                        'ARP': 0,  # Ambil dari trafik ARP jika perlu
                        'ICMP': icmp_flag,
                        'IGMP': 0,  # Ambil dari trafik IGMP jika perlu
                        'IPv': 0,  # Ambil dari trafik IPv jika perlu
                        'LLC': 0,  # Ambil dari trafik LLC jika perlu
                        'Tot sum': 0,  # Anda bisa mengupdate sesuai data yang diinginkan
                        'Min': 0,  # Anda bisa mengupdate sesuai data yang diinginkan
                        'Max': 0,  # Anda bisa mengupdate sesuai data yang diinginkan
                        'AVG': 0,  # Anda bisa mengupdate sesuai data yang diinginkan
                        'Std': 0,  # Anda bisa mengupdate sesuai data yang diinginkan
                        'Tot size': tot_size,
                        'IAT': iat,  # Inter-arrival time
                        'Number': number,
                        'Magnitue': 0,  # Mengambil nilai sesuai perhitungan Anda
                        'Radius': 0,  # Mengambil nilai sesuai perhitungan Anda
                        'Covariance': 0,  # Mengambil nilai sesuai perhitungan Anda
                        'Variance': 0,  # Mengambil nilai sesuai perhitungan Anda
                        'Weight': 0  # Mengambil nilai sesuai perhitungan Anda
                    }
                    
                    # Membuat DataFrame baru dan menambahkannya ke dummy_data
                    df_new = pd.DataFrame([new_data])
                    dummy_data = pd.concat([dummy_data, df_new], ignore_index=True)
                    
                    # Menampilkan data terbaru
                    print(dummy_data.tail(1))  # Tampilkan data terbaru
                    print(dummy_data.iloc[1]) 

                    # Lakukan scaling dan prediksi
                    dummy_scaled = scaler.transform(dummy_data)
                    dmatrix_data = xgb.DMatrix(dummy_scaled)

                    # Prediksi menggunakan model XGBoost
                    prediction = model.predict(dmatrix_data)

                    status = "Normal" if prediction[0] == 0 else "Attack"
                    print(f"Prediction: {status} {prediction}")
                    
                    packets_received = True


# Mulai sniffing
sniff(prn=packet_callback, iface="\\Device\\NPF_Loopback", timeout=10, count=10, store=False)

# Jika tidak ada paket yang diterima, tampilkan status "Normal"
if not packets_received:
    print("Prediction: Normal (No packets received)")
