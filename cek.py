from scapy.all import sniff, IP, TCP, UDP, ICMP
import pandas as pd

# IP localhost
target_ip = "127.0.0.1"
target_port = 5000  # Bisa diganti dengan port lain

# Inisialisasi DataFrame
dummy_data = pd.DataFrame(columns=[
    'Header_Length', 'Protocol Type', 'Duration', 'Rate', 'Srate', 'Drate', 
    'TCP', 'UDP', 'ICMP', 'Tot size', 'IAT', 'Number'
])

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
    global dummy_data  # Mendeklarasikan dummy_data sebagai global
    
    if IP in packet:  # Pastikan paket memiliki layer IP
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if TCP in packet or UDP in packet:  # Pastikan ada protokol transport
            sport = packet[TCP].sport if TCP in packet else packet[UDP].sport
            dport = packet[TCP].dport if TCP in packet else packet[UDP].dport

            # Filter berdasarkan IP dan port
            if src_ip == target_ip or dst_ip == target_ip:
                if sport == target_port or dport == target_port:
                    # Update nilai dalam DataFrame
                    new_data = {
                        'Header_Length': len(packet),
                        'Protocol Type': get_protocol_type(packet),  # Tidak tetap 1
                        'Duration': packet.time,
                        'Rate': len(packet),  # Ukuran paket
                        'Srate': sport,
                        'Drate': dport,
                        'TCP': int(TCP in packet),
                        'UDP': int(UDP in packet),
                        'ICMP': int(ICMP in packet),
                        'Tot size': len(packet),
                        'IAT': packet.time,  # Inter-arrival time
                        'Number': 1  # Jumlah paket
                    }
                    
                    df_new = pd.DataFrame([new_data])
                    dummy_data = pd.concat([dummy_data, df_new], ignore_index=True)
                    print(dummy_data.tail(1))  # Tampilkan data terbaru

# Mulai sniffing tanpa filter interface
sniff(prn=packet_callback, iface="\\Device\\NPF_Loopback", timeout=10, count=10, store=False)
