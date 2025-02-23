from scapy.all import send, IP, UDP
import time

TARGET_IP = "127.0.0.1"  # Ubah jika server ada di jaringan lain
TARGET_PORT = 5000  # Port server Flask

def send_dummy_packets():
    while True:
        packet = IP(dst=TARGET_IP) / UDP(dport=TARGET_PORT)
        send(packet, verbose=False)
        print(f"Sent packet to {TARGET_IP}:{TARGET_PORT}")
        time.sleep(1)  # Kirim setiap 1 detik

if __name__ == "__main__":
    send_dummy_packets()
