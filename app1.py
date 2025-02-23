from flask import Flask, render_template
from flask_socketio import SocketIO
from scapy.all import sniff
import eventlet

app = Flask(__name__)
socketio = SocketIO(app, async_mode='eventlet')

# Variabel global untuk menyimpan jumlah paket
traffic_data = {"count": 0}

def packet_callback(packet):
    """Fungsi callback untuk menangkap paket."""
    traffic_data["count"] += 1
    socketio.emit('update_traffic', {'count': traffic_data["count"]})

def start_sniffing():
    """Menjalankan sniffing dalam thread terpisah."""
    sniff(prn=packet_callback, store=False)

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    # Jalankan sniffing dalam thread eventlet
    eventlet.spawn(start_sniffing)
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
