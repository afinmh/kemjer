import pygame
import asyncio
import websockets
import json
import ssl

# WebSocket server URL
WS_URL = "wss://dusty-steel-atlasaurus.glitch.me"  # Ganti dengan URL server Anda

# Inisialisasi pygame dan joystick
pygame.init()
pygame.joystick.init()

# Pastikan ada joystick yang terdeteksi
if pygame.joystick.get_count() == 0:
    print("Tidak ada joystick yang terdeteksi!")
    exit()

joystick = pygame.joystick.Joystick(0)
joystick.init()

async def send_message():
    # Membuka koneksi WebSocket
    ssl_context = ssl._create_unverified_context()  # Bypass SSL
    async with websockets.connect(WS_URL, ssl=ssl_context) as ws:
        print("Terhubung ke WebSocket!")

        # Mengirim pesan untuk mendaftar sebagai sender
        sender_message = {"type": "sender"}
        await ws.send(json.dumps(sender_message))
        print("Sender terdaftar!")

        # Variabel untuk melacak status tombol joystick
        direction = ""
        steer = "netral"
        gas_status = False
        button_pressed = False
        music = 3
        strobo = "OFF"
        pompa = "OFF"

        while True:
            pygame.event.pump()  # Memperbarui status input joystick

            # Arahkan motor maju/mundur
            if joystick.get_button(5):  # R1
                if direction != "maju":
                    direction = "maju"
                    await ws.send(json.dumps({"topic": "direction", "value": "maju"}))
                    print("Motor maju")
            elif joystick.get_button(4):  # L1
                if direction != "mundur":
                    direction = "mundur"
                    await ws.send(json.dumps({"topic": "direction", "value": "mundur"}))
                    print("Motor mundur")

            # Mengatur steer kiri/kanan/netral berdasarkan sumbu joystick
            steer_axis = joystick.get_axis(0)  # Joystick Bagian Kiri (Kiri Kanan)
            if steer_axis > 0.5:  # Joystick ke kanan
                if steer != "kanan":
                    steer = "kanan"
                    await ws.send(json.dumps({"topic": "steer", "value": "kanan"}))
                    print("Belok Kanan")
            elif steer_axis < -0.5:  # Joystick ke kiri
                if steer != "kiri":
                    steer = "kiri"
                    await ws.send(json.dumps({"topic": "steer", "value": "kiri"}))
                    print("Belok Kiri")
            else:  # Joystick di tengah atau netral
                if steer != "netral":
                    steer = "netral"
                    await ws.send(json.dumps({"topic": "steer", "value": "netral"}))
                    print("Netral")

            # Mengatur gas (atas/bawah)
            pedal_axis = joystick.get_axis(1)  # Joystick bagian Kiri (Atas Bawah)
            if pedal_axis < -0.5:  # Joystick ke atas
                if not gas_status:
                    gas_status = True
                    await ws.send(json.dumps({"topic": "gas", "value": "start"}))
                    print("Gas dinyalakan!")
            else:
                if gas_status:
                    gas_status = False
                    await ws.send(json.dumps({"topic": "gas", "value": "stop"}))
                    print("Gas dimatikan!")

            # Kontrol untuk tombol
            if joystick.get_button(1):  # Lingkaran (2)
                if not button_pressed:
                    await ws.send(json.dumps({"topic": "sound", "value": str(music)}))
                    print(f"Telolet {music}")
                button_pressed = True

            if joystick.get_button(7):  # L2 Next lagu
                if not button_pressed:
                    if music < 7:
                        music += 1
                        print(f"Music {music}")
                    button_pressed = True

            if joystick.get_button(6):  # R2 Prev lagu
                if not button_pressed:
                    if music > 3:
                        music -= 1
                        print(f"Music {music}")
                    button_pressed = True

            if joystick.get_button(3):  # Kotak
                if not button_pressed:
                    await ws.send(json.dumps({"topic": "sound", "value": "Stop"}))
                    print("Stop")
                button_pressed = True

            if joystick.get_button(0):  # Segitiga
                if not button_pressed:
                    if strobo == "OFF":
                        await ws.send(json.dumps({"topic": "strobo", "value": "ON"}))
                        strobo = "ON"
                        print("Strobo ON")
                    elif strobo == "ON":
                        await ws.send(json.dumps({"topic": "strobo", "value": "OFF"}))
                        strobo = "OFF"
                        print("Strobo OFF")
                button_pressed = True

            if joystick.get_button(2):  # Silang
                if not button_pressed:
                    if pompa == "OFF":
                        await ws.send(json.dumps({"topic": "pompa", "value": "ON"}))
                        print("Pompa ON")
                        pompa = "ON"
                    elif pompa == "ON":
                        await ws.send(json.dumps({"topic": "pompa", "value": "OFF"}))
                        print("Pompa OFF")
                        pompa = "OFF"
                button_pressed = True

            # Reset tombol ketika tidak ada tombol yang ditekan
            if not joystick.get_button(6) and not joystick.get_button(7) and not joystick.get_button(1) and not joystick.get_button(3) and not joystick.get_button(0) and not joystick.get_button(2):
                button_pressed = False

            await asyncio.sleep(0) 

# Menjalankan program
asyncio.get_event_loop().run_until_complete(send_message())