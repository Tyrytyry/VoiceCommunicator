import socket
import struct
import sounddevice as sd
import numpy as np
import threading
import queue
import time


from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ----- KONFIGURACJA -----
CONTROL_PORT = 5002
AUDIO_PORT   = 5003
SAMPLE_RATE  = 44100
CHANNELS     = 1      # były problemy z 2 kanałami,do sprawdzenia
BLOCK_FRAMES = 256
# ------------------------

PACKET_SIZE = BLOCK_FRAMES * CHANNELS * 2
AUDIO_QUEUE = queue.Queue()

stop_audio = threading.Event()

########################################################################
# Globalne zmienne do przechowywania stanu szyfrowania
aesgcm = None
send_nonce_counter = 0
recv_nonce_counter = 0
########################################################################

def generate_ecdh_key():
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key

def get_public_bytes(private_key):
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    return public_bytes

def load_peer_public_key(pub_bytes):
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub_bytes)

def derive_shared_key(my_private_key, their_public_key):
    shared_secret = my_private_key.exchange(ec.ECDH(), their_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"voip-demo"
    ).derive(shared_secret)
    return derived_key

def network_audio_receiver(sock):
    global recv_nonce_counter
    while not stop_audio.is_set():
        try:
            data, addr = sock.recvfrom(1500)
        except OSError:
            break
        if not data:
            continue

        if len(data) < 12:
            continue
        nonce = data[:12]
        ciphertext = data[12:]

        #  ODSZYFROWANIE
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as e:
            print("Błąd deszyfrowania:", e)
            continue

        AUDIO_QUEUE.put(plaintext)
    print("Zakończono wątek odbioru audio.")

def audio_play_callback(outdata, frames, time_info, status):
    if status:
        print("Status audio (play):", status)

    try:
        data = AUDIO_QUEUE.get_nowait()
    except queue.Empty:
        outdata[:] = 0
        return

    # data to surowe bajty int16
    samples_int16 = np.frombuffer(data, dtype=np.int16)
    samples_float32 = samples_int16.astype(np.float32) / 32767.0

    needed_samples = frames * CHANNELS
    if len(samples_float32) < needed_samples:
        samples_float32 = np.pad(samples_float32,
                                 (0, needed_samples - len(samples_float32)),
                                 mode='constant')
    outdata[:] = samples_float32[:needed_samples].reshape(-1, CHANNELS)

def audio_send_callback(indata, frames, time_info, status):
    global send_nonce_counter
    if status:
        print("Status audio (send):", status)

    samples_int16 = (indata.flatten() * 32767).astype(np.int16)
    plaintext = samples_int16.tobytes()

    # --- SZYFROWANIE ---
    nonce = (send_nonce_counter).to_bytes(8, 'big') + b'\x00\x00\x00\x00'
    send_nonce_counter += 1

    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    packet = nonce + ciphertext

    audio_sock.sendto(packet, (remote_ip_for_send, AUDIO_PORT))

def start_audio_stream(remote_ip):
    print("Uruchamiam dwukierunkowy streaming audio z szyfrowaniem AES-GCM")
    global remote_ip_for_send
    remote_ip_for_send = remote_ip

    rx_thread = threading.Thread(target=network_audio_receiver, args=(audio_sock,), daemon=True)
    rx_thread.start()

    with sd.OutputStream(
            samplerate=SAMPLE_RATE,
            channels=CHANNELS,
            blocksize=BLOCK_FRAMES,
            dtype="float32",
            callback=audio_play_callback
    ), sd.InputStream(
        samplerate=SAMPLE_RATE,
        channels=CHANNELS,
        blocksize=BLOCK_FRAMES,
        dtype="float32",
        callback=audio_send_callback
    ):
        print("Połączenie szyfrowane aktywne (Ctrl+C, by zakończyć).")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("Kończę rozmowę...")
    stop_audio.set()
    audio_sock.close()
    print("Zakończono transmisję audio.")

def do_call():
    remote_ip = input("Podaj IP docelowe: ").strip()

    my_private_key = generate_ecdh_key()
    my_public_bytes = get_public_bytes(my_private_key)
    # ----------------------

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(5.0)
        # Wysyłamy "CALL" + nasz klucz publiczny
        call_payload = b"CALL" + my_public_bytes
        s.sendto(call_payload, (remote_ip, CONTROL_PORT))

        try:
            data, addr = s.recvfrom(2048)
        except socket.timeout:
            print("Brak odpowiedzi - rozłączam.")
            return

        if data.startswith(b"ACCEPT"):
            # Odsyłający dołączył swój public key
            their_public_bytes = data[len(b"ACCEPT"):]
            # Odtwarzamy klucz publiczny i wyprowadzamy wspólny klucz
            their_pub = load_peer_public_key(their_public_bytes)
            shared_key = derive_shared_key(my_private_key, their_pub)

            global aesgcm
            aesgcm = AESGCM(shared_key)

            print("Połączenie zaakceptowane. Ustalono klucz ECDH.")
            start_audio_stream(remote_ip)

        elif data.startswith(b"REJECT"):
            print("Połączenie odrzucone.")
        else:
            print("Otrzymano zły komunikat - rozłączam.")


def do_listen():
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen_sock.bind(("0.0.0.0", CONTROL_PORT))

    print(f"Oczekiwanie na porcie {CONTROL_PORT} ...")
    while True:
        try:
            data, addr = listen_sock.recvfrom(2048)
        except KeyboardInterrupt:
            print("Zakończono oczekiwanie ")
            break

        if data.startswith(b"CALL"):
            caller_ip = addr[0]

            their_public_bytes = data[len(b"CALL"):]
            print(f"\nPrzychodzące połączenie od {caller_ip}")
            pick = input("Odebrać? (y/n): ").strip().lower()
            if pick == 'y':

                my_private_key = generate_ecdh_key()
                my_public_bytes = get_public_bytes(my_private_key)
                response = b"ACCEPT" + my_public_bytes
                listen_sock.sendto(response, addr)


                their_pub = load_peer_public_key(their_public_bytes)
                shared_key = derive_shared_key(my_private_key, their_pub)

                global aesgcm
                aesgcm = AESGCM(shared_key)
                print("Połączenie zaakceptowane, klucz ECDH ustalony.")

                listen_sock.close()
                start_audio_stream(caller_ip)
                break
            else:

                listen_sock.sendto(b"REJECT", addr)
                print("Połączenie odrzucone.")


def main():
    global audio_sock
    audio_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    audio_sock.bind(("0.0.0.0", AUDIO_PORT))

    print("Wybierz opcję:")
    print("1. Zadzwoń")
    print("2. Oczekuj (nasłuchuj)")

    choice = input("Wybór [1/2]: ").strip()
    if choice == '1':
        do_call()
    else:
        do_listen()
    print("Koniec programu.")


if __name__ == "__main__":
    main()
