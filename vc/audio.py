from .crypto import derive_shared_key
import os, hashlib
import threading
import queue
import socket
import numpy as np
import sounddevice as sd
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
aesgcm = None

call_active = False             # czy trwa połączenie audio
remote_call_ip = None           # IP rozmówcy (potrzebne w end_call)
remote_ip_for_send = None       # używany w audio_send_callback



CONTROL_PORT = 5002
AUDIO_PORT = 5003
SAMPLE_RATE = 44100
CHANNELS = 1 #  poprawić to
BLOCK_FRAMES = 256
PACKET_SIZE = BLOCK_FRAMES * CHANNELS * 2

stop_audio = threading.Event()
AUDIO_QUEUE = queue.Queue()

call_lock = threading.Lock()
on_call_started = None
on_call_ended   = None



def is_call_active() -> bool:
    with call_lock:
        return call_active


def create_audio_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", AUDIO_PORT))
    return s

audio_sock = create_audio_socket()


def network_audio_receiver(sock):
    global aesgcm
    sock.settimeout(1.0)

    while True:
        if stop_audio.is_set():
            break
        try:
            data, _ = sock.recvfrom(1500)
        except socket.timeout:
            continue
        except OSError as e:
            break

        if len(data) < 12:
            continue
        nonce, ciphertext = data[:12], data[12:]
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            AUDIO_QUEUE.put(plaintext)
        except Exception as e:
            continue

def audio_play_callback(outdata, frames, time_info, status):
    if status:
        print("Audio (play) status:", status)
    try:
        data = AUDIO_QUEUE.get_nowait()
    except queue.Empty:
        outdata[:] = np.zeros((frames, CHANNELS))
        return
    samples = np.frombuffer(data, dtype=np.int16).astype(np.float32) / 32767.0
    outdata[:len(samples) // CHANNELS] = samples.reshape(-1, CHANNELS)

def audio_send_callback(indata, frames, time_info, status):
    global send_nonce_counter, nonce_prefix
    if status:
        print("Audio (send) status:", status)
    samples = (indata.flatten() * 32767).astype(np.int16)
    nonce = nonce_prefix + send_nonce_counter.to_bytes(8, 'big')
    send_nonce_counter += 2  # 0,2,4… albo 1,3,5…
    packet = nonce + aesgcm.encrypt(nonce, samples.tobytes(), None)
    audio_sock.sendto(packet, (remote_ip_for_send, AUDIO_PORT))

def start_audio_stream(remote_ip: str, initiator_role: bool):
    global remote_call_ip, audio_sock, nonce_prefix, send_nonce_counter
    global call_active, remote_ip_for_send, stop_audio

    with call_lock:
        if call_active:
            print("[INFO] Już trwa połączenie – start_audio_stream zignorowany")
            return
        call_active = True

    remote_call_ip = remote_ip
    remote_ip_for_send = remote_ip
    stop_audio.clear()

    nonce_prefix = b"\x00\x00\x00\x00" if initiator_role else b"\x01\x00\x00\x00"
    send_nonce_counter = 0

    if on_call_started:
        try:
            on_call_started(remote_ip)
        except Exception:
            pass

    rx_thread = threading.Thread(
        target=network_audio_receiver, args=(audio_sock,), daemon=True
    )
    rx_thread.start()


    try:
        with sd.OutputStream(
            samplerate=SAMPLE_RATE,
            channels=CHANNELS,
            blocksize=BLOCK_FRAMES,
            dtype="float32",
            callback=audio_play_callback,
        ), sd.InputStream(
            samplerate=SAMPLE_RATE,
            channels=CHANNELS,
            blocksize=BLOCK_FRAMES,
            dtype="float32",
            callback=audio_send_callback,
        ):

            while not stop_audio.is_set():
                time.sleep(0.1)

    except Exception as e:
        print("[ERROR] Audio stream:", e)

    stop_audio.set()

    if on_call_ended:
        try:
            on_call_ended(remote_ip)
        except Exception:
            pass

    with call_lock:
        call_active = False
        remote_call_ip = None
        remote_ip_for_send = None

def end_call(send_signal=True):
    global call_active, remote_call_ip, stop_audio
    with call_lock:
        if not call_active:
            return
        call_active = False

    stop_audio.set()

    if send_signal and remote_call_ip:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(b"END", (remote_call_ip, CONTROL_PORT))
        except Exception:
            pass

    if on_call_ended:
        try:
            on_call_ended(remote_call_ip)
        except Exception:
            pass

    remote_call_ip = None