import socket
import hashlib
import threading
import time
import os
import queue
import numpy as np
import sounddevice as sd

from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from datetime import datetime
from pathlib import Path


CONTROL_PORT = 5002
AUDIO_PORT = 5003
SAMPLE_RATE = 44100
CHANNELS = 1 #  poprawić to
BLOCK_FRAMES = 256
PACKET_SIZE = BLOCK_FRAMES * CHANNELS * 2

RSA_PRIVATE_FILE = "rsa_key.pem"
CONTACTS_FILE = "contacts.txt"

AUDIO_QUEUE = queue.Queue()
stop_audio = threading.Event()
aesgcm = None
send_nonce_counter = 0
nonce_prefix = b''
remote_ip_for_send = None
listener_stop_event = threading.Event()
listener_sock = None
on_request_contact_name = None
TEXT_PORT   = CONTROL_PORT
MSG_PREFIX  = b"MSG"

call_active = False
call_lock = threading.Lock()
remote_call_ip = None

on_call_started = None
on_call_ended   = None

CHAT_HELLO = b"CHELLO"
CHAT_ACK   = b"CACK"
TEXT_MSG_PREFIX   = b"MS2"
CHAT_PREFIX_CALLER = b"\x02\x00\x00\x00"
CHAT_PREFIX_CALLEE = b"\x03\x00\x00\x00"

CHAT_KEYS         = {}
CHAT_NONCE_PREFIX = {}
CHAT_SEND_COUNTER = {}
PENDING_CHAT = {}


on_incoming_call_request = None
on_call_started          = None
on_call_ended            = None
on_new_fpr               = None
on_contact_saved         = None
on_busy                  = None
on_text_message          = None



def _finalize_chat_key(ip: str, my_priv, their_pub_bytes: bytes, caller: bool):
    chat_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"vc-chat-v1"
    ).derive(my_priv.exchange(ec.ECDH(), load_peer_public_key(their_pub_bytes)))

    CHAT_KEYS[ip] = chat_key
    CHAT_NONCE_PREFIX[ip] = CHAT_PREFIX_CALLER if caller else CHAT_PREFIX_CALLEE
    CHAT_SEND_COUNTER[ip] = 0 if caller else 1
    print(f"[CHAT] handshake OK z {ip}")


def _send_chat_ack(ip: str, their_pub_bytes: bytes):
    """Wysyłamy CACK i kończymy handshake."""
    priv = generate_ecdh_key()
    pub  = get_public_bytes(priv)

    rsa_priv = load_or_generate_rsa_keys()
    signature = sign_data_rsa(rsa_priv, pub)

    payload = CHAT_ACK + pub + signature
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(payload, (ip, CONTROL_PORT))

    _finalize_chat_key(ip, priv, their_pub_bytes, caller=False)


def send_chat_hello(remote_ip: str):
    priv = generate_ecdh_key()
    pub  = get_public_bytes(priv)

    rsa_priv = load_or_generate_rsa_keys()
    signature = sign_data_rsa(rsa_priv, pub)

    payload = CHAT_HELLO + pub + signature + get_rsa_public_bytes(rsa_priv)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(payload, (remote_ip, CONTROL_PORT))

    PENDING_CHAT[remote_ip] = priv 
    CHAT_NONCE_PREFIX[remote_ip] = CHAT_PREFIX_CALLER
    CHAT_SEND_COUNTER[remote_ip] = 0

def _msg_file(ip: str) -> Path:
    return Path(f"messages_{ip}.txt")

def _append_history(ip: str, who: str, ts: str, text: str):
    with _msg_file(ip).open("a", encoding="utf-8") as f:
        f.write(f"{who}|{ts}|{text}\n")


def send_text_message(remote_ip: str, text: str):
    key = CHAT_KEYS.get(remote_ip)
    if key is None:
        print("[CHAT] Brak klucza – nawiąż rozmowę audio, aby uzyskać key.")
        return False

    prefix  = CHAT_NONCE_PREFIX[remote_ip]
    counter = CHAT_SEND_COUNTER[remote_ip]
    nonce   = prefix + counter.to_bytes(8, "big")
    CHAT_SEND_COUNTER[remote_ip] += 2

    ciphertext = AESGCM(key).encrypt(nonce, text.encode("utf-8"), None)
    packet = TEXT_MSG_PREFIX + nonce + ciphertext

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(packet, (remote_ip, CONTROL_PORT))

    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    _append_history(remote_ip, "ME", ts, text)
    _safe(on_text_message, remote_ip, ts, text, False)
    return True

def _create_audio_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", AUDIO_PORT))
    return s

audio_sock = _create_audio_socket()


def send_busy(ip: str):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(b"BUSY", (ip, CONTROL_PORT))

def _safe(cb, *a):
    if cb:
        try:
            cb(*a)
        except Exception:
            pass


def is_call_active() -> bool:
    with call_lock:
        return call_active

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

def load_or_generate_rsa_keys():
    if os.path.exists(RSA_PRIVATE_FILE):
        with open(RSA_PRIVATE_FILE, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(RSA_PRIVATE_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))
    return private_key

def get_rsa_public_bytes(private_key):
    return private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

def sign_data_rsa(private_key, data: bytes) -> bytes:
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

def verify_rsa_signature(public_key_pem: bytes, signature: bytes, data: bytes):
    pub = serialization.load_pem_public_key(public_key_pem)
    pub.verify(signature, data,
               padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
               hashes.SHA256()
               )

def generate_ecdh_key():
    return ec.generate_private_key(ec.SECP256R1())

def get_public_bytes(private_key):
    return private_key.public_key().public_bytes(
        serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

def load_peer_public_key(pub_bytes):
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub_bytes)

def derive_shared_key(my_private_key, their_public_key):
    shared_secret = my_private_key.exchange(ec.ECDH(), their_public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"voip-demo"
    ).derive(shared_secret)

def save_contact(name: str, ip: str, rsa_pub_bytes: bytes):
    fingerprint = hashlib.sha256(rsa_pub_bytes).hexdigest()[:32]
    rsa_str = rsa_pub_bytes.decode('utf-8').replace('\n', '\\n')

    contacts = load_contacts(raw=True)
    with open(CONTACTS_FILE, "w") as f:
        replaced = False
        for parts in contacts:
            if parts[1] == ip:
                f.write(f"{name}|{ip}|{rsa_str}|{fingerprint}\n")
                replaced = True
            else:
                f.write("|".join(parts) + "\n")
        if not replaced:
            f.write(f"{name}|{ip}|{rsa_str}|{fingerprint}\n")
    print(f"[INFO] Zapisano / zaktualizowano kontakt: {name} ({ip})")

def load_contacts(raw: bool = False):
    if not os.path.exists(CONTACTS_FILE):
        return []

    entries = []
    with open(CONTACTS_FILE, "r") as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) < 3:
                continue
            if raw:
                entries.append(parts)
            else:
                name, ip, rsa_str = parts[:3]
                rsa_pem = rsa_str.replace('\\n', '\n').encode("utf-8")
                entries.append((name, ip, rsa_pem))
    return entries

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

def stop_listener():
    listener_stop_event.set()
    if listener_sock:
        try:
            listener_sock.close()
        except:
            pass

def send_okfpr(ip):
    rsa_private = load_or_generate_rsa_keys()
    rsa_pub = get_rsa_public_bytes(rsa_private)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(b"OKFPR" + rsa_pub, (ip, CONTROL_PORT))

def send_myrsa(ip):
    rsa_private = load_or_generate_rsa_keys()
    rsa_pub = get_rsa_public_bytes(rsa_private)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(b"MYRSA" + rsa_pub, (ip, CONTROL_PORT))

def start_listener():
    listener_stop_event.clear()

    def listen():
        global listener_sock
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", CONTROL_PORT))
        listener_sock = sock

        while not listener_stop_event.is_set():
            try:
                sock.settimeout(1.0)
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except Exception:
                break

            ip, port = addr
            try:
                if data.startswith(b"CALL"):
                    ecdh_pub = data[4:69]
                    signature = data[69:325]
                    rsa_bytes = data[325:]

                    if is_call_active():
                        send_busy(ip)
                        continue

                    def _accept():
                        accept_incoming_call(ip, port, ecdh_pub)

                    def _reject():
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s2:
                            s2.sendto(b"REJECT", (ip, CONTROL_PORT))

                    stored_rsa = next((rsa for _, saved_ip, rsa in load_contacts() if saved_ip == ip), None)

                    if stored_rsa is None:
                        fpr_short = hashlib.sha256(rsa_bytes).hexdigest()[:32]
                        _safe(on_incoming_call_request, ip, fpr_short, _accept, _reject)
                        continue

                    try:
                        verify_rsa_signature(stored_rsa, signature, ecdh_pub)
                    except Exception:
                        _reject()
                        continue

                    if stored_rsa != rsa_bytes:
                        _safe(on_incoming_call_request, ip, None, None, _reject)
                        continue

                    _safe(on_incoming_call_request, ip, None, _accept, _reject)
                    continue

                elif data.startswith(b"FPR"):
                    fingerprint = data[3:].decode()

                    def _accept():
                        send_okfpr(ip)                     # odsyłamy nasz RSA
                    _safe(on_new_fpr, ip, fingerprint, _accept)

                elif data.startswith(b"OKFPR"):
                    rsa_data = data[len(b"OKFPR"):]
                    def _save(name):
                        save_contact(name, ip, rsa_data)
                        send_myrsa(ip)  # wyślemy nasz RSA
                        _safe(on_contact_saved, name, ip)
                    _safe(on_request_contact_name, ip, rsa_data, _save)

                elif data.startswith(b"MYRSA"):
                    rsa_data = data[len(b"MYRSA"):]
                    def _save(name):
                        save_contact(name, ip, rsa_data)
                        _safe(on_contact_saved, name, ip)
                    _safe(on_request_contact_name, ip, rsa_data, _save)

                # odbiorca kończy rozmowę
                elif data.startswith(b"END"):
                    end_call(send_signal=False)

                # odbiorca zajęty
                elif data.startswith(b"BUSY"):
                    _safe(on_busy, ip)

                elif data.startswith(MSG_PREFIX):
                    try:
                        payload = data[len(MSG_PREFIX):].decode("utf-8", errors="ignore")
                        ts, text = payload.split("|", 1)
                    except ValueError:
                        continue 

                    _append_history(ip, "THEM", ts, text)
                    _safe(on_text_message, ip, ts, text, True)  # True = incoming

                elif data.startswith(CHAT_HELLO):
                    their_pub = data[6:71]
                    their_sig = data[71:327]
                    their_rsa = data[327:]

                    stored_rsa = next((rsa for _, saved_ip, rsa in load_contacts() if saved_ip == ip), None)
                    if not stored_rsa or stored_rsa != their_rsa:
                        continue
                    try:
                        verify_rsa_signature(stored_rsa, their_sig, their_pub)
                    except Exception:
                        continue

                    _send_chat_ack(ip, their_pub)

                elif data.startswith(CHAT_ACK):
                    their_pub = data[4:69]
                    their_sig = data[69:325]

                    my_priv = PENDING_CHAT.pop(ip, None)
                    if my_priv is None:
                        continue
                    stored_rsa = next((rsa for _, saved_ip, rsa in load_contacts() if saved_ip == ip), None)
                    if not stored_rsa:
                        continue
                    try:
                        verify_rsa_signature(stored_rsa, their_sig, their_pub)
                    except Exception:
                        continue

                    _finalize_chat_key(ip, my_priv, their_pub, caller=True)

                elif data.startswith(TEXT_MSG_PREFIX):
                    nonce = data[3:15]
                    ciphertext = data[15:]
                    key = CHAT_KEYS.get(ip)
                    if key is None:
                        continue
                    try:
                        text = AESGCM(key).decrypt(nonce, ciphertext, None).decode("utf-8", "ignore")
                    except Exception:
                        print("[CHAT] Błędna autentyczność lub nonce.")
                        continue
                    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
                    _append_history(ip, "THEM", ts, text)
                    _safe(on_text_message, ip, ts, text, True)

            except Exception as e:
                print("[listener] błąd przy obsłudze pakietu:", e)

        sock.close()
        listener_sock = None

    threading.Thread(target=listen, daemon=True).start()

def accept_incoming_call(ip: str, port, ecdh_pub: bytes):

    my_priv = generate_ecdh_key()
    my_pub = get_public_bytes(my_priv)

    rsa_private = load_or_generate_rsa_keys()
    signature = sign_data_rsa(rsa_private, my_pub)

    shared_key = derive_shared_key(my_priv, load_peer_public_key(ecdh_pub))
    global aesgcm
    aesgcm = AESGCM(shared_key)
    chat_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"vc-chat-v1"
    ).derive(shared_key)
    CHAT_KEYS[ip] = chat_key
    CHAT_NONCE_PREFIX[ip] = CHAT_PREFIX_CALLEE
    CHAT_SEND_COUNTER[ip] = 1
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(b"ACCEPT" + my_pub + signature, (ip, port))

    threading.Thread(
        target=start_audio_stream,
        args=(ip, False),
        daemon=True
    ).start()

def initiate_call(remote_ip):
    if is_call_active():
        print("[INFO] Już rozmawiasz – nie można nawiązać drugiego połączenia.")
        return

    global aesgcm
    contacts = load_contacts()
    peer_rsa = next((rsa for _, ip, rsa in load_contacts() if ip == remote_ip), None)
    if peer_rsa is None:
        print("[INFO] Nie masz klucza tego kontaktu. Najpierw wymień fingerprinty.")
        return
    for name, ip, rsa in contacts:
        if ip == remote_ip:
            peer_rsa = rsa
            break
    if not peer_rsa:
        print("Brak klucza RSA dla kontaktu")
        return
    my_priv = generate_ecdh_key()
    my_pub = get_public_bytes(my_priv)
    rsa_private = load_or_generate_rsa_keys()
    signature = sign_data_rsa(rsa_private, my_pub)
    payload = b"CALL" + my_pub + signature + get_rsa_public_bytes(rsa_private)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(10.0)
        s.sendto(payload, (remote_ip, CONTROL_PORT))
        print(payload, "oraz", CONTROL_PORT)
        try:
            print("Nadawca słucha na porcie:", s.getsockname())
            for i in range(5):
                print("czekam na pakiet...")
            data, addr = s.recvfrom(2048)
            if data.startswith(b"ACCEPT"):
                if len(data) < 6 + 65 + 256:
                    print("Odebrano nieprawidłowy pakiet ACCEPT.")
                    return
                their_pub = data[6:71]
                their_sig = data[71:327]

                try:
                    verify_rsa_signature(peer_rsa, their_sig, their_pub)
                except Exception as e:
                    print("[ERROR] Niepoprawny podpis w pakiecie ACCEPT:", e)
                    return

                shared = derive_shared_key(my_priv, load_peer_public_key(their_pub))
                aesgcm = AESGCM(shared)
                chat_key = HKDF(
                    algorithm=hashes.SHA256(), length=32, salt=None, info=b"vc-chat-v1"
                ).derive(shared)
                CHAT_KEYS[remote_ip] = chat_key
                CHAT_NONCE_PREFIX[remote_ip] = CHAT_PREFIX_CALLER
                CHAT_SEND_COUNTER[remote_ip] = 0  # 0,2,4…
                start_audio_stream(remote_ip, initiator_role=True)
        except socket.timeout:
            print("Brak odpowiedzi.")
