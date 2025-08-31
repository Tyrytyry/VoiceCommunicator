import socket
import hashlib
import os
import threading
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from .crypto import (
    generate_ecdh_key, get_public_bytes, sign_data_rsa, verify_rsa_signature,
    load_or_generate_rsa_keys, derive_shared_key, get_rsa_public_bytes, load_peer_public_key,
    compute_sas_pin,
)
from .audio import start_audio_stream, end_call
from . import audio as _audio
from datetime import datetime
from pathlib import Path



CONTROL_PORT = 5002
TEXT_PORT   = CONTROL_PORT


#CHAT_HELLO = b"HELLO"
#CHAT_ACK   = b"CACK"
#TEXT_MSG_PREFIX   = b"MS2"
#MSG_PREFIX  = b"MSG"

CHAT_PREFIX_CALLER = b"\x02\x00\x00\x00"
CHAT_PREFIX_CALLEE = b"\x03\x00\x00\x00"
PENDING_NAMES = {}
listener_stop_event = threading.Event()
listener_sock = None

call_active = False
call_lock = threading.Lock()

CHAT_KEYS         = {}
CHAT_NONCE_PREFIX = {}
CHAT_SEND_COUNTER = {}
PENDING_CHAT = {}

CONTACTS_FILE = "contacts.txt"

on_request_contact_name = None
on_incoming_call_request = None
on_call_started          = None
on_call_ended            = None
on_new_fpr               = None
on_contact_saved         = None
on_busy                  = None
on_text_message          = None


PENDING_FPR   = {}

on_sas_confirm     = None
on_security_alert  = None


def delete_contact(ip: str, remove_history: bool = True) -> bool:
    """Usuwa kontakt o podanym IP z pliku kontaktów oraz (domyślnie) całą konwersację."""
    try:
        # Przepisz plik kontaktów bez wskazanego IP
        entries = load_contacts(raw=True)
        changed = False
        with open(CONTACTS_FILE, "w") as f:
            for parts in entries:
                if len(parts) < 2:
                    continue
                if parts[1] == ip:
                    changed = True
                    continue
                f.write("|".join(parts) + "\n")

        # Usuń historię rozmów
        if remove_history:
            try:
                _msg_file(ip).unlink(missing_ok=True)
            except Exception:
                pass

        # Wyczyść stan czatu dla tego IP
        CHAT_KEYS.pop(ip, None)
        CHAT_NONCE_PREFIX.pop(ip, None)
        CHAT_SEND_COUNTER.pop(ip, None)
        PENDING_CHAT.pop(ip, None)
        try:
            PENDING_NAMES.pop(ip, None)  # jeśli dodałeś wcześniej PENDING_NAMES
        except NameError:
            pass

        return changed
    except Exception as e:
        print("[delete_contact] error:", e)
        return False




def initiate_contact(ip: str, name: str):
    """
    Inicjuje wymianę fingerprintów z podaną nazwą.
    Po OKFPR/MYRSA zapisze kontakt bez ponownego pytania o nazwę.
    """
    rsa_priv = load_or_generate_rsa_keys()
    rsa_pub = get_rsa_public_bytes(rsa_priv)
    fpr = hashlib.sha256(rsa_pub).hexdigest()

    # zapamiętaj nazwę, aby nie pytać drugi raz
    PENDING_NAMES[ip] = name

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(b"FPR" + fpr.encode(), (ip, CONTROL_PORT))


def is_online() -> bool:
    return not listener_stop_event.is_set()

def ensure_chat_ready(remote_ip: str, timeout: float = 2.0) -> bool:
    """
    Zapewnia, że istnieje klucz czatu do remote_ip.
    Jeśli nie ma – wysyła HELLO i czeka na zakończenie handshaku (CACK/FINALIZE) do 'timeout' s.
    Zwraca True, jeśli klucz gotowy, False w przeciwnym razie.
    """
    if not is_online():
        return False

    # już gotowe
    if CHAT_KEYS.get(remote_ip):
        return True

    # musimy znać kontakt i jego klucz RSA
    peer_rsa = next((rsa for _, ip, rsa in load_contacts() if ip == remote_ip), None)
    if peer_rsa is None:
        return False

    # wyślij HELLO i czekaj
    send_chat_hello(remote_ip)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if CHAT_KEYS.get(remote_ip):
            return True
        if not is_online():
            break
        time.sleep(0.05)
    return False

def _msg_file(ip: str) -> Path:
    return Path(f"messages_{ip}.txt")

def _append_history(ip: str, who: str, ts: str, text: str):
    with _msg_file(ip).open("a", encoding="utf-8") as f:
        f.write(f"{who}|{ts}|{text}\n")

def _safe(cb, *a):
    if cb:
        try:
            cb(*a)
        except Exception:
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


def send_busy(ip: str):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(b"BUSY", (ip, CONTROL_PORT))

def send_chat_hello(remote_ip: str):
    priv = generate_ecdh_key()
    pub  = get_public_bytes(priv)

    rsa_priv = load_or_generate_rsa_keys()
    signature = sign_data_rsa(rsa_priv, pub)

    payload = b"HELLO" + pub + signature + get_rsa_public_bytes(rsa_priv)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(payload, (remote_ip, CONTROL_PORT))

    PENDING_CHAT[remote_ip] = priv
    CHAT_NONCE_PREFIX[remote_ip] = CHAT_PREFIX_CALLER
    CHAT_SEND_COUNTER[remote_ip] = 0



def send_text_message(remote_ip: str, text: str):
    # >>> ZMIANA: nie wysyłamy, jeśli my jesteśmy offline
    if not is_online():
        print("[CHAT] Lokalnie offline – nie wysyłam.")
        return False

    key = CHAT_KEYS.get(remote_ip)
    if key is None:
        print("[CHAT] Brak klucza – nawiąż czat (ensure_chat_ready) przed wysłaniem.")
        return False

    prefix  = CHAT_NONCE_PREFIX[remote_ip]
    counter = CHAT_SEND_COUNTER[remote_ip]
    nonce   = prefix + counter.to_bytes(8, "big")
    CHAT_SEND_COUNTER[remote_ip] += 2

    ciphertext = AESGCM(key).encrypt(nonce, text.encode("utf-8"), None)
    packet = b"MS2" + nonce + ciphertext

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(packet, (remote_ip, CONTROL_PORT))
    except Exception:
        # brak wysyłki -> nic nie zapisuj
        return False

    # >>> WAŻNE: zapis tylko gdy (lokalnie) online i mamy klucz (czyli obie strony były online w chwili handshaku)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    _append_history(remote_ip, "ME", ts, text)
    _safe(on_text_message, remote_ip, ts, text, False)
    return True



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


def is_call_active() -> bool:
    with call_lock:
        return call_active

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



def stop_listener():
    listener_stop_event.set()
    if listener_sock:
        try:
            listener_sock.close()
        except:
            pass

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



                elif data.startswith(b"OKFPR"):
                    rsa_data = data[len(b"OKFPR"):]
                    my_priv = load_or_generate_rsa_keys()
                    my_pub = get_rsa_public_bytes(my_priv)
                    pin = compute_sas_pin(my_pub, rsa_data)
                    pending_name = PENDING_NAMES.get(ip)
                    def _accept():
                        if pending_name:
                            save_contact(pending_name, ip, rsa_data)
                            PENDING_NAMES.pop(ip, None)
                            send_myrsa(ip)
                            _safe(on_contact_saved, pending_name, ip)
                        else:
                            def _save(name):
                                save_contact(name, ip, rsa_data)
                                send_myrsa(ip)
                                _safe(on_contact_saved, name, ip)
                            _safe(on_request_contact_name, ip, rsa_data, _save)
                    def _reject():
                        pass
                    _safe(on_sas_confirm, ip, pin, _accept, _reject)





                elif data.startswith(b"MYRSA"):
                    rsa_data = data[len(b"MYRSA"):]
                    expected = PENDING_FPR.pop(ip, None)
                    if expected:
                        calc = hashlib.sha256(rsa_data).hexdigest()
                        if calc != expected:
                            _safe(on_security_alert, ip, "Odrzucono: klucz RSA nie pasuje do fingerprintu (FPR).")
                            continue  # nie zapisuj, przerwij
                    my_priv = load_or_generate_rsa_keys()
                    my_pub = get_rsa_public_bytes(my_priv)
                    pin = compute_sas_pin(my_pub, rsa_data)
                    def _accept():
                        pending_name = PENDING_NAMES.pop(ip, None)
                        if pending_name:
                            save_contact(pending_name, ip, rsa_data)
                            _safe(on_contact_saved, pending_name, ip)
                        else:
                            def _save(name):
                                save_contact(name, ip, rsa_data)
                                _safe(on_contact_saved, name, ip)
                            _safe(on_request_contact_name, ip, rsa_data, _save)
                    def _reject():
                        pass
                    _safe(on_sas_confirm, ip, pin, _accept, _reject)

                # odbiorca kończy rozmowę
                elif data.startswith(b"END"):
                    end_call(send_signal=False)

                # odbiorca zajęty
                elif data.startswith(b"BUSY"):
                    _safe(on_busy, ip)

                elif data.startswith(b"HELLO"):
                    their_pub = data[5:70]
                    their_sig = data[70:326]
                    their_rsa = data[326:]

                    stored_rsa = next((rsa for _, saved_ip, rsa in load_contacts() if saved_ip == ip), None)
                    if not stored_rsa or stored_rsa != their_rsa:
                        continue
                    try:
                        verify_rsa_signature(stored_rsa, their_sig, their_pub)
                    except Exception:
                        continue

                    _send_chat_ack(ip, their_pub)

                elif data.startswith(b"CACK"):
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

                elif data.startswith(b"MS2"):
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



def _send_chat_ack(ip: str, their_pub_bytes: bytes):
    """Wysyłamy CACK i kończymy handshake."""
    priv = generate_ecdh_key()
    pub  = get_public_bytes(priv)

    rsa_priv = load_or_generate_rsa_keys()
    signature = sign_data_rsa(rsa_priv, pub)

    payload = b"CACK" + pub + signature
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(payload, (ip, CONTROL_PORT))

    _finalize_chat_key(ip, priv, their_pub_bytes, caller=False)


def _finalize_chat_key(ip: str, my_priv, their_pub_bytes: bytes, caller: bool):
    chat_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"vc-chat-v1"
    ).derive(my_priv.exchange(ec.ECDH(), load_peer_public_key(their_pub_bytes)))

    CHAT_KEYS[ip] = chat_key
    CHAT_NONCE_PREFIX[ip] = CHAT_PREFIX_CALLER if caller else CHAT_PREFIX_CALLEE
    CHAT_SEND_COUNTER[ip] = 0 if caller else 1
    print(f"[CHAT] handshake OK z {ip}")

def accept_incoming_call(ip: str, port, ecdh_pub: bytes):

    my_priv = generate_ecdh_key()
    my_pub = get_public_bytes(my_priv)

    rsa_private = load_or_generate_rsa_keys()
    signature = sign_data_rsa(rsa_private, my_pub)

    shared_key = derive_shared_key(my_priv, load_peer_public_key(ecdh_pub))
    global aesgcm
    from . import audio as _audio
    aesgcm = AESGCM(shared_key)
    _audio.aesgcm = aesgcm
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
                _audio.aesgcm = aesgcm
                chat_key = HKDF(
                    algorithm=hashes.SHA256(), length=32, salt=None, info=b"vc-chat-v1"
                ).derive(shared)
                CHAT_KEYS[remote_ip] = chat_key
                CHAT_NONCE_PREFIX[remote_ip] = CHAT_PREFIX_CALLER
                CHAT_SEND_COUNTER[remote_ip] = 0  # 0,2,4…
                start_audio_stream(remote_ip, initiator_role=True)
        except socket.timeout:
            print("Brak odpowiedzi.")