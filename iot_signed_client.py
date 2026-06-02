#!/usr/bin/env python3
import socket
import json
import hashlib
import binascii
import sys
from ecdsa import SigningKey, NIST256p, util

# --- KONFIGURACJA ---
ARDUINO_IP = ""  
ARDUINO_PORT = 6668

# Ścieżka do pliku z prywatnym kluczem klienta (wygenerowanym wcześniej)
CLIENT_PRIV_HEX_FILE = "client_priv.hex"

# Wczytuje private key z pliku klienta
def load_client_private_key():
    try:
        with open(CLIENT_PRIV_HEX_FILE, "r") as f:
            hexstr = f.read().strip()
        priv_bytes = binascii.unhexlify(hexstr)
        sk = SigningKey.from_string(priv_bytes, curve=NIST256p)
        return sk
    except Exception as e:
        print("Błąd wczytywania private key klienta:", e)
        sys.exit(1)

# Podpisuje JSON-ową komendę: bierze dict bez pola "signature", serializuje bez spacji,
# oblicza SHA256, podpisuje kluczem prywatnym, zwraca dict z dołączonym polem "signature"
def sign_command_dict(sk: SigningKey, cmd_dict: dict) -> dict:
    # Serializacja bez spacji
    js = json.dumps(cmd_dict, separators=(',',':'))
    # SHA256
    h = hashlib.sha256(js.encode('utf-8')).digest()
    # podpis r||s (raw 64 bajty)
    sig = sk.sign_digest(h, sigencode=util.sigencode_string)
    sig_hex = binascii.hexlify(sig).decode().upper()
    # dołączamy podpis
    signed = dict(cmd_dict)
    signed["signature"] = sig_hex
    return signed

# Wysyła podpisaną komendę do Arduino i zwraca odpowiedź jako string
def send_signed_command(signed_cmd: dict) -> str:
    payload = json.dumps(signed_cmd, separators=(',',':')) + "\n"
    # Połączenie TCP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((ARDUINO_IP, ARDUINO_PORT))
        except Exception as e:
            print("Błąd połączenia do Arduino:", e)
            sys.exit(1)
        s.sendall(payload.encode('utf-8'))
        # odbierz odpowiedź (do zamknięcia po stronie Arduino)
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    try:
        return data.decode('utf-8').strip()
    except:
        return repr(data)

def print_usage():
    print("Użycie:")
    print("  python3 iot_signed_client.py get_pubkey")
    print("  python3 iot_signed_client.py led_on")
    print("  python3 iot_signed_client.py led_off")
    print("  python3 iot_signed_client.py status")
    sys.exit(1)

def main():
    if len(sys.argv) != 2:
        print_usage()
    cmd = sys.argv[1]
    valid_cmds = ["get_pubkey","led_on","led_off","status"]
    if cmd not in valid_cmds:
        print("Nieznana komenda:", cmd)
        print_usage()

    sk = load_client_private_key()

    # Przygotuj dict komendy
    cmd_dict = {"command": cmd}
    signed = sign_command_dict(sk, cmd_dict)
    print("Wysyłam:", json.dumps(signed, separators=(',',':')))
    resp = send_signed_command(signed)
    print("Odpowiedź Arduino:", resp)

    # Jeśli to get_pubkey, możesz pokazać publiczny klucz Arduino:
    if cmd == "get_pubkey":
        try:
            j = json.loads(resp)
            if j.get("response") == "pubkey" or j.get("response")=="arduino_pubkey":
                pubhex = j.get("pubkey")
                print("Arduino public key HEX:", pubhex)
            else:
                print("Odpowiedź nie zawiera pubkey.")
        except:
            pass

if __name__ == "__main__":
    main()
