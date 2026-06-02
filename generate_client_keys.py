# generate_client_keys.py
from ecdsa import SigningKey, NIST256p
import binascii

# Generujemy parę secp256r1
sk = SigningKey.generate(curve=NIST256p)
vk = sk.get_verifying_key()

priv_bytes = sk.to_string()    # 32 bajty
pub_bytes = vk.to_string()     # 64 bajty (X||Y)

priv_hex = binascii.hexlify(priv_bytes).decode()
pub_hex = binascii.hexlify(pub_bytes).decode()

print("CLIENT PRIVATE KEY HEX (32 bytes):")
print(priv_hex)
print()
print("CLIENT PUBLIC KEY HEX (64 bytes):")
print(pub_hex)

# (opcjonalnie) zapis do plików:
with open("client_priv.hex", "w") as f:
    f.write(priv_hex)
with open("client_pub.hex", "w") as f:
    f.write(pub_hex)
print("\nZapisano client_priv.hex i client_pub.hex")