import os


from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding

RSA_PRIVATE_FILE = "rsa_key.pem"


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