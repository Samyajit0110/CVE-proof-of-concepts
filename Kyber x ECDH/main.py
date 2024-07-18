from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.backends import default_backend
import base64
import os

# Placeholder functions for Kyber KEM operations
def kyber_keygen():
    public_key = os.urandom(800)  # Mock public key
    secret_key = os.urandom(1632)  # Mock secret key
    return public_key, secret_key

def kyber_encapsulate(public_key):
    ciphertext = os.urandom(1088)  # Mock ciphertext
    shared_secret = os.urandom(32)  # Mock shared secret
    return ciphertext, shared_secret

def kyber_decapsulate(secret_key, ciphertext):
    shared_secret = os.urandom(32)  # Mock shared secret
    return shared_secret

# ECDH Key Generation
def ecdh_keygen():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# ECDH Shared Secret Computation
def ecdh_shared_secret(private_key, peer_public_key):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_secret

# Combine Shared Secrets
def combine_shared_secrets(secret1, secret2):
    combined_kdf = ConcatKDFHash(algorithm=hashes.SHA256(), length=32, otherinfo=None, backend=default_backend())
    combined_secret = combined_kdf.derive(secret1 + secret2)
    return combined_secret

# Example Usage
if __name__ == "__main__":
    # ECDH Key Generation
    ecdh_private_key, ecdh_public_key = ecdh_keygen()
    ecdh_peer_private_key, ecdh_peer_public_key = ecdh_keygen()

    print("ECDH Public Key (Base64):", base64.b64encode(ecdh_public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)).decode())
    print("ECDH Peer Public Key (Base64):", base64.b64encode(ecdh_peer_public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)).decode())

    # ECDH Shared Secret
    ecdh_shared_secret_local = ecdh_shared_secret(ecdh_private_key, ecdh_peer_public_key)
    ecdh_shared_secret_peer = ecdh_shared_secret(ecdh_peer_private_key, ecdh_public_key)

    print("ECDH Shared Secret (Local):", base64.b64encode(ecdh_shared_secret_local).decode())
    print("ECDH Shared Secret (Peer):", base64.b64encode(ecdh_shared_secret_peer).decode())

    # Kyber Key Generation
    kyber_public_key, kyber_secret_key = kyber_keygen()
    print("Kyber Public Key (Base64):", base64.b64encode(kyber_public_key).decode())

    # Kyber Encapsulation
    kyber_ciphertext, kyber_shared_secret = kyber_encapsulate(kyber_public_key)
    print("Kyber Ciphertext (Base64):", base64.b64encode(kyber_ciphertext).decode())
    print("Kyber Shared Secret:", base64.b64encode(kyber_shared_secret).decode())

    # Kyber Decapsulation
    kyber_recovered_shared_secret = kyber_decapsulate(kyber_secret_key, kyber_ciphertext)
    print("Kyber Recovered Shared Secret:", base64.b64encode(kyber_recovered_shared_secret).decode())

    # Combine Shared Secrets
    hybrid_shared_secret_local = combine_shared_secrets(ecdh_shared_secret_local, kyber_shared_secret)
    hybrid_shared_secret_peer = combine_shared_secrets(ecdh_shared_secret_peer, kyber_recovered_shared_secret)

    print("Hybrid Shared Secret (Local):", base64.b64encode(hybrid_shared_secret_local).decode())
    print("Hybrid Shared Secret (Peer):", base64.b64encode(hybrid_shared_secret_peer).decode())

    # Verify that the hybrid shared secrets match
    assert hybrid_shared_secret_local == hybrid_shared_secret_peer
    print("Hybrid Shared Secrets Match!")

