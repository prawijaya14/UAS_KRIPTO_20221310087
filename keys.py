# keys.py
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def npm_20221310087_load_or_create_keys():
    try:
        # Try to load existing keys
        with open("private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
            )
    except FileNotFoundError:
        # Create new keys if none exist
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        # Save private key
        with open("private_key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
    
    public_key = private_key.public_key()
    return private_key, public_key
