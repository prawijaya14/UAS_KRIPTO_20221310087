from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Generate RSA key sekali saja
_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

def NPM_20221310087_sign_message(message: str) -> str:
    signature = _private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature.hex()

def NPM_20221310087_get_public_key():
    return _private_key.public_key()
