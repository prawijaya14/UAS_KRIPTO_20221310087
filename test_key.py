from cryptography.hazmat.primitives import serialization

with open("public_key.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

print("PUBLIC KEY BERHASIL DIBACA")
