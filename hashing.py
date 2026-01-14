import hashlib

def hash_message(message):
    return hashlib.sha256(message.encode()).hexdigest()
