from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from base64 import b64decode

def pad(data):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data

def unpad(data):
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(data) + unpadder.finalize()
    return unpadded_data

def decrypt(key, encrypted_data):
    backend = default_backend()
    iv = b'\x00' * 16  # Use proper IV (Initialization Vector) in a real scenario
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    decryptor = cipher.decryptor()
    encrypted_data = b64decode(encrypted_data)
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadded_data = unpad(decrypted_padded_data)
    return unpadded_data
