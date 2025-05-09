from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

KEY = b"ThisIsA16ByteKey"  # 16-byte AES key

def encrypt(data: bytes) -> bytes:
    cipher = AES.new(KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv + ct_bytes  # prepend IV

def decrypt(data: bytes) -> bytes:
    iv = data[:16]
    ct = data[16:]
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)
