import os
import sys
from base64 import b64decode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)

def generate_key(password, salt, iterations=100000):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    key = kdf.derive(password)
    return key
 
def encrypt(data, password, salt, iv):
    modeValue = len(data) % 16
    if modeValue != 0:
        fillCount = 16 - modeValue
        data = data + b"0" * fillCount
        data = data + b"0" * 15
        data = data + fillCount.to_bytes((fillCount.bit_length() + 7) // 8, 'big')

    key = generate_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return encrypted_data
 
def decrypt(encrypted_data, password, salt, iv):
    key = generate_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    if decrypted_data[-16:-1] == b"000000000000000":
        fillCount = int.from_bytes(decrypted_data[-1:], byteorder='big')
        if fillCount > 0 and fillCount < 16:
            index = -16-fillCount
            decrypted_data = decrypted_data[:index]

    return decrypted_data

if __name__ == "__main__":
    if sys.argv[1] == "save":
        data = None
        with open(sys.argv[2], "rb") as sourceFile:
            data = sourceFile.read()

        with open(sys.argv[3], "wb") as destFile:
            if data == None:
                destFile.write(b"")
            else:
                encrypted_data = encrypt(data, sys.argv[4].encode('utf-8'), sys.argv[5].encode('utf-8'), b64decode(sys.argv[6].encode('utf-8')))
                destFile.write(encrypted_data)

    elif sys.argv[1] == "load":
        data = None
        with open(sys.argv[2], "rb") as sourceFile:
            data = sourceFile.read()

        with open(sys.argv[3], "wb") as destFile:
            if data == None:
                destFile.write(b"")
            else:
                decrypted_data = decrypt(data, sys.argv[4].encode('utf-8'), sys.argv[5].encode('utf-8'), b64decode(sys.argv[6].encode('utf-8')))
                destFile.write(decrypted_data)