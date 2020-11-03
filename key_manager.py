import socket
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode
from Crypto.Util.Padding import pad


k3 = get_random_bytes(16)

cipher = AES.new(k3, AES.MODE_ECB)

with open('key_n3.txt', 'wb') as f:
	f.write(k3)

with open('q.txt') as f:
	q = f.read()

PORT = 8888

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind(('localhost', PORT))
    s.listen(100)
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        while True:
            data = conn.recv(3)

            if data == b'CBC':
                k1 = get_random_bytes(16)
                print(k1)
                ciphertext = cipher.encrypt(k1)
                conn.sendall(ciphertext)
            elif data == b'OFB':
                k2 = get_random_bytes(16)
                ciphertext  = cipher.encrypt(k2)
                conn.sendall(ciphertext)
                print(k2)
            elif data == b'END':
                break

