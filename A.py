import socket
import json
from Crypto.Cipher import AES
from base64 import b64decode, b64encode
from Crypto.Util.Padding import unpad, pad
from Crypto.Random import get_random_bytes

HOST = 'localhost'
PORT = 8888

def socket_send(text):
    length = len(text)
    print('0' * (16 - len(str(length))) + str(length))
    conn.sendall(('0' * (16 - len(str(length))) + str(length)).encode())
    conn.sendall(text.encode())


def xor_bytes(a, b):
    return bytes(i ^ j for i, j in zip(a, b))


def encrypt_ecb(raw):
    cipher = AES.new(KEY, AES.MODE_ECB)
    return cipher.encrypt(raw)


def encrypt_cbc(raw):
    encrypted_block = []
    fiv = get_random_bytes(16)
    iv = fiv
    for i in raw:
        xored = xor_bytes(i, iv)
        part_cipher_text = encrypt_ecb(xored)

        encrypted_block.append(part_cipher_text)

        iv = part_cipher_text
    return (encrypted_block, fiv)


def encrypt_ofb(raw):
    encrypted_block = []
    fiv = get_random_bytes(16)
    iv = fiv
    for i in raw:
        part_cipher_text = encrypt_ecb(iv)
        a = xor_bytes(part_cipher_text, i)

        encrypted_block.append(a)

        iv = part_cipher_text
    return (encrypted_block, fiv)


def get_the_key(mod_op):
    global KEY, SOCKET_KEY_MANAGER

    SOCKET_KEY_MANAGER.sendall(mod_op.encode())

    data = SOCKET_KEY_MANAGER.recv(16)
    cipher = AES.new(K3, AES.MODE_ECB)
    KEY = cipher.decrypt(data)


def configurate_socket():
    global SOCKET_B, SOCKET_KEY_MANAGER, conn

    SOCKET_KEY_MANAGER = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    SOCKET_KEY_MANAGER.connect((HOST, PORT))

    SOCKET_B = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    SOCKET_B.bind(('localhost', 8484))
    SOCKET_B.listen(1)
    conn, addr = SOCKET_B.accept()


def propagate_key():
    global conn

    if conn:
        cipher = AES.new(K3, AES.MODE_ECB)
        ciphertext = cipher.encrypt(KEY)
        ct = b64encode(ciphertext).decode('utf-8')
        print(KEY)
        print('first')
        conn.sendall(json.dumps({"ct": ct, 'mod': CHOOSED_MOD}).encode())


def split_by_length(length, arr):
    split_blocks = [arr[i * length: (i + 1) * length] for i in range(len(arr) // length)]

    if len(arr) > length:
        if len(arr) % length != 0:
            split_blocks.append(arr[(len(arr) // length) * length: len(arr)])
    else:
        split_blocks = [arr]

    return split_blocks


def transfer(inp):
    global KEY, conn, CHOOSED_MOD

    split_blocks = split_by_length(16, inp)

    if len(split_blocks) // Q < len(split_blocks) / Q:
        length = (len(split_blocks) // Q) + 1
    else:
        length = len(split_blocks) // Q

    all_block = [[] for i in range(length)]
    z = 0
    counter = 0
    for i in split_blocks:
        if z < Q:
            z = z + 1
        else:
            counter += 1
            z = 1
        all_block[counter].append(i)

    index = 1
    print('second')
    socket_send(str(len(all_block)))


    for i in all_block:
        i = pad(''.join(i).encode(), 16)
        i = split_by_length(16, i)

        if CHOOSED_MOD == 'CBC':
            encrypted_blocks, iv = encrypt_cbc(i)
        else:
            encrypted_blocks, iv = encrypt_ofb(i)
        print('iv = ', end='')
        print(iv)
        print('third')
        conn.sendall(iv)

        print('fourth')
        print(str(len(encrypted_blocks)).encode())
        socket_send(str(len(encrypted_blocks)))

        for encrypted_block in encrypted_blocks:
            print('fifth')
            print(encrypted_block)
            conn.sendall(encrypted_block)

        if index == Q:
            while True:
                CHOOSED_MOD = input('ENTER THE MOD:')
                if CHOOSED_MOD == 'CBC' or CHOOSED_MOD == 'OFB':
                    index = 1
                    break
            get_the_key(CHOOSED_MOD)
            propagate_key()

        index = index + 1

    SOCKET_B.close()
    SOCKET_KEY_MANAGER.sendall(b'END')
    SOCKET_KEY_MANAGER.close()

def main():
    global K3, Q, CHOOSED_MOD, KEY
    configurate_socket()

    with open('key_n3.txt', 'rb') as f:
        K3 = f.read()

    with open('q.txt') as f:
        Q = f.read()
        Q = int(Q)

    while True:
        print('Modul de operare')
        CHOOSED_MOD = input()
        if CHOOSED_MOD == 'CBC' or CHOOSED_MOD == 'OFB':
            break

    get_the_key(CHOOSED_MOD)
    propagate_key()
    transfer('SOME TEXT')


if __name__ == '__main__':
    main()
