import socket
import json
from Crypto.Cipher import AES
from base64 import b64decode, b64encode
from Crypto.Util.Padding import unpad, pad


HOST = 'localhost'    # The remote host
PORT = 8484              # The same port as used by the server


def bytes_to_int(bytes):
    result = 0

    for b in bytes:
        result = result * 256 + int(b)

    return result


def xor_bytes(a, b):
    return bytes(i^j for i, j in zip(a, b))

def decrypt_ecb(enc):
	cipher = AES.new(KEY, AES.MODE_ECB)
	return cipher.decrypt(enc)

def encrypt_ecb(raw):
	cipher = AES.new(KEY, AES.MODE_ECB)
	return cipher.encrypt(raw)

def decrypt_cbc(enc, iv):
	r = []
	fiv = iv
	for i in enc:
		p = decrypt_ecb(i)
		xored = xor_bytes(p, fiv)
		
		r.append(xored)
		
		fiv = i
	return r

def decrypt_ofb(enc, iv):
	r = []
	fiv = iv

	for i in enc:
		part_cipher_text = encrypt_ecb(fiv)
		a = xor_bytes(part_cipher_text, i)
		
		r.append(a)
		
		fiv = part_cipher_text
	return r


def get_the_key():
	global CHOOSED_MOD, KEY, SOCKET

	data = SOCKET.recv(48)
	print('first')
	print(data)
	b64 = json.loads(data)
	CHOOSED_MOD = b64['mod']
	ct = b64decode(b64['ct'])
	cipher = AES.new(K3, AES.MODE_ECB)
	KEY = cipher.decrypt(ct)
	print(KEY)


def socket_recv():
	len = int(SOCKET.recv(16).decode())
	data = SOCKET.recv(len)

	return data

def configure():
	global SOCKET
	SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	SOCKET.connect((HOST, PORT))


def transfer():
	global CHOOSED_MOD, KEY
	print('second')	
	total_length = int(socket_recv().decode())

	index = 1
	for n in range(total_length):
		decrypted_text = ''
		print('third')	
		print('iv = ', end = '')
		iv = SOCKET.recv(16)
		print(iv)
		print('fourth')
		lenght = int(socket_recv().decode())
		print(lenght)

		encrypted_blocks = []
		for i in range(lenght):
			print('fifth')
			print(i)
			encrypted_blocks.append(SOCKET.recv(16))
		print(encrypted_blocks)

		# # iv = b'&|\x13\x80\xc9We\xdf\xba\xc3\xe9\x08J\x9f\x94z'
		# # encrypted_block = [b'\x80s\xb8\xb9p31\xdc\xd0\xb6n5\xc2\xb8Ht']
		# # KEY = b'\xa2\x7f\xcd\xfd\x11\x15#\n\x97\x04Z\x85w\xd8\xc8R'

		if CHOOSED_MOD == 'CBC':
			for q in decrypt_cbc(encrypted_blocks, iv):
				decrypted_text += q.decode()
		else:
			for q in decrypt_ofb(encrypted_blocks, iv):
				decrypted_text += q.decode()
		
		print('DECRYPTED ONE Q BLOCK = ', end = '')
		print(unpad(decrypted_text.encode(), 16))

		if index == Q:
			index = 1
			get_the_key()
		index = index + 1

	SOCKET.close()

def main():
	global K3, KEY, Q

	with open('key_n3.txt', 'rb') as f:
		K3 = f.read()
	
	with open('q.txt') as f:
		Q = f.read()
		Q = int(Q)

	
	configure()
	get_the_key()
	transfer()
	
if __name__ == '__main__':
	main()
