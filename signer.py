import argparse
import select
import socket
import sys
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import binascii


def client_init(hostname, msg):

	padded_len = '0' * (4-len(str(len(msg)))) + str(len(msg))

	key = RSA.import_key(open('myRSAkey.pem').read())

	h = SHA256.new(str.encode(msg))
	signature_hex = binascii.hexlify(pkcs1_15.new(key).sign(h))

	signature_len = '0' * (4-len(str(len(signature_hex)))) + str(len(signature_hex))

	signed_message = padded_len + msg + signature_len + signature_hex.decode('utf8')

	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.connect((hostname, 9998))

		s.send(signed_message.encode('utf8'))

		return


def genkey():
	key = RSA.generate(4096)
	f_pub = open("mypubkey.pem", "wb")
	f_pub.write(key.publickey().export_key())
	f_pub.close()

	f_private = open("myRSAkey.pem", "wb")
	f_private.write(key.export_key('PEM'))
	f_private.close()

	return
	


if (len(sys.argv) < 2):
	print('Usage: signer.py --genkey | --c hostname --m message')

elif (sys.argv[1] == '--genkey'): 
	if (len(sys.argv) != 2): print('Usage: signer.py --genkey | --c hostname --m message')
	else: 
		genkey()

elif (sys.argv[1] == '--c'):
	if (len(sys.argv) <= 2): print('Usage: signer.py --genkey | --c hostname --m message')
	else: 
		client_init(sys.argv[2], sys.argv[4])

else: print('Usage: signer.py --genkey | --c hostname --m message')