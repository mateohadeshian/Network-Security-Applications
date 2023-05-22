import argparse
import select
import socket
import sys
from Crypto.Random.random import randint

p = 0x00cc81ea8157352a9e9a318aac4e33ffba80fc8da3373fb44895109e4c3ff6cedcc55c02228fccbd551a504feb4346d2aef47053311ceaba95f6c540b967b9409e9f0502e598cfc71327c5a455e2e807bede1e0b7d23fbea054b951ca964eaecae7ba842ba1fc6818c453bf19eb9c5c86e723e69a210d4b72561cab97b3fb3060b
g = 2

def client_init(hostname):

	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.connect((hostname, 9999))

		a = randint(1, p)
		A = pow(g, a, p)
		s.send(bytes(str(A) + '\n','utf8'))

		B = int(s.recv(310).decode('utf8'))   # 310 is len(bytes(str(p) + '\n','utf8')) as p is the largest possible value of A

		print(pow(B, a, p))

		return


def server_init():
	listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	listen_sock.bind(('', 9999))
	listen_sock.listen()

	while True:
		try:
			conn, addr = listen_sock.accept()

			A = int(conn.recv(310).decode('utf8'))

			b = randint(1, p)
			B = pow(g, b, p)
			conn.send(bytes(str(B) + '\n','utf8'))

			print(pow(A, b, p))

			return

		except KeyboardInterrupt:
			sys.exit()

		except:
			pass



if (len(sys.argv) < 2):
	print('Usage: dh.py --s| --c hostname')

elif (sys.argv[1] == '--c'): 
	if (len(sys.argv) != 3): print('Client Usage: python3 dh.py --c "hostname".')
	else: 
		client_init(sys.argv[2])

elif (sys.argv[1] == '--s'):
	if (len(sys.argv) != 2): print('Server Usage: python3 dh.py --s')
	else: 
		server_init()

else: print('Usage: dh.py --s| --c hostname')