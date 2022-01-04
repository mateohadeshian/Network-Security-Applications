import argparse
import select
import socket
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import unpad
from Crypto.Util.Padding import pad
from Crypto import Random

def aesEncrypt(msg):
	iv = get_random_bytes(AES.block_size)

	cipher = AES.new(confkey, AES.MODE_CBC, iv)


	encrypted_len = cipher.encrypt(len(msg).to_bytes(AES.block_size, sys.byteorder)) # E_k1(len(m))
	encrypted_msg = cipher.encrypt(pad(msg, AES.block_size))      # E_k1(m)

	hmac_len = HMAC.new(authkey, digestmod=SHA256) # with iv
	hmac_len.update(iv + encrypted_len)
	hmac_msg = HMAC.new(authkey, digestmod=SHA256)
	hmac_msg.update(encrypted_msg)

	return iv + encrypted_len + hmac_len.digest() + encrypted_msg + hmac_msg.digest()


# Takes a connected socket, receives its full_message,
# removes the header, and prints the message
def receiveMessage(s):

	try:
		data = s.recv(1024)

		if (len(data) < (AES.block_size * 2)):
			# EOF
			sys.exit()

		iv = data[0 : AES.block_size]

		encrypted_len = data[AES.block_size : AES.block_size * 2]

		hmac_len = data[AES.block_size * 2 : AES.block_size * 4]
		hmac_len_verifier = HMAC.new(authkey, digestmod=SHA256)
		hmac_len_verifier.update(iv + encrypted_len)

		try:
			hmac_len_verifier.verify(hmac_len)
		except: 
			print("ERROR: HMAC verification failed")
			quit()

		cipher = AES.new(confkey, AES.MODE_CBC, iv)
		msg_len = int.from_bytes(cipher.decrypt(encrypted_len), sys.byteorder)

		if ((msg_len % 16) == 0):
			msg_len += 1
		msg_len += 16 - (msg_len % 16)
		# ^^ add until next multiple of 16 to adjust for padding

		while (len(data) < msg_len + (6 * AES.block_size)):
			data += s.recv(min((msg_len + (6 * AES.block_size) - len(data)), 1024))
		
		encrypted_msg = data[4 * AES.block_size : len(data) - (2 * AES.block_size)]

		hmac_msg = data[len(data) - 32 : len(data)]
		hmac_msg_verifier = HMAC.new(authkey, digestmod=SHA256)
		hmac_msg_verifier.update(encrypted_msg)

		try:
			hmac_msg_verifier.verify(hmac_msg)
		except:
			print("ERROR: HMAC verification failed")
			sys.exit()

		msg = str(unpad(cipher.decrypt(encrypted_msg), AES.block_size).decode("utf-8"))
		print(msg)
		sys.stdout.flush()

		return

	except: 
		return 

# takes a connected socket and a message, 
# creates a header containing the size of the msg and prepends it to the msg
# sends the header + msg through the socket
def sendMessage(s, msg):
	s.send(aesEncrypt(msg.encode("utf-8")))

	return

# clientConnect takes in a hostname as a parameter, creates a socket, and 
# connects the new socket to the server
# The function parses inputs from the various sockets using select, 
# sends all stdin to the server, and prints all other inputs to stdin 
#
# on close (ctrl+c or ctrl+d), closes connection w/ server
def clientConnect(hostname):
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	try:
		server.connect((hostname, 9999))
	except:
		server.close()
		sys.exit()


	while True:
		try:
			other_clients = [sys.stdin, server]
			(ready_read, _, _) = select.select(other_clients,[],[])

			for sock in ready_read:
				if sock is server:
					receiveMessage(sock)

				elif sock is sys.stdin: 
					try: 
						message = input()
						sendMessage(server, message)

					# EOF
					except: 
						server.close()
						sys.exit()

				else: 
					try: receiveMessage(sock)
					except: pass
		

		except KeyboardInterrupt:
			server.close()
			sys.exit()

		except: 
			server.close()
			sys.exit()

# serverStart creates a listen_socket bound to port 9999 that remains 
# open 
# The function parses inputs from the various sockets using select, 
# sends all stdin to the client(s), and prints all other inputs to stdin 
def serverStart():
	server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	server_sock.bind(('', 9999))
	server_sock.listen(100)
	client_sockets = []

	while True:
		try:
			read_list = [server_sock, sys.stdin] + client_sockets
			try:
				(ready_read, _, _) = select.select(read_list, [], [])
			except ValueError:
				sys.exit()

			for sock in ready_read:
				if sock is server_sock:
					new_conn, addr = server_sock.accept()
					client_sockets.append(new_conn)

				elif sock is sys.stdin:
					try:
						msg = input()
						for client in client_sockets:
							try:
								sendMessage(client, msg)
							except: 
								client.close()
								client_sockets.remove(client)

					# EOF
					except: 
						server_sock.close()
						for sock in client_sockets:
							client_sockets.remove(sock)
							sock.close()
						sys.exit()		

				else: 
					receiveMessage(sock) 

		except KeyboardInterrupt:
			server_sock.close()
			for sock in client_sockets:
				client_sockets.remove(sock)
				sock.close()
			sys.exit()			

# Argument Parser: Main program driver
# Either starts a server, or initializes a client's conection

hConf = SHA256.new()
hAuth = SHA256.new()

if (sys.argv[1] == '--c'): 
	if (len(sys.argv) != 7): print('Error. Incorrect usage.')
	else: 
		hConf.update(sys.argv[4].encode())
		confkey = hConf.digest()
		hAuth.update(sys.argv[6].encode())
		authkey = hAuth.digest()
		clientConnect(sys.argv[2])
		# valid client call

elif (sys.argv[1] == '--s'):
	if (len(sys.argv) != 6): print('Error: Incorrect Usage')
	else: 
		hConf.update(sys.argv[3].encode())
		confkey = hConf.digest()
		hAuth.update(sys.argv[5].encode())
		authkey = hAuth.digest()
		serverStart()
		# valid call to start server

else: print('Error: unrecognized argument(s)\nUsage: unencryptedim.py --s| --c hostname')

