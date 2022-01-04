import socket
import sys
import timeit

def scan(ip):
	try:
		i = 2
		while i < 65536:
			scanport(ip, i)
			i += 2

		i = 1
		while i < 65536:
			scanport(ip, i)
			i += 2

	except KeyboardInterrupt:
		return

def scanport(ip, port):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	if s.connect_ex((ip, port)):
		return
	else:
		try: 
			service = socket.getservbyport(port, 'tcp')
			f.write(str(port) + " (" + service + ") was open\n")
			s.close()
		except: 
			service = "NA"
			f.write(str(port) + " (" + service + ") was open\n")
			s.close()	

if len(sys.argv) < 2:
	print("Usage: python PortScan.py [target]")
else: 
	f = open("scannertoo.txt", "w")
	init = timeit.default_timer()
	scan(sys.argv[1])
	elapsed = timeit.default_timer() - init
	pps = elapsed / 65536
	f.write("time elapsed = " + str(elapsed) + "s\n")
	f.write("time per scan = " + str(pps) + "s\n")
	f.close()
