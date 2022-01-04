# Mateo Hadeshian
# Network Security 
# December 2021

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sniff
from scapy.all import ls
from scapy.all import conf as scapyconf
from scapy.layers.inet import IP, TCP
import timeit
import sys, signal
import os

# quitting done by setting global quit flag after ^C raised
def signal_handler(signal, frame):
	global quit
	print("\nExit Request Received.")
	quit = True

# stopfilter for scapy.sniff. tells scapy to stop sniffing if true
def quitter(p):
	global quit
	return quit

# packet_callback:
# for each packet it recieves, checks destination port for sussness.
# adds 1 to the sussness score if previous port connected to 
# by that ip was adjacent to the current dport.
# If sussness score reaches 15, updateSuspects detects it and reports
# it, then adds the confirmed sus ip to detected.
def packet_callback(pkt):
	global suspects, detected

	if IP not in pkt:
		return
	
	ip = pkt[IP].src

	# If packet is from an already detected ip, we drop it because we've 
	# already reported
	if ip in detected:
		return

	if TCP not in pkt:
		return 

	dport = pkt[TCP].dport

	#if previous and current dports are consecutive, increase sussess of ip ad update
	if ip in list(suspects):
		if int(dport) + 1 == suspects[ip][2] or int(dport) - 1 == suspects[ip][2]:
			suspects[ip][0] += 1
			suspects[ip][2] = int(dport)
	else:
		suspects[ip] = [1, timeit.default_timer(), int(dport)]

	updateSuspects()
	return	


# checks susness of all ips in dictionary. also checks their expiration
def updateSuspects():
	global suspects, detected

	for ip in list(suspects):
		if suspects[ip][0] >= 15:
			f.write("Scanner detected. The scanner originated from host " + str(ip) + "\n")

			detected.append(ip)
			del suspects[ip]

		elif (timeit.default_timer() - suspects[ip][1]) > 300:
			del suspects[ip]


# signal handler for ^C
signal.signal(signal.SIGINT, signal_handler)

# a quit flag that is set by the signal handler. 
# tells program to quit once current sniff call is complete.
quit = False

f = open("detector.txt", "w")

# dictionary of suspects. each suspect is a 3tuple.
# the key of each suspect is its ip.
# suspect[0]: number of consecutive connections
# suspect[1]: time of first packet sniffed
# suspect[2]: port this suspect most recently conected to.
suspects = {}

# list of reported ips. used to check for redundant reports. 
# good for runtime as it allows us to immediately drop packets from 
# already detected ips
detected = []

# scapyconf.sniff_promisc = 0

# filters for only TCP packets with ips
scapyconf.layers.filter([IP, TCP])
scapyconf.iface = "lo0"

# begin sniffing until quitter returns true (will happen soon after a ^C press)
sniff(prn=packet_callback, stop_filter=quitter)

f.close()
sys.exit()





