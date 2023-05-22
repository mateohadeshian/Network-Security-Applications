# Cybersecurity-Applications

PSDetect: 
A program that detects whether an ip has attempted to connect to 15 or more consecutive 
ports (ascending or descending) within 5 minutes, and reports that ip to a file.

PortScanToo: 
a port scanner (TCP connect scan) that effectively evades the above detector without losing 
runtime efficiency.

dh:
A Diffie-Hellman key exchanger over a network written with python sockets.

encryptedim:
An instant messenger program encrypts messages using AES-256 in CBC mode with randomly generated 
initialization vectors and an HMAC with SHA256 for message authentication. Program uses an 
encrypt-then-MAC scheme to send the message. The program is dependent on a pre-shared secret for
encryption (one time pad). Messages are sent over a network.

signer:
Generates an RSA keypair, writes the public portion of the key to a file, and sends a message over a 
network, followed by its signature.
