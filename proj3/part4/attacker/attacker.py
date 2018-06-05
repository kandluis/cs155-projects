import os
import argparse
import socket
from scapy.all import *

conf.L3socket = L3RawSocket
WEB_PORT = 8000
HOSTNAME = "fakeBank.com"

def resolveHostname(hostname):
	# IP address of HOSTNAME. Used to forward tcp connection. 
	# Normally obtained via DNS lookup.
	return "127.1.1.1"

def log_credentials(username, password):
	# Write stolen credentials out to file
	# Do not change this
	with open("lib/StolenCreds.txt","wb") as fd:
		fd.write("Stolen credentials: username="+username+" password="+password)

def check_credentials(client_data):
	# TODO: Take a block of client data and search for username/password credentials
	# If found, log the credentials to the system by calling log_credentials().
	raise NotImplementedError

def handle_tcp_forwarding(client_socket, client_ip, hostname):
	# TODO: Continuously intercept new connections from the client
	# and initiate a connection with the host in order to forward data

	while True:

		# TODO: accept a new connection from the client on client_socket and
		# create a new socket to connect to the actual host associated with hostname
		

		# TODO: read data from client socket, check for credentials, and forward along to
		# host socket. Check for POST to '/post_logout' and exit after that request has completed.

		raise NotImplementedError

def dns_callback(packet,extra_args):
	# TODO: Write callback function for handling DNS packets.
	# Sends a spoofed DNS response for a query to HOSTNAME and calls handle_tcp_forwarding() after successful spoof
	raise NotImplementedError

def sniff_and_spoof(source_ip):
	# TODO: Open a socket and bind it to the attacker's IP and WEB_PORT
	# This socket will be used to accept connections from victimized clients

	# TODO: sniff for DNS packets on the network. Make sure to pass source_ip
	# and the socket you created as extra callback arguments. 
	raise NotImplementedError

def main():
	parser = argparse.ArgumentParser(description='Attacker who spoofs dns packet and hijacks connection')
	parser.add_argument('--source_ip',nargs='?', const=1, default="127.0.0.3", help='ip of the attacker')

	args = parser.parse_args()
	sniff_and_spoof(args.source_ip)

if __name__=="__main__":
	# Change working directory to script's dir
	# Do not change this
	abspath = os.path.abspath(__file__)
	dname = os.path.dirname(abspath)
	os.chdir(dname)
	main()
