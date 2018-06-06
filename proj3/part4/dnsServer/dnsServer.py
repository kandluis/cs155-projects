import argparse
import socket
import os
import sys


def main():
  DNS_PORT = 53
  My_IP = "127.0.0.2"

  if not os.geteuid() == 0:
    sys.exit("\nRun script as root so it can bind to privileged port 53.\n")

  try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((My_IP, DNS_PORT))
  except:
    print "Couldn't bind to port 53."
    sys.stdout.flush()
    exit()

  while True:
    data, addr = sock.recvfrom(2048)

    print data, addr
    sys.stdout.flush()


if __name__ == "__main__":
  main()
