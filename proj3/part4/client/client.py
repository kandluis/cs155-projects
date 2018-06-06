import argparse
import dns.resolver
import socket
import sys
import os
from urllib import urlencode

GLOBAL_source_ip = "127.0.0.1"
GLOBAL_dest_ip = "1.2.3.4"
WEBSITE_NAME = "fakeBank.com"


def sendAndReceive_HTTP1_0(dest_ip, dest_port, request):
  # Connect to (dest_ip,dest_port), send request, and return response
  try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((dest_ip, dest_port))
    s.send(request)
    resp = s.recv(50000)
    s.close()
    return resp
  except:
    print("Failed to open TCP socket")
    sys.stdout.flush()
    exit()


def getCookie(resp):
  # Search a response for a cookie and return it
  cookie_ind = resp.find("cookie=")
  endl = resp[cookie_ind:].find("\r")
  return resp[cookie_ind+len("cookie="):cookie_ind+len("cookie=")+endl]


def httpConnection(my_ip, resolver_ip):
  # Set IP of the DNS resolver we are going to use
  resolver = dns.resolver.Resolver()
  resolver.nameservers = [resolver_ip]

  # Query the DNS resolver for our hostname's IP
  result = resolver.query(WEBSITE_NAME)

  for res in result:
    print(res.address)

  # Connect as client to a selected server
  # on a specified port
  dest_ip = result[0].address
  dest_port = 8000

  # Load the login page
  resp = sendAndReceive_HTTP1_0(
      dest_ip, dest_port, "GET /login HTTP/1.0\r\n\r\n")
  print("<------- Result of GET /login  --------->")
  print resp
  print("<-----=============================----->")

  # Send form on login page
  content = "username='Alex'&password='C0mput3rS3curity'"
  request = "POST /post_login HTTP/1.0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " +\
      str(len(content))+"\r\n\r\n"+content+"\r\n\r\n"
  resp = sendAndReceive_HTTP1_0(dest_ip, dest_port, request)

  print("<------ Result of POST /post_login ----->")
  print resp
  print("<------============================----->")
  sys.stdout.flush()

  # Get a cookie from logging in
  cookie = getCookie(resp)

  # Use cookie to download a user's file
  resp = sendAndReceive_HTTP1_0(
      dest_ip, dest_port, "GET /download_file?cookie="+cookie + " HTTP/1.0\r\n\r\n")

  # Save downloaded file to disk
  print("Did GET /download_file")
  print(resp)
  with open("lib/downloadedPage.txt", 'wb') as outFile:
    outFile.write(resp)
  print("File saved to lib/downloadedPage.txt")
  sys.stdout.flush()

  # Logout user
  content = "I WANT TO LOG OUT PLEASE!'"
  request = "POST /post_logout HTTP/1.0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " +\
      str(len(content))+"\r\n\r\n"+content+"\r\n\r\n"
  resp = sendAndReceive_HTTP1_0(dest_ip, dest_port, request)

  print("<------ Result of POST /post_logout ----->")
  print resp
  print("<------============================----->")

  # Close the connection when completed
  print "\nClient done!"
  sys.stdout.flush()


def main():
  parser = argparse.ArgumentParser(
      description='Client sends packets after dns lookup.')

  parser.add_argument('--source_ip', nargs='?', const=1,
                      default="127.0.0.1", help='ip of the host sending packets')
  parser.add_argument('--resolver_ip', nargs='?', const=1,
                      default="127.0.0.2", help='ip of the DNS resolver')

  args = parser.parse_args()

  httpConnection(args.source_ip, args.resolver_ip)


if __name__ == "__main__":

  # Change working directory to script's dir
  abspath = os.path.abspath(__file__)
  dname = os.path.dirname(abspath)
  os.chdir(dname)

  main()
