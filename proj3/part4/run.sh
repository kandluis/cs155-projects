#!/bin/sh

sudo kill $(ps aux | grep "python .*httpServer.py" | awk '{print $2}')
sudo kill $(ps aux | grep "python .*dnsServer.py" | awk '{print $2}')
sudo kill $(ps aux | grep "python .*client.py" | awk '{print $2}')

sudo python dnsServer/dnsServer.py > log/dnsOut.txt &
sudo python httpServer/httpServer.py > log/httpserverOut.txt &
sudo python client/client.py > log/clientOut.txt &
sudo python attacker/attacker.py 
