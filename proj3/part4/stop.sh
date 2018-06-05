#!/bin/sh

sudo kill $(ps aux | grep "python .*httpServer.py" | awk '{print $2}')
sudo kill $(ps aux | grep "python .*dnsServer.py" | awk '{print $2}')
sudo kill $(ps aux | grep "python .*client.py" | awk '{print $2}')
