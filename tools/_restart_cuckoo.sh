#!/bin/bash
sudo pkill -9 -f cuckoo
sleep 2
sudo fuser -k 2042/tcp
sleep 2
sudo virsh snapshot-revert win10-sandbox clean_snapshot
sleep 15
sudo rm -f /tmp/cuckoo_out.log
sudo touch /tmp/cuckoo_out.log
sudo chmod 666 /tmp/cuckoo_out.log
cd /opt/CAPEv2
sudo -u cape nohup python3 -m poetry run python3 cuckoo.py >> /tmp/cuckoo_out.log 2>&1 &
sleep 5
pgrep -f cuckoo.py
echo DONE
