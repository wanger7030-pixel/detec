#!/bin/bash
set -e
TCPDUMP_BIN="$(which tcpdump)"
echo "tcpdump path: $TCPDUMP_BIN"

sudo groupadd pcap || true
sudo usermod -a -G pcap cape
sudo chgrp pcap $TCPDUMP_BIN
sudo setcap cap_net_raw,cap_net_admin=eip $TCPDUMP_BIN
sudo aa-disable $TCPDUMP_BIN || true

export PATH="$HOME/.local/bin:$PATH"
cd /opt/CAPEv2
echo "Installing python dependencies via poetry..."
poetry install
echo "POETRY_INSTALL_DONE"
