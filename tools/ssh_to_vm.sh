#!/bin/bash
# SSH into CAPEv2-Host VM from WSL
# Usage: wsl -d Ubuntu-22.04 -- bash /path/to/ssh_to_vm.sh "command"

apt-get install -y sshpass 2>/dev/null | tail -1

# Windows host IP from WSL
WIN_IP=$(cat /etc/resolv.conf | grep nameserver | awk '{print $2}')
echo "Windows host IP: $WIN_IP"

CMD="${1:-echo SSH_SUCCESS && uname -a}"
echo "Running: $CMD"

sshpass -p 'cape123' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=15 -p 2222 "cape@$WIN_IP" "$CMD" 2>&1
