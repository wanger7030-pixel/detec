#!/bin/bash
# WSL Ubuntu Setup Script for Snort 3
# Run this inside WSL after Ubuntu is installed:
#   wsl -d Ubuntu-22.04 -- bash /path/to/project/tools/setup_wsl_snort.sh

set -e

echo "============================================"
echo "  Snort 3 Installation for WSL Ubuntu"
echo "============================================"

# 1. Update system
echo "[1/4] Updating system packages..."
sudo apt-get update -qq
sudo apt-get upgrade -y -qq

# 2. Install Snort 3 from Ubuntu repos
echo "[2/4] Installing Snort 3..."
sudo apt-get install -y snort 2>/dev/null || {
    echo "  Snort 3 not in repos, installing from PPA..."
    sudo add-apt-repository -y ppa:oisf/suricata-stable 2>/dev/null || true
    sudo apt-get update -qq
    # If snort3 is not available, install snort2 as fallback
    sudo apt-get install -y snort 2>/dev/null || {
        echo "  Trying manual Snort 3 install..."
        sudo apt-get install -y \
            build-essential cmake libpcap-dev libdnet-dev \
            libdumbnet-dev libluajit-5.1-dev libssl-dev \
            libpcre3-dev zlib1g-dev liblzma-dev \
            libhwloc-dev pkg-config flex bison

        # Install libdaq
        cd /tmp
        if [ ! -d "libdaq" ]; then
            git clone https://github.com/snort3/libdaq.git
            cd libdaq
            ./bootstrap
            ./configure
            make -j$(nproc)
            sudo make install
        fi

        # Install Snort 3
        cd /tmp
        if [ ! -d "snort3" ]; then
            git clone https://github.com/snort3/snort3.git
            cd snort3
            ./configure_cmake.sh --prefix=/usr/local
            cd build
            make -j$(nproc)
            sudo make install
        fi

        sudo ldconfig
    }
}

# 3. Verify installation
echo "[3/4] Verifying Snort installation..."
if command -v snort &> /dev/null; then
    snort --version 2>&1 | head -5
    echo "  [OK] Snort installed successfully!"
elif [ -f /usr/local/bin/snort ]; then
    /usr/local/bin/snort --version 2>&1 | head -5
    echo "  [OK] Snort 3 installed at /usr/local/bin/snort"
else
    echo "  [FAIL] Snort not found!"
    exit 1
fi

# 4. Install additional tools
echo "[4/4] Installing network utilities..."
sudo apt-get install -y tcpdump tshark net-tools -qq 2>/dev/null || true

echo ""
echo "============================================"
echo "  Setup Complete!"
echo "============================================"
echo "  Run Snort on a PCAP file:"
echo "    snort -r /mnt/c/.../pcap/file.pcap -A alert_fast -c /etc/snort/snort.conf"
echo ""
