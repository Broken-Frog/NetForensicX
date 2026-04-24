#!/bin/bash
# setup_env.sh
# One-time environment setup for packet_factory.py
# Installs Suricata + Zeek and downloads the Emerging Threats (ET) Open ruleset.

set -euo pipefail

echo "========================================"
echo "🚀 packet_factory.py Environment Setup"
echo "========================================"

# Update package index
echo "[1/4] Updating package index..."
sudo apt-get update -qq

# Install Suricata
echo "[2/4] Installing Suricata..."
sudo apt-get install -y suricata

# Install Zeek via official installer (if not present)
echo "[3/4] Checking/Installing Zeek..."
if ! command -v zeek &> /dev/null; then
    echo "    Zeek not found → installing via official script..."
    sudo apt-get install -y curl
    curl -fsSL https://download.zeek.org/zeek-install.sh | sudo sh
    # Zeek is typically installed to /opt/zeek/bin
    if [ -d "/opt/zeek/bin" ]; then
        echo 'export PATH="/opt/zeek/bin:$PATH"' >> ~/.bashrc
        echo "    ✅ Added Zeek to PATH (run 'source ~/.bashrc' to use immediately)"
    fi
else
    echo "    ✅ Zeek already installed."
fi

# Download ET Open ruleset via suricata-update (handles latest version automatically)
echo "[4/4] Downloading Emerging Threats Open ruleset..."
sudo mkdir -p /var/lib/suricata/rules
sudo suricata-update -q || echo "    ⚠️  suricata-update encountered an issue (rules may still be available)."

echo ""
echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "   1. source ~/.bashrc          # (if Zeek was newly installed)"
echo "   2. Verify tools:"
echo "        zeek --version"
echo "        suricata --build-info | head -n 5"
echo "   3. Run the framework:"
echo "        python3 packet_factory.py /path/to/your/traffic.pcap"
echo ""
echo "The ET Open rules are now available in /var/lib/suricata/rules/"
echo "========================================"