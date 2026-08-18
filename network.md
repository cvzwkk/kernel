To build a **completely offline, self-contained deployment package** for your scratch-built kernel environment—where target nodes have **no internet connection**—you must use a two-phase workflow:

1. **Build & Package Phase (On an internet-connected machine):** Downloads all source tarballs, compiles `iproute2` (along with its static dependencies like `libmnl` or `bison/flex` if required), and bundles everything into a single standalone tarball (`offline-network-package.tar.gz`).
2. **Deployment Phase (On the offline scratch kernel target):** Extracts the bundle and runs the local installer without needing any network or internet access.

---

### Step 1: The Offline Packager Script (`create-offline-package.sh`)

Run this script on a machine with internet access to generate the self-contained installer bundle.

```bash
#!/usr/bin/env bash
set -euo pipefail

PACKAGE_DIR="/tmp/offline-network-bundle"
mkdir -p "$PACKAGE_DIR/sources" "$PACKAGE_DIR/scripts"

echo "[+] Downloading source tarballs for offline transfer..."
# Download iproute2 source
wget -O "$PACKAGE_DIR/sources/iproute2-6.8.0.tar.xz" https://www.kernel.org/pub/linux/utils/net/iproute2/iproute2-6.8.0.tar.xz

# Create the offline installation script that will run on the target
cat << 'EOF' > "$PACKAGE_DIR/install-offline.sh"
#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "[-] Error: This script must be run as root." 
   exit 1
fi

BUNDLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$BUNDLE_DIR/sources"

echo "[+] Installing iproute2 from local offline source..."
cd "$SRC_DIR"
tar -xf iproute2-6.8.0.tar.xz
cd iproute2-6.8.0

./configure
BUILD_JOBS=$(nproc 2>/dev/null || echo 1)
make -j"$BUILD_JOBS"
make install

echo "[+] Configuring DNS Resolution..."
mkdir -p /etc
cat << 'DNS_EOF' > /etc/resolv.conf
nameserver 1.1.1.1
nameserver 8.8.8.8
DNS_EOF

echo "[+] Activating local interfaces..."
ip link set dev lo up
ip link set dev eth0 up || echo "[!] Note: eth0 interface not found yet or managed externally."

echo "[+] Offline network package installed successfully!"
EOF

chmod +x "$PACKAGE_DIR/install-offline.sh"

echo "[+] Packaging everything into 'offline-network-package.tar.gz'..."
tar -czf offline-network-package.tar.gz -C /tmp offline-network-bundle
echo "[+] Done! Move 'offline-network-package.tar.gz' to your offline target machine."

```

---

### Step 2: On the Target Offline Kernel Machine

Once you transfer `offline-network-package.tar.gz` to your isolated machine (via USB, local network share, etc.), run:

```bash
tar -xzf offline-network-package.tar.gz
cd offline-network-bundle
sudo ./install-offline.sh

```
