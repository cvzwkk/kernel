#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "[-] Error: This script must be run as root (sudo)." 
   exit 1
fi

SRC_DIR="/usr/src/absolute-firewall-scratch"
mkdir -p "$SRC_DIR"
cd "$SRC_DIR"

echo "[+] Step 0: Compiling Native Build Tools & Toolchains Completely From Source (No APT)..."

# 0.1: Build GNU Make from source
wget -O make.tar.gz https://ftp.gnu.org/gnu/make/make-4.4.1.tar.gz
tar -xzf make.tar.gz
cd make-4.4.1
./configure --prefix=/usr/local
BUILD_JOBS=$(nproc 2>/dev/null || echo 1)
./build.sh
./make install
cd "$SRC_DIR"

# Enforce local source tools in path
export PATH="/usr/local/bin:$PATH"
export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:/usr/local/share/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="/usr/local/lib:$LD_LIBRARY_PATH"

# 0.2: Build M4 (Macro processor required for autotools)
wget -O m4.tar.gz https://ftp.gnu.org/gnu/m4/m4-1.4.19.tar.gz
tar -xzf m4.tar.gz
cd m4-1.4.19
./configure --prefix=/usr/local
make -j"$BUILD_JOBS" && make install
cd "$SRC_DIR"

# 0.3: Build Autoconf from source
wget -O autoconf.tar.gz https://ftp.gnu.org/gnu/autoconf/autoconf-2.72.tar.gz
tar -xzf autoconf.tar.gz
cd autoconf-2.72
./configure --prefix=/usr/local
make -j"$BUILD_JOBS" && make install
cd "$SRC_DIR"

# 0.4: Build Automake from source
wget -O automake.tar.gz https://ftp.gnu.org/gnu/automake/automake-1.16.5.tar.gz
tar -xzf automake.tar.gz
cd automake-1.16.5
./configure --prefix=/usr/local
make -j"$BUILD_JOBS" && make install
cd "$SRC_DIR"

# 0.5: Build Libtool from source
wget -O libtool.tar.gz https://ftp.gnu.org/gnu/libtool/libtool-2.4.7.tar.gz
tar -xzf libtool.tar.gz
cd libtool-2.4.7
./configure --prefix=/usr/local
make -j"$BUILD_JOBS" && make install
cd "$SRC_DIR"

# 0.6: Build Flex (Lexical Analyzer) from source
wget -O flex.tar.gz https://github.com/westes/flex/releases/download/v2.6.4/flex-2.6.4.tar.gz
tar -xzf flex.tar.gz
cd flex-2.6.4
./configure --prefix=/usr/local
make -j"$BUILD_JOBS" && make install
cd "$SRC_DIR"

# 0.7: Build Bison (Parser Generator) from source
wget -O bison.tar.xz https://ftp.gnu.org/gnu/bison/bison-3.8.2.tar.xz
tar -xzf bison.tar.xz
cd bison-3.8.2
./configure --prefix=/usr/local
make -j"$BUILD_JOBS" && make install
cd "$SRC_DIR"

echo "[+] Step 1: Compiling and Installing libmnl from source..."
cd "$SRC_DIR"
wget https://www.netfilter.org/projects/libmnl/files/libmnl-1.0.5.tar.xz
tar -xf libmnl-1.0.5.tar.xz
cd libmnl-1.0.5
./configure --prefix=/usr/local
make -j"$BUILD_JOBS" && make install
cd "$SRC_DIR"

echo "[+] Step 2: Compiling and Installing libnftnl from source..."
cd "$SRC_DIR"
wget https://www.netfilter.org/projects/libnftnl/files/libnftnl-1.2.6.tar.xz
tar -xf libnftnl-1.2.6.tar.xz
cd libnftnl-1.2.6
./configure --prefix=/usr/local
make -j"$BUILD_JOBS" && make install
cd "$SRC_DIR"

echo "[+] Step 3: Compiling and Installing nftables from source..."
cd "$SRC_DIR"
wget https://www.netfilter.org/projects/nftables/files/nftables-1.1.0.tar.xz
tar -xf nftables-1.1.0.tar.xz
cd nftables-1.1.0
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var
make -j"$BUILD_JOBS" && make install
cd "$SRC_DIR"

echo "[+] Step 4: Compiling and Installing libnfnetlink from source..."
cd "$SRC_DIR"
wget https://www.netfilter.org/projects/libnfnetlink/files/libnfnetlink-1.0.2.tar.bz2
tar -xf libnfnetlink-1.0.2.tar.bz2
cd libnfnetlink-1.0.2
./configure --prefix=/usr/local
make -j"$BUILD_JOBS" && make install
cd "$SRC_DIR"

echo "[+] Step 5: Compiling and Installing libnetfilter_conntrack from source..."
cd "$SRC_DIR"
wget https://www.netfilter.org/projects/libnetfilter_conntrack/files/libnetfilter_conntrack-1.0.9.tar.bz2
tar -xf libnetfilter_conntrack-1.0.9.tar.bz2
cd libnetfilter_conntrack-1.0.9
./configure --prefix=/usr/local
make -j"$BUILD_JOBS" && make install
cd "$SRC_DIR"

echo "[+] Step 6: Compiling and Installing iptables from source..."
cd "$SRC_DIR"
wget https://www.netfilter.org/projects/iptables/files/iptables-1.8.10.tar.xz
tar -xf iptables-1.8.10.tar.xz
cd iptables-1.8.10
./configure --prefix=/usr --sbindir=/sbin --sysconfdir=/etc --enable-libnftables
make -j"$BUILD_JOBS" && make install
cd "$SRC_DIR"

echo "[+] Step 7: Updating dynamic linker cache..."
ldconfig

echo "[+] Verification: Checking source-compiled binaries..."
nft --version
iptables --version

echo "[+] Complete! Native build tools (Make, Autotools, Flex, Bison) and firewall suites have all been built and installed completely from sourc
"

#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;

        # Allow established and related incoming connections
        ct state established,related accept

        # Allow loopback interface traffic
        iifname "lo" accept

        # Drop invalid packets
        ct state invalid drop
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
    }

    chain output {
        type filter hook output priority filter; policy drop;

        # Allow loopback interface traffic
        oifname "lo" accept

        # Allow established and related outgoing connections
        ct state established,related accept

        # Allow DNS (UDP/TCP port 53)
        udp dport 53 accept
        tcp dport 53 accept

        # Allow HTTP (TCP port 80) and HTTPS (TCP port 443)
        tcp dport 80 accept
        tcp dport 443 accept
    }
}

#!/usr/bin/env bash
set -euo pipefail

# Flush existing rules and reset counters
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Set default policies to DROP everything
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# 1. Allow loopback traffic
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# 2. Allow established and related incoming/outgoing connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# 3. Allow Outbound DNS (UDP and TCP port 53)
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

# 4. Allow Outbound HTTP (port 80) and HTTPS (port 443)
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT

echo "[+] iptables strict egress policy applied: Only DNS, HTTP, and HTTPS are permitted."

