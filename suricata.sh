#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "[-] Error: This script must be run as root (sudo)." 
   exit 1
fi

SRC_DIR="/usr/src/absolute-scratch-build"
mkdir -p "$SRC_DIR"
cd "$SRC_DIR"

echo "[+] Step 0: Compiling GNU Make from source (Stage 0 Baseline Build Tool)..."
wget -O make.tar.gz https://ftp.gnu.org/gnu/make/make-4.4.1.tar.gz
tar -xzf make.tar.gz
cd make-4.4.1
./configure --prefix=/usr/local
build_jobs=$(nproc 2>/dev/null || echo 1)
./build.sh
./make install
cd "$SRC_DIR"

# Prepend /usr/local/bin to enforce usage of source-compiled tools
export PATH="/usr/local/bin:$PATH"
export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:/usr/local/share/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="/usr/local/lib:$LD_LIBRARY_PATH"

echo "[+] Step 1: Compiling and Installing GNU Binutils from source..."
wget -O binutils.tar.xz https://ftp.gnu.org/gnu/binutils/binutils-2.42.tar.xz
tar -xf binutils.tar.xz
cd binutils-2.42
mkdir -p build && cd build
../configure --prefix=/usr/local --enable-gold --enable-plugins --disable-werror
make -j"$build_jobs"
make install
cd "$SRC_DIR"

echo "[+] Step 2: Compiling and Installing GNU GCC Compiler from source..."
wget -O gcc.tar.xz https://ftp.gnu.org/gnu/gcc/gcc-13.2.0/gcc-13.2.0.tar.xz
tar -xf gcc.tar.xz
cd gcc-13.2.0
# Download prerequisite libraries required by GCC internally
./contrib/download_prerequisites
mkdir -p build && cd build
../configure \
    --prefix=/usr/local \
    --enable-languages=c,c++ \
    --disable-multilib \
    --enable-bootstrap
make -j"$build_jobs" bootstrap
make install
cd "$SRC_DIR"

echo "[+] Step 3: Compiling and Installing Rust Toolchain from source..."
wget https://static.rust-lang.org/dist/rustc-1.75.0-src.tar.gz
tar -xzf rustc-1.75.0-src.tar.gz
cd rustc-1.75.0-src
./configure --prefix=/usr/local
./x.py build && ./x.py install
cd "$SRC_DIR"

echo "[+] Step 4: Compiling and Installing libyaml from source..."
wget -O libyaml.tar.gz https://github.com/yaml/libyaml/archive/refs/tags/0.2.5.tar.gz
tar -xzf libyaml.tar.gz
cd libyaml-0.2.5
./bootstrap
./configure --prefix=/usr/local
make -j"$build_jobs"
make install
cd "$SRC_DIR"

echo "[+] Step 5: Compiling and Installing libpcap from source..."
wget -O libpcap.tar.gz https://www.tcpdump.org/release/libpcap-1.10.4.tar.gz
tar -xzf libpcap.tar.gz
cd libpcap-1.10.4
./configure --prefix=/usr/local
make -j"$build_jobs"
make install
cd "$SRC_DIR"

echo "[+] Step 6: Compiling and Installing libnet from source..."
wget -O libnet.tar.gz https://github.com/libnet/libnet/releases/download/v1.3.1/libnet-1.3.1.tar.gz
tar -xzf libnet.tar.gz
cd libnet-1.3.1
./configure --prefix=/usr/local
make -j"$build_jobs"
make install
cd "$SRC_DIR"

echo "[+] Step 7: Compiling and Installing Jansson (JSON) from source..."
wget -O jansson.tar.gz https://github.com/akheron/jansson/releases/download/v2.14/jansson-2.14.tar.gz
tar -xzf jansson.tar.gz
cd jansson-2.14
autoreconf -i
./configure --prefix=/usr/local
make -j"$build_jobs"
make install
cd "$SRC_DIR"

echo "[+] Step 8: Updating dynamic linker library cache..."
ldconfig

echo "[+] Step 9: Downloading and Compiling Suricata from absolute source..."
if [[ -d "suricata" ]]; then
    rm -rf suricata
fi
git clone https://github.com/OISF/suricata.git suricata
cd suricata

./autogen.sh
./configure \
    --prefix=/usr \
    --sysconfdir=/etc \
    --localstatedir=/var \
    --enable-nfqueue \
    --enable-rust \
    LDFLAGS="-L/usr/local/lib" \
    CPPFLAGS="-I/usr/local/include"

make -j"$build_jobs"
make install
make install-full

echo "[+] Complete! GNU Make, Compilers (GCC/Binutils/Rust), libraries, and Suricata have all been built from scratch."
suricata --build-info
