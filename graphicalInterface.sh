#!/bin/bash

# Exit immediately if any command fails
set -e

echo "=========================================================="
echo "Phase 0: Bootstrapping Minimum Raw Environment"
echo "=========================================================="
# Setup a clean workspace directory
WORKSPACE="$HOME/absolute-scratch-workspace"
mkdir -p "$WORKSPACE"
cd "$WORKSPACE"

# Ensure local custom prefix is checked by compilers, pkg-config, and linker
export PATH="/usr/local/bin:$PATH"
export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:/usr/local/share/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="/usr/local/lib:$LD_LIBRARY_PATH"

echo "=========================================================="
echo "Phase 1: Compiling Linux Kernel Headers (linux-libc-dev) from Source"
echo "=========================================================="
KERNEL_VERSION="6.8.9"
echo "-> Downloading Linux Kernel v${KERNEL_VERSION} source..."
wget -nc https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_VERSION}.tar.xz
tar -xf linux-${KERNEL_VERSION}.tar.xz
cd linux-${KERNEL_VERSION}

echo "-> Installing kernel headers to /usr/local..."
make headers_install INSTALL_HDR_PATH=/usr/local
cd ..

echo "=========================================================="
echo "Phase 2: Compiling GNU C Library (glibc / libc6-dev) from Source"
echo "=========================================================="
GLIBC_VERSION="2.39"
echo "-> Downloading glibc v${GLIBC_VERSION} source..."
wget -nc https://ftp.gnu.org/gnu/glibc/glibc-${GLIBC_VERSION}.tar.xz
tar -xf glibc-${GLIBC_VERSION}.tar.xz
mkdir -p glibc-build
cd glibc-build

echo "-> Configuring glibc..."
../glibc-${GLIBC_VERSION}/configure --prefix=/usr/local --with-headers=/usr/local/include

echo "-> Compiling glibc from source..."
make -j$(nproc)
echo "-> Installing glibc..."
sudo make install
cd ..

echo "=========================================================="
echo "Phase 3: Compiling dpkg-dev & Package Utilities from Source"
echo "=========================================================="
DPKG_VERSION="1.22.6"
wget -nc https://deb.debian.org/debian/pool/main/d/dpkg/dpkg_${DPKG_VERSION}.tar.xz
tar -xf dpkg_${DPKG_VERSION}.tar.xz
cd dpkg-${DPKG_VERSION}
./autogen.sh || true
./configure --prefix=/usr/local
make -j$(nproc)
sudo make install
cd ..

echo "=========================================================="
echo "Phase 4: Compiling GNU Make and Build Essentials from Source"
echo "=========================================================="
GNU_MAKE_VERSION="4.4.1"
wget -nc https://ftp.gnu.org/gnu/make/make-${GNU_MAKE_VERSION}.tar.gz
tar -zxvf make-${GNU_MAKE_VERSION}.tar.gz
cd make-${GNU_MAKE_VERSION}
./configure --prefix=/usr/local
./build.sh
sudo ./src/make install
cd ..

echo "=========================================================="
echo "Phase 5: Compiling Autotools & Toolchain Dependencies from Source"
echo "=========================================================="

# 1. m4
M4_VERSION="1.4.19"
wget -nc https://ftp.gnu.org/gnu/m4/m4-${M4_VERSION}.tar.gz
tar -zxvf m4-${M4_VERSION}.tar.gz
cd m4-${M4_VERSION}
./configure --prefix=/usr/local
make -j$(nproc)
sudo make install
cd ..

# 2. autoconf
AUTOCONF_VERSION="2.72"
wget -nc https://ftp.gnu.org/gnu/autoconf/autoconf-${AUTOCONF_VERSION}.tar.gz
tar -zxvf autoconf-${AUTOCONF_VERSION}.tar.gz
cd autoconf-${AUTOCONF_VERSION}
./configure --prefix=/usr/local
make -j$(nproc)
sudo make install
cd ..

# 3. automake
AUTOMAKE_VERSION="1.16.5"
wget -nc https://ftp.gnu.org/gnu/automake/automake-${AUTOMAKE_VERSION}.tar.gz
tar -zxvf automake-${AUTOMAKE_VERSION}.tar.gz
cd automake-${AUTOMAKE_VERSION}
./configure --prefix=/usr/local
make -j$(nproc)
sudo make install
cd ..

# 4. libtool
LIBTOOL_VERSION="2.4.7"
wget -nc https://ftp.gnu.org/gnu/libtool/libtool-${LIBTOOL_VERSION}.tar.gz
tar -zxvf libtool-${LIBTOOL_VERSION}.tar.gz
cd libtool-${LIBTOOL_VERSION}
./configure --prefix=/usr/local
make -j$(nproc)
sudo make install
cd ..

echo "=========================================================="
echo "Phase 6: Compiling Compression & Dev Libraries from Source"
echo "=========================================================="

# 1. zlib
ZLIB_VERSION="1.3.1"
wget -nc https://www.zlib.net/zlib-${ZLIB_VERSION}.tar.gz
tar -zxvf zlib-${ZLIB_VERSION}.tar.gz
cd zlib-${ZLIB_VERSION}
./configure --prefix=/usr/local
make -j$(nproc)
sudo make install
cd ..

# 2. OpenSSL
OPENSSL_VERSION="3.2.1"
wget -nc https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz
tar -zxvf openssl-${OPENSSL_VERSION}.tar.gz
cd openssl-${OPENSSL_VERSION}
./config --prefix=/usr/local --openssldir=/usr/local/ssl shared zlib
make -j$(nproc)
sudo make install
cd ..

# 3. libffi
git clone https://github.com/libffi/libffi.git --depth 1 || true
cd libffi
./autogen.sh
./configure --prefix=/usr/local
make -j$(nproc)
sudo make install
cd ..

# 4. bzip2
BZIP2_VERSION="1.0.8"
wget -nc https://sourceware.org/pub/bzip2/bzip2-${BZIP2_VERSION}.tar.gz
tar -zxvf bzip2-${BZIP2_VERSION}.tar.gz
cd bzip2-${BZIP2_VERSION}
make -f Makefile-libbz2_so
make clean
make -j$(nproc)
sudo make install PREFIX=/usr/local
cd ..

# 5. Readline
READLINE_VERSION="8.2"
wget -nc https://ftp.gnu.org/gnu/readline/readline-${READLINE_VERSION}.tar.gz
tar -zxvf readline-${READLINE_VERSION}.tar.gz
cd readline-${READLINE_VERSION}
./configure --prefix=/usr/local
make -j$(nproc)
sudo make install
cd ..

# 6. SQLite
SQLITE_VERSION="3450300"
wget -nc https://www.sqlite.org/2024/sqlite-autoconf-${SQLITE_VERSION}.tar.gz
tar -zxvf sqlite-autoconf-${SQLITE_VERSION}.tar.gz
cd sqlite-autoconf-${SQLITE_VERSION}
./configure --prefix=/usr/local
make -j$(nproc)
sudo make install
cd ..

# 7. XZ / lzma
XZ_VERSION="5.4.6"
wget -nc https://github.com/tukaani-project/xz/releases/download/v${XZ_VERSION}/xz-${XZ_VERSION}.tar.gz
tar -zxvf xz-${XZ_VERSION}.tar.gz
cd xz-${XZ_VERSION}
./configure --prefix=/usr/local
make -j$(nproc)
sudo make install
cd ..

echo "=========================================================="
echo "Phase 7: Compiling Python 3 & Toolchain from Source"
echo "=========================================================="
PYTHON_VERSION="3.11.9"
wget -nc https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz
tar -zxvf Python-${PYTHON_VERSION}.tgz
cd Python-${PYTHON_VERSION}
./configure --prefix=/usr/local --enable-optimizations --with-ensurepip=install
make -j$(nproc)
sudo make altinstall
sudo ln -sf /usr/local/bin/python3.11 /usr/local/bin/python3
sudo ln -sf /usr/local/bin/pip3.11 /usr/local/bin/pip3
cd ..

# setuptools & pip from source
git clone https://github.com/pypa/setuptools.git --depth 1 || true
cd setuptools
python3 -m pip install --no-build-isolation . || python3 setup.py install
cd ..

git clone https://github.com/pypa/pip.git --depth 1 || true
cd pip
python3 -m pip install --no-build-isolation . || python3 setup.py install
cd ..

echo "=========================================================="
echo "Phase 8: Compiling Base Build Tools & Wayland Stack"
echo "=========================================================="

# CMake
CMAKE_VERSION="3.29.3"
wget -nc https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}.tar.gz
tar -zxvf cmake-${CMAKE_VERSION}.tar.gz
cd cmake-${CMAKE_VERSION}
./bootstrap --prefix=/usr/local
make -j$(nproc)
sudo make install
cd ..

# Git
GIT_VERSION="2.45.1"
wget -nc https://github.com/git/git/archive/refs/tags/v${GIT_VERSION}.tar.gz -O git-${GIT_VERSION}.tar.gz
tar -zxvf git-${GIT_VERSION}.tar.gz
cd git-${GIT_VERSION}
make configure
./configure --prefix=/usr/local
make -j$(nproc)
sudo make install
cd ..

# pkg-config
PKG_CONFIG_VERSION="0.29.2"
wget -nc https://pkgconfig.freedesktop.org/releases/pkg-config-${PKG_CONFIG_VERSION}.tar.gz
tar -zxvf pkg-config-${PKG_CONFIG_VERSION}.tar.gz
cd pkg-config-${PKG_CONFIG_VERSION}
./configure --prefix=/usr/local --with-internal-glib
make -j$(nproc)
sudo make install
cd ..

# Ninja
git clone https://github.com/ninja-build/ninja.git --depth 1 || true
cd ninja
python3 configure.py --bootstrap
sudo cp ninja /usr/local/bin/
cd ..

# Meson
git clone https://github.com/mesonbuild/meson.git --depth 1 || true
cd meson
sudo python3 setup.py install
cd ..

# scdoc
git clone https://git.sr.ht/~sircmpwn/scdoc --depth 1 || true
cd scdoc
make PREFIX=/usr/local
sudo make PREFIX=/usr/local install
cd ..

# Wayland
git clone https://gitlab.freedesktop.org/wayland/wayland.git --depth 1 || true
cd wayland
meson setup build/ --reconfigure --prefix=/usr/local -Ddocumentation=false -Dtests=false
ninja -C build/
sudo ninja -C build/install
cd ..

# Wayland Protocols
git clone https://gitlab.freedesktop.org/wayland/wayland-protocols.git --depth 1 || true
cd wayland-protocols
meson setup build/ --reconfigure --prefix=/usr/local
ninja -C build/
sudo ninja -C build/install
cd ..

# libdrm
git clone https://gitlab.freedesktop.org/mesa/drm.git libdrm --depth 1 || true
cd libdrm
meson setup build/ --reconfigure --prefix=/usr/local
ninja -C build/
sudo ninja -C build/install
cd ..

# libxkbcommon
git clone https://github.com/xkbcommon/libxkbcommon.git --depth 1 || true
cd libxkbcommon
meson setup build/ --reconfigure --prefix=/usr/local -Denable-docs=false
ninja -C build/
sudo ninja -C build/install
cd ..

# pixman
git clone https://gitlab.freedesktop.org/pixman/pixman.git --depth 1 || true
cd pixman
meson setup build/ --reconfigure --prefix=/usr/local
ninja -C build/
sudo ninja -C build/install
cd ..

# libevdev
git clone https://gitlab.freedesktop.org/libevdev/libevdev.git --depth 1 || true
cd libevdev
meson setup build/ --reconfigure --prefix=/usr/local
ninja -C build/
sudo ninja -C build/install
cd ..

# libinput
git clone https://gitlab.freedesktop.org/libinput/libinput.git --depth 1 || true
cd libinput
meson setup build/ --reconfigure --prefix=/usr/local -Ddocumentation=false -Dtests=false
ninja -C build/
sudo ninja -C build/install
cd ..

# json-c
git clone https://github.com/json-c/json-c.git --depth 1 || true
cd json-c
mkdir -p build && cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local
make -j$(nproc)
sudo make install
cd ../..

# libpcre2
git clone https://github.com/PCRE2Project/pcre2.git --depth 1 || true
cd pcre2
./autogen.sh
./configure --prefix=/usr/local
make -j$(nproc)
sudo make install
cd ..

echo "=========================================================="
echo "Phase 9: Refreshing Dynamic Linker Cache"
echo "=========================================================="
sudo ldconfig

echo "=========================================================="
echo "SUCCESS! Linux headers, glibc, dpkg, compilers, and the entire"
echo "Wayland stack have been built and compiled from raw source."
echo "=========================================================="

# If building swaylock/swayidle from source in your scratch workspace:
git clone https://github.com/swaywm/swaylock.git --depth 1 || true
cd swaylock
meson setup build --prefix=/usr/local
ninja -C build
sudo ninja -C build/install
cd ..

git clone https://github.com/swaywm/swayidle.git --depth 1 || true
cd swayidle
meson setup build --prefix=/usr/local
ninja -C build
sudo ninja -C build/install
cd ..

cat << 'EOF' >> /home/guest/.bash_profile

# Automatically launch Sway on TTY1 login for the guest user
if [[ -z "$DISPLAY" ]] && [[ "$(tty)" = "/dev/tty1" ]]; then
    exec sway
fi
EOF

# Ensure proper ownership
sudo chown guest:guest /home/guest/.bash_profile

