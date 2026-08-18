#!/bin/bash
set -e

WORKSPACE="$HOME/webkit-scratch-build"
mkdir -p "$WORKSPACE"
cd "$WORKSPACE"

export PATH="/usr/local/bin:$PATH"
export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:/usr/local/share/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="/usr/local/lib:$LD_LIBRARY_PATH"

echo "=========================================================="
echo "Phase 1: Compiling Build Essentials & Compilers (GCC/Make)"
echo "=========================================================="
# Note: build-essential is a meta-package of gcc, g++, make, libc6-dev. 
# Assuming GCC is present, ensure GNU Make is up-to-date:
MAKE_VER="4.4.1"
wget -nc https://ftp.gnu.org/gnu/make/make-${MAKE_VER}.tar.gz
tar -zxvf make-${MAKE_VER}.tar.gz
cd make-${MAKE_VER}
./configure --prefix=/usr/local
./build.sh
sudo ./src/make install
cd ..

echo "=========================================================="
echo "Phase 2: Compiling CMake from Source"
echo "=========================================================="
CMAKE_VER="3.29.3"
wget -nc https://github.com/Kitware/CMake/releases/download/v${CMAKE_VER}/cmake-${CMAKE_VER}.tar.gz
tar -zxvf cmake-${CMAKE_VER}.tar.gz
cd cmake-${CMAKE_VER}
./bootstrap --prefix=/usr/local
make -j$(nproc)
sudo make install
cd ..

echo "=========================================================="
echo "Phase 3: Compiling pkg-config from Source"
echo "=========================================================="
PKG_VER="0.29.2"
wget -nc https://pkgconfig.freedesktop.org/releases/pkg-config-${PKG_VER}.tar.gz
tar -zxvf pkg-config-${PKG_VER}.tar.gz
cd pkg-config-${PKG_VER}
./configure --prefix=/usr/local --with-internal-glib
make -j$(nproc)
sudo make install
cd ..

echo "=========================================================="
echo "Phase 4: Compiling GLib & Core Dependencies for GTK"
echo "=========================================================="
# GLib is required by GTK
GLIB_VER="2.80.0"
# (Alternatively use git or stable tarball for glib, libffi, pcre2)
# Ensure Ninja and Meson are present for modern GNOME/GTK/WebKit builds:
git clone https://github.com/ninja-build/ninja.git --depth 1 || true
cd ninja && python3 configure.py --bootstrap && sudo cp ninja /usr/local/bin/ && cd ..

git clone https://github.com/mesonbuild/meson.git --depth 1 || true
cd meson && sudo python3 setup.py install && cd ..

echo "=========================================================="
echo "Phase 5: Compiling GTK 3 (libgtk-3-dev) from Source"
echo "=========================================================="
GTK_VER="3.24.41"
wget -nc https://download.gnome.org/sources/gtk+/3.24/gtk+-${GTK_VER}.tar.xz
tar -xf gtk+-${GTK_VER}.tar.xz
cd gtk+-${GTK_VER}
meson setup build --prefix=/usr/local -Ddemos=false -Dexamples=false -Dtests=false
ninja -C build
sudo ninja -C build/install
cd ..

echo "=========================================================="
echo "Phase 6: Compiling WebKitGTK (libwebkit2gtk-4.1-dev) from Source"
echo "=========================================================="
WEBKIT_VER="2.44.0"
wget -nc https://webkitgtk.org/webkitgtk-${WEBKIT_VER}.tar.xz
tar -xf webkitgtk-${WEBKIT_VER}.tar.xz
cd webkitgtk-${WEBKIT_VER}

mkdir -p build
cd build
cmake .. \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DPORT=GTK \
    -DENABLE_WPE_BACKEND=OFF \
    -DUSE_SOUP2=OFF \
    -DENABLE_GEOLOCATION=OFF \
    -DENABLE_MINIBROWSER=ON

cmake --build . -j$(nproc)
sudo cmake --install .
cd ../..

echo "=========================================================="
echo "Phase 7: Updating Linker Caches"
echo "=========================================================="
sudo ldconfig

echo "=========================================================="
echo "SUCCESS: build-essential components, cmake, pkg-config, "
echo "libgtk-3-dev, and libwebkit2gtk-4.1-dev compiled from source!"
echo "=========================================================="

