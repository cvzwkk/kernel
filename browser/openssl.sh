#!/usr/bin/env bash
set -euo pipefail

# Configuration options
OPENSSL_BRANCH="${1:-master}"  # Can be 'master' or a stable tag like 'openssl-4.0.1' or 'openssl-3.5.7'
INSTALL_PREFIX="${INSTALL_PREFIX:-/usr/local/custom-openssl}"
BUILD_DIR="$(mktemp -d)"

echo "=== OpenSSL Automated Build Script ==="
echo "Target Branch/Tag: ${OPENSSL_BRANCH}"
echo "Install Prefix:    ${INSTALL_PREFIX}"
echo "Build Directory:   ${BUILD_DIR}"
echo "======================================"

# Ensure required build tools are installed (Debian/Ubuntu example)
echo "[+] Checking build prerequisites..."
if command -v apt-get &> /dev/null; then
    sudo apt-get update
    sudo apt-get install -y build-essential checkinstall zlib1g-dev git perl wget
fi

# Clone repository
echo "[+] Cloning OpenSSL repository..."
git clone --depth 1 --branch "${OPENSSL_BRANCH}" https://github.com/openssl/openssl.git "${BUILD_DIR}/openssl"

cd "${BUILD_DIR}/openssl"

# Configure build flags
echo "[+] Configuring OpenSSL..."
./config \
    --prefix="${INSTALL_PREFIX}" \
    --openssldir="${INSTALL_PREFIX}" \
    shared \
    zlib \
    enable-ec_explicit_curves

# Compile using all available CPU cores
CPU_CORES=$(nproc)
echo "[+] Compiling OpenSSL using ${CPU_CORES} cores..."
make -j "${CPU_CORES}"

# Optional: Run tests (uncomment if you want to verify crypto correctness)
# echo "[+] Running test suite..."
# make test

# Install
echo "[+] Installing OpenSSL to ${INSTALL_PREFIX}..."
if [ "$EUID" -ne 0 ] && [[ "$INSTALL_PREFIX" == /usr* ]]; then
    sudo make install
else
    make install
fi

# Cleanup
echo "[+] Cleaning up build directory..."
rm -rf "${BUILD_DIR}"

echo "=== Build Complete Successfully! ==="
echo "To use your custom OpenSSL build, update your environment paths:"
echo "  export PATH=\"${INSTALL_PREFIX}/bin:\$PATH\""
echo "  export LD_LIBRARY_PATH=\"${INSTALL_PREFIX}/lib64:\$LD_LIBRARY_PATH\""
echo "Verify version via: ${INSTALL_PREFIX}/bin/openssl version -a"
