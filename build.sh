#!/usr/bin/env bash
# ==============================================================================
# Script: build_hardened_kernel.sh
# Description: Automated Zero-Trust Linux Kernel Build, Hardening, and Signing
# ==============================================================================

set -euo pipefail

# ------------------------------------------------------------------------------
# Configuration Variables
# ------------------------------------------------------------------------------
KERNEL_VERSION="6.6.151"
KERNEL_TARBALL="linux-${KERNEL_VERSION}.tar.xz"
BASE_URL="https://cdn.kernel.org/pub/linux/kernel/v6.x"
BUILD_DIR="$(pwd)/kernel_build"
SRC_DIR="${BUILD_DIR}/linux-${KERNEL_VERSION}"
KEYS_DIR="${BUILD_DIR}/keys"

# Torvalds & Stable Release PGP Key Fingerprints
PGP_KEYS=(
  "ABAF11C65A2970B130ABE3C479BE3E4300411886" # Linus Torvalds
  "647F28654894E3BD457199BE38DBBDC86092693E" # Greg Kroah-Hartman
)

# Inline PGP Signature provided for linux-6.6.151 (.tar version)
read -r -d '' KERNEL_SIG_DATA << 'EOF' || true
-----BEGIN PGP SIGNATURE-----
Comment: This signature is for the .tar version of the archive
Comment: git archive --format tar --prefix=linux-6.6.151/ v6.6.151
Comment: git version 2.55.0

iQIzBAABCgAdFiEEZH8oZUiU471FcZm+ONu9yGCSaT4FAmp4xYAACgkQONu9yGCS
aT4ERhAAiEKckujE3K5hZ2aQCyDK1O1hGL0YbBUgS7JPa9ddyKEUfGX8tmYFkwCx
7LFcijHfQvOvo+XBx2DOq3zMwmg8z44eau6snM5Lpc7PD+wzqr4WKP+Y0t2dTaLX
j6BWnQFAV4qtjEjm+lCxV5FjlDVBjh6PJ18u2aX7gYG9OxAx26rvgCC7FYpObb2G
lBD7xOvIGdxD4GldB+i+fC6p17I1QH6Eh85kU6BtfuSEXSVKd50MlxN5jKirEfoM
3sBT2V+4wejcbSOgZPk8EIU1MJT/AjkS6yjIJS6UUbK7ju+9WwFEmonfhHDWP1kG
r5H/PQJ8A8Dl4a0isPWtHOKry2IrWU/Cz32L3qJLzP9z4MrWse5o2tWnR92zDQvX
mFd8E+o4mQbUO4DCsAmfEYXZyuV5pp+ACBjtkoWiFNpdH9QPdOnBzE+F5uEhj3x7
UXuFpX0UOZcAcaIcu+z809RHQUrflavbif01Qxmhxqs2+7UdKsKBNNiTfwUKSjnk
uOlAuxQuhdTjocADMLY1i5SEMlOUCQF+i57lRLZ9mI9njEznofIaV1w17RqYtwb7
L9ChIXnHW+0vvU/6ny4/9GyiWeKgBqcpGrLOOFA690nQRebUbw+XAmotU2uTaWuZ
MM0lT/V6rm9gj5AO9LHoLVUrOT6vnG4+eHG3MegT1axZnRSXwDY=
=FXro
-----END PGP SIGNATURE-----
EOF

# ------------------------------------------------------------------------------
# Helper Functions
# ------------------------------------------------------------------------------
log_info()  { echo -e "\e[34m[INFO]\e[0m $1"; }
log_warn()  { echo -e "\e[33m[WARN]\e[0m $1"; }
log_error() { echo -e "\e[31m[ERROR]\e[0m $1"; exit 1; }

check_dependencies() {
    log_info "Verifying required build toolchain and security utilities..."
    local deps=(wget xz gpg make gcc flex bison bc libssl-dev libelf-dev sbsigntool openssl dwarves libncurses-dev)
    for cmd in "${deps[@]}"; do
        if ! dpkg -s "$cmd" >/dev/null 2>&1 && ! command -v "$cmd" >/dev/null 2>&1; then
            log_warn "Missing dependency: $cmd. Attempting installation..."
            apt-get update && apt-get install -y "$cmd" || log_error "Failed to install $cmd."
        fi
    done
}

# ------------------------------------------------------------------------------
# Step 1: Secure Source Acquisition & Cryptographic Verification
# ------------------------------------------------------------------------------
setup_workspace() {
    mkdir -p "${BUILD_DIR}" "${KEYS_DIR}"
    cd "${BUILD_DIR}"

    if [ ! -f "${KERNEL_TARBALL}" ]; then
        log_info "Downloading Linux Kernel v${KERNEL_VERSION} source..."
        wget -q --show-progress "${BASE_URL}/${KERNEL_TARBALL}"
    fi

    log_info "Importing Kernel Maintainer PGP Keys via WKD and fallback keyservers..."
    gpg --batch --quiet --locate-keys torvalds@kernel.org gregkh@kernel.org || \
    gpg --batch --quiet --keyserver hkps://keys.openpgp.org --recv-keys "${PGP_KEYS[@]}" || \
    gpg --batch --quiet --keyserver hkp://keyserver.ubuntu.com --recv-keys "${PGP_KEYS[@]}" || \
        log_warn "Key reception warning: Continuing with local keyring check."

    log_info "Verifying PGP cryptographic signature of the source archive..."
    echo "${KERNEL_SIG_DATA}" > "${BUILD_DIR}/kernel.sig"
    
    xzcat "${KERNEL_TARBALL}" | gpg --batch --verify "${BUILD_DIR}/kernel.sig" - || \
        log_error "PGP Signature verification failed! Source compromised."

    log_info "Extracting kernel source code..."
    rm -rf "${SRC_DIR}"
    tar -xf "${KERNEL_TARBALL}"
}

# ------------------------------------------------------------------------------
# Step 2: Generate Cryptographic Signing Keys
# ------------------------------------------------------------------------------
generate_keys() {
    log_info "Generating local X.509 Secure Boot and Kernel Module signing keypair..."
    
    mkdir -p "${SRC_DIR}/certs"

    if [ ! -f "${KEYS_DIR}/DB.key" ]; then
        # Generate traditional PKCS#1 private key required by kernel extract-cert
        openssl genrsa -out "${KEYS_DIR}/DB.key.tmp" 4096
        openssl rsa -in "${KEYS_DIR}/DB.key.tmp" -out "${KEYS_DIR}/DB.key"
        rm -f "${KEYS_DIR}/DB.key.tmp"

        # Generate self-signed X.509 certificate using the key
        openssl req -new -x509 -days 3650 -key "${KEYS_DIR}/DB.key" \
            -out "${KEYS_DIR}/DB.crt" \
            -subj "/CN=Zero Trust Custom Kernel Signing Key/"
            
        chmod 600 "${KEYS_DIR}/DB.key"
    else
        log_info "Existing keys found in ${KEYS_DIR}, skipping generation."
    fi

    # Copy keys directly into kernel source certs directory for clean compilation linkage
    cp "${KEYS_DIR}/DB.key" "${SRC_DIR}/certs/signing_key.pem"
    cp "${KEYS_DIR}/DB.crt" "${SRC_DIR}/certs/signing_key.x509"
}

# ------------------------------------------------------------------------------
# Step 3: Hardened Config Injection
# ------------------------------------------------------------------------------
configure_kernel() {
    cd "${SRC_DIR}"
    log_info "Generating default baseline configuration..."
    make defconfig

    log_info "Injecting Zero-Trust Hardening & Exploitation Mitigation Flags..."

    set_cfg() {
        local option=$1
        local value=$2
        ./scripts/config --file .config --set-val "$option" "$value" 2>/dev/null || \
        ./scripts/config --file .config --"$value" "$option"
    }

    enable_cfg()  { ./scripts/config --file .config --enable "$1"; }
    disable_cfg() { ./scripts/config --file .config --disable "$1"; }
    str_cfg()     { ./scripts/config --file .config --set-str "$1" "$2"; }

    # --- Baseline Memory Safety & Entropy ---
    enable_cfg  CONFIG_RANDOMIZE_BASE
    enable_cfg  CONFIG_RANDOMIZE_MEMORY
    enable_cfg  CONFIG_STRICT_KERNEL_RWX
    enable_cfg  CONFIG_STRICT_MODULE_RWX
    enable_cfg  CONFIG_INIT_ON_ALLOC_DEFAULT_ON
    enable_cfg  CONFIG_INIT_ON_FREE_DEFAULT_ON
    enable_cfg  CONFIG_HARDENED_USERCOPY
    enable_cfg  CONFIG_FORTIFY_SOURCE
    enable_cfg  CONFIG_SHUFFLE_PAGE_ALLOCATOR
    enable_cfg  CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT

    # --- Allocator & Stack Hardening ---
    enable_cfg  CONFIG_SLAB_FREELIST_HARDENED
    enable_cfg  CONFIG_SLAB_FREELIST_RANDOM
    enable_cfg  CONFIG_GCC_PLUGIN_STACKLEAK
    enable_cfg  CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF_ALL
    enable_cfg  CONFIG_GCC_PLUGIN_RANDSTRUCT
    enable_cfg  CONFIG_VMAP_STACK

    # --- Kernel Boundaries & Lockdown ---
    enable_cfg  CONFIG_SECURITY
    enable_cfg  CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY
    enable_cfg  CONFIG_SECURITY_DMESG_RESTRICT
    enable_cfg  CONFIG_SECURITY_TIOCSTI_RESTRICT
    enable_cfg  CONFIG_STRICT_DEVMEM
    enable_cfg  CONFIG_IO_STRICT_DEVMEM
    disable_cfg CONFIG_DEVMEM

    # --- Mandatory Access Control & Integrity ---
    enable_cfg  CONFIG_SECURITY_SELINUX
    enable_cfg  CONFIG_SECURITY_APPARMOR
    enable_cfg  CONFIG_SECURITY_IPE
    enable_cfg  CONFIG_IMA
    enable_cfg  CONFIG_IMA_DEFAULT_POLICY
    enable_cfg  CONFIG_EVM

    # --- Module Integrity & Verification ---
    enable_cfg  CONFIG_MODULE_SIG
    enable_cfg  CONFIG_MODULE_SIG_FORCE
    enable_cfg  CONFIG_MODULE_SIG_ALL
    enable_cfg  CONFIG_MODULE_SIG_SHA512
    str_cfg     CONFIG_MODULE_SIG_HASH "sha512"
    str_cfg     CONFIG_MODULE_SIG_KEY "certs/signing_key.pem"
    
    str_cfg     CONFIG_SYSTEM_TRUSTED_KEYS ""
    str_cfg     CONFIG_SYSTEM_REVOCATION_KEYS ""

    # --- Block Integrity ---
    enable_cfg  CONFIG_BLK_DEV_DM
    enable_cfg  CONFIG_DM_VERITY
    enable_cfg  CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG

    # --- Hardware Control-Flow & CPU Protections ---
    enable_cfg  CONFIG_X86_KERNEL_IBT
    enable_cfg  CONFIG_X86_USER_SHSTK
    enable_cfg  CONFIG_X86_SMAP
    enable_cfg  CONFIG_X86_UMIP
    enable_cfg  CONFIG_PAGE_TABLE_ISOLATION
    enable_cfg  CONFIG_RETPOLINE

    # --- Fault & Panic Containment ---
    enable_cfg  CONFIG_PANIC_ON_OOPS
    set_cfg     CONFIG_PANIC_TIMEOUT "-1"
    enable_cfg  CONFIG_RESET_ATTACK_MITIGATION
    disable_cfg CONFIG_CRYPTO_MANAGER_DISABLE_TESTS

    # --- Additional Hardening Flags ---
    enable_cfg  CONFIG_STATIC_USERMODEHELPER
    str_cfg     CONFIG_STATIC_USERMODEHELPER_PATH "/sbin/usermodehelper"
    enable_cfg  CONFIG_SECCOMP
    enable_cfg  CONFIG_SECCOMP_FILTER
    enable_cfg  CONFIG_BPF_JIT_ALWAYS_ON
    disable_cfg CONFIG_COMPAT_BRK
    disable_cfg CONFIG_ACPI_CUSTOM_METHOD
    disable_cfg CONFIG_PROC_KCORE
    disable_cfg CONFIG_LEGACY_PTYS

    # --- High-Risk Attack Surface Stripping ---
    disable_cfg CONFIG_IO_URING
    disable_cfg CONFIG_TIPC
    disable_cfg CONFIG_SCTP
    disable_cfg CONFIG_RDS
    disable_cfg CONFIG_COMPAT
    disable_cfg CONFIG_BPF_SYSCALL
    disable_cfg CONFIG_DEBUG_FS
    disable_cfg CONFIG_KEXEC
    disable_cfg CONFIG_HIBERNATION

    # --- Embed Hardened Boot Command Line Arguments ---
    local cmdline="oops=panic randomize_kstack_offset=on vsyscall=none audit=1 page_alloc.shuffle=1 mitigations=auto,nosmt spectre_v2=on spec_store_bypass_disable=on tsx=off tsx_async_abort=full,nosmt l1tf=full,force mds=full,nosmt kvm.nx_huge_pages=force slab_nomerge pti=on iommu=force"
    enable_cfg  CONFIG_CMDLINE_BOOL
    str_cfg     CONFIG_CMDLINE "$cmdline"
    enable_cfg  CONFIG_CMDLINE_OVERRIDE

    log_info "Updating dependencies for target configuration..."
    make olddefconfig
}

# ------------------------------------------------------------------------------
# Step 4: Pure Source Compilation
# ------------------------------------------------------------------------------
compile_kernel() {
    cd "${SRC_DIR}"
    log_info "Compiling Linux Kernel v${KERNEL_VERSION} from pure source..."
    local threads
    threads=$(nproc)
    
    if ! make -j"${threads}" bzImage; then
        log_warn "Parallel compilation encountered an issue. Rerunning sequentially (-j1) to isolate error..."
        make -j1 bzImage || log_error "Kernel compilation failed."
    fi
    
    if grep -q "CONFIG_MODULES=y" .config; then
        log_info "Building kernel modules..."
        if ! make -j"${threads}" modules; then
            log_warn "Parallel module compilation failed. Rerunning sequentially (-j1)..."
            make -j1 modules || log_error "Kernel modules compilation failed."
        fi
    fi
}

# ------------------------------------------------------------------------------
# Step 5: Secure Boot Binary Signing
# ------------------------------------------------------------------------------
sign_kernel() {
    cd "${SRC_DIR}"
    log_info "Signing the compiled bzImage for UEFI Secure Boot enforcement..."
    
    local target_img="arch/x86/boot/bzImage"
    local signed_img="${BUILD_DIR}/vmlinuz-${KERNEL_VERSION}-zerotrust.signed"

    sbsign --key "${KEYS_DIR}/DB.key" \
           --cert "${KEYS_DIR}/DB.crt" \
           --output "${signed_img}" \
           "${target_img}"

    log_info "Successfully generated signed kernel binary:"
    log_info "  -> ${signed_img}"
}

# ------------------------------------------------------------------------------
# Main Execution Flow
# ------------------------------------------------------------------------------
main() {
    log_info "Starting Hardened Zero-Trust Kernel Build Pipeline..."
    check_dependencies
    setup_workspace
    generate_keys
    configure_kernel
    compile_kernel
    sign_kernel
    log_info "Pipeline execution complete!"
}

main "$@"
