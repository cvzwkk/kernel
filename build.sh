#!/usr/bin/env bash
# ==============================================================================
# build5.sh
#
# Hardened Linux 6.6 kernel build, verification, signing and installation.
#
# Target:
#   Debian / Ubuntu x86_64
#
# IMPORTANT:
#   This script deliberately does NOT execute "make install".
#
# Installation order:
#   1. Build kernel
#   2. Build modules
#   3. Kbuild signs modules during modules_install
#   4. Verify installed module signatures
#   5. Sign kernel EFI image
#   6. Generate initramfs
#   7. Verify initramfs
#   8. Install signed kernel into /boot
#   9. Update GRUB
#
# TARGET_ROOT:
#
#   TARGET_ROOT=/
#       Normal installed system.
#
#   TARGET_ROOT=/mnt
#       Debian/Ubuntu installation mounted under /mnt from a live system.
#
# Example:
#
#   sudo TARGET_ROOT=/mnt ./build5.sh
#
# Before using TARGET_ROOT=/mnt, ensure:
#
#   /mnt/boot
#   /mnt/boot/efi
#
# are mounted where appropriate.
# ==============================================================================

set -Eeuo pipefail

# ------------------------------------------------------------------------------
# Error handling
# ------------------------------------------------------------------------------

on_error()
{
    local rc=$?
    local line="${BASH_LINENO[0]:-unknown}"

    printf '\n' >&2
    printf '\033[31m[ERROR]\033[0m line %s, exit code %s\n' "$line" "$rc" >&2

    exit "$rc"
}

trap on_error ERR

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------

KERNEL_VERSION="${KERNEL_VERSION:-6.6.147}"
LOCALVERSION="${LOCALVERSION:--zerotrust}"

BUILD_DIR="${BUILD_DIR:-$(pwd)/kernel_build}"
SRC_DIR="${BUILD_DIR}/linux-${KERNEL_VERSION}"

BASE_URL="https://cdn.kernel.org/pub/linux/kernel/v6.x"

KERNEL_TARBALL="linux-${KERNEL_VERSION}.tar.xz"
KERNEL_SIGNATURE="linux-${KERNEL_VERSION}.tar.sign"

KEYS_DIR="${BUILD_DIR}/keys"
GPG_HOME="${BUILD_DIR}/gnupg"

CPU_LIMIT="${CPU_LIMIT:-70}"
BUILD_JOBS="${BUILD_JOBS:-}"

INSTALL_KERNEL="${INSTALL_KERNEL:-1}"
GENERATE_INITRAMFS="${GENERATE_INITRAMFS:-1}"
UPDATE_GRUB="${UPDATE_GRUB:-1}"

DKMS_AUTOINSTALL="${DKMS_AUTOINSTALL:-0}"
ENROLL_MOK="${ENROLL_MOK:-0}"

KEY_DAYS="${KEY_DAYS:-3650}"

TARGET_ROOT="${TARGET_ROOT:-/}"

# ------------------------------------------------------------------------------
# Trusted kernel.org fingerprints
# ------------------------------------------------------------------------------

LINUS_FINGERPRINT="ABAF11C65A2970B130ABE3C479BE3E4300411886"
GREG_FINGERPRINT="647F28654894E3BD457199BE38DBBDC86092693E"

# ------------------------------------------------------------------------------
# Runtime target paths
# ------------------------------------------------------------------------------

KERNEL_RELEASE=""
TARGET_BOOT=""
TARGET_MODULES=""
TARGET_INITRAMFS=""
TARGET_CONFIG=""
TARGET_SYSTEM_MAP=""

# ------------------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------------------

log_info()
{
    printf '\033[34m[INFO]\033[0m %s\n' "$*"
}

log_warn()
{
    printf '\033[33m[WARN]\033[0m %s\n' "$*" >&2
}

log_error()
{
    printf '\033[31m[ERROR]\033[0m %s\n' "$*" >&2
    exit 1
}

log_success()
{
    printf '\033[32m[ OK ]\033[0m %s\n' "$*"
}

# ------------------------------------------------------------------------------
# Root handling
# ------------------------------------------------------------------------------

if [[ "$EUID" -eq 0 ]]; then
    SUDO=()
else
    command -v sudo >/dev/null 2>&1 || \
        log_error "sudo is required when not running as root."

    SUDO=(sudo)

    log_info "Refreshing sudo credentials..."
    sudo -v
fi

run_root()
{
    if [[ "$EUID" -eq 0 ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

# ------------------------------------------------------------------------------
# Target helpers
# ------------------------------------------------------------------------------

normalize_target_root()
{
    if [[ "$TARGET_ROOT" != "/" ]]; then
        TARGET_ROOT="${TARGET_ROOT%/}"

        if [[ -z "$TARGET_ROOT" ]]; then
            TARGET_ROOT="/"
        fi
    fi
}

target_path()
{
    local path="$1"

    if [[ "$TARGET_ROOT" == "/" ]]; then
        printf '%s\n' "$path"
    else
        printf '%s%s\n' "$TARGET_ROOT" "$path"
    fi
}

configure_target_paths()
{
    normalize_target_root

    TARGET_BOOT="$(target_path "/boot")"
    TARGET_MODULES="$(target_path "/lib/modules/${KERNEL_RELEASE}")"
    TARGET_INITRAMFS="$(target_path "/boot/initrd.img-${KERNEL_RELEASE}")"
    TARGET_CONFIG="$(target_path "/boot/config-${KERNEL_RELEASE}")"
    TARGET_SYSTEM_MAP="$(target_path "/boot/System.map-${KERNEL_RELEASE}")"
}

# ------------------------------------------------------------------------------
# Platform
# ------------------------------------------------------------------------------

check_platform()
{
    log_info "Checking platform..."

    [[ "$(uname -m)" == "x86_64" ]] || \
        log_error "This script supports x86_64 only."

    [[ -f /etc/debian_version ]] || \
        log_error "This script targets Debian/Ubuntu."

    command -v apt-get >/dev/null 2>&1 || \
        log_error "apt-get was not found."

    log_success "Platform check passed."
}

# ------------------------------------------------------------------------------
# Target validation
# ------------------------------------------------------------------------------

check_target_root()
{
    log_info "Checking target root..."

    [[ -d "$TARGET_ROOT" ]] || \
        log_error "TARGET_ROOT does not exist: $TARGET_ROOT"

    [[ -d "$TARGET_BOOT" ]] || \
        log_error "Target /boot does not exist: $TARGET_BOOT"

    [[ -d "$(target_path "/lib")" ]] || \
        log_error "Target /lib does not exist."

    if [[ "$TARGET_ROOT" == "/" ]]; then
        log_info "Using current installed system."
    else
        log_info "Using external target root: $TARGET_ROOT"

        [[ -f "$TARGET_ROOT/etc/debian_version" ]] || \
            log_error \
                "TARGET_ROOT does not appear to contain Debian/Ubuntu."

        command -v chroot >/dev/null 2>&1 || \
            log_error "chroot is required."
    fi

    log_success "Target root validated."
}

# ------------------------------------------------------------------------------
# Mount checks
# ------------------------------------------------------------------------------

check_target_mounts()
{
    log_info "Checking target filesystem mounts..."

    if [[ "$TARGET_ROOT" == "/" ]]; then

        if findmnt -no OPTIONS / 2>/dev/null | grep -qw ro; then
            log_error "Root filesystem is read-only."
        fi

        if findmnt -no OPTIONS /boot 2>/dev/null | grep -qw ro; then
            log_error "/boot filesystem is read-only."
        fi

    else

        [[ -w "$TARGET_ROOT" ]] || \
            log_error "Target root is not writable: $TARGET_ROOT"

        [[ -w "$TARGET_BOOT" ]] || \
            log_error "Target /boot is not writable: $TARGET_BOOT"
    fi

    log_success "Target filesystem appears writable."
}

# ------------------------------------------------------------------------------
# Dependencies
# ------------------------------------------------------------------------------

check_dependencies()
{
    log_info "Checking build dependencies..."

    local packages=(
        build-essential
        bc
        bison
        flex
        gcc
        g++
        make
        wget
        xz-utils
        gnupg
        openssl
        libssl-dev
        libelf-dev
        libncurses-dev
        dwarves
        cpio
        kmod
        initramfs-tools
        grub-common
        grub2-common
        sbsigntool
        mokutil
        ca-certificates
        cpulimit
    )

    local missing=()
    local package

    for package in "${packages[@]}"; do
        if ! dpkg-query \
            -W \
            -f='${Status}' \
            "$package" 2>/dev/null |
            grep -q "install ok installed"
        then
            missing+=("$package")
        fi
    done

    if (( ${#missing[@]} > 0 )); then
        log_info "Installing missing packages:"
        printf '  %s\n' "${missing[@]}"

        run_root apt-get update
        run_root apt-get install -y "${missing[@]}"
    fi

    local commands=(
        gcc
        g++
        make
        flex
        bison
        bc
        wget
        xzcat
        gpg
        openssl
        sbsign
        sbverify
        mokutil
        depmod
        update-initramfs
        cpulimit
        chroot
        findmnt
    )

    for package in "${commands[@]}"; do
        command -v "$package" >/dev/null 2>&1 || \
            log_error "Required command unavailable: $package"
    done

    log_success "All required dependencies are available."
}

# ------------------------------------------------------------------------------
# CPU configuration
# ------------------------------------------------------------------------------

configure_cpu_protection()
{
    local cpu_count

    cpu_count="$(nproc)"

    [[ "$CPU_LIMIT" =~ ^[0-9]+$ ]] || \
        log_error "CPU_LIMIT must be an integer."

    (( CPU_LIMIT >= 10 && CPU_LIMIT <= 100 )) || \
        log_error "CPU_LIMIT must be between 10 and 100."

    if [[ -z "$BUILD_JOBS" ]]; then
        BUILD_JOBS=$(( (cpu_count * CPU_LIMIT + 99) / 100 ))

        (( BUILD_JOBS < 1 )) && BUILD_JOBS=1
        (( BUILD_JOBS > cpu_count )) && BUILD_JOBS="$cpu_count"
    fi

    [[ "$BUILD_JOBS" =~ ^[0-9]+$ ]] || \
        log_error "BUILD_JOBS must be an integer."

    (( BUILD_JOBS >= 1 )) || \
        log_error "BUILD_JOBS must be >= 1."

    log_info "Logical CPUs: $cpu_count"
    log_info "CPU limit: ${CPU_LIMIT}%"
    log_info "Build jobs: $BUILD_JOBS"

    log_warn \
        "CPU limiting cannot guarantee prevention of kernel panics."
}

# ------------------------------------------------------------------------------
# Make helpers
# ------------------------------------------------------------------------------

make_kernel()
{
    make LOCALVERSION="$LOCALVERSION" "$@"
}

run_cpu_limited()
{
    local src="$SRC_DIR"
    local limit="$CPU_LIMIT"

    if command -v cpulimit >/dev/null 2>&1; then

        cpulimit \
            --limit="$limit" \
            --foreground \
            -- \
            bash -c '
                set -Eeuo pipefail
                cd "$1"
                shift
                make LOCALVERSION="$LOCALVERSION" "$@"
            ' \
            _ \
            "$src" \
            "$@"

    else

        log_warn "cpulimit unavailable; using job limiting only."

        (
            cd "$src"
            make LOCALVERSION="$LOCALVERSION" "$@"
        )
    fi
}

# ------------------------------------------------------------------------------
# Kernel availability
# ------------------------------------------------------------------------------

validate_kernel_release()
{
    log_info "Checking kernel.org availability..."

    local tar_url="${BASE_URL}/${KERNEL_TARBALL}"
    local sig_url="${BASE_URL}/${KERNEL_SIGNATURE}"

    wget \
        --spider \
        --https-only \
        --quiet \
        "$tar_url" || \
        log_error "Kernel archive unavailable: $KERNEL_TARBALL"

    wget \
        --spider \
        --https-only \
        --quiet \
        "$sig_url" || \
        log_error "Kernel signature unavailable: $KERNEL_SIGNATURE"

    log_success "Linux $KERNEL_VERSION is available."
}

# ------------------------------------------------------------------------------
# Workspace
# ------------------------------------------------------------------------------

setup_workspace()
{
    log_info "Creating isolated build workspace..."

    umask 077

    mkdir -p \
        "$BUILD_DIR" \
        "$KEYS_DIR" \
        "$GPG_HOME"

    chmod 700 \
        "$BUILD_DIR" \
        "$KEYS_DIR" \
        "$GPG_HOME"

    log_success "Build directory: $BUILD_DIR"
}

# ------------------------------------------------------------------------------
# Download
# ------------------------------------------------------------------------------

download_source()
{
    cd "$BUILD_DIR"

    local tar_url="${BASE_URL}/${KERNEL_TARBALL}"
    local sig_url="${BASE_URL}/${KERNEL_SIGNATURE}"

    if [[ ! -s "$KERNEL_TARBALL" ]]; then

        log_info "Downloading $KERNEL_TARBALL..."

        wget \
            --https-only \
            --continue \
            --show-progress \
            --output-document="$KERNEL_TARBALL" \
            "$tar_url"

    else
        log_info "Using existing $KERNEL_TARBALL"
    fi

    if [[ ! -s "$KERNEL_SIGNATURE" ]]; then

        log_info "Downloading $KERNEL_SIGNATURE..."

        wget \
            --https-only \
            --continue \
            --show-progress \
            --output-document="$KERNEL_SIGNATURE" \
            "$sig_url"

    else
        log_info "Using existing $KERNEL_SIGNATURE"
    fi

    [[ -s "$KERNEL_TARBALL" ]] || \
        log_error "Kernel archive is empty."

    [[ -s "$KERNEL_SIGNATURE" ]] || \
        log_error "Kernel signature is empty."

    log_success "Kernel archive and signature downloaded."
}

# ------------------------------------------------------------------------------
# GPG
# ------------------------------------------------------------------------------

import_kernel_keys()
{
    export GNUPGHOME="$GPG_HOME"

    chmod 700 "$GNUPGHOME"

    log_info "Importing kernel.org maintainer keys..."

    local status=0

    gpg \
        --batch \
        --locate-keys \
        torvalds@kernel.org \
        gregkh@kernel.org \
        >/dev/null 2>&1 || status=$?

    if [[ "$status" -ne 0 ]]; then

        log_warn "WKD key lookup failed."
        log_info "Trying keys.openpgp.org..."

        gpg \
            --batch \
            --keyserver hkps://keys.openpgp.org \
            --recv-keys \
            "$LINUS_FINGERPRINT" \
            "$GREG_FINGERPRINT" \
            >/dev/null
    fi

    local fingerprint
    local found=0

    for fingerprint in \
        "$LINUS_FINGERPRINT" \
        "$GREG_FINGERPRINT"
    do

        if gpg \
            --batch \
            --with-colons \
            --list-keys \
            "$fingerprint" 2>/dev/null |
            grep -q "^fpr:::::::::${fingerprint}:"
        then

            log_success "Trusted key found: $fingerprint"
            found=$((found + 1))
        fi
    done

    (( found > 0 )) || \
        log_error "No trusted kernel.org maintainer key found."
}

# ------------------------------------------------------------------------------
# Verify source
# ------------------------------------------------------------------------------

verify_source()
{
    cd "$BUILD_DIR"

    export GNUPGHOME="$GPG_HOME"

    log_info "Verifying kernel.org PGP signature..."

    local output

    if ! output="$(
        xzcat "$KERNEL_TARBALL" |
        gpg \
            --batch \
            --status-fd=1 \
            --verify \
            "$KERNEL_SIGNATURE" \
            - \
            2>&1
    )"
    then
        printf '%s\n' "$output" >&2
        log_error "PGP signature verification failed."
    fi

    printf '%s\n' "$output"

    if ! printf '%s\n' "$output" |
        grep -Eq \
        "^\[GNUPG:\] VALIDSIG (${LINUS_FINGERPRINT}|${GREG_FINGERPRINT}) "
    then
        log_error "Signature was not made by a trusted kernel.org maintainer."
    fi

    log_success "Kernel.org PGP signature verified."

    log_info "Checking XZ archive integrity..."

    xz --test "$KERNEL_TARBALL" || \
        log_error "XZ archive integrity check failed."

    log_success "XZ archive integrity verified."

    log_info "Checking tar archive structure..."

    xzcat "$KERNEL_TARBALL" |
        tar --list --file=- >/dev/null || \
        log_error "Kernel tar stream failed validation."

    log_success "Kernel tar stream verified."
}

# ------------------------------------------------------------------------------
# Extract
# ------------------------------------------------------------------------------

extract_source()
{
    cd "$BUILD_DIR"

    log_info "Extracting verified kernel source..."

    rm -rf "$SRC_DIR"

    tar \
        --extract \
        --file="$KERNEL_TARBALL"

    [[ -d "$SRC_DIR" ]] || \
        log_error "Expected source directory was not created."

    log_success "Kernel source extracted."
}

# ------------------------------------------------------------------------------
# Key generation
# ------------------------------------------------------------------------------

generate_keypair()
{
    local name="$1"
    local subject="$2"

    local key="${KEYS_DIR}/${name}.key"
    local crt="${KEYS_DIR}/${name}.crt"

    if [[ -f "$key" && -f "$crt" ]]; then
        log_info "Existing $name keypair found."
        return
    fi

    log_info "Generating RSA-4096 $name key..."

    openssl genpkey \
        -algorithm RSA \
        -pkeyopt rsa_keygen_bits:4096 \
        -out "$key"

    chmod 600 "$key"

    openssl req \
        -new \
        -x509 \
        -sha512 \
        -days "$KEY_DAYS" \
        -key "$key" \
        -out "$crt" \
        -subj "/CN=${subject}/"

    chmod 644 "$crt"

    log_success "$name keypair generated."
}

generate_keys()
{
    log_info "Preparing signing keys..."

    generate_keypair \
        "kernel-module" \
        "Zero Trust Kernel Module Signing ${KERNEL_VERSION}"

    generate_keypair \
        "secureboot" \
        "Zero Trust UEFI Secure Boot Kernel ${KERNEL_VERSION}"

    cat \
        "${KEYS_DIR}/kernel-module.key" \
        "${KEYS_DIR}/kernel-module.crt" \
        > "${KEYS_DIR}/kernel-module-signing.pem"

    chmod 600 "${KEYS_DIR}/kernel-module-signing.pem"

    openssl x509 \
        -in "${KEYS_DIR}/secureboot.crt" \
        -outform DER \
        -out "${KEYS_DIR}/secureboot.der"

    chmod 644 "${KEYS_DIR}/secureboot.der"

    log_success "Signing keys prepared."

    log_info "Kernel-module certificate:"

    openssl x509 \
        -in "${KEYS_DIR}/kernel-module.crt" \
        -noout \
        -subject \
        -fingerprint \
        -sha256

    log_info "Secure Boot certificate:"

    openssl x509 \
        -in "${KEYS_DIR}/secureboot.crt" \
        -noout \
        -subject \
        -fingerprint \
        -sha256
}

# ------------------------------------------------------------------------------
# Kconfig
# ------------------------------------------------------------------------------

enable_cfg()
{
    ./scripts/config \
        --file .config \
        --enable "$1"
}

disable_cfg()
{
    ./scripts/config \
        --file .config \
        --disable "$1"
}

set_cfg_value()
{
    ./scripts/config \
        --file .config \
        --set-val "$1" "$2"
}

set_cfg_string()
{
    ./scripts/config \
        --file .config \
        --set-str "$1" "$2"
}

# ------------------------------------------------------------------------------
# Configure kernel
# ------------------------------------------------------------------------------

configure_kernel()
{
    cd "$SRC_DIR"

    log_info "Creating x86_64 defconfig..."

    make_kernel defconfig

    # --------------------------------------------------------------------------
    # Memory hardening
    # --------------------------------------------------------------------------

    enable_cfg CONFIG_RANDOMIZE_BASE
    enable_cfg CONFIG_RANDOMIZE_MEMORY
    enable_cfg CONFIG_STRICT_KERNEL_RWX
    enable_cfg CONFIG_STRICT_MODULE_RWX
    enable_cfg CONFIG_INIT_ON_ALLOC_DEFAULT_ON
    enable_cfg CONFIG_INIT_ON_FREE_DEFAULT_ON
    enable_cfg CONFIG_HARDENED_USERCOPY
    enable_cfg CONFIG_FORTIFY_SOURCE
    enable_cfg CONFIG_SHUFFLE_PAGE_ALLOCATOR
    enable_cfg CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT
    enable_cfg CONFIG_SLAB_FREELIST_HARDENED
    enable_cfg CONFIG_SLAB_FREELIST_RANDOM
    enable_cfg CONFIG_VMAP_STACK

    # --------------------------------------------------------------------------
    # Compiler hardening
    # --------------------------------------------------------------------------

    enable_cfg CONFIG_GCC_PLUGINS

    ./scripts/config \
        --file .config \
        --enable CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF_ALL \
        2>/dev/null || true

    ./scripts/config \
        --file .config \
        --enable CONFIG_GCC_PLUGIN_STACKLEAK \
        2>/dev/null || true

    ./scripts/config \
        --file .config \
        --enable CONFIG_GCC_PLUGIN_RANDSTRUCT \
        2>/dev/null || true

    # --------------------------------------------------------------------------
    # x86 protection
    # --------------------------------------------------------------------------

    ./scripts/config \
        --file .config \
        --enable CONFIG_X86_KERNEL_IBT \
        2>/dev/null || true

    ./scripts/config \
        --file .config \
        --enable CONFIG_X86_USER_SHADOW_STACK \
        2>/dev/null || true

    enable_cfg CONFIG_X86_SMAP
    enable_cfg CONFIG_X86_UMIP
    enable_cfg CONFIG_PAGE_TABLE_ISOLATION
    enable_cfg CONFIG_RETPOLINE

    # --------------------------------------------------------------------------
    # EFI
    # --------------------------------------------------------------------------

    enable_cfg CONFIG_EFI
    enable_cfg CONFIG_EFI_STUB
    enable_cfg CONFIG_EFIVAR_FS

    ./scripts/config \
        --file .config \
        --enable CONFIG_EFI_DISABLE_PCI_DMA \
        2>/dev/null || true

    ./scripts/config \
        --file .config \
        --enable CONFIG_RESET_ATTACK_MITIGATION \
        2>/dev/null || true

    # --------------------------------------------------------------------------
    # IOMMU
    # --------------------------------------------------------------------------

    enable_cfg CONFIG_IOMMU_SUPPORT

    ./scripts/config \
        --file .config \
        --enable CONFIG_IOMMU_DEFAULT_DMA_STRICT \
        2>/dev/null || true

    ./scripts/config \
        --file .config \
        --enable CONFIG_INTEL_IOMMU \
        2>/dev/null || true

    ./scripts/config \
        --file .config \
        --enable CONFIG_AMD_IOMMU \
        2>/dev/null || true

    # --------------------------------------------------------------------------
    # Lockdown/security
    # --------------------------------------------------------------------------

    enable_cfg CONFIG_SECURITY
    enable_cfg CONFIG_SECURITY_LOCKDOWN_LSM
    enable_cfg CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY
    enable_cfg CONFIG_SECURITY_DMESG_RESTRICT

    ./scripts/config \
        --file .config \
        --enable CONFIG_SECURITY_TIOCSTI_RESTRICT \
        2>/dev/null || true

    enable_cfg CONFIG_STRICT_DEVMEM
    enable_cfg CONFIG_IO_STRICT_DEVMEM

    disable_cfg CONFIG_DEVMEM

    # --------------------------------------------------------------------------
    # LSM
    # --------------------------------------------------------------------------

    enable_cfg CONFIG_SECURITY_SELINUX
    enable_cfg CONFIG_SECURITY_APPARMOR

    # --------------------------------------------------------------------------
    # Integrity
    # --------------------------------------------------------------------------

    enable_cfg CONFIG_INTEGRITY
    enable_cfg CONFIG_IMA
    enable_cfg CONFIG_EVM

    ./scripts/config \
        --file .config \
        --enable CONFIG_IMA_DEFAULT_POLICY \
        2>/dev/null || true

    # --------------------------------------------------------------------------
    # Module signing
    # --------------------------------------------------------------------------

    enable_cfg CONFIG_MODULES
    enable_cfg CONFIG_MODULE_SIG
    enable_cfg CONFIG_MODULE_SIG_FORCE
    enable_cfg CONFIG_MODULE_SIG_ALL
    enable_cfg CONFIG_MODULE_SIG_SHA512

    set_cfg_string \
        CONFIG_MODULE_SIG_KEY \
        "${KEYS_DIR}/kernel-module-signing.pem"

    set_cfg_string \
        CONFIG_SYSTEM_TRUSTED_KEYS \
        ""

    set_cfg_string \
        CONFIG_SYSTEM_REVOCATION_KEYS \
        ""

    # --------------------------------------------------------------------------
    # dm-verity
    # --------------------------------------------------------------------------

    enable_cfg CONFIG_BLK_DEV_DM
    enable_cfg CONFIG_DM_VERITY

    ./scripts/config \
        --file .config \
        --enable CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG \
        2>/dev/null || true

    # --------------------------------------------------------------------------
    # Seccomp
    # --------------------------------------------------------------------------

    enable_cfg CONFIG_SECCOMP
    enable_cfg CONFIG_SECCOMP_FILTER

    # --------------------------------------------------------------------------
    # BPF
    # --------------------------------------------------------------------------

    disable_cfg CONFIG_BPF_SYSCALL

    ./scripts/config \
        --file .config \
        --disable CONFIG_BPF_JIT_ALWAYS_ON \
        2>/dev/null || true

    # --------------------------------------------------------------------------
    # Audit
    # --------------------------------------------------------------------------

    enable_cfg CONFIG_AUDIT
    enable_cfg CONFIG_AUDITSYSCALL

    # --------------------------------------------------------------------------
    # Attack surface reduction
    # --------------------------------------------------------------------------

    disable_cfg CONFIG_COMPAT_BRK
    disable_cfg CONFIG_ACPI_CUSTOM_METHOD
    disable_cfg CONFIG_PROC_KCORE
    disable_cfg CONFIG_LEGACY_PTYS
    disable_cfg CONFIG_IO_URING
    disable_cfg CONFIG_TIPC
    disable_cfg CONFIG_SCTP
    disable_cfg CONFIG_RDS
    disable_cfg CONFIG_COMPAT
    disable_cfg CONFIG_KEXEC
    disable_cfg CONFIG_HIBERNATION

    # --------------------------------------------------------------------------
    # Debug/tracing reduction
    # --------------------------------------------------------------------------

    disable_cfg CONFIG_DEBUG_INFO
    disable_cfg CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT
    disable_cfg CONFIG_DEBUG_INFO_DWARF4
    disable_cfg CONFIG_DEBUG_INFO_DWARF5
    disable_cfg CONFIG_GDB_SCRIPTS
    disable_cfg CONFIG_DEBUG_KERNEL
    disable_cfg CONFIG_DEBUG_MISC
    disable_cfg CONFIG_DEBUG_OBJECTS
    disable_cfg CONFIG_DEBUG_OBJECTS_FREE
    disable_cfg CONFIG_DEBUG_OBJECTS_RCU_HEAD
    disable_cfg CONFIG_DEBUG_OBJECTS_PERCPU_COUNTER
    disable_cfg CONFIG_DEBUG_OBJECTS_WORK
    disable_cfg CONFIG_SLUB_DEBUG
    disable_cfg CONFIG_SLUB_DEBUG_ON
    disable_cfg CONFIG_PAGE_OWNER
    disable_cfg CONFIG_PAGE_POISONING
    disable_cfg CONFIG_PAGE_EXTENSION
    disable_cfg CONFIG_KASAN
    disable_cfg CONFIG_KCSAN
    disable_cfg CONFIG_KCOV
    disable_cfg CONFIG_UBSAN
    disable_cfg CONFIG_UBSAN_TRAP
    disable_cfg CONFIG_UBSAN_BOUNDS
    disable_cfg CONFIG_UBSAN_SHIFT
    disable_cfg CONFIG_UBSAN_DIVREM
    disable_cfg CONFIG_FTRACE
    disable_cfg CONFIG_FUNCTION_TRACER
    disable_cfg CONFIG_FUNCTION_GRAPH_TRACER
    disable_cfg CONFIG_DYNAMIC_FTRACE
    disable_cfg CONFIG_FUNCTION_PROFILER
    disable_cfg CONFIG_STACK_TRACER
    disable_cfg CONFIG_KPROBES
    disable_cfg CONFIG_KRETPROBES
    disable_cfg CONFIG_UPROBES
    disable_cfg CONFIG_PERF_EVENTS
    disable_cfg CONFIG_GCOV_KERNEL
    disable_cfg CONFIG_GCOV_PROFILE_ALL
    disable_cfg CONFIG_DEBUG_FS

    # --------------------------------------------------------------------------
    # Panic behavior
    # --------------------------------------------------------------------------

    enable_cfg CONFIG_PANIC_ON_OOPS

    set_cfg_value \
        CONFIG_PANIC_TIMEOUT \
        "-1"

    # --------------------------------------------------------------------------
    # Embedded command line
    # --------------------------------------------------------------------------

    local cmdline

    cmdline="oops=panic"
    cmdline+=" lockdown=confidentiality"
    cmdline+=" randomize_kstack_offset=on"
    cmdline+=" vsyscall=none"
    cmdline+=" audit=1"
    cmdline+=" page_alloc.shuffle=1"
    cmdline+=" mitigations=auto,nosmt"
    cmdline+=" spectre_v2=on"
    cmdline+=" spec_store_bypass_disable=on"
    cmdline+=" tsx=off"
    cmdline+=" tsx_async_abort=full,nosmt"
    cmdline+=" l1tf=full,force"
    cmdline+=" mds=full,nosmt"
    cmdline+=" kvm.nx_huge_pages=force"
    cmdline+=" slab_nomerge"
    cmdline+=" pti=on"
    cmdline+=" iommu=force"
    cmdline+=" iommu.strict=1"
    cmdline+=" debugfs=off"
    cmdline+=" module.sig_enforce=1"

    enable_cfg CONFIG_CMDLINE_BOOL

    set_cfg_string \
        CONFIG_CMDLINE \
        "$cmdline"

    disable_cfg CONFIG_CMDLINE_OVERRIDE

    # --------------------------------------------------------------------------
    # Resolve dependencies
    # --------------------------------------------------------------------------

    log_info "Resolving Kconfig dependencies..."

    KCONFIG_WARN_UNKNOWN_SYMBOLS=1 \
    KCONFIG_WARN_CHANGED_INPUT=1 \
        make_kernel olddefconfig

    # --------------------------------------------------------------------------
    # Reassert critical settings after olddefconfig
    # --------------------------------------------------------------------------

    disable_cfg CONFIG_KEXEC
    disable_cfg CONFIG_HIBERNATION
    disable_cfg CONFIG_COMPAT
    disable_cfg CONFIG_IO_URING
    disable_cfg CONFIG_TIPC
    disable_cfg CONFIG_SCTP
    disable_cfg CONFIG_RDS
    disable_cfg CONFIG_PROC_KCORE
    disable_cfg CONFIG_ACPI_CUSTOM_METHOD
    disable_cfg CONFIG_LEGACY_PTYS
    disable_cfg CONFIG_DEVMEM
    disable_cfg CONFIG_DEBUG_FS

    enable_cfg CONFIG_MODULES
    enable_cfg CONFIG_MODULE_SIG
    enable_cfg CONFIG_MODULE_SIG_FORCE
    enable_cfg CONFIG_MODULE_SIG_ALL
    enable_cfg CONFIG_MODULE_SIG_SHA512

    set_cfg_string \
        CONFIG_MODULE_SIG_KEY \
        "${KEYS_DIR}/kernel-module-signing.pem"

    set_cfg_string \
        CONFIG_SYSTEM_TRUSTED_KEYS \
        ""

    set_cfg_string \
        CONFIG_SYSTEM_REVOCATION_KEYS \
        ""

    # --------------------------------------------------------------------------
    # Verify critical settings
    # --------------------------------------------------------------------------

    check_config()
    {
        local symbol="$1"
        local expected="$2"
        local actual

        actual="$(
            ./scripts/config \
                --file .config \
                --state "$symbol" \
                2>/dev/null || true
        )"

        if [[ "$actual" != "$expected" ]]; then
            log_error \
                "Critical configuration $symbol=$actual; expected $expected."
        fi
    }

    check_config CONFIG_MODULES y
    check_config CONFIG_MODULE_SIG y
    check_config CONFIG_MODULE_SIG_FORCE y
    check_config CONFIG_MODULE_SIG_ALL y
    check_config CONFIG_MODULE_SIG_SHA512 y

    check_config CONFIG_RANDOMIZE_BASE y
    check_config CONFIG_RANDOMIZE_MEMORY y
    check_config CONFIG_STRICT_KERNEL_RWX y
    check_config CONFIG_STRICT_MODULE_RWX y
    check_config CONFIG_VMAP_STACK y

    check_config CONFIG_SECCOMP y
    check_config CONFIG_SECCOMP_FILTER y

    check_config CONFIG_KEXEC n
    check_config CONFIG_HIBERNATION n
    check_config CONFIG_COMPAT n
    check_config CONFIG_IO_URING n

    local final_cmdline

    final_cmdline="$(
        sed \
            -n \
            's/^CONFIG_CMDLINE="\([^"]*\)"/\1/p' \
            .config
    )"

    [[ "$final_cmdline" == *"lockdown=confidentiality"* ]] || \
        log_error "Embedded command line lacks lockdown=confidentiality."

    [[ "$final_cmdline" == *"debugfs=off"* ]] || \
        log_error "Embedded command line lacks debugfs=off."

    [[ "$final_cmdline" == *"module.sig_enforce=1"* ]] || \
        log_error "Embedded command line lacks module.sig_enforce=1."

    determine_kernel_release

    log_success "Hardened kernel configuration verified."
    log_info "Kernel release: $KERNEL_RELEASE"
}

# ------------------------------------------------------------------------------
# Determine release
# ------------------------------------------------------------------------------

determine_kernel_release()
{
    cd "$SRC_DIR"

    local actual_release

    actual_release="$(make_kernel -s kernelrelease)"

    [[ -n "$actual_release" ]] || \
        log_error "Kbuild returned an empty kernel release."

    KERNEL_RELEASE="$actual_release"

    configure_target_paths

    log_info "Kbuild release: $KERNEL_RELEASE"
}

# ------------------------------------------------------------------------------
# Signing tools
# ------------------------------------------------------------------------------

prepare_signing_tools()
{
    cd "$SRC_DIR"

    log_info "Preparing kernel signing tools..."

    if [[ ! -x "./scripts/sign-file" ]]; then
        make_kernel -s scripts
    fi

    [[ -x "./scripts/sign-file" ]] || \
        log_error "scripts/sign-file was not built."

    [[ -f "${KEYS_DIR}/kernel-module.key" ]] || \
        log_error "Kernel module private key missing."

    [[ -f "${KEYS_DIR}/kernel-module.crt" ]] || \
        log_error "Kernel module certificate missing."

    [[ -f "${KEYS_DIR}/secureboot.key" ]] || \
        log_error "Secure Boot private key missing."

    [[ -f "${KEYS_DIR}/secureboot.crt" ]] || \
        log_error "Secure Boot certificate missing."

    log_success "Signing tools ready."
}

# ------------------------------------------------------------------------------
# Compile
# ------------------------------------------------------------------------------

compile_kernel()
{
    cd "$SRC_DIR"

    log_info "Compiling Linux $KERNEL_RELEASE..."

    if ! run_cpu_limited \
        -j"$BUILD_JOBS" \
        bzImage
    then

        log_warn "Parallel kernel compilation failed."
        log_warn "Retrying with one job..."

        run_cpu_limited \
            -j1 \
            bzImage
    fi

    [[ -f "arch/x86/boot/bzImage" ]] || \
        log_error "Kernel bzImage was not produced."

    log_success "Kernel image compiled."

    log_info "Compiling kernel modules..."

    if ! run_cpu_limited \
        -j"$BUILD_JOBS" \
        modules
    then

        log_warn "Parallel module compilation failed."
        log_warn "Retrying with one job..."

        run_cpu_limited \
            -j1 \
            modules
    fi

    log_success "Kernel modules compiled."

    local compiled_release

    compiled_release="$(make_kernel -s kernelrelease)"

    [[ "$compiled_release" == "$KERNEL_RELEASE" ]] || \
        log_error \
            "Kernel release changed: expected $KERNEL_RELEASE, got $compiled_release."
}

# ------------------------------------------------------------------------------
# Verify module signing configuration
# ------------------------------------------------------------------------------

verify_module_signing_configuration()
{
    cd "$SRC_DIR"

    log_info "Verifying module signing configuration..."

    local key_path

    key_path="$(
        sed \
            -n \
            's/^CONFIG_MODULE_SIG_KEY="\([^"]*\)"/\1/p' \
            .config
    )"

    [[ -n "$key_path" ]] || \
        log_error "CONFIG_MODULE_SIG_KEY is empty."

    [[ -f "$key_path" ]] || \
        log_error "Module signing key does not exist: $key_path"

    local sig_all
    sig_all="$(
        ./scripts/config \
            --file .config \
            --state CONFIG_MODULE_SIG_ALL \
            2>/dev/null || true
    )"

    [[ "$sig_all" == "y" ]] || \
        log_error "CONFIG_MODULE_SIG_ALL is not enabled."

    local sig_sha512
    sig_sha512="$(
        ./scripts/config \
            --file .config \
            --state CONFIG_MODULE_SIG_SHA512 \
            2>/dev/null || true
    )"

    [[ "$sig_sha512" == "y" ]] || \
        log_error "CONFIG_MODULE_SIG_SHA512 is not enabled."

    log_success "Module signing configuration verified."
}

# ------------------------------------------------------------------------------
# Install modules
# ------------------------------------------------------------------------------

install_modules()
{
    cd "$SRC_DIR"

    log_info "Installing kernel modules..."
    log_info "Expected directory: $TARGET_MODULES"

    if [[ "$TARGET_ROOT" == "/" ]]; then

        run_root make \
            LOCALVERSION="$LOCALVERSION" \
            -j1 \
            modules_install

    else

        run_root env \
            INSTALL_MOD_PATH="$TARGET_ROOT" \
            make \
                LOCALVERSION="$LOCALVERSION" \
                -j1 \
                modules_install
    fi

    [[ -d "$TARGET_MODULES" ]] || \
        log_error \
            "Kbuild installed modules under an unexpected release."

    if [[ "$TARGET_ROOT" == "/" ]]; then

        run_root depmod \
            -a \
            "$KERNEL_RELEASE"

    else

        run_root chroot \
            "$TARGET_ROOT" \
            depmod \
            -a \
            "$KERNEL_RELEASE"
    fi

    log_success "Kernel modules installed and depmod completed."
}

# ------------------------------------------------------------------------------
# Verify module signatures
# ------------------------------------------------------------------------------

verify_installed_modules()
{
    log_info "Verifying installed module signatures..."

    local modules_dir="$TARGET_MODULES"

    [[ -d "$modules_dir" ]] || \
        log_error "Module directory does not exist: $modules_dir"

    local module
    local count=0
    local signer

    while IFS= read -r -d '' module
    do

        count=$((count + 1))

        if [[ "$TARGET_ROOT" == "/" ]]; then

            signer="$(
                modinfo \
                    -F signer \
                    -k "$KERNEL_RELEASE" \
                    "$module" \
                    2>/dev/null || true
            )"

        else

            local relative_module
            relative_module="${module#"$TARGET_ROOT"}"

            signer="$(
                chroot \
                    "$TARGET_ROOT" \
                    modinfo \
                        -F signer \
                        -k "$KERNEL_RELEASE" \
                        "$relative_module" \
                        2>/dev/null || true
            )"
        fi

        [[ -n "$signer" ]] || \
            log_error \
                "Installed module has no detectable signature: $module"

    done < <(
        find "$modules_dir" \
            -type f \
            \( \
                -name '*.ko' \
                -o -name '*.ko.xz' \
                -o -name '*.ko.zst' \
                -o -name '*.ko.gz' \
            \) \
            -print0
    )

    if (( count == 0 )); then
        log_warn "No installed kernel modules were found."
    else
        log_success \
            "Verified signatures on $count installed kernel modules."
    fi
}

# ------------------------------------------------------------------------------
# Secure Boot signing
# ------------------------------------------------------------------------------

sign_kernel()
{
    cd "$SRC_DIR"

    local unsigned_image="${SRC_DIR}/arch/x86/boot/bzImage"
    local signed_image="${BUILD_DIR}/vmlinuz-${KERNEL_RELEASE}.efi.signed"

    log_info "Signing kernel for UEFI Secure Boot..."

    [[ -f "$unsigned_image" ]] || \
        log_error "Unsigned bzImage does not exist."

    sbsign \
        --key "${KEYS_DIR}/secureboot.key" \
        --cert "${KEYS_DIR}/secureboot.crt" \
        --output "$signed_image" \
        "$unsigned_image"

    [[ -s "$signed_image" ]] || \
        log_error "Signed EFI kernel was not created."

    log_info "Verifying Secure Boot signature..."

    sbverify \
        --list \
        "$signed_image"

    log_success "Secure Boot signature verified."
}

# ------------------------------------------------------------------------------
# Runtime mounts for target chroot
# ------------------------------------------------------------------------------

mount_target_runtime_filesystems()
{
    if [[ "$TARGET_ROOT" == "/" ]]; then
        return
    fi

    log_info "Preparing target runtime filesystems..."

    mkdir -p \
        "$TARGET_ROOT/dev" \
        "$TARGET_ROOT/proc" \
        "$TARGET_ROOT/sys" \
        "$TARGET_ROOT/run"

    if ! mountpoint -q "$TARGET_ROOT/dev"; then

        run_root mount \
            --rbind \
            /dev \
            "$TARGET_ROOT/dev"

        run_root mount \
            --make-rslave \
            "$TARGET_ROOT/dev"
    fi

    if ! mountpoint -q "$TARGET_ROOT/proc"; then

        run_root mount \
            -t proc \
            proc \
            "$TARGET_ROOT/proc"
    fi

    if ! mountpoint -q "$TARGET_ROOT/sys"; then

        run_root mount \
            --rbind \
            /sys \
            "$TARGET_ROOT/sys"

        run_root mount \
            --make-rslave \
            "$TARGET_ROOT/sys"
    fi

    if ! mountpoint -q "$TARGET_ROOT/run"; then

        run_root mount \
            --rbind \
            /run \
            "$TARGET_ROOT/run"

        run_root mount \
            --make-rslave \
            "$TARGET_ROOT/run"
    fi

    log_success "Target runtime filesystems prepared."
}

# ------------------------------------------------------------------------------
# Generate initramfs
# ------------------------------------------------------------------------------

generate_initramfs()
{
    if [[ "$GENERATE_INITRAMFS" != "1" ]]; then
        log_info "Initramfs generation disabled."
        return
    fi

    log_info "Generating initramfs for $KERNEL_RELEASE..."

    [[ -d "$TARGET_BOOT" ]] || \
        log_error "Target /boot does not exist: $TARGET_BOOT"

    [[ -w "$TARGET_BOOT" ]] || \
        log_error "Target /boot is not writable: $TARGET_BOOT"

    if [[ "$TARGET_ROOT" == "/" ]]; then

        if findmnt -no OPTIONS / 2>/dev/null | grep -qw ro; then
            log_error "Root filesystem is read-only."
        fi

        if findmnt -no OPTIONS /boot 2>/dev/null | grep -qw ro; then
            log_error "/boot is read-only."
        fi

        if [[ -f "$TARGET_INITRAMFS" ]]; then

            run_root update-initramfs \
                -u \
                -k "$KERNEL_RELEASE"

        else

            run_root update-initramfs \
                -c \
                -k "$KERNEL_RELEASE"
        fi

    else

        [[ -x "$TARGET_ROOT/usr/sbin/update-initramfs" ]] || \
            log_error \
                "Target does not contain update-initramfs."

        mount_target_runtime_filesystems

        if [[ -f "$TARGET_INITRAMFS" ]]; then

            run_root chroot \
                "$TARGET_ROOT" \
                /usr/sbin/update-initramfs \
                -u \
                -k "$KERNEL_RELEASE"

        else

            run_root chroot \
                "$TARGET_ROOT" \
                /usr/sbin/update-initramfs \
                -c \
                -k "$KERNEL_RELEASE"
        fi
    fi

    [[ -s "$TARGET_INITRAMFS" ]] || \
        log_error \
            "Initramfs was not created: $TARGET_INITRAMFS"

    log_success "Initramfs generated: $TARGET_INITRAMFS"
}

# ------------------------------------------------------------------------------
# Verify initramfs
# ------------------------------------------------------------------------------

verify_initramfs()
{
    log_info "Verifying initramfs..."

    [[ -f "$TARGET_INITRAMFS" ]] || \
        log_error "Initramfs does not exist: $TARGET_INITRAMFS"

    [[ -s "$TARGET_INITRAMFS" ]] || \
        log_error "Initramfs is empty: $TARGET_INITRAMFS"

    file "$TARGET_INITRAMFS" 2>/dev/null || true

    log_success "Initramfs verified."
}

# ------------------------------------------------------------------------------
# Install signed kernel
# ------------------------------------------------------------------------------

install_kernel_image()
{
    cd "$SRC_DIR"

    local signed_image="${BUILD_DIR}/vmlinuz-${KERNEL_RELEASE}.efi.signed"

    local boot_image="${TARGET_BOOT}/vmlinuz-${KERNEL_RELEASE}"

    log_info "Installing signed kernel image..."

    [[ -f "$signed_image" ]] || \
        log_error "Signed kernel image is missing."

    run_root install \
        -m 0644 \
        "$signed_image" \
        "$boot_image"

    if [[ -f System.map ]]; then

        run_root install \
            -m 0644 \
            System.map \
            "$TARGET_SYSTEM_MAP"
    fi

    run_root install \
        -m 0644 \
        .config \
        "$TARGET_CONFIG"

    log_info "Verifying installed kernel Secure Boot signature..."

    run_root sbverify \
        --list \
        "$boot_image"

    log_success "Installed kernel Secure Boot signature verified."
    log_success "Kernel installed: $boot_image"
}

# ------------------------------------------------------------------------------
# GRUB
# ------------------------------------------------------------------------------

update_grub()
{
    if [[ "$UPDATE_GRUB" != "1" ]]; then
        log_info "GRUB update disabled."
        return
    fi

    log_info "Updating GRUB..."

    if [[ "$TARGET_ROOT" == "/" ]]; then

        command -v update-grub >/dev/null 2>&1 || \
            log_error "update-grub is unavailable."

        run_root update-grub

    else

        mount_target_runtime_filesystems

        if [[ -x "$TARGET_ROOT/usr/sbin/update-grub" ]]; then

            run_root chroot \
                "$TARGET_ROOT" \
                /usr/sbin/update-grub

        elif [[ -x "$TARGET_ROOT/usr/sbin/grub-mkconfig" ]]; then

            run_root chroot \
                "$TARGET_ROOT" \
                /usr/sbin/grub-mkconfig \
                -o \
                /boot/grub/grub.cfg

        else

            log_error "Target system does not contain GRUB tooling."
        fi
    fi

    log_success "GRUB updated."
}

# ------------------------------------------------------------------------------
# Optional DKMS
# ------------------------------------------------------------------------------

run_optional_dkms()
{
    if [[ "$DKMS_AUTOINSTALL" != "1" ]]; then
        log_info "DKMS autoinstall disabled."
        return
    fi

    if [[ "$TARGET_ROOT" != "/" ]]; then
        log_warn \
            "DKMS autoinstall from an external target root is skipped."
        return
    fi

    if ! command -v dkms >/dev/null 2>&1; then
        log_warn "DKMS requested but not installed."
        return
    fi

    log_info "Running optional DKMS autoinstall..."

    local status=0

    set +e

    run_root dkms autoinstall -k "$KERNEL_RELEASE"

    status=$?

    set -e

    if [[ "$status" -ne 0 ]]; then
        log_warn "Some DKMS modules failed to build."
        log_warn "Kernel installation itself remains complete."
    else
        log_success "DKMS modules installed."
    fi
}

# ------------------------------------------------------------------------------
# Secure Boot state
# ------------------------------------------------------------------------------

show_secure_boot_state()
{
    if ! command -v mokutil >/dev/null 2>&1; then
        log_warn "mokutil unavailable."
        return
    fi

    log_info "Current Secure Boot state:"

    run_root mokutil --sb-state || true
}

# ------------------------------------------------------------------------------
# MOK enrollment
# ------------------------------------------------------------------------------

enroll_secureboot_key()
{
    if [[ "$ENROLL_MOK" != "1" ]]; then
        log_info "Automatic MOK enrollment disabled."
        return
    fi

    command -v mokutil >/dev/null 2>&1 || \
        log_error "mokutil is required."

    log_info "Queueing Secure Boot certificate for MOK enrollment..."

    run_root mokutil \
        --import \
        "${KEYS_DIR}/secureboot.der"

    log_warn "MOK enrollment has been queued."
    log_warn "Reboot and approve the certificate in the firmware MOK manager."
}

# ------------------------------------------------------------------------------
# Final validation
# ------------------------------------------------------------------------------

validate_installation()
{
    log_info "Running final installation checks..."

    local boot_image="${TARGET_BOOT}/vmlinuz-${KERNEL_RELEASE}"

    [[ -f "$boot_image" ]] || \
        log_error "Installed kernel image is missing."

    [[ -f "$TARGET_INITRAMFS" ]] || \
        log_error "Installed initramfs is missing."

    [[ -s "$TARGET_INITRAMFS" ]] || \
        log_error "Installed initramfs is empty."

    [[ -f "$TARGET_CONFIG" ]] || \
        log_error "Installed kernel configuration is missing."

    [[ -d "$TARGET_MODULES" ]] || \
        log_error "Installed module directory is missing."

    log_success "Kernel image exists."
    log_success "Initramfs exists."
    log_success "Kernel configuration exists."
    log_success "Kernel modules exist."

    log_info "Installed files:"

    ls -lh \
        "$boot_image" \
        "$TARGET_INITRAMFS" \
        "$TARGET_CONFIG" \
        "$TARGET_SYSTEM_MAP" \
        2>/dev/null || true

    log_info "Installed module count:"

    find "$TARGET_MODULES" \
        -type f \
        \( \
            -name '*.ko' \
            -o -name '*.ko.xz' \
            -o -name '*.ko.zst' \
            -o -name '*.ko.gz' \
        \) \
        2>/dev/null |
        wc -l
}

# ------------------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------------------

print_summary()
{
    cat <<EOF

===============================================================================
                    HARDENED KERNEL BUILD COMPLETE
===============================================================================

Kernel version:
    ${KERNEL_VERSION}

Kernel release:
    ${KERNEL_RELEASE}

Target root:
    ${TARGET_ROOT}

Build directory:
    ${BUILD_DIR}

Source directory:
    ${SRC_DIR}

-------------------------------------------------------------------------------
CPU
-------------------------------------------------------------------------------

CPU limit:
    ${CPU_LIMIT}%

Logical CPUs:
    $(nproc)

Build jobs:
    ${BUILD_JOBS}

-------------------------------------------------------------------------------
INSTALLED KERNEL
-------------------------------------------------------------------------------

Kernel:
    ${TARGET_BOOT}/vmlinuz-${KERNEL_RELEASE}

Initramfs:
    ${TARGET_INITRAMFS}

Config:
    ${TARGET_CONFIG}

System.map:
    ${TARGET_SYSTEM_MAP}

Modules:
    ${TARGET_MODULES}

-------------------------------------------------------------------------------
SECURE BOOT
-------------------------------------------------------------------------------

Signed kernel:
    ${BUILD_DIR}/vmlinuz-${KERNEL_RELEASE}.efi.signed

Private key:
    ${KEYS_DIR}/secureboot.key

Certificate:
    ${KEYS_DIR}/secureboot.crt

MOK certificate:
    ${KEYS_DIR}/secureboot.der

-------------------------------------------------------------------------------
MODULE SIGNING
-------------------------------------------------------------------------------

Private key:
    ${KEYS_DIR}/kernel-module.key

Certificate:
    ${KEYS_DIR}/kernel-module.crt

Hash:
    SHA-512

CONFIG_MODULE_SIG:
    enabled

CONFIG_MODULE_SIG_FORCE:
    enabled

CONFIG_MODULE_SIG_ALL:
    enabled

CONFIG_MODULE_SIG_SHA512:
    enabled

Kernel command line:
    module.sig_enforce=1

-------------------------------------------------------------------------------
SECURITY
-------------------------------------------------------------------------------

Lockdown:
    lockdown=confidentiality

Seccomp:
    enabled

SELinux:
    enabled

AppArmor:
    enabled

IMA:
    enabled

EVM:
    enabled

dm-verity:
    enabled

IOMMU:
    strict mode requested

debugfs:
    disabled

BPF syscall:
    disabled

io_uring:
    disabled

kexec:
    disabled

hibernation:
    disabled

CONFIG_COMPAT:
    disabled

-------------------------------------------------------------------------------
DKMS
-------------------------------------------------------------------------------

DKMS autoinstall:
    ${DKMS_AUTOINSTALL}

-------------------------------------------------------------------------------
IMPORTANT
-------------------------------------------------------------------------------

This script does NOT execute:

    make install

Modules are signed by Kbuild during:

    make modules_install

Module signatures are checked AFTER modules_install.

The initramfs is generated BEFORE the signed kernel image is copied
into /boot.

-------------------------------------------------------------------------------
AFTER REBOOT
-------------------------------------------------------------------------------

uname -r

Expected:

    ${KERNEL_RELEASE}

Secure Boot:

    sudo mokutil --sb-state

Kernel command line:

    cat /proc/cmdline

Lockdown:

    cat /sys/kernel/security/lockdown

Active LSMs:

    cat /sys/kernel/security/lsm

Module signature enforcement:

    cat /proc/cmdline | grep -o 'module.sig_enforce=1' || true

CPU/thermal:

    sensors

===============================================================================

EOF
}

# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------

main()
{
    log_info "Starting hardened Zero-Trust Linux kernel pipeline..."
    log_info "Kernel version: $KERNEL_VERSION"
    log_info "Requested local version: $LOCALVERSION"
    log_info "Target root: $TARGET_ROOT"

    normalize_target_root

    check_platform
    check_dependencies
    configure_cpu_protection
    validate_kernel_release
    setup_workspace
    download_source
    import_kernel_keys
    verify_source
    extract_source
    generate_keys
    configure_kernel
    prepare_signing_tools
    compile_kernel
    verify_module_signing_configuration

    if [[ "$INSTALL_KERNEL" == "1" ]]; then

        # ----------------------------------------------------------------------
        # IMPORTANT INSTALLATION ORDER
        # ----------------------------------------------------------------------
        #
        # modules_install
        #     -> Kbuild signs modules
        #
        # verify installed modules
        #
        # sign kernel
        #
        # generate initramfs
        #
        # verify initramfs
        #
        # install kernel
        #
        # update GRUB
        # ----------------------------------------------------------------------

        check_target_root
        check_target_mounts

        install_modules
        verify_installed_modules

        sign_kernel

        generate_initramfs
        verify_initramfs

        install_kernel_image

        update_grub

        run_optional_dkms

        show_secure_boot_state
        enroll_secureboot_key

        validate_installation

    else

        log_info "System installation disabled: INSTALL_KERNEL=0"

        sign_kernel
    fi

    print_summary

    log_success "Hardened kernel pipeline completed successfully."
}

main "$@"
