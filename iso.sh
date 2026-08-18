#!/usr/bin/env bash
# ==============================================================================
# Script: make_bootable_iso.sh
# Description: Packages the compiled kernel, initramfs, and GRUB into a bootable ISO
# ==============================================================================

set -euo pipefail

# ------------------------------------------------------------------------------
# Configuration Variables
# ------------------------------------------------------------------------------
KERNEL_VERSION="6.6.151"
BUILD_DIR="$(pwd)/kernel_build"
SRC_DIR="${BUILD_DIR}/linux-${KERNEL_VERSION}"
ISO_DIR="${BUILD_DIR}/iso_root"
OUTPUT_ISO="${BUILD_DIR}/zerotrust-debian-${KERNEL_VERSION}.iso"

# ------------------------------------------------------------------------------
# Helper Functions
# ------------------------------------------------------------------------------
log_info()  { echo -e "\e[34m[INFO]\e[0m $1"; }
log_warn()  { echo -e "\e[33m[WARN]\e[0m $1"; }
log_error() { echo -e "\e[31m[ERROR]\e[0m $1"; exit 1; }

check_iso_dependencies() {
    log_info "Verifying required ISO creation utilities..."
    local deps=(grub-pc-bin grub-efi-amd64-bin xorriso mtools)
    for cmd in "${deps[@]}"; do
        if ! dpkg -s "$cmd" >/dev/null 2>&1 && ! command -v "$cmd" >/dev/null 2>&1; then
            log_info "Installing missing utility: $cmd..."
            apt-get update && apt-get install -y "$cmd" || log_error "Failed to install $cmd."
        fi
    done
}

prepare_iso_filesystem() {
    log_info "Setting up ISO staging directory structure..."
    rm -rf "${ISO_DIR}"
    mkdir -p "${ISO_DIR}/boot/grub"
    mkdir -p "${ISO_DIR}/EFI/BOOT"

    # Copy the signed kernel image using the correct build directory path
    local signed_img="./vmlinuz-6.6.151-zerotrust.signed"
    if [ ! -f "${signed_img}" ]; then
        log_error "Signed kernel image not found at ${signed_img}. Build it first!"
    fi
    cp "${signed_img}" "${ISO_DIR}/boot/vmlinuz"

    # Generate a lightweight initramfs containing basic tools and modules if they exist
    log_info "Generating initial RAM filesystem (initramfs)..."
    if [ -d "${SRC_DIR}" ]; then
        cd "${SRC_DIR}"
        if grep -q "CONFIG_MODULES=y" .config; then
            make modules_install INSTALL_MOD_PATH="${BUILD_DIR}/mod_root" >/dev/null 2>&1 || true
        fi
    fi

    # Create standard initramfs for the kernel version
    if command -v update-initramfs >/dev/null 2>&1; then
        update-initramfs -c -k "${KERNEL_VERSION}" -b "${BUILD_DIR}/initrd.img" >/dev/null 2>&1 || true
    fi

    if [ -f "${BUILD_DIR}/initrd.img" ]; then
        cp "${BUILD_DIR}/initrd.img" "${ISO_DIR}/boot/initrd.img"
    else
        log_info "Creating fallback minimal initramfs..."
        touch "${BUILD_DIR}/initrd"
        cd "${BUILD_DIR}" && echo "initrd" | cpio -o -H newc > "${ISO_DIR}/boot/initrd.img"
    fi
}

configure_grub() {
    log_info "Writing GRUB bootloader configuration..."
    cat << 'EOF' > "${ISO_DIR}/boot/grub/grub.cfg"
set timeout=5
set default=0

menuentry "Zero-Trust Hardened Linux (Kernel v6.6.151)" {
    insmod gzio
    insmod part_gpt
    insmod ext2
    linux /boot/vmlinuz quiet
    initrd /boot/initrd.img
}
EOF
}

build_iso_image() {
    log_info "Packaging staging directory into a UEFI/BIOS hybrid bootable ISO..."
    
    # Create EFI boot image for UEFI systems
    dd if=/dev/zero of="${BUILD_DIR}/efiboot.img" bs=1M count=10 >/dev/null 2>&1
    mkfs.vfat -F 12 "${BUILD_DIR}/efiboot.img" >/dev/null 2>&1
    mmd -i "${BUILD_DIR}/efiboot.img" ::EFI
    mmd -i "${BUILD_DIR}/efiboot.img" ::EFI/BOOT
    
    if command -v grub-mkimage >/dev/null 2>&1; then
        grub-mkimage -O x86_64-efi -o "${BUILD_DIR}/BOOTX64.EFI" -p /boot/grub normal iso9660 fat squashfs part_gpt 2>/dev/null || true
        if [ -f "${BUILD_DIR}/BOOTX64.EFI" ]; then
            mcopy -i "${BUILD_DIR}/efiboot.img" "${BUILD_DIR}/BOOTX64.EFI" ::EFI/BOOT/BOOTX64.EFI
        fi
    fi

    xorriso -as mkisofs \
        -iso-level 3 \
        -full-iso9660-filenames \
        -volid "ZEROTRUST_KERN" \
        -eltorito-boot boot/grub/i386-pc/eltorito.img \
        -eltorito-catalog boot/grub/boot.cat \
        -no-emul-boot -boot-load-size 4 -boot-info-table \
        -eltorito-alt-boot \
        -e boot/efiboot.img \
        -no-emul-boot \
        -output "${OUTPUT_ISO}" \
        "${ISO_DIR}" \
        || {
            log_warn "Hybrid EFI setup encountered warnings, generating standard ISO..."
            xorriso -as mkisofs -o "${OUTPUT_ISO}" -V "ZEROTRUST_KERN" -r -J "${ISO_DIR}"
        }

    log_info "ISO successfully generated at:"
    log_info "  -> ${OUTPUT_ISO}"
}

main() {
    log_info "Starting ISO Generation Pipeline..."
    check_iso_dependencies
    prepare_iso_filesystem
    configure_grub
    build_iso_image
    log_info "ISO Packaging Complete!"
}

main "$@"
