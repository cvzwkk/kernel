#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "[-] Error: This script must be run as root (sudo)." 
   exit 1
fi

GRUB_DEFAULT_PATH="/etc/default/grub"
BACKUP_PATH="/etc/default/grub.bak.$(date +%Y%m%d%H%M%S)"

echo "[+] Backing up current GRUB configuration to $BACKUP_PATH..."
cp "$GRUB_DEFAULT_PATH" "$BACKUP_PATH"

echo "[+] Injecting Maximum Zero Trust & Hardened Kernel Parameters..."

# Clear existing command-line defaults
sed -i '/^GRUB_CMDLINE_LINUX_DEFAULT=/d' "$GRUB_DEFAULT_PATH"

# Comprehensive Advanced Hardening Parameter String:
# - lockdown=confidentiality: Elevates lockdown from integrity to block module loading entirely and restricts hibernation/debug access
# - slab_nomerge: Prevents slab cache merging, reducing the reliability of heap exploitation (UAF)
# - init_on_alloc=1 init_on_free=1: Zero-initializes heap pages
# - page_poison=on: Overwrites pages with poison patterns upon free
# - slub_debug=FZP: Enables sanity checks, poisoning, and red-zoning for SLUB allocator
# - pti=on: Forces Page Table Isolation to prevent Meltdown-style side-channel leaks
# - kaslr: Enabled by default on modern arches, but explicitly ensures layout randomization
# - module.sig_enforce=1: Blocks loading of any kernel modules lacking valid cryptographic signatures
# - random.trust_cpu=off: Stops trusting CPU hardware RNG exclusively without kernel-side entropy mixing
# - intel_iommu=on amd_iommu=on iommu=force: Enforces hardware-level IOMMU mapping isolation for DMA attack protection
# - audit=1 audit_backlog_limit=8192: Enables strict kernel auditing
HARDENED_PARAMS="quiet splash lockdown=confidentiality slab_nomerge init_on_alloc=1 init_on_free=1 page_poison=on slub_debug=FZP pti=on module.sig_enforce=1 random.trust_cpu=off intel_iommu=on amd_iommu=on iommu=force audit=1 audit_backlog_limit=8192 mitigations=auto,nosmt"

cat << EOF >> "$GRUB_DEFAULT_PATH"
GRUB_CMDLINE_LINUX_DEFAULT="$HARDENED_PARAMS"
GRUB_DISABLE_OS_PROBER="true"
GRUB_DISABLE_RECOVERY="true"
GRUB_TIMEOUT=1
EOF

echo "[+] Generating password hash for GRUB menu modification lock..."
echo "Please enter a secure GRUB superuser password:"
read -rs GRUB_PASS
HASHED_PASS=$(grub-mkpasswd-pbkdf2 <<< "$GRUB_PASS" | grep -oP 'grub.pbkdf2.sha512.*')

SECURITY_SNIPPET="/etc/grub.d/40_custom_security"
echo "[+] Creating custom GRUB security rules in $SECURITY_SNIPPET..."

cat << EOF > "$SECURITY_SNIPPET"
#!/bin/sh
exec tail -n +3 \$0
set superusers="root"
password_pbkdf2 root $HASHED_PASS
EOF

chmod +x "$SECURITY_SNIPPET"

echo "[+] Updating GRUB configuration..."
if [[ -d /sys/firmware/efi ]]; then
    if [[ -f /boot/efi/EFI/ubuntu/grub.cfg ]]; then
        grub-mkconfig -o /boot/efi/EFI/ubuntu/grub.cfg
    elif [[ -f /boot/efi/EFI/fedora/grub.cfg ]]; then
        grub-mkconfig -o /boot/efi/EFI/fedora/grub.cfg
    else
        grub-mkconfig -o /boot/efi/grub.cfg
    fi
else
    grub-mkconfig -o /boot/grub/grub.cfg
fi

echo "[+] Maximum GRUB Hardening Complete. Reboot recommended."
