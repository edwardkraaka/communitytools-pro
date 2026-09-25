#!/usr/bin/env bash
# install-mobile-toolchain.sh — install the mobile-app-farm toolchain into a Debian/Kali image.
# Invoked from scripts/kali-claude-setup.sh (Dockerfile). Resilient: a failed optional download
# warns instead of failing the build (the skill documents manual fallbacks). Run as root.
#
#   apkeep · jadx · apktool · androguard · ripgrep · openjdk · adb · aapt · APKEditor.jar · ipatool
set -u
warn() { echo "[toolchain][WARN] $*" >&2; }

APKEEP_VER="${APKEEP_VER:-1.0.0}"        # 1.0.0 (2026-04): Play API auth fix + Aurora dispenser tokens
APKEDITOR_VER="${APKEDITOR_VER:-1.4.9}"  # 1.4.9 (2026-05): split/XAPK merge fix (#228)
IPATOOL_VER="${IPATOOL_VER:-2.1.6}"
ARCH="$(uname -m)"   # x86_64 / aarch64

echo "[toolchain] apt packages..."
apt-get update -qq || warn "apt update failed"
# Try the fuller set first; fall back to the essentials if a package name is unavailable.
apt-get install -y -qq default-jdk-headless unzip wget ca-certificates ripgrep apktool jadx adb aapt >/dev/null 2>&1 \
  || apt-get install -y -qq default-jdk-headless unzip wget ca-certificates ripgrep apktool jadx adb >/dev/null 2>&1 \
  || warn "some apt packages unavailable — install apktool/jadx/adb manually if missing"

echo "[toolchain] pip: androguard..."
pip3 install --break-system-packages --quiet 'androguard==4.1.4' 2>/dev/null || warn "androguard pip install failed"   # pin: unpinned installs drift toward the v5 line

echo "[toolchain] apkeep ${APKEEP_VER}..."
case "$ARCH" in
  x86_64) AK="apkeep-x86_64-unknown-linux-gnu" ;;
  aarch64) AK="apkeep-aarch64-unknown-linux-gnu" ;;
  *) AK="" ;;
esac
if [ -n "$AK" ] && wget -qO /usr/local/bin/apkeep \
     "https://github.com/EFForg/apkeep/releases/download/${APKEEP_VER}/${AK}"; then
  chmod +x /usr/local/bin/apkeep
else
  warn "apkeep download failed — fall back to: cargo install apkeep"
fi

echo "[toolchain] APKEditor ${APKEDITOR_VER}..."
wget -qO /opt/APKEditor.jar \
  "https://github.com/REAndroid/APKEditor/releases/download/V${APKEDITOR_VER}/APKEditor-${APKEDITOR_VER}.jar" \
  || warn "APKEditor download failed — split/XAPK merge will be unavailable"

echo "[toolchain] ipatool ${IPATOOL_VER}..."
case "$ARCH" in
  x86_64) IT="ipatool-${IPATOOL_VER}-linux-amd64.tar.gz" ;;
  aarch64) IT="ipatool-${IPATOOL_VER}-linux-arm64.tar.gz" ;;
  *) IT="" ;;
esac
if [ -n "$IT" ] && wget -qO /tmp/ipatool.tgz \
     "https://github.com/majd/ipatool/releases/download/v${IPATOOL_VER}/${IT}"; then
  tar -xzf /tmp/ipatool.tgz -C /tmp && \
    install -m0755 "$(find /tmp -name ipatool -type f | head -1)" /usr/local/bin/ipatool 2>/dev/null \
    || warn "ipatool extract failed"
  rm -f /tmp/ipatool.tgz
else
  warn "ipatool download failed (iOS acquisition unavailable)"
fi

apt-get clean; rm -rf /var/lib/apt/lists/* /tmp/* 2>/dev/null || true
echo "[toolchain] done. Present:"
for t in apkeep jadx apktool adb rg java ipatool; do
  printf '  %-10s %s\n' "$t" "$(command -v "$t" 2>/dev/null || echo MISSING)"
done
[ -f /opt/APKEditor.jar ] && echo "  APKEditor  /opt/APKEditor.jar" || echo "  APKEditor  MISSING"
exit 0
