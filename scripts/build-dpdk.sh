#!/usr/bin/env bash
#
# Build DPDK 25.11 LTS from source with only the drivers quictun needs.
# Produces a static library install suitable for linking into quictun.
#
# Usage:
#   sudo ./scripts/build-dpdk.sh
#
# Environment variables:
#   DPDK_VERSION   DPDK version to build (default: 25.11)
#   DPDK_PREFIX    Install prefix (default: /opt/dpdk)
#   BUILD_DIR      Temporary build directory (default: /tmp/dpdk-build)

set -euo pipefail

DPDK_VERSION="${DPDK_VERSION:-25.11}"
DPDK_PREFIX="${DPDK_PREFIX:-/opt/dpdk}"
BUILD_DIR="${BUILD_DIR:-/tmp/dpdk-build}"

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (sudo)"
    exit 1
fi

# ── 1. Install build dependencies ────────────────────────────────────

info "Installing build dependencies..."
apt-get update -qq
apt-get install -y -qq \
    build-essential meson ninja-build python3-pyelftools \
    libnuma-dev pkg-config \
    libxdp-dev libbpf-dev \
    libsystemd-dev libfdt-dev libbsd-dev libpcap-dev \
    libdbus-1-dev libibverbs-dev libnl-route-3-dev \
    libzstd-dev libjansson-dev libmd-dev \
    wget

# ── 2. Download ──────────────────────────────────────────────────────

mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

tarball="dpdk-${DPDK_VERSION}.tar.xz"
if [[ ! -f "${tarball}" ]]; then
    info "Downloading DPDK ${DPDK_VERSION}..."
    wget -q "https://fast.dpdk.org/rel/${tarball}"
fi

src_dir="dpdk-${DPDK_VERSION}"
if [[ ! -d "${src_dir}" ]]; then
    tar xJf "${tarball}"
fi
cd "${src_dir}"

# ── 3. Configure ─────────────────────────────────────────────────────
#
# Drivers included:
#   bus/pci       — PCI bus (required for physical NICs)
#   bus/vdev      — Virtual device bus (required for TAP, virtio-user, memif)
#   mempool/ring  — Ring-based mempool (default, required)
#   net/virtio    — Virtio NIC + virtio-user (inner interface via vhost-net)
#   net/af_xdp    — AF_XDP socket PMD (alternative inner interface)
#   net/tap       — TAP PMD (simple inner interface)

info "Configuring DPDK ${DPDK_VERSION} (static, 6 drivers)..."
[[ -d build ]] && rm -rf build

meson setup build \
    --prefix="${DPDK_PREFIX}" \
    -Dplatform=native \
    -Ddefault_library=static \
    -Denable_drivers=bus/pci,bus/vdev,mempool/ring,net/virtio,net/af_xdp,net/tap \
    -Ddisable_apps='*' \
    -Dtests=false \
    -Dexamples='' \
    -Denable_docs=false \
    -Dmax_lcores=128

# ── 4. Build and install ─────────────────────────────────────────────

info "Building (this takes 2-5 minutes)..."
ninja -C build -j"$(nproc)"

info "Installing to ${DPDK_PREFIX}..."
ninja -C build install
ldconfig

# ── 5. Verify ────────────────────────────────────────────────────────

# Find pkg-config path (varies by distro).
pc_path=""
for candidate in \
    "${DPDK_PREFIX}/lib/x86_64-linux-gnu/pkgconfig" \
    "${DPDK_PREFIX}/lib64/pkgconfig" \
    "${DPDK_PREFIX}/lib/pkgconfig"; do
    if [[ -f "${candidate}/libdpdk.pc" ]]; then
        pc_path="${candidate}"
        break
    fi
done

if [[ -z "${pc_path}" ]]; then
    error "Could not find libdpdk.pc under ${DPDK_PREFIX}"
    exit 1
fi

ver=$(PKG_CONFIG_PATH="${pc_path}" pkg-config --modversion libdpdk)
info "DPDK ${ver} installed at ${DPDK_PREFIX}"
info ""
info "To build quictun:"
info "  PKG_CONFIG_PATH=${pc_path} cargo build --release"

# ── 6. Clean up ──────────────────────────────────────────────────────

cd /
rm -rf "${BUILD_DIR}"
info "Build directory cleaned up."
