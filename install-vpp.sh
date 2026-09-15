#!/usr/bin/env bash
#
# install-vpp.sh -- install the VPP binaries built in this tree into the OS.
#
# Removes the old sarhad-guard systemd units and any previously installed VPP
# binaries/libraries/plugins from $PREFIX, then installs the freshly built ones
# from the CMake build directory.
#
# Usage:  sudo ./install-vpp.sh [options]
#
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${BUILD_DIR:-${SRC_DIR}/build}"
PREFIX="${PREFIX:-/usr/local}"
ARCH_TRIPLET="$(gcc -dumpmachine 2>/dev/null || echo x86_64-linux-gnu)"
LIB_DIR="${PREFIX}/lib/${ARCH_TRIPLET}"

# systemd units removed before installing (old services).
OLD_SERVICES=(sarhad-vpp.service sarhad-backend.service vpp.service)

# The unit installed afterwards. The name is load-bearing: the Go management
# plane starts/stops the dataplane by this exact unit name.
VPP_UNIT="vpp.service"
VPP_CONF="${VPP_CONF:-/etc/sarhad-guard/startup.conf}"

# The management-plane repo ships the canonical unit (it carries the vfio-pci
# and mlx5 modprobe lines). Prefer it over the built-in fallback below, but
# rewrite its ExecStart: it ships /usr/bin/vpp for the deb/ISO layout, while a
# source build lands in ${PREFIX}/bin.
UNIT_SRC="${UNIT_SRC:-${SRC_DIR}/../vpp-go-test/deploy/vpp.service}"

PURGE=1
KEEP_SERVICES=0
INSTALL_UNIT=1
DRY_RUN=0
STRIP=0

usage() {
	cat <<EOF
Usage: sudo $0 [options]

Options:
  --no-purge        keep the previously installed binaries (just overwrite)
  --keep-services   do not stop/disable/remove the old systemd units
  --no-service      do not install the vpp.service systemd unit
  --strip           install stripped binaries (smaller, no debug symbols)
  --dry-run         show what would be done, change nothing
  -h, --help        this help

Environment:
  BUILD_DIR   CMake build directory  (default: ${SRC_DIR}/build)
  PREFIX      install prefix         (default: /usr/local)
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
	--no-purge) PURGE=0 ;;
	--keep-services) KEEP_SERVICES=1 ;;
	--no-service) INSTALL_UNIT=0 ;;
	--strip) STRIP=1 ;;
	--dry-run) DRY_RUN=1 ;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "unknown option: $1" >&2
		usage >&2
		exit 1
		;;
	esac
	shift
done

say() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m==> WARNING:\033[0m %s\n' "$*" >&2; }
die() {
	printf '\033[1;31m==> ERROR:\033[0m %s\n' "$*" >&2
	exit 1
}

run() {
	if [ "$DRY_RUN" = 1 ]; then
		printf '    [dry-run] %s\n' "$*"
	else
		"$@"
	fi
}

#
# preflight
#
[ "$(id -u)" -eq 0 ] || die "must run as root: sudo $0 $*"
[ -d "$BUILD_DIR" ] || die "build directory not found: $BUILD_DIR (run 'make build-release' first)"
[ -x "${BUILD_DIR}/bin/vpp" ] || die "no vpp binary in ${BUILD_DIR}/bin -- build the tree first"
[ -d "${BUILD_DIR}/lib/${ARCH_TRIPLET}" ] || die "no libraries in ${BUILD_DIR}/lib/${ARCH_TRIPLET}"
command -v cmake >/dev/null || die "cmake not found"

say "source tree : ${SRC_DIR}"
say "build dir   : ${BUILD_DIR}"
say "prefix      : ${PREFIX}"
say "libdir      : ${LIB_DIR}"
[ "$DRY_RUN" = 1 ] && say "DRY RUN -- nothing will be changed"

#
# 1. stop and remove the old services
#
if [ "$KEEP_SERVICES" = 0 ]; then
	say "removing old systemd services"
	for svc in "${OLD_SERVICES[@]}"; do
		if systemctl list-unit-files "$svc" --no-legend 2>/dev/null | grep -q .; then
			echo "    - $svc"
			run systemctl stop "$svc" || true
			run systemctl disable "$svc" || true
		fi
		for unit in "/etc/systemd/system/${svc}" "/lib/systemd/system/${svc}" \
			"/usr/lib/systemd/system/${svc}"; do
			[ -e "$unit" ] && run rm -f "$unit"
		done
		run rm -rf "/etc/systemd/system/${svc}.d" "/etc/systemd/system/${svc}.wants"
	done
	run systemctl daemon-reload
	run systemctl reset-failed || true
else
	say "keeping old systemd services (--keep-services)"
fi

# Nothing may hold the old shared libraries open while we replace them.
#
# Stop the unit through systemd, not with pkill. The unit is Restart=always /
# RestartSec=2, so killing the process just makes systemd start a new vpp two
# seconds later -- in the middle of `cmake --install`, which is still copying
# ~150 plugins. That process comes up on whatever mix of old and new .so files
# happens to be on disk at that instant, and the freshly built fixes silently
# do not take effect. Remember whether it was running so we can bring it back
# on the new binaries once the install is complete.
VPP_WAS_RUNNING=0
if systemctl is-active --quiet "$VPP_UNIT" 2>/dev/null; then
	VPP_WAS_RUNNING=1
	say "stopping ${VPP_UNIT}"
	run systemctl stop "$VPP_UNIT" || true
fi

# Anything still holding the libraries (a manually started vpp, or a unit that
# failed to stop) has to go too.
if pgrep -x vpp >/dev/null 2>&1; then
	say "stopping leftover vpp processes"
	run pkill -x vpp || true
	for _ in $(seq 1 10); do
		pgrep -x vpp >/dev/null 2>&1 || break
		sleep 1
	done
	pgrep -x vpp >/dev/null 2>&1 && run pkill -9 -x vpp || true
fi

#
# 2. purge the previously installed binaries
#
# Only files whose names are produced by this build tree are removed, so
# unrelated things living in ${PREFIX}/bin (mitmproxy & friends) are untouched.
# The wildcard suffix also catches stale sonames from older VPP versions
# (e.g. libvlib.so.26.02 next to the new libvlib.so.0.0.0).
#
if [ "$PURGE" = 1 ]; then
	say "removing previously installed VPP binaries from ${PREFIX}"

	n=0
	while IFS= read -r f; do
		old="${PREFIX}/bin/$(basename "$f")"
		[ -e "$old" ] || continue
		run rm -f "$old"
		n=$((n + 1))
	done < <(find "${BUILD_DIR}/bin" -maxdepth 1 -type f)
	echo "    - ${n} binaries from ${PREFIX}/bin"

	n=0
	while IFS= read -r f; do
		b="$(basename "$f")"
		for old in "${LIB_DIR}/${b}"*; do
			[ -e "$old" ] || continue
			run rm -f "$old"
			n=$((n + 1))
		done
	done < <(find "${BUILD_DIR}/lib/${ARCH_TRIPLET}" -maxdepth 1 \( -name 'lib*.so' -o -name 'lib*.so.*' \))
	echo "    - ${n} libraries from ${LIB_DIR}"

	for d in vpp_plugins vpp_api_test_plugins vat2_plugins vpp_crypto_engines; do
		[ -d "${LIB_DIR}/${d}" ] || continue
		echo "    - ${LIB_DIR}/${d} ($(find "${LIB_DIR}/${d}" -name '*.so' | wc -l) plugins)"
		run rm -rf "${LIB_DIR}/${d}"
	done

	for d in vlib vlibapi vlibmemory vnet vppinfra vpp-api vapi vat vat2 vcl svm \
		lcp nat selog_client vpp_plugins; do
		[ -d "${PREFIX}/include/${d}" ] || continue
		echo "    - ${PREFIX}/include/${d}"
		run rm -rf "${PREFIX}/include/${d}"
	done
	run rm -rf "${PREFIX}/share/vpp"
else
	say "skipping purge (--no-purge)"
fi

#
# 3. install the freshly built binaries
#
say "installing into ${PREFIX}"
if [ "$STRIP" = 1 ]; then
	run cmake --install "$BUILD_DIR" --prefix "$PREFIX" --strip
else
	run cmake --install "$BUILD_DIR" --prefix "$PREFIX"
fi

#
# 4. install the systemd unit
#
# The Go management plane supervises the dataplane through systemd and expects
# the unit to be called exactly "vpp.service" (vpp-go-test/main.go: vppUnit);
# it never spawns vpp itself, so without this unit the supervisor sits in a
# restart loop even when a vpp process is running.
#
if [ "$INSTALL_UNIT" = 1 ]; then
	say "installing ${VPP_UNIT}"
	if [ -f "$UNIT_SRC" ]; then
		echo "    from ${UNIT_SRC} (ExecStart -> ${PREFIX}/bin/vpp)"
		if [ "$DRY_RUN" = 1 ]; then
			printf '    [dry-run] install /etc/systemd/system/%s\n' "$VPP_UNIT"
		else
			sed -E "s|^ExecStart=[^ ]*/vpp |ExecStart=${PREFIX}/bin/vpp |" \
				"$UNIT_SRC" >"/etc/systemd/system/${VPP_UNIT}"
			chmod 644 "/etc/systemd/system/${VPP_UNIT}"
			grep -q "^ExecStart=${PREFIX}/bin/vpp " "/etc/systemd/system/${VPP_UNIT}" ||
				warn "could not rewrite ExecStart in ${VPP_UNIT} -- check it by hand"
		fi
	elif [ "$DRY_RUN" = 1 ]; then
		printf '    [dry-run] write /etc/systemd/system/%s (built-in fallback)\n' "$VPP_UNIT"
	else
		cat >"/etc/systemd/system/${VPP_UNIT}" <<EOF
[Unit]
Description=Sarhad Guard VPP Dataplane
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=-/sbin/modprobe vfio-pci
ExecStartPre=/bin/mkdir -p /run/sarhad-guard /dev/shm/sarhad-guard /var/log/sarhad-guard
ExecStart=${PREFIX}/bin/vpp -c ${VPP_CONF}
Restart=always
RestartSec=2
# vpp maps its buffer pool from hugepages and locks it; both need these raised.
LimitNOFILE=1048576
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF
	fi
	run systemctl daemon-reload
	run systemctl enable "$VPP_UNIT"
	[ -f "$VPP_CONF" ] || warn "${VPP_CONF} does not exist -- ${VPP_UNIT} will fail to start"
else
	say "skipping systemd unit install (--no-service)"
fi

#
# 5. refresh the dynamic linker cache
#
say "refreshing the linker cache"
if ! grep -rqs "^${LIB_DIR}\$" /etc/ld.so.conf /etc/ld.so.conf.d/; then
	run sh -c "echo '${LIB_DIR}' > /etc/ld.so.conf.d/vpp.conf"
fi
run ldconfig

#
# 6. verify
#
if [ "$DRY_RUN" = 1 ]; then
	say "dry run finished"
	exit 0
fi

say "verifying the installation"
[ -x "${PREFIX}/bin/vpp" ] || die "${PREFIX}/bin/vpp is missing after install"
[ -x "${PREFIX}/bin/vppctl" ] || die "${PREFIX}/bin/vppctl is missing after install"

if ldd "${PREFIX}/bin/vpp" | grep -q "not found"; then
	ldd "${PREFIX}/bin/vpp" | grep "not found" >&2
	die "vpp has unresolved shared libraries"
fi

plugins=$(find "${LIB_DIR}/vpp_plugins" -name '*.so' 2>/dev/null | wc -l)
echo "    vpp      : $("${PREFIX}/bin/vpp" version 2>/dev/null || echo "${PREFIX}/bin/vpp")"
echo "    binaries : $(find "${BUILD_DIR}/bin" -maxdepth 1 -type f | wc -l) in ${PREFIX}/bin"
echo "    plugins  : ${plugins} in ${LIB_DIR}/vpp_plugins"

# Bring the dataplane back on the new binaries. Doing it here, after the copy
# has finished, is the whole point of having stopped the unit above.
if [ "$VPP_WAS_RUNNING" = 1 ]; then
	say "starting ${VPP_UNIT} on the new binaries"
	run systemctl start "$VPP_UNIT" || warn "could not start ${VPP_UNIT}"
fi

say "done"
echo
echo "Next steps:"
if [ "$VPP_WAS_RUNNING" = 1 ]; then
	echo "  systemctl status ${VPP_UNIT}    # already restarted on the new build"
else
	echo "  systemctl start ${VPP_UNIT}"
fi
echo "  vppctl -s /run/sarhad-guard/cli.sock show version"
