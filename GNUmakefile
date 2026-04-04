# VPP Build Wrapper
# Simple makefile that wraps ./configure + ninja for easy building.
# Overrides the upstream Makefile (GNU make prefers GNUmakefile).
#
# Usage:
#   make                  - configure (if needed) + build release
#   make debug            - configure (if needed) + build debug
#   make configure        - run configure only (release)
#   make configure-debug  - run configure only (debug)
#   make clean            - remove build directory
#   make install-dep      - install system dependencies (needs sudo)
#   make run              - run VPP with default startup.conf
#   make install          - install VPP to /usr/local

SHELL      := /bin/bash
BUILD_DIR  ?= $(CURDIR)/build
BUILD_TYPE ?= release
INSTALL_DIR?= /usr/local
NINJA      ?= ninja
SUDO       ?= sudo -E
CONFIGURE  := $(CURDIR)/configure

# Marker file to track if configure has been run
CONFIGURED := $(BUILD_DIR)/build.ninja

# OS detection for install-dep (reused from upstream Makefile)
OS_ID        = $(shell grep '^ID=' /etc/os-release 2>/dev/null | cut -f2- -d= | sed -e 's/\"//g')
OS_VERSION_ID= $(shell grep '^VERSION_ID=' /etc/os-release 2>/dev/null | cut -f2- -d= | sed -e 's/\"//g')

##############################################################################
# Default target: build release
##############################################################################

.PHONY: all
all: release

.PHONY: release
release: BUILD_TYPE=release
release: $(BUILD_DIR)/release.stamp
	@$(NINJA) -C $(BUILD_DIR)

$(BUILD_DIR)/release.stamp:
	$(CONFIGURE) -b $(BUILD_DIR) -t release
	@touch $@

.PHONY: debug
debug: $(BUILD_DIR)/debug.stamp
	@$(NINJA) -C $(BUILD_DIR)

$(BUILD_DIR)/debug.stamp:
	$(CONFIGURE) -b $(BUILD_DIR) -t debug
	@touch $@

##############################################################################
# Configure only
##############################################################################

.PHONY: configure
configure:
	$(CONFIGURE) -b $(BUILD_DIR) -t release

.PHONY: configure-debug
configure-debug:
	$(CONFIGURE) -b $(BUILD_DIR) -t debug

##############################################################################
# Reconfigure (wipe + configure)
##############################################################################

.PHONY: reconfigure
reconfigure: clean configure

.PHONY: reconfigure-debug
reconfigure-debug: clean configure-debug

##############################################################################
# Build with ninja directly (assumes already configured)
##############################################################################

.PHONY: build
build:
	@if [ ! -f $(BUILD_DIR)/build.ninja ]; then \
		echo "Not configured yet. Run 'make configure' or 'make' first."; \
		exit 1; \
	fi
	@$(NINJA) -C $(BUILD_DIR)

##############################################################################
# Install
##############################################################################

.PHONY: install
install:
	@$(NINJA) -C $(BUILD_DIR) install

##############################################################################
# Run / Debug
##############################################################################

.PHONY: run
run:
	@$(NINJA) -C $(BUILD_DIR) run

.PHONY: gdb
gdb:
	@$(NINJA) -C $(BUILD_DIR) debug

##############################################################################
# Install system dependencies
##############################################################################

.PHONY: install-dep install-deps
install-dep:
ifeq ($(filter ubuntu debian linuxmint,$(OS_ID)),$(OS_ID))
	@$(SUDO) apt-get update
	@$(SUDO) apt-get -y install \
		curl build-essential ccache debhelper git \
		clang gcovr lcov chrpath \
		python3-all python3-setuptools check \
		python3-ply libunwind-dev \
		cmake ninja-build python3-jsonschema python3-yaml \
		python3-venv python3-dev python3-pip \
		libnl-3-dev libnl-route-3-dev libmnl-dev \
		python3-virtualenv libssl-dev \
		libelf-dev libpcap-dev libnuma-dev nasm
else ifeq ($(filter fedora rhel centos rocky almalinux,$(OS_ID)),$(OS_ID))
	@$(SUDO) dnf install -y \
		gcc gcc-c++ make cmake ninja-build ccache \
		openssl-devel elfutils-libelf-devel libpcap-devel \
		libnl3-devel libmnl-devel numactl-devel nasm \
		python3-devel python3-ply python3-jsonschema python3-pip
else
	@echo "Unsupported OS: $(OS_ID). Install cmake, ninja-build, clang/gcc, and dev libraries manually."
	@exit 1
endif

install-deps: install-dep

##############################################################################
# Clean
##############################################################################

.PHONY: clean
clean:
	@rm -rf $(BUILD_DIR)
	@echo "Build directory removed: $(BUILD_DIR)"

.PHONY: distclean
distclean: clean
	@rm -f build.ninja
	@echo "Stale root build.ninja removed"

##############################################################################
# Packaging
##############################################################################

.PHONY: pkg-deb
pkg-deb:
	@$(NINJA) -C $(BUILD_DIR) pkg-deb

.PHONY: pkg-rpm
pkg-rpm:
	@$(NINJA) -C $(BUILD_DIR) pkg-rpm

##############################################################################
# Convenience: pass through to upstream Makefile
##############################################################################

.PHONY: upstream-%
upstream-%:
	@$(MAKE) -f $(CURDIR)/Makefile $*

##############################################################################
# Help
##############################################################################

.PHONY: help
help:
	@echo ""
	@echo "VPP Build Targets:"
	@echo "  make                - build release (configure if needed)"
	@echo "  make debug          - build debug   (configure if needed)"
	@echo "  make configure      - configure release build"
	@echo "  make configure-debug- configure debug build"
	@echo "  make build          - ninja build (must be configured)"
	@echo "  make clean          - remove build directory"
	@echo "  make distclean      - clean + remove stale root build.ninja"
	@echo "  make install        - install VPP to $(INSTALL_DIR)"
	@echo "  make install-dep    - install system dependencies (sudo)"
	@echo "  make run            - run VPP"
	@echo "  make gdb            - run VPP under GDB"
	@echo "  make pkg-deb        - build .deb packages"
	@echo "  make pkg-rpm        - build .rpm packages"
	@echo "  make upstream-<tgt> - run target from upstream Makefile"
	@echo ""
	@echo "Variables:"
	@echo "  BUILD_DIR=$(BUILD_DIR)"
	@echo "  INSTALL_DIR=$(INSTALL_DIR)"
	@echo ""
