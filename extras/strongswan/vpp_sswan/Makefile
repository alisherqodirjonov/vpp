# the directory to the strongSwan sources
SWANDIR=${CURDIR}/../../../build-root/build-vpp-native/external/sswan
# location of config.h
CONFIGH=$(SWANDIR)/config.h
# default install prefix: /usr/local or /usr
PREFIX=/usr
# location of the installed strongSwan libraries
SWANLIBS=$(PREFIX)/lib/ipsec/
# location of the strongSwan plugins
SWANPLUGINS=$(PREFIX)/lib/ipsec/plugins
# location of the strongSwan archive
SWANARCHIVE=${CURDIR}/../../../build/external/downloads
# default install configuration files:
PREFIX_SYS_CONF=/etc
# target location of the plugin config snippet: $(PREFIX)/etc/strongswan.d/charon/ or /etc/strongswan.d/charon/
PLUGINCONF=$(PREFIX_SYS_CONF)/strongswan.d/charon/
# location of the  VPP libraries
VPPLIBS=$(CURDIR)/../../../build-root/install-vpp-native/vpp/lib/x86_64-linux-gnu
# the directory to the VPP sources
VPPDIR=../../../build-root/install-vpp-native/vpp/include

TARGET=libstrongswan-kernel-vpp.so

# tested only with 5.9.5 and 5.9.6 version of strongSwan
VERSION_SSWAN=5.9.6

CFLAGS=-O2 -g -Wall -Wextra -fpic

CFLAGS_I=-include $(CONFIGH) \
	-I$(SWANDIR)/src/libstrongswan \
	-I$(SWANDIR)/src/libcharon

# VPP headers. The conditional block further down only adds -I$(VPPDIR)
# when vppinfra.so is ABSENT from ldconfig, and $(VPPDIR)
# (install-vpp-native/.../include) is not produced by every VPP build
# layout — so on a box where VPP is in ldconfig but its headers are not
# installed system-wide, the plugin fails to compile (vlibapi/api.h not
# found). Point straight at the in-tree source + the generated
# .api_*.h headers so the build works regardless of how VPP was set up.
VPP_SRC_INC=$(CURDIR)/../../../src
VPP_GEN_INC=$(CURDIR)/../../../build/CMakeFiles
ifeq ($(shell test -d $(VPP_SRC_INC)/vlibapi && echo yes), yes)
	CFLAGS_I += -I$(VPP_SRC_INC) -I$(VPP_GEN_INC)
endif

# Link against the IN-TREE VPP build (build/lib), NOT whatever stale VPP may be
# in ldconfig (e.g. an old `make install` under /usr/local/lib). The appliance
# ships VPP from build/, so this plugin MUST record the same lib SONAMEs — else
# charon can't load it ("libvppinfra.so.X.Y: cannot open shared object file").
# -L must precede -l so build/ wins over the system search path. -rpath-link is
# link-time only (no dev path baked into the shipped .so).
VPP_BUILD_LIB=$(CURDIR)/../../../build/lib/x86_64-linux-gnu
LDFLAGS= -L$(VPP_BUILD_LIB) -Wl,-rpath-link=$(VPP_BUILD_LIB) \
	-lvppinfra \
	-lvlibmemoryclient \
	-lvlibapi \
	-lsvm \
	-lvppapiclient

VERSION_VPP=$(shell (dpkg -s vpp | grep Version) | grep -Po '(?<=Version: )\d\d.\d\d')

# check if VPP is installed
ifneq ($(shell test "$(shell ldconfig -p | grep vppinfra.so | awk 'NR==1{print $$1;}')" && echo "yes"), yes)
# check if VPPDIR exists
ifeq ($(shell test -d $(VPPDIR) && echo "yes"), yes)
	CFLAGS_I += -I$(VPPDIR)
endif
# check if VPPLIBS exists
ifeq ($(shell test -d $(VPPLIBS) && echo "yes"), yes)
	LDFLAGS += -L$(VPPLIBS)
	LDFLAGS += -Wl,-rpath=$(VPPLIBS)
endif
endif

SOURCES=$(wildcard *.c)
OBJECTS=$(SOURCES:.c=.o)

all: pull-swan install-swan $(TARGET)

pull-swan:
	@if [ -d "${SWANDIR}" ]; then \
	  rm -rf ${SWANDIR} ; \
	fi
	@if ! [ -f "${SWANARCHIVE}/strongswan-${VERSION_SSWAN}.tar.gz" ]; then \
	  curl -o ${SWANARCHIVE}/strongswan-${VERSION_SSWAN}.tar.gz -LO https://github.com/strongswan/strongswan/archive/${VERSION_SSWAN}.tar.gz; \
	fi
	@if ! [ -d "${CURDIR}/../../../build-root/build-vpp-native/external/" ]; then \
	  mkdir ${CURDIR}/../../../build-root/build-vpp-native/external; \
	fi
	tar -zxof ${SWANARCHIVE}/strongswan-${VERSION_SSWAN}.tar.gz -C ${CURDIR}/../../../build-root/build-vpp-native/external/
	mv ${CURDIR}/../../../build-root/build-vpp-native/external/strongswan-${VERSION_SSWAN} ${SWANDIR}
	cd ${SWANDIR} && ./autogen.sh
	cd ${SWANDIR} && ./configure --prefix=${PREFIX} --sysconfdir=${PREFIX_SYS_CONF} --enable-libipsec --enable-systemd --enable-swanctl --disable-gmp --enable-openssl

install-swan:
	@if ! [ -f "${SWANDIR}/configure" ]; then \
	  echo "SSWAN not downloaded, please run "make" or "make pull-swan" first." ; \
	  exit 1 ; \
	fi
	cd ${SWANDIR} && $(MAKE) -j$(nproc)
	cd ${SWANDIR} && sudo $(MAKE) install

# check if VPP is installed
ifneq ($(shell test "$(shell ldconfig -p | grep vppinfra.so | awk 'NR==1{print $$1;}')" && echo "yes"), yes)
	$(info INFO: Not found installed VPP - checking if locally VPP exists)
# check if VPPDIR exists
ifneq ($(shell test -d $(VPPDIR) && echo "yes"), yes)
	$(error ERROR: Not found installed VPP and locally VPP - please install or build)
else
# check if VPPLIBS exists
ifneq ($(shell test -d $(VPPLIBS) && echo "yes"), yes)
	$(error ERROR: directory $(VPPLIBS) - doesn't exists, please compile VPP before build this)
else
	$(info INFO: Found locally VPP)
endif
endif
else
	$(info INFO: Found installed VPP in version: $(VERSION_VPP))
endif

$(TARGET): $(OBJECTS)
	gcc $(CFLAGS) -shared -DPIC $(OBJECTS) $(LDFLAGS) -Wl,-soname -Wl,$(TARGET) -o $@
	cp $(TARGET) ${SWANDIR}

%.o: %.c
	gcc $(CFLAGS) $(CFLAGS_I) -c $< -o $@ $(LDFLAGS)

install:
	cp $(TARGET) $(SWANPLUGINS)/$(TARGET)
	@# Do not clobber an existing conf — operator setting (route_mode etc.) wins.
	@# Use 'make install-conf' to force-overwrite from source.
	@if [ ! -f "$(PLUGINCONF)/kernel-vpp.conf" ]; then \
	  cp kernel-vpp.conf $(PLUGINCONF); \
	  echo "installed kernel-vpp.conf to $(PLUGINCONF)"; \
	else \
	  echo "kernel-vpp.conf already present in $(PLUGINCONF) — leaving as-is"; \
	fi

install-conf:
	cp kernel-vpp.conf $(PLUGINCONF)

clean:
	rm -f ${SWANARCHIVE}/strongswan-${VERSION_SSWAN}.tar.gz
	rm -rf ${SWANDIR}
	rm -f *.so *.o

.PHONY: clean install all
