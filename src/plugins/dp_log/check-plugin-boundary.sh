#!/bin/sh
# Fail the build if a plugin references another plugin's symbols directly.
#
# VPP dlopen()s plugins independently and does not link them to one another,
# so such a reference survives compilation and linking and only fails at
# dlopen time -- where the loader answers by refusing the whole plugin. When
# that plugin is acl_plugin, the acl-plugin-in-ip4-fa feature node ceases to
# exist, every NAT / ABF / cnat feature-arc registration anchored on it
# fails, and VPP exits during startup. The symptom is a systemd restart loop
# with no traffic, and the cause is invisible in the build log.
#
# So it is checked here instead: undefined symbols belonging to a foreign
# plugin are a build failure in the plugin that made them.
#
# Usage: check-plugin-boundary.sh <plugin.so> <foreign-symbol-prefix>...
set -e

so=$1
shift
[ -f "$so" ] || { echo "check-plugin-boundary: no such file: $so" >&2; exit 1; }

# No nm means no check rather than a false pass: say so loudly.
command -v nm >/dev/null 2>&1 || {
  echo "check-plugin-boundary: nm not found; cannot verify $so" >&2
  exit 1
}

undef=$(nm -D --undefined-only "$so" 2>/dev/null | awk '{print $NF}')
rc=0
for prefix in "$@"; do
  hits=$(printf '%s\n' "$undef" | grep "^${prefix}" || true)
  if [ -n "$hits" ]; then
    echo "" >&2
    echo "ERROR: $(basename "$so") references '${prefix}*' symbols directly:" >&2
    printf '  %s\n' $hits >&2
    echo "" >&2
    echo "  Plugins are not linked to each other. Reach the other plugin" >&2
    echo "  through vlib_get_plugin_symbol () -- for dp_log that is the" >&2
    echo "  dp_log_client_t half of dp_log.h." >&2
    echo "" >&2
    rc=1
  fi
done
exit $rc
