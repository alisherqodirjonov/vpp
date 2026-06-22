# Licensing of the strongSwan `kernel-vpp` plugin

**Short answer: the built binary `libstrongswan-kernel-vpp.so` is distributed
under the GNU General Public License, version 2 or later (GPL-2.0-or-later).**

## Why

The individual source files in this directory (`kernel_vpp_*.c/.h`) carry an
**Apache License 2.0** grant from their original authors (Intel, 2022; based on
earlier work by Matus Fabian at Cisco). That grant is preserved and remains
valid for those files' original contribution.

However, this plugin `#include`s strongSwan headers (`<daemon.h>`,
`<utils/debug.h>`, `<kernel/kernel_ipsec.h>`, `<plugins/plugin.h>`, …) and links
against **libstrongswan** and **libcharon**, which are licensed under the
**GNU GPL, version 2 or later**. The compiled plugin is therefore a *derivative
work* of strongSwan. Under the terms of the GPL, the resulting combined binary
must be distributed under the GPL.

Because strongSwan is offered as "version 2 **or any later version**", the
combination is distributable under the GNU GPL (and the Apache-2.0-licensed
original files are compatible with GPLv3), so there is no license conflict.

## What this means for redistribution

- The binary `libstrongswan-kernel-vpp.so` is conveyed under GPL-2.0-or-later.
- The complete corresponding source for this plugin (these files) is made
  available per the written offer shipped with the appliance
  (`/opt/sarhad-guard/THIRD-PARTY-LICENSES/WRITTEN-OFFER.txt`).
- The original Apache-2.0 notices in the source files are retained (Apache-2.0
  §4) and must not be removed.

## SPDX

Per-file effective licensing:

    SPDX-License-Identifier: Apache-2.0 AND GPL-2.0-or-later

See `LICENSE` / `COPYING` (GPL v2 text) and `AUTHORS` in this directory, and the
strongSwan project for its own license: https://www.strongswan.org/
