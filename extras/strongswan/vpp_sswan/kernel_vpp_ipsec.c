/*
 * Copyright (c) 2022 Intel and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <daemon.h>
#include <utils/debug.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/ipsec/ipsec.h>
#include <vnet/vnet.h>
#include <collections/hashtable.h>
#include <threading/mutex.h>
#include <processing/jobs/callback_job.h>
#include <vpp-api/client/stat_client.h>

#define vl_typedefs
#define vl_endianfun
/* Include the (first) vlib-api API definition layer */
#include <vlibmemory/vl_memory_api_h.h>
/* Include the current layer (third) vpp API definition layer */
#include <vpp/api/vpe_types.api.h>
#include <vpp/api/vpe.api.h>

#include <vnet/ip-neighbor/ip_neighbor.api_enum.h>
#include <vnet/ip-neighbor/ip_neighbor.api_types.h>
#include <vnet/ip/ip.api_enum.h>
#include <vnet/ip/ip.api_types.h>
#include <vnet/ipsec/ipsec.api_enum.h>
#include <vnet/ipsec/ipsec.api_types.h>
#include <vnet/interface.api_enum.h>
#include <vnet/interface.api_types.h>
#undef vl_typedefs
#undef vl_endianfun

#include "kernel_vpp_ipsec.h"
#include "kernel_vpp_shared.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/route.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <net/if_arp.h>
#include <sys/stat.h>
#include <dirent.h>

#define PRIO_BASE 384

u32 natt_port;

/**
 * One and only instance of the daemon.
 */
daemon_t *charon;

typedef struct private_kernel_vpp_ipsec_t private_kernel_vpp_ipsec_t;

/**
 * Private variables of kernel_vpp_ipsec class.
 */
struct private_kernel_vpp_ipsec_t
{

  /**
   * Public interface
   */
  kernel_vpp_ipsec_t public;

  /**
   * Next security association database entry ID to allocate
   */
  refcount_t next_sad_id;

  /**
   * Next security policy database entry ID to allocate
   */
  refcount_t next_spd_id;

  /**
   * Mutex to lock access to installed policies
   */
  mutex_t *mutex;

  /**
   * Hash table of instaled SA, as kernel_ipsec_sa_id_t => sa_t
   */
  hashtable_t *sas;

  /**
   * Hash table of security policy databases, as nterface => spd_t
   */
  hashtable_t *spds;

  /**
   * Linked list of installed routes
   */
  linked_list_t *routes;

  /**
   * Next SPI to allocate
   */
  refcount_t nextspi;

  /**
   * Mix value to distribute SPI allocation randomly
   */
  uint32_t mixspi;

  /**
   * Whether to install routes along policies
   */
  bool install_routes;

  /**
   * Whether to install SAs with tunnel flag. Disabling this can be useful
   * in some scenarios e.g. using SAs to "ipsec tunnel protect" for the
   * route-based IPsec
   */
  bool use_tunnel_mode_sa;

  /**
   * Route-based IPsec mode. When TRUE, policies are installed by binding
   * SAs to a shared p2mp ipsec-itf and adding FIB routes via that interface;
   * no SPD entries are created. Default FALSE (legacy SPD behavior).
   */
  bool route_mode;

  /**
   * Hash table of ipsec-itf interfaces, keyed by local-endpoint string
   * (host address) -> ipsec_itf_t. One entry per distinct local endpoint
   * used by any CHILD_SA. Only populated in route_mode.
   */
  hashtable_t *ipsec_itfs;

  /**
   * Hash table of tunnel-protect bindings, keyed by (sw_if_index, peer)
   * -> tunnel_protect_t. One entry per active CHILD_SA in route_mode.
   */
  hashtable_t *tunnel_protects;

  /**
   * VPP interface name whose IPv4 the ipsec-itf borrows via unnumbered.
   * Read from charon.plugins.kernel-vpp.wan_interface. NULL = don't
   * unnumber (data path will drop with ip4-not-enabled on ipsec-itf).
   */
  char *wan_interface;

  /**
   * Connections to VPP Stats
   */
  stat_client_main_t *sm;

  /**
   * Set once query_sa() fails to reach VPP's stats segment. charon polls
   * list-sas every few seconds; without this latch every poll would
   * retry the (failing) stats connection and log about it, flooding the
   * journal. When set, query_sa() returns NOT_FOUND immediately and
   * silently — per-SA byte counters just read 0.
   */
  bool stats_unavailable;
};

/**
 * Security association entry
 */
typedef struct
{
  /** VPP SA ID */
  uint32_t sa_id;
  uint32_t stat_index;
  kernel_ipsec_sa_id_t *sa_id_p;
  /** strongSwan reqid of the owning CHILD_SA. Both the inbound and the
   * outbound SA of one CHILD_SA share this value — it is how route-mode
   * pairs them up (lookup_sa_pair). Unique per CHILD_SA, so two clients
   * behind the same NAT — who share an outer IP — still resolve to
   * distinct SA pairs. */
  uint32_t reqid;
  /** TRUE if this is the inbound SA of the pair, FALSE if outbound. */
  bool inbound;
} sa_t;

/**
 * Security policy database
 */
typedef struct
{
  /** VPP SPD ID */
  uint32_t spd_id;
  /** Networking interface ID restricting policy */
  uint32_t sw_if_index;
  /** Policy count for this SPD */
  refcount_t policy_num;
  /** Name of the interface the SPD is bound to */
  char *if_name;
} spd_t;

/**
 * Installed route
 */
typedef struct
{
  /** Name of the interface the route is bound to */
  char *if_name;
  /** Gateway of route */
  host_t *gateway;
  /** Destination network of route */
  host_t *dst_net;
  /** Prefix length of dst_net */
  uint8_t prefixlen;
  /** References for route */
  refcount_t refs;
} route_entry_t;

/**
 * Shared p2mp ipsec-itf interface, one per local endpoint (route mode).
 * All CHILD_SAs whose local tunnel address matches share the same
 * ipsec-itf, with peer-protections discriminated by next-hop.
 */
typedef struct
{
  /** VPP sw_if_index of the ipsec-itf */
  uint32_t sw_if_index;
  /** Local endpoint string used as hash key (owned) */
  char *local_key;
  /** Refcount: number of tunnel-protects bound to this itf */
  refcount_t refs;
} ipsec_itf_t;

/**
 * A tunnel-protect binding installed on an ipsec-itf for one peer.
 * Tracks the SA pair and the routes installed via this binding so
 * teardown is clean.
 */
typedef struct
{
  /** sw_if_index of the ipsec-itf hosting this binding */
  uint32_t sw_if_index;
  /** Peer endpoint (also used as nh in tunnel-protect and routes) */
  host_t *peer;
  /** Outbound SA id (VPP sad_id) */
  uint32_t sa_out;
  /** Inbound SA id (VPP sad_id) */
  uint32_t sa_in;
} tunnel_protect_t;

/**
 * Composite key for tunnel_protect hashtable: (sw_if_index, peer-host).
 * Stored alongside the value so the table can free it on remove.
 */
typedef struct
{
  uint32_t sw_if_index;
  host_t *peer;
} tp_key_t;

#define htonll(x)                                                             \
  ((1 == htonl (1)) ?                                                         \
	   (x) :                                                                    \
	   ((uint64_t) htonl ((x) &0xFFFFFFFF) << 32) | htonl ((x) >> 32))
#define ntohll(x)                                                             \
  ((1 == ntohl (1)) ?                                                         \
	   (x) :                                                                    \
	   ((uint64_t) ntohl ((x) &0xFFFFFFFF) << 32) | ntohl ((x) >> 32))

CALLBACK (route_equals, bool, route_entry_t *a, va_list args)
{
  host_t *dst_net, *gateway;
  uint8_t *prefixlen;
  char *if_name;

  VA_ARGS_VGET (args, if_name, gateway, dst_net, prefixlen);

  return a->if_name && if_name && streq (a->if_name, if_name) &&
	 a->gateway->ip_equals (a->gateway, gateway) &&
	 a->dst_net->ip_equals (a->dst_net, dst_net) &&
	 a->prefixlen == *prefixlen;
}

/**
 * Clean up a route entry
 */
static void
route_destroy (route_entry_t *this)
{
  this->dst_net->destroy (this->dst_net);
  this->gateway->destroy (this->gateway);
  free (this->if_name);
  free (this);
}

static uint32_t get_sw_if_index ();

static int
set_arp (char *ipStr, char *if_name, bool add)
{
  char *out = NULL;
  int out_len = 0;
  vl_api_ip_neighbor_add_del_t *mp = NULL;
  vl_api_ip_neighbor_add_del_reply_t *rmp = NULL;
  int rc = SUCCESS;
  uint32_t sw_if_index = ~0;

  FILE *fp;
  int nread = 0;
  ssize_t len = 0;
  char *buffer = NULL;
  char buf[2][20];
  char *file = "/proc/net/arp";
  unsigned char mac[8] = {
    0,
  };
  uint32_t addr = 0;

  if (if_name == NULL || ipStr == NULL)
    {
      DBG2 (DBG_KNL, "para is null\n");
      rc = FAILED;
      goto error;
    }
  DBG2 (DBG_KNL, "from kernel read mac\n");

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  sw_if_index = get_sw_if_index (if_name);
  if (sw_if_index == (uint32_t) ~0)
    {
      DBG1 (DBG_KNL, "sw_if_index for %s not found", if_name);
      goto error;
    }

  fp = fopen (file, "rb");
  while (fp && ((nread = getline (&buffer, &len, fp)) != -1))
    {
      sscanf (buffer, "%s %*s %*s %s %*s %*s", &buf[0], &buf[1]);
      inet_aton (&buf[0], &addr);

      if (addr == *((u32 *) (ipStr)))
	{
	  sscanf (buf[1], "%02x:%02x:%02x:%02x:%02x:%02x", &mac[0], &mac[1],
		  &mac[2], &mac[3], &mac[4], &mac[5]);
	  u16 msg_id =
	    vl_msg_api_get_msg_index ((u8 *) "ip_neighbor_add_del_0607c257");
	  mp->_vl_msg_id = htons (msg_id);
	  mp->is_add = add;
	  memcpy (mp->neighbor.ip_address.un.ip4, (u8 *) &addr, sizeof (addr));
	  mp->neighbor.ip_address.af = 0;
	  memcpy (mp->neighbor.mac_address, mac, 6);
	  mp->neighbor.sw_if_index = htonl (sw_if_index);
	  mp->neighbor.flags = 1;

	  if (vac->send (vac, (char *) mp, sizeof (*mp), &out, &out_len))
	    {
	      DBG1 (DBG_KNL, "vac %s neighbor entry",
		    add ? "adding" : "removing");
	      fclose (fp);
	      goto error;
	    }
	  rmp = (void *) out;
	  if (rmp->retval)
	    {
	      DBG1 (DBG_KNL, "%s neighbor add rv:%d", add ? "add" : "remove",
		    ntohl (rmp->retval));
	      fclose (fp);
	      goto error;
	    }
	  fclose (fp);
	  free (out);
	  vl_msg_api_free (mp);
	  free (buffer);

	  return rc;
	}
    }

  if (fp != NULL)
    {
      fclose (fp);
      fp = NULL;
    }

error:
  free (out);
  vl_msg_api_free (mp);
  if (buffer != NULL)
    {
      free (buffer);
      buffer = NULL;
    }
  return rc;
}

static int
add_Route (char *ipAddr, int len, char *mask, char *gateWay)
{
  int fd;
  int rc = SUCCESS;
  struct sockaddr_in _sin;
  struct sockaddr_in *sin = &_sin;
  struct rtentry rt;

  do
    {
      fd = socket (AF_INET, SOCK_DGRAM, 0);
      if (fd < 0)
	{
	  DBG2 (DBG_KNL, "addRoute: socket error\n");
	  rc = FAILED;
	  break;
	}
      memset (&rt, 0, sizeof (struct rtentry));
      memset (sin, 0, sizeof (struct sockaddr_in));
      sin->sin_family = AF_INET;
      sin->sin_port = 0;

      if (inet_aton (gateWay, &sin->sin_addr) < 0)
	{
	  rc = FAILED;
	  break;
	}
      memcpy (&rt.rt_gateway, sin, sizeof (struct sockaddr_in));

      ((struct sockaddr_in *) &rt.rt_dst)->sin_family = AF_INET;
      memcpy (&((struct sockaddr_in *) &rt.rt_dst)->sin_addr, ipAddr, len);

      ((struct sockaddr_in *) &rt.rt_genmask)->sin_family = AF_INET;
      if (inet_aton (mask,
		     &((struct sockaddr_in *) &rt.rt_genmask)->sin_addr) < 0)
	{
	  rc = FAILED;
	  break;
	}
      rt.rt_flags = RTF_GATEWAY;
      if (ioctl (fd, SIOCADDRT, &rt) < 0)
	{
	  rc = FAILED;
	}
    }
  while (0);

  close (fd);
  return rc;
}

static int
set_address (u32 ipAddr, u32 sw_if_index, bool add)
{
  char *out = NULL;
  int out_len = 0;
  vl_api_sw_interface_add_del_address_t *mp;
  vl_api_sw_interface_add_del_address_reply_t *rmp;

  int rc = SUCCESS;

  uint32_t addr;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));

  u16 msg_id =
    vl_msg_api_get_msg_index ((u8 *) "sw_interface_add_del_address_5463d73b");
  mp->_vl_msg_id = htons (msg_id);
  mp->is_add = add;
  memcpy (mp->prefix.address.un.ip4, (u8 *) &ipAddr, sizeof (ipAddr));
  mp->prefix.len = 24;
  mp->sw_if_index = sw_if_index;

  if (vac->send (vac, (char *) mp, sizeof (*mp), &out, &out_len))
    {
      DBG2 (DBG_KNL, "vac %s neighbor entry", add ? "adding" : "removing");
      goto error;
    }
  rmp = (void *) out;
  if (rmp->retval)
    {
      DBG2 (DBG_KNL, "%s neighbor add rv:%d", add ? "add" : "remove",
	    ntohl (rmp->retval));
      goto error;
    }
  return rc;

error:
  free (out);
  vl_msg_api_free (mp);
  return rc;
}

/* ===================================================================
 * Route-mode helpers (ipsec-itf + tunnel-protect + per-tunnel FIB routes)
 * ===================================================================
 *
 * In route_mode, every CHILD_SA causes the plugin to:
 *   1. Ensure a shared p2mp ipsec-itf exists for the local endpoint.
 *   2. Bind the SA pair to that interface via ipsec_tunnel_protect_update,
 *      keyed by peer next-hop.
 *   3. Install a FIB route for each negotiated remote traffic selector,
 *      with the ipsec-itf as the egress interface and peer as next-hop.
 *
 * This bypasses VPP's SPD entirely. The benefit is that decrypted inner
 * packets emerge on the ipsec-itf (not on the WAN's sw_if_index), so
 * NAT44 on the WAN does not double-process them and `nat44 forwarding'
 * can stay disabled.
 */

/**
 * Hash a string key (used by ipsec_itfs table).
 */
static u_int
itf_hash (char *key)
{
  return chunk_hash (chunk_from_str (key));
}

static bool
itf_equals (char *a, char *b)
{
  return streq (a, b);
}

/**
 * Hash a tp_key_t (sw_if_index + peer host).
 */
static u_int
tp_hash (tp_key_t *k)
{
  return chunk_hash_inc (chunk_from_thing (k->sw_if_index),
			 chunk_hash (k->peer->get_address (k->peer)));
}

static bool
tp_equals (tp_key_t *a, tp_key_t *b)
{
  return a->sw_if_index == b->sw_if_index &&
	 a->peer->ip_equals (a->peer, b->peer);
}

/**
 * Build a stable string key for an ipsec-itf entry from a host_t.
 * Caller frees.
 *
 * We deliberately do NOT use strongSwan's "%H" printf hook here because
 * it is only registered against strongSwan's logging printf wrappers,
 * not against libc snprintf. Use inet_ntop for a plain dotted/colon form.
 */
static char *
itf_key_from_host (host_t *h)
{
  char buf[INET6_ADDRSTRLEN];
  chunk_t addr = h->get_address (h);
  int af = (h->get_family (h) == AF_INET6) ? AF_INET6 : AF_INET;
  if (!inet_ntop (af, addr.ptr, buf, sizeof (buf)))
    {
      /* Fallback: hex-encode the raw address bytes so the key is still
       * deterministic even if inet_ntop fails. */
      static const char hex[] = "0123456789abcdef";
      size_t n = (addr.len > 16) ? 16 : addr.len;
      for (size_t i = 0; i < n; i++)
	{
	  buf[2 * i] = hex[(addr.ptr[i] >> 4) & 0xf];
	  buf[2 * i + 1] = hex[addr.ptr[i] & 0xf];
	}
      buf[2 * n] = '\0';
    }
  return strdup (buf);
}

/**
 * Make `target_sw_if_index` borrow the IPv4 of `donor_sw_if_index` via
 * VPP's `sw_interface_set_unnumbered` API. Enables ip4-unicast on the
 * borrower so decrypted inner packets emerging on an ipsec-itf can be
 * routed by the FIB.
 */
static status_t
set_interface_unnumbered (uint32_t target_sw_if_index,
			  uint32_t donor_sw_if_index)
{
  vl_api_sw_interface_set_unnumbered_t *mp = NULL;
  vl_api_sw_interface_set_unnumbered_reply_t *rmp = NULL;
  char *out = NULL;
  int out_len = 0;
  status_t rv = FAILED;
  u16 msg_id;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  msg_id =
    vl_msg_api_get_msg_index ((u8 *) "sw_interface_set_unnumbered_154a6439");
  mp->_vl_msg_id = htons (msg_id);
  /* CLI maps "<target> use <donor>" to:
   *   unnumbered_sw_if_index = target  (the borrower / ipsec-itf)
   *   sw_if_index            = donor   (the IP-bearing iface / WAN) */
  mp->unnumbered_sw_if_index = htonl (target_sw_if_index);
  mp->sw_if_index = htonl (donor_sw_if_index);
  mp->is_add = 1;

  if (vac->send (vac, (char *) mp, sizeof (*mp), &out, &out_len))
    {
      DBG1 (DBG_KNL, "vac sw_interface_set_unnumbered failed");
      goto error;
    }
  rmp = (void *) out;
  if (rmp->retval)
    {
      DBG1 (DBG_KNL, "sw_interface_set_unnumbered failed rv:%d",
	    ntohl (rmp->retval));
      goto error;
    }
  DBG2 (DBG_KNL, "sw_if_index %d unnumbered to %d", target_sw_if_index,
	donor_sw_if_index);
  rv = SUCCESS;

error:
  if (out)
    free (out);
  if (mp)
    vl_msg_api_free (mp);
  return rv;
}

/**
 * Bring an interface admin-up via VPP API.
 * Necessary after ipsec_itf_create — newly created ipsec-itfs come up
 * admin-DOWN, and ipsec4-tun-input drops "ipsec packets received on
 * disabled" until this is called.
 */
static status_t
bring_up_sw_interface (uint32_t sw_if_index)
{
  vl_api_sw_interface_set_flags_t *mp = NULL;
  vl_api_sw_interface_set_flags_reply_t *rmp = NULL;
  char *out = NULL;
  int out_len = 0;
  status_t rv = FAILED;
  u16 msg_id;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  msg_id =
    vl_msg_api_get_msg_index ((u8 *) "sw_interface_set_flags_f5aec1b8");
  mp->_vl_msg_id = htons (msg_id);
  mp->sw_if_index = htonl (sw_if_index);
  mp->flags = htonl (IF_STATUS_API_FLAG_ADMIN_UP);

  if (vac->send (vac, (char *) mp, sizeof (*mp), &out, &out_len))
    {
      DBG1 (DBG_KNL, "vac sw_interface_set_flags failed");
      goto error;
    }
  rmp = (void *) out;
  if (rmp->retval)
    {
      DBG1 (DBG_KNL, "sw_interface_set_flags failed rv:%d",
	    ntohl (rmp->retval));
      goto error;
    }
  DBG2 (DBG_KNL, "sw_if_index %d brought admin-up", sw_if_index);
  rv = SUCCESS;

error:
  if (out)
    free (out);
  if (mp)
    vl_msg_api_free (mp);
  return rv;
}

/**
 * Create or look up the shared ipsec-itf for a local endpoint.
 *
 * Returns the sw_if_index of the interface, or ~0 on failure.
 * Refcounts the entry: every successful call must be balanced by
 * a release_ipsec_itf() call when the corresponding tunnel-protect
 * is torn down.
 */
static uint32_t
ensure_ipsec_itf (private_kernel_vpp_ipsec_t *this, host_t *local)
{
  char *key = NULL;
  ipsec_itf_t *itf = NULL;
  uint32_t sw_if_index = ~0;
  char *out = NULL;
  int out_len = 0;
  vl_api_ipsec_itf_create_t *mp = NULL;
  vl_api_ipsec_itf_create_reply_t *rmp = NULL;
  u16 msg_id;

  key = itf_key_from_host (local);
  this->mutex->lock (this->mutex);
  itf = this->ipsec_itfs->get (this->ipsec_itfs, key);
  if (itf)
    {
      ref_get (&itf->refs);
      sw_if_index = itf->sw_if_index;
      this->mutex->unlock (this->mutex);
      free (key);
      DBG2 (DBG_KNL, "ipsec-itf for %H exists sw_if_index %d", local,
	    sw_if_index);
      return sw_if_index;
    }
  this->mutex->unlock (this->mutex);

  /* Not present: create a new p2mp ipsec-itf in VPP. */
  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  msg_id = vl_msg_api_get_msg_index ((u8 *) "ipsec_itf_create_6f50b3bc");
  mp->_vl_msg_id = htons (msg_id);
  mp->itf.user_instance = htonl (~0); /* let VPP pick */
  /* mode is a u8 (vl_api_tunnel_mode_t) — DO NOT byte-swap a u8.
   * Writing htonl(1) here was a bug: on little-endian it stores 0x00 in
   * the low byte (P2P), silently downgrading the multi-peer interface to
   * point-to-point. With P2P the FIRST tunnel-protect succeeds and the
   * SECOND peer's bind fails — fatal for any multi-client RA gateway. */
  mp->itf.mode = 1; /* TUNNEL_API_MODE_MP (p2mp) */

  if (vac->send (vac, (char *) mp, sizeof (*mp), &out, &out_len))
    {
      DBG1 (DBG_KNL, "vac ipsec_itf_create failed");
      goto error;
    }
  rmp = (void *) out;
  if (rmp->retval)
    {
      DBG1 (DBG_KNL, "ipsec_itf_create failed rv:%d", ntohl (rmp->retval));
      goto error;
    }
  sw_if_index = ntohl (rmp->sw_if_index);

  /* Newly created ipsec-itf is admin-DOWN. Bring it up immediately,
   * otherwise ipsec4-tun-input drops decrypted/encrypt-bound packets
   * with "ipsec packets received on disabled". */
  if (bring_up_sw_interface (sw_if_index) != SUCCESS)
    {
      DBG1 (DBG_KNL,
	    "ipsec-itf %d created but admin-up failed; data path will drop",
	    sw_if_index);
      /* continue anyway — the interface exists; operator can bring it
       * up manually with 'set interface state ipsec0 up' as a fallback */
    }

  /* Make the ipsec-itf unnumbered to the WAN so it has an IPv4 context.
   * Without this, decrypted inner packets emerging on ipsec0 hit
   * "ip4-not-enabled" and drop. wan_interface must be set in
   * /etc/strongswan.d/charon/kernel-vpp.conf for this to fire. */
  if (this->wan_interface)
    {
      uint32_t donor = get_sw_if_index (this->wan_interface);
      if (donor != ~0u)
	{
	  if (set_interface_unnumbered (sw_if_index, donor) != SUCCESS)
	    DBG1 (DBG_KNL,
		  "ipsec-itf %d created but unnumber-to-%s failed; "
		  "data path may drop at ip4-not-enabled",
		  sw_if_index, this->wan_interface);
	}
      else
	{
	  DBG1 (DBG_KNL,
		"wan_interface '%s' not found in VPP; ipsec-itf %d will not "
		"be unnumbered (decrypted packets may drop)",
		this->wan_interface, sw_if_index);
	}
    }
  else
    {
      DBG1 (DBG_KNL,
	    "wan_interface not configured; ipsec-itf %d has no IP context. "
	    "Set charon.plugins.kernel-vpp.wan_interface = <vpp-iface-name>",
	    sw_if_index);
    }

  INIT (itf, .sw_if_index = sw_if_index, .local_key = key, .refs = 1, );
  this->mutex->lock (this->mutex);
  this->ipsec_itfs->put (this->ipsec_itfs, itf->local_key, itf);
  this->mutex->unlock (this->mutex);
  DBG1 (DBG_KNL, "created ipsec-itf for %H sw_if_index %d (admin-up)",
	local, sw_if_index);
  /* leave 'key' owned by itf->local_key */
  free (out);
  vl_msg_api_free (mp);
  return sw_if_index;

error:
  if (out)
    free (out);
  if (mp)
    vl_msg_api_free (mp);
  if (key)
    free (key);
  return ~0;
}

/**
 * Delete one ipsec-itf from VPP by sw_if_index.
 *
 * Shared by release_ipsec_itf() (refcount-driven teardown) and
 * destroy() (plugin shutdown). Without the destroy()-time call, every
 * ipsec-itf the plugin ever created would leak in VPP across a charon
 * restart: the next charon instance starts with an empty ipsec_itfs
 * table, so it never reuses — it creates a fresh interface and the old
 * one lingers, still carrying a stale tunnel-protect bound to a now-
 * dangling SA id. Over a few restarts VPP fills up with orphaned
 * ipsecN interfaces.
 */
static void
delete_ipsec_itf_vpp (uint32_t sw_if_index)
{
  vl_api_ipsec_itf_delete_t *mp = NULL;
  vl_api_ipsec_itf_delete_reply_t *rmp = NULL;
  char *out = NULL;
  int out_len = 0;
  u16 msg_id;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  msg_id = vl_msg_api_get_msg_index ((u8 *) "ipsec_itf_delete_f9e6675e");
  mp->_vl_msg_id = htons (msg_id);
  mp->sw_if_index = htonl (sw_if_index);
  if (vac->send (vac, (char *) mp, sizeof (*mp), &out, &out_len))
    {
      DBG1 (DBG_KNL, "vac ipsec_itf_delete failed");
      goto cleanup;
    }
  rmp = (void *) out;
  if (rmp->retval)
    DBG1 (DBG_KNL, "ipsec_itf_delete failed rv:%d", ntohl (rmp->retval));
  else
    DBG1 (DBG_KNL, "deleted ipsec-itf sw_if_index %d", sw_if_index);

cleanup:
  if (out)
    free (out);
  if (mp)
    vl_msg_api_free (mp);
}

/**
 * Decrement refcount on an ipsec-itf. When the last reference is gone,
 * delete the VPP interface and drop the table entry.
 */
static void
release_ipsec_itf (private_kernel_vpp_ipsec_t *this, host_t *local)
{
  char *key = NULL;
  ipsec_itf_t *itf = NULL;
  uint32_t sw_if_index;

  key = itf_key_from_host (local);
  this->mutex->lock (this->mutex);
  itf = this->ipsec_itfs->get (this->ipsec_itfs, key);
  if (!itf)
    {
      this->mutex->unlock (this->mutex);
      free (key);
      return;
    }
  if (!ref_put (&itf->refs))
    {
      this->mutex->unlock (this->mutex);
      free (key);
      return;
    }
  /* last reference: remove from table and tear down */
  this->ipsec_itfs->remove (this->ipsec_itfs, key);
  sw_if_index = itf->sw_if_index;
  free (itf->local_key);
  free (itf);
  this->mutex->unlock (this->mutex);
  free (key);

  delete_ipsec_itf_vpp (sw_if_index);
}

/**
 * Issue an ipsec_tunnel_protect_update for (sw_if_index, peer) with the
 * given SA pair. The message carries a VLA of inbound SA ids; for now we
 * pass exactly one (rekey overlap handling is a follow-up).
 */
static status_t
tunnel_protect_update (uint32_t sw_if_index, host_t *peer, uint32_t sa_in,
		       uint32_t sa_out)
{
  vl_api_ipsec_tunnel_protect_update_t *mp = NULL;
  vl_api_ipsec_tunnel_protect_update_reply_t *rmp = NULL;
  char *out = NULL;
  int out_len = 0;
  status_t rv = FAILED;
  u16 msg_id;
  size_t msg_size;
  chunk_t addr;

  /* sa_in[] is a VLA at the end of the message; size for n_sa_in = 1 */
  msg_size = sizeof (*mp) + sizeof (uint32_t);
  mp = vl_msg_api_alloc (msg_size);
  memset (mp, 0, msg_size);
  msg_id =
    vl_msg_api_get_msg_index ((u8 *) "ipsec_tunnel_protect_update_30d5f133");
  mp->_vl_msg_id = htons (msg_id);
  mp->tunnel.sw_if_index = htonl (sw_if_index);
  mp->tunnel.sa_out = htonl (sa_out);
  mp->tunnel.n_sa_in = 1;
  mp->tunnel.sa_in[0] = htonl (sa_in);

  addr = peer->get_address (peer);
  /* af is a u8 enum (vl_api_address_family_t) — direct assign, no htonl. */
  if (peer->get_family (peer) == AF_INET6)
    {
      mp->tunnel.nh.af = ADDRESS_IP6;
      memcpy (mp->tunnel.nh.un.ip6, addr.ptr, 16);
    }
  else
    {
      mp->tunnel.nh.af = ADDRESS_IP4;
      memcpy (mp->tunnel.nh.un.ip4, addr.ptr, 4);
    }

  if (vac->send (vac, (char *) mp, msg_size, &out, &out_len))
    {
      DBG1 (DBG_KNL, "vac ipsec_tunnel_protect_update failed");
      goto error;
    }
  rmp = (void *) out;
  if (rmp->retval)
    {
      DBG1 (DBG_KNL, "ipsec_tunnel_protect_update failed rv:%d",
	    ntohl (rmp->retval));
      goto error;
    }
  DBG2 (DBG_KNL, "tunnel-protect bound on sw_if_index %d nh %H sa_in %d "
		 "sa_out %d",
	sw_if_index, peer, sa_in, sa_out);
  rv = SUCCESS;

error:
  if (out)
    free (out);
  if (mp)
    vl_msg_api_free (mp);
  return rv;
}

/**
 * Remove tunnel-protect for (sw_if_index, peer).
 */
static status_t
tunnel_protect_remove (uint32_t sw_if_index, host_t *peer)
{
  vl_api_ipsec_tunnel_protect_del_t *mp = NULL;
  vl_api_ipsec_tunnel_protect_del_reply_t *rmp = NULL;
  char *out = NULL;
  int out_len = 0;
  status_t rv = FAILED;
  u16 msg_id;
  chunk_t addr;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  msg_id =
    vl_msg_api_get_msg_index ((u8 *) "ipsec_tunnel_protect_del_cd239930");
  mp->_vl_msg_id = htons (msg_id);
  mp->sw_if_index = htonl (sw_if_index);
  addr = peer->get_address (peer);
  /* af is u8 — no byte swap. */
  if (peer->get_family (peer) == AF_INET6)
    {
      mp->nh.af = ADDRESS_IP6;
      memcpy (mp->nh.un.ip6, addr.ptr, 16);
    }
  else
    {
      mp->nh.af = ADDRESS_IP4;
      memcpy (mp->nh.un.ip4, addr.ptr, 4);
    }
  if (vac->send (vac, (char *) mp, sizeof (*mp), &out, &out_len))
    {
      DBG1 (DBG_KNL, "vac ipsec_tunnel_protect_del failed");
      goto error;
    }
  rmp = (void *) out;
  if (rmp->retval)
    {
      DBG1 (DBG_KNL, "ipsec_tunnel_protect_del failed rv:%d",
	    ntohl (rmp->retval));
      goto error;
    }
  rv = SUCCESS;

error:
  if (out)
    free (out);
  if (mp)
    vl_msg_api_free (mp);
  return rv;
}

/**
 * Add or delete a FIB route for the given prefix, sending it out of the
 * specified ipsec-itf with the given peer address as next-hop. This is
 * the route-mode counterpart of the SPD path's manage_route().
 */
static status_t
route_via_ipsec_itf (bool add, host_t *dst_net, uint8_t prefixlen,
		     uint32_t sw_if_index, host_t *peer)
{
  vl_api_ip_route_add_del_t *mp = NULL;
  vl_api_ip_route_add_del_reply_t *rmp = NULL;
  vl_api_fib_path_t *apath = NULL;
  char *out = NULL;
  int out_len = 0;
  status_t rv = FAILED;
  u16 msg_id;
  chunk_t dst_chunk, peer_chunk;
  size_t msg_size;
  bool is_v6 = (dst_net->get_family (dst_net) == AF_INET6);

  msg_size = sizeof (*mp) + sizeof (*apath);
  mp = vl_msg_api_alloc (msg_size);
  memset (mp, 0, msg_size);
  msg_id = vl_msg_api_get_msg_index ((u8 *) "ip_route_add_del_b8ecfe0d");
  mp->_vl_msg_id = htons (msg_id);
  mp->is_add = add;
  mp->is_multipath = 0;
  mp->route.prefix.len = prefixlen;
  mp->route.n_paths = 1;
  apath = &mp->route.paths[0];
  apath->sw_if_index = htonl (sw_if_index);
  apath->rpf_id = ~0;
  apath->weight = 1;

  dst_chunk = dst_net->get_address (dst_net);
  peer_chunk = peer->get_address (peer);
  /* af is u8 (no swap); proto is int-sized typedef enum (swap with htonl). */
  if (is_v6)
    {
      mp->route.prefix.address.af = ADDRESS_IP6;
      memcpy (mp->route.prefix.address.un.ip6, dst_chunk.ptr, 16);
      apath->proto = htonl (FIB_API_PATH_NH_PROTO_IP6);
      memcpy (apath->nh.address.ip6, peer_chunk.ptr, 16);
    }
  else
    {
      mp->route.prefix.address.af = ADDRESS_IP4;
      memcpy (mp->route.prefix.address.un.ip4, dst_chunk.ptr, 4);
      apath->proto = htonl (FIB_API_PATH_NH_PROTO_IP4);
      memcpy (apath->nh.address.ip4, peer_chunk.ptr, 4);
    }

  if (vac->send (vac, (char *) mp, msg_size, &out, &out_len))
    {
      DBG1 (DBG_KNL, "vac ip_route_add_del failed");
      goto error;
    }
  rmp = (void *) out;
  if (rmp->retval)
    {
      DBG1 (DBG_KNL, "ip_route_add_del failed rv:%d", ntohl (rmp->retval));
      goto error;
    }
  DBG2 (DBG_KNL, "route %s %H/%d via %H ipsec-itf:%d",
	add ? "installed" : "removed", dst_net, prefixlen, peer, sw_if_index);
  rv = SUCCESS;

error:
  if (out)
    free (out);
  if (mp)
    vl_msg_api_free (mp);
  return rv;
}

/**
 * Look up the SA pair (in, out) for a CHILD_SA by its strongSwan reqid.
 * Returns SUCCESS if both the inbound and the outbound SA are found in
 * the plugin's SA table, FAILED otherwise.
 *
 * In route-mode this is called from manage_policy_route() to translate
 * "the policy charon is asking me to install" into "the SAD IDs I should
 * bind to the ipsec-itf".
 *
 * Why reqid and not the (src,dst) tunnel endpoints: two remote-access
 * clients behind the same NAT present the SAME outer src/dst IP pair to
 * the gateway. Matching SAs by IP would return whichever enumerates
 * first — so a client's tunnel-protect would get bound to another
 * client's keys. reqid is unique per CHILD_SA, so it pairs the right
 * inbound+outbound SAs regardless of shared outer addresses.
 */
static status_t
lookup_sa_pair (private_kernel_vpp_ipsec_t *this, uint32_t reqid,
		uint32_t *sa_in, uint32_t *sa_out)
{
  enumerator_t *e;
  kernel_ipsec_sa_id_t *id;
  sa_t *sa;
  bool found_in = FALSE, found_out = FALSE;

  this->mutex->lock (this->mutex);
  e = this->sas->create_enumerator (this->sas);
  while (e->enumerate (e, &id, &sa))
    {
      if (sa->reqid != reqid)
	continue;
      if (sa->inbound && !found_in)
	{
	  *sa_in = sa->sa_id;
	  found_in = TRUE;
	}
      else if (!sa->inbound && !found_out)
	{
	  *sa_out = sa->sa_id;
	  found_out = TRUE;
	}
      if (found_in && found_out)
	break;
    }
  e->destroy (e);
  this->mutex->unlock (this->mutex);
  return (found_in && found_out) ? SUCCESS : FAILED;
}

/**
 * Route-mode counterpart of manage_policy(). Installs or removes a
 * tunnel-protect binding plus a FIB route for the given policy.
 *
 * Only outbound policies trigger work; inbound policies are no-ops in
 * route-mode (the route is symmetric and the inbound SA list on the
 * tunnel-protect entry handles return traffic).
 */
static status_t
manage_policy_route (private_kernel_vpp_ipsec_t *this, bool add,
		     kernel_ipsec_policy_id_t *id,
		     kernel_ipsec_manage_policy_t *data)
{
  uint32_t sw_if_index = ~0;
  uint32_t sa_in = ~0, sa_out = ~0;
  uint32_t reqid;
  host_t *local = NULL, *peer = NULL;
  host_t *dst_net = NULL;
  uint8_t prefixlen;
  tp_key_t key, *stored_key = NULL;
  tunnel_protect_t *tp = NULL;
  status_t rv = FAILED;

  if (id->dir == POLICY_FWD)
    return SUCCESS;
  if (id->dir == POLICY_IN)
    {
      /* In route mode, only the outbound policy drives state. The matching
       * inbound policy is implicit in the tunnel-protect entry. */
      return SUCCESS;
    }
  if (data->type != POLICY_IPSEC || !data->sa ||
      data->sa->mode == MODE_TRANSPORT)
    return SUCCESS;

  /* In route mode, charon's "src" is our local tunnel endpoint and "dst"
   * is the peer's outer address. local keys the shared p2mp ipsec-itf.
   * The peer's outer address is deliberately NOT used past this point —
   * see the dst_net comment below. */
  local = data->src;
  peer = data->dst;
  if (!local || !peer || local->is_anyaddr (local) || peer->is_anyaddr (peer))
    {
      DBG1 (DBG_KNL, "route_mode: anyaddr endpoint, skipping");
      return SUCCESS;
    }
  reqid = data->sa->reqid;

  /* dst_net is the per-client virtual IP: charon narrows id->dst_ts to
   * the assigned VIP /32 (the gateway's remote_ts must be 0.0.0.0/0 for
   * this to happen). We use this VIP as BOTH the tunnel-protect
   * next-hop and the FIB route prefix+next-hop — never the peer's outer
   * address. Two remote-access clients behind the same NAT share an
   * outer IP, so keying tunnel-protects/routes on it makes the second
   * client overwrite the first. VIPs are always distinct, so keying on
   * the VIP keeps them isolated on the one shared ipsec-itf. */
  id->dst_ts->to_subnet (id->dst_ts, &dst_net, &prefixlen);
  if (!dst_net || dst_net->is_anyaddr (dst_net))
    {
      DBG1 (DBG_KNL,
	    "route_mode: policy dst_ts is not a concrete VIP (reqid %u) — "
	    "the gateway's remote_ts must be 0.0.0.0/0 so charon narrows it "
	    "to the assigned virtual IP; skipping",
	    reqid);
      if (dst_net)
	dst_net->destroy (dst_net);
      return add ? FAILED : SUCCESS;
    }

  if (add)
    {
      sw_if_index = ensure_ipsec_itf (this, local);
      if (sw_if_index == (uint32_t) ~0)
	{
	  DBG1 (DBG_KNL, "route_mode: ensure_ipsec_itf failed");
	  dst_net->destroy (dst_net);
	  return FAILED;
	}
      if (lookup_sa_pair (this, reqid, &sa_in, &sa_out) != SUCCESS)
	{
	  DBG1 (DBG_KNL,
		"route_mode: SA pair for reqid %u not in table yet; "
		"deferring (charon should add SAs before policy)",
		reqid);
	  release_ipsec_itf (this, local);
	  dst_net->destroy (dst_net);
	  return FAILED;
	}
      if (tunnel_protect_update (sw_if_index, dst_net, sa_in, sa_out) !=
	  SUCCESS)
	{
	  release_ipsec_itf (this, local);
	  dst_net->destroy (dst_net);
	  return FAILED;
	}

      /* tp_key_t / tunnel_protect_t .peer holds the VIP here, not the
       * peer's outer address — see the dst_net comment above. */
      INIT (tp, .sw_if_index = sw_if_index, .peer = dst_net->clone (dst_net),
	    .sa_in = sa_in, .sa_out = sa_out, );
      INIT (stored_key, .sw_if_index = sw_if_index,
	    .peer = dst_net->clone (dst_net), );

      this->mutex->lock (this->mutex);
      this->tunnel_protects->put (this->tunnel_protects, stored_key, tp);
      this->mutex->unlock (this->mutex);

      if (route_via_ipsec_itf (TRUE, dst_net, prefixlen, sw_if_index,
			       dst_net) != SUCCESS)
	DBG1 (DBG_KNL, "route_mode: route install failed (continuing)");
      rv = SUCCESS;
    }
  else
    {
      /* Delete: route -> tunnel-protect -> release itf ref. */
      sw_if_index = ensure_ipsec_itf (this, local);
      if (sw_if_index != (uint32_t) ~0)
	route_via_ipsec_itf (FALSE, dst_net, prefixlen, sw_if_index, dst_net);
      /* ensure_ipsec_itf bumped refs by 1; balance it. */
      if (sw_if_index != (uint32_t) ~0)
	release_ipsec_itf (this, local);

      key.sw_if_index = sw_if_index;
      key.peer = dst_net;
      this->mutex->lock (this->mutex);
      tp = this->tunnel_protects->remove (this->tunnel_protects, &key);
      this->mutex->unlock (this->mutex);
      if (tp)
	{
	  tunnel_protect_remove (tp->sw_if_index, tp->peer);
	  release_ipsec_itf (this, local);
	  tp->peer->destroy (tp->peer);
	  free (tp);
	}
      rv = SUCCESS;
    }

  dst_net->destroy (dst_net);
  return rv;
}

/**
 * (Un)-install a single route
 */
static void
manage_route (private_kernel_vpp_ipsec_t *this, bool add,
	      traffic_selector_t *dst_ts, host_t *src, host_t *dst)
{
  host_t *dst_net = NULL, *gateway = NULL;
  uint8_t prefixlen;
  char *if_name = NULL;
  route_entry_t *route;
  bool route_exist = FALSE;

  char *netmask = "255.255.255.0";
  char *tap_gateway = "1.1.1.1";
  int arp_rc = 0;
  if (dst->is_anyaddr (dst))
    {
      return;
    }
  gateway =
    charon->kernel->get_nexthop (charon->kernel, dst, -1, NULL, &if_name);
  dst_ts->to_subnet (dst_ts, &dst_net, &prefixlen);
  if (!if_name)
    {
      if (src->is_anyaddr (src))
	{
	  goto error;
	}
      if (!charon->kernel->get_interface (charon->kernel, src, &if_name))
	{
	  goto error;
	}
    }
  route_exist =
    this->routes->find_first (this->routes, route_equals, (void **) &route,
			      if_name, gateway, dst_net, &prefixlen);
  if (add)
    {
      DBG2 (DBG_KNL, "installing route: %H/%d via %H dev %s", dst_net,
	    prefixlen, gateway, if_name);
      if (route_exist)
	{
	  unsigned int refs_num = ref_get (&route->refs);
	  DBG2 (DBG_KNL, "add route but it exist %d", refs_num);
	}
      else
	{
	  INIT (route, .if_name = strdup (if_name),
		.gateway = gateway->clone (gateway),
		.dst_net = dst_net->clone (dst_net), .prefixlen = prefixlen,
		.refs = 1, );
	  this->routes->insert_last (this->routes, route);
	  charon->kernel->add_route (charon->kernel,
				     dst_net->get_address (dst_net), prefixlen,
				     gateway, dst, if_name, 1);
	}

      add_Route (dst_net->get_address (dst_net).ptr,
		 dst_net->get_address (dst_net).len, netmask, tap_gateway);

      arp_rc = set_arp (gateway->get_address (gateway).ptr, if_name, TRUE);
      if (arp_rc)
	DBG2 (DBG_KNL, "arpGet success!\n");
    }
  else
    {
      DBG2 (DBG_KNL, "uninstalling route: %H/%d via %H dev %s", dst_net,
	    prefixlen, gateway, if_name);
      if (!route_exist)
	{
	  DBG2 (DBG_KNL, "del route but it not exist");
	  goto error;
	}
      if (ref_put (&route->refs))
	{
	  this->routes->remove (this->routes, route, NULL);
	  route_destroy (route);
	  charon->kernel->del_route (charon->kernel,
				     dst_net->get_address (dst_net), prefixlen,
				     gateway, dst, if_name, 1);
	}
    }
error:
  if (gateway != NULL)
    gateway->destroy (gateway);
  if (dst_net != NULL)
    dst_net->destroy (dst_net);
  if (if_name != NULL)
    free (if_name);
  return;
}

/**
 * Hash function for IPsec SA
 */
static u_int
sa_hash (kernel_ipsec_sa_id_t *sa)
{
  return chunk_hash_inc (
    sa->src->get_address (sa->src),
    chunk_hash_inc (
      sa->dst->get_address (sa->dst),
      chunk_hash_inc (chunk_from_thing (sa->spi),
		      chunk_hash (chunk_from_thing (sa->proto)))));
}

/**
 * Equality function for IPsec SA
 */
static bool
sa_equals (kernel_ipsec_sa_id_t *sa, kernel_ipsec_sa_id_t *other_sa)
{
  return sa->src->ip_equals (sa->src, other_sa->src) &&
	 sa->dst->ip_equals (sa->dst, other_sa->dst) &&
	 sa->spi == other_sa->spi && sa->proto == other_sa->proto;
}

/**
 * Equality function for policy SPD
 */
static bool
policy_equals (vl_api_ipsec_spd_entry_t *policy,
	       vl_api_ipsec_spd_entry_t *other_policy)
{

  /* change protocol due to legacy implementation of ANY protocol inside VPP */
  if (other_policy->protocol == 255)
    other_policy->protocol = 0;

  /* return true if both policies are equal */
  return !memcmp (policy, other_policy, sizeof (*policy));
}

/**
 * Hash function for interface
 */
static u_int
interface_hash (char *interface)
{
  return chunk_hash (chunk_from_str (interface));
}

/**
 * Equality function for interface
 */
static bool
interface_equals (char *interface1, char *interface2)
{
  return streq (interface1, interface2);
}

/**
 * Map an integer x with a one-to-one function using quadratic residues
 */
static u_int
permute (u_int x, u_int p)
{
  u_int qr;

  x = x % p;
  qr = ((uint64_t) x * x) % p;
  if (x <= p / 2)
    {
      return qr;
    }
  return p - qr;
}

/**
 * Initialize seeds for SPI generation
 */
static bool
init_spi (private_kernel_vpp_ipsec_t *this)
{
  bool ok = TRUE;
  rng_t *rng;

  rng = lib->crypto->create_rng (lib->crypto, RNG_STRONG);
  if (!rng)
    {
      return FALSE;
    }
  ok =
    rng->get_bytes (rng, sizeof (this->nextspi), (uint8_t *) &this->nextspi);
  if (ok)
    {
      ok =
	rng->get_bytes (rng, sizeof (this->mixspi), (uint8_t *) &this->mixspi);
    }
  rng->destroy (rng);
  return ok;
}

/**
 * Calculate policy priority
 */
static uint32_t
calculate_priority (policy_priority_t policy_priority, traffic_selector_t *src,
		    traffic_selector_t *dst)
{
  uint32_t priority = PRIO_BASE;
  uint16_t port;
  uint8_t mask, proto;
  host_t *net;

  switch (policy_priority)
    {
    case POLICY_PRIORITY_FALLBACK:
      priority <<= 1;
      /* fall-through */
    case POLICY_PRIORITY_ROUTED:
      priority <<= 1;
      /* fall-through */
    case POLICY_PRIORITY_DEFAULT:
      priority <<= 1;
      /* fall-through */
    case POLICY_PRIORITY_PASS:
      break;
    }
  /* calculate priority based on selector size, small size = high prio */
  src->to_subnet (src, &net, &mask);
  priority -= mask;
  proto = src->get_protocol (src);
  port = net->get_port (net);
  net->destroy (net);

  dst->to_subnet (dst, &net, &mask);
  priority -= mask;
  proto = max (proto, dst->get_protocol (dst));
  port = max (port, net->get_port (net));
  net->destroy (net);

  priority <<= 2; /* make some room for the two flags */
  priority += port ? 0 : 2;
  priority += proto ? 0 : 1;
  return priority;
}

/**
 * Get sw_if_index from interface name
 */
static uint32_t
get_sw_if_index (char *interface)
{
  char *out = NULL;
  int out_len, name_filter_len = 0, msg_len = 0;
  int num, i;
  vl_api_sw_interface_dump_t *mp = NULL;
  vl_api_sw_interface_details_t *rmp = NULL;
  uint32_t sw_if_index = ~0;

  if (interface == NULL)
    goto error;

  name_filter_len = strlen (interface);
  msg_len = sizeof (*mp) + name_filter_len;
  mp = vl_msg_api_alloc (msg_len);
  clib_memset (mp, 0, msg_len);
  u16 msg_id = vl_msg_api_get_msg_index ((u8 *) "sw_interface_dump_aa610c27");
  mp->_vl_msg_id = htons (msg_id);
  mp->name_filter_valid = TRUE;
  mp->name_filter.length = htonl (name_filter_len);
  memcpy ((char *) mp->name_filter.buf, interface, name_filter_len);

  if (vac->send_dump (vac, (char *) mp, msg_len, &out, &out_len))
    {
      goto error;
    }
  if (!out_len)
    {
      goto error;
    }
  num = out_len / sizeof (*rmp);
  rmp = (vl_api_sw_interface_details_t *) out;
  for (i = 0; i < num; i++)
    {
      if (strlen (rmp->interface_name) &&
	  streq (interface, rmp->interface_name))
	{
	  sw_if_index = ntohl (rmp->sw_if_index);
	  break;
	}
      rmp += 1;
    }

error:
  if (out)
    free (out);
  if (mp)
    vl_msg_api_free (mp);
  return sw_if_index;
}

/**
 * (Un)-install a security policy database
 */
static status_t
spd_add_del (bool add, uint32_t spd_id)
{
  char *out = NULL;
  int out_len;
  vl_api_ipsec_spd_add_del_t *mp;
  vl_api_ipsec_spd_add_del_reply_t *rmp;
  status_t rv = FAILED;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));

  u16 msg_id = vl_msg_api_get_msg_index ((u8 *) "ipsec_spd_add_del_20e89a95");
  mp->_vl_msg_id = htons (msg_id);
  mp->is_add = add;
  mp->spd_id = htonl (spd_id);
  if (vac->send (vac, (char *) mp, sizeof (*mp), &out, &out_len))
    {
      DBG1 (DBG_KNL, "vac %s SPD failed", add ? "adding" : "removing");
      goto error;
    }
  rmp = (void *) out;
  if (rmp->retval)
    {
      DBG1 (DBG_KNL, "%s SPD failed rv:%d", add ? "add" : "remove",
	    ntohl (rmp->retval));
      goto error;
    }
  rv = SUCCESS;

error:
  free (out);
  vl_msg_api_free (mp);
  return rv;
}

/**
 * Enable or disable SPD on an insterface
 */
static status_t
interface_add_del_spd (bool add, uint32_t spd_id, uint32_t sw_if_index)
{
  char *out = NULL;
  int out_len;
  vl_api_ipsec_interface_add_del_spd_t *mp;
  vl_api_ipsec_interface_add_del_spd_reply_t *rmp;
  status_t rv = FAILED;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  u16 msg_id =
    vl_msg_api_get_msg_index ((u8 *) "ipsec_interface_add_del_spd_80f80cbb");
  mp->_vl_msg_id = htons (msg_id);
  mp->is_add = add;
  mp->spd_id = htonl (spd_id);
  mp->sw_if_index = htonl (sw_if_index);
  if (vac->send (vac, (char *) mp, sizeof (*mp), &out, &out_len))
    {
      DBG1 (DBG_KNL, "vac %s interface SPD failed",
	    add ? "adding" : "removing");
      goto error;
    }
  rmp = (void *) out;
  if (rmp->retval)
    {
      DBG1 (DBG_KNL, "%s interface SPD failed rv:%d", add ? "add" : "remove",
	    ntohl (rmp->retval));
      goto error;
    }
  rv = SUCCESS;

error:
  free (out);
  vl_msg_api_free (mp);
  return rv;
}

static int
bypass_all (bool add, uint32_t spd_id, uint32_t sa_id, uint32_t priority)
{
  vl_api_ipsec_spd_entry_add_del_t *mp;
  vl_api_ipsec_spd_entry_add_del_reply_t *rmp;
  char *out = NULL;
  int out_len;
  status_t rv = FAILED;

  DBG2 (DBG_KNL, "bypass_all [%s] spd_id %d sa_id %d", add ? "ADD" : "DEL",
	spd_id, sa_id);

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));

  u16 msg_id =
    vl_msg_api_get_msg_index ((u8 *) "ipsec_spd_entry_add_del_338b7411");
  mp->_vl_msg_id = ntohs (msg_id);
  mp->is_add = add;
  mp->entry.sa_id = ntohl (sa_id);
  mp->entry.spd_id = ntohl (spd_id);
  mp->entry.priority = ntohl (priority - POLICY_PRIORITY_PASS);
  mp->entry.is_outbound = 0;
  mp->entry.policy = ntohl (IPSEC_API_SPD_ACTION_BYPASS);
  memset (mp->entry.local_address_stop.un.ip6, 0xFF, 16);
  memset (mp->entry.remote_address_stop.un.ip6, 0xFF, 16);
  mp->entry.remote_port_start = mp->entry.local_port_start = ntohs (0);
  mp->entry.remote_port_stop = mp->entry.local_port_stop = ntohs (0xFFFF);
  mp->entry.protocol = IP_API_PROTO_ESP;
  if (vac->send (vac, (char *) mp, sizeof (*mp), &out, &out_len))
    {
      DBG1 (DBG_KNL, "vac %s SPD entry failed", add ? "adding" : "removing");
      goto error;
    }
  rmp = (void *) out;
  if (rmp->retval)
    {
      DBG1 (DBG_KNL, "%s SPD entry failed rv:%d", add ? "add" : "remove",
	    ntohl (rmp->retval));
      goto error;
    }
  /* address "out" needs to be freed after vec->send */
  if (out != NULL)
    {
      free (out);
      out = NULL;
    }
  mp->entry.is_outbound = 1;
  if (vac->send (vac, (char *) mp, sizeof (*mp), &out, &out_len))
    {
      DBG1 (DBG_KNL, "vac %s SPD entry failed", add ? "adding" : "removing");
      goto error;
    }
  rmp = (void *) out;
  if (rmp->retval)
    {
      DBG1 (DBG_KNL, "%s SPD entry failed rv:%d", add ? "add" : "remove",
	    ntohl (rmp->retval));
      goto error;
    }
  /* address "out" needs to be freed after vec->send */
  if (out != NULL)
    {
      free (out);
      out = NULL;
    }
  mp->entry.is_outbound = 0;
  mp->entry.protocol = IP_API_PROTO_AH;
  if (vac->send (vac, (char *) mp, sizeof (*mp), &out, &out_len))
    {
      DBG1 (DBG_KNL, "vac %s SPD entry failed", add ? "adding" : "removing");
      goto error;
    }
  rmp = (void *) out;
  if (rmp->retval)
    {
      DBG1 (DBG_KNL, "%s SPD entry failed rv:%d", add ? "add" : "remove",
	    ntohl (rmp->retval));
      goto error;
    }
  /* address "out" needs to be freed after vec->send */
  if (out != NULL)
    {
      free (out);
      out = NULL;
    }
  mp->entry.is_outbound = 1;
  if (vac->send (vac, (char *) mp, sizeof (*mp), &out, &out_len))
    {
      DBG1 (DBG_KNL, "vac %s SPD entry failed", add ? "adding" : "removing");
      goto error;
    }
  rmp = (void *) out;
  if (rmp->retval)
    {
      DBG1 (DBG_KNL, "%s SPD entry failed rv:%d", add ? "add" : "remove",
	    ntohl (rmp->retval));
      goto error;
    }

  rv = SUCCESS;

error:
  if (out)
    free (out);
  vl_msg_api_free (mp);

  return rv;
}

static int
bypass_port (bool add, uint32_t spd_id, uint32_t sa_id, uint16_t port,
	     uint32_t priority)
{
  vl_api_ipsec_spd_entry_add_del_t *mp;
  vl_api_ipsec_spd_entry_add_del_reply_t *rmp;
  char *out = NULL;
  int out_len;
  status_t rv = FAILED;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));

  u16 msg_id =
    vl_msg_api_get_msg_index ((u8 *) "ipsec_spd_entry_add_del_338b7411");
  mp->_vl_msg_id = ntohs (msg_id);
  mp->is_add = add;
  mp->entry.sa_id = ntohl (sa_id);
  mp->entry.spd_id = ntohl (spd_id);
  mp->entry.priority = ntohl (priority - POLICY_PRIORITY_PASS);
  mp->entry.policy = ntohl (IPSEC_API_SPD_ACTION_BYPASS);
  memset (mp->entry.local_address_stop.un.ip6, 0xFF, 16);
  memset (mp->entry.remote_address_stop.un.ip6, 0xFF, 16);
  mp->entry.is_outbound = 0;
  mp->entry.remote_port_start = mp->entry.local_port_start = ntohs (port);
  mp->entry.remote_port_stop = mp->entry.local_port_stop = ntohs (port);
  mp->entry.protocol = IP_API_PROTO_UDP;

  if (vac->send (vac, (char *) mp, sizeof (*mp), &out, &out_len))
    {
      DBG1 (DBG_KNL, "vac %s SPD entry failed", add ? "adding" : "removing");
      goto error;
    }
  rmp = (void *) out;
  if (rmp->retval)
    {
      DBG1 (DBG_KNL, "%s SPD entry failed rv:%d", add ? "add" : "remove",
	    ntohl (rmp->retval));
      goto error;
    }
  /* address "out" needs to be freed after vec->send */
  if (out != NULL)
    {
      free (out);
      out = NULL;
    }
  mp->entry.is_outbound = 1;
  if (vac->send (vac, (char *) mp, sizeof (*mp), &out, &out_len))
    {
      DBG1 (DBG_KNL, "vac %s SPD entry failed", add ? "adding" : "removing");
      goto error;
    }
  rmp = (void *) out;
  if (rmp->retval)
    {
      DBG1 (DBG_KNL, "%s SPD entry failed rv:%d", add ? "add" : "remove",
	    ntohl (rmp->retval));
      goto error;
    }
  rv = SUCCESS;

error:
  if (out)
    free (out);
  vl_msg_api_free (mp);

  return rv;
}

/**
 * Add or remove a bypass policy
 */
static status_t
manage_bypass (bool add, uint32_t spd_id, uint32_t sa_id, uint32_t priority)
{
  uint16_t port;
  status_t rv;

  bypass_all (add, spd_id, sa_id, priority);

  port =
    lib->settings->get_int (lib->settings, "%s.port", IKEV2_UDP_PORT, lib->ns);

  if (port)
    {
      rv = bypass_port (add, spd_id, sa_id, port, priority);
      if (rv != SUCCESS)
	{
	  return rv;
	}
    }

  port = lib->settings->get_int (lib->settings, "%s.port_nat_t",
				 IKEV2_NATT_PORT, lib->ns);
  if (port)
    {
      rv = bypass_port (add, spd_id, sa_id, port, priority);
      if (rv != SUCCESS)
	{
	  return rv;
	}
    }

  return SUCCESS;
}

/**
 * Add or remove a policy
 */
static status_t
manage_policy (private_kernel_vpp_ipsec_t *this, bool add,
	       kernel_ipsec_policy_id_t *id,
	       kernel_ipsec_manage_policy_t *data)
{
  if (this->route_mode)
    return manage_policy_route (this, add, id, data);

  spd_t *spd = NULL;
  char *out = NULL, *interface = NULL;
  int out_len;
  uint32_t sw_if_index, spd_id = ~0, sad_id = ~0;
  status_t rv = FAILED;
  uint32_t priority, auto_priority;
  chunk_t src_from, src_to, dst_from, dst_to;
  host_t *src = NULL, *dst = NULL, *addr = NULL;
  vl_api_ipsec_spd_entry_add_del_t *mp = NULL;
  vl_api_ipsec_spd_entry_add_del_reply_t *rmp = NULL;
  bool n_spd = false; /* is a new SPD? */
  vl_api_ipsec_spd_dump_t *mp_dump = NULL;
  vl_api_ipsec_spd_details_t *rmp_dump = NULL, *tmp = NULL;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));

  this->mutex->lock (this->mutex);
  if (id->dir == POLICY_FWD)
    {
      DBG1 (DBG_KNL, "policy FWD interface");
      rv = SUCCESS;
      goto error;
    }
  addr = id->dir == POLICY_IN ? data->dst : data->src;
  for (int i = 0; i < N_RETRY_GET_IF; i++)
    {
      if (!charon->kernel->get_interface (charon->kernel, addr, &interface))
	{
	  DBG1 (DBG_KNL, "policy no interface %H", addr);
	  free (interface);
	  interface = NULL;
	  sleep (1);
	}

      if (interface)
	{
	  DBG1 (DBG_KNL, "policy have interface %H", addr);
	  break;
	}
    }
  if (!interface)
    goto error;

  DBG2 (DBG_KNL, "manage policy [%s] interface [%s]", add ? "ADD" : "DEL",
	interface);

  spd = this->spds->get (this->spds, interface);
  if (!spd)
    {
      if (!add)
	{
	  DBG1 (DBG_KNL, "SPD for %s not found, should not be deleted",
		interface);
	  goto error;
	}
      sw_if_index = get_sw_if_index (interface);
      DBG1 (DBG_KNL, "firstly created, spd for %s found sw_if_index is %d",
	    interface, sw_if_index);
      if (sw_if_index == (uint32_t) ~0)
	{
	  DBG1 (DBG_KNL, "sw_if_index for %s not found", interface);
	  goto error;
	}
      spd_id = ref_get (&this->next_spd_id);
      if (spd_add_del (TRUE, spd_id))
	{
	  DBG1 (DBG_KNL, "spd_add_del %d failed!!!!!", spd_id);
	  goto error;
	}
      if (interface_add_del_spd (TRUE, spd_id, sw_if_index))
	{
	  DBG1 (DBG_KNL, "interface_add_del_spd  %d %d failed!!!!!", spd_id,
		sw_if_index);
	  goto error;
	}
      INIT (spd, .spd_id = spd_id, .sw_if_index = sw_if_index, .policy_num = 0,
	    .if_name = strdup (interface), );
      this->spds->put (this->spds, spd->if_name, spd);
      n_spd = true;
    }

  auto_priority = calculate_priority (data->prio, id->src_ts, id->dst_ts);
  priority = data->manual_prio ? data->manual_prio : auto_priority;

  u16 msg_id =
    vl_msg_api_get_msg_index ((u8 *) "ipsec_spd_entry_add_del_338b7411");
  mp->_vl_msg_id = htons (msg_id);
  mp->is_add = add;
  mp->entry.spd_id = htonl (spd->spd_id);
  mp->entry.priority = htonl (priority - POLICY_PRIORITY_DEFAULT);
  mp->entry.is_outbound = id->dir == POLICY_OUT;
  switch (data->type)
    {
    case POLICY_IPSEC:
      mp->entry.policy = htonl (IPSEC_API_SPD_ACTION_PROTECT);
      break;
    case POLICY_PASS:
      mp->entry.policy = htonl (IPSEC_API_SPD_ACTION_BYPASS);
      break;
    case POLICY_DROP:
      mp->entry.policy = htonl (IPSEC_API_SPD_ACTION_DISCARD);
      break;
    }
  if ((data->type == POLICY_IPSEC) && data->sa)
    {
      kernel_ipsec_sa_id_t id = {
	.src = data->src,
	.dst = data->dst,
	.proto = data->sa->esp.use ? IPPROTO_ESP : IPPROTO_AH,
	.spi = data->sa->esp.use ? data->sa->esp.spi : data->sa->ah.spi,
      };
      sa_t *sa = NULL;
      sa = this->sas->get (this->sas, &id);
      if (!sa)
	{
	  DBG1 (DBG_KNL, "SA ID not found");
	  goto error;
	}
      sad_id = sa->sa_id;
      if (n_spd)
	{
	  if (manage_bypass (TRUE, spd_id, ~0, priority))
	    {
	      DBG1 (DBG_KNL, "manage_bypass %d failed!!!!", spd_id);
	      goto error;
	    }
	}
    }

  mp->entry.sa_id = htonl (sad_id);

  bool is_ipv6 = false;
  if (id->src_ts->get_type (id->src_ts) == TS_IPV6_ADDR_RANGE)
    {
      is_ipv6 = true;
      mp->entry.local_address_start.af = htonl (ADDRESS_IP6);
      mp->entry.local_address_stop.af = htonl (ADDRESS_IP6);
      mp->entry.remote_address_start.af = htonl (ADDRESS_IP6);
      mp->entry.remote_address_stop.af = htonl (ADDRESS_IP6);
    }
  else
    {
      mp->entry.local_address_start.af = htonl (ADDRESS_IP4);
      mp->entry.local_address_stop.af = htonl (ADDRESS_IP4);
      mp->entry.remote_address_start.af = htonl (ADDRESS_IP4);
      mp->entry.remote_address_stop.af = htonl (ADDRESS_IP4);
    }
  mp->entry.protocol = id->src_ts->get_protocol (id->src_ts);

  if (id->dir == POLICY_OUT)
    {
      src_from = id->src_ts->get_from_address (id->src_ts);
      src_to = id->src_ts->get_to_address (id->src_ts);
      src = host_create_from_chunk (is_ipv6 ? AF_INET6 : AF_INET, src_to, 0);
      dst_from = id->dst_ts->get_from_address (id->dst_ts);
      dst_to = id->dst_ts->get_to_address (id->dst_ts);
      dst = host_create_from_chunk (is_ipv6 ? AF_INET6 : AF_INET, dst_to, 0);
    }
  else
    {
      dst_from = id->src_ts->get_from_address (id->src_ts);
      dst_to = id->src_ts->get_to_address (id->src_ts);
      dst = host_create_from_chunk (is_ipv6 ? AF_INET6 : AF_INET, dst_from, 0);
      src_from = id->dst_ts->get_from_address (id->dst_ts);
      src_to = id->dst_ts->get_to_address (id->dst_ts);
      src = host_create_from_chunk (is_ipv6 ? AF_INET6 : AF_INET, src_from, 0);
    }

  if (src->is_anyaddr (src) && dst->is_anyaddr (dst))
    {
      memset (mp->entry.local_address_stop.un.ip6, 0xFF, 16);
      memset (mp->entry.remote_address_stop.un.ip6, 0xFF, 16);
    }
  else
    {
      memcpy (is_ipv6 ? mp->entry.local_address_start.un.ip6 :
			      mp->entry.local_address_start.un.ip4,
	      src_from.ptr, src_from.len);
      memcpy (is_ipv6 ? mp->entry.local_address_stop.un.ip6 :
			      mp->entry.local_address_stop.un.ip4,
	      src_to.ptr, src_to.len);
      memcpy (is_ipv6 ? mp->entry.remote_address_start.un.ip6 :
			      mp->entry.remote_address_start.un.ip4,
	      dst_from.ptr, dst_from.len);
      memcpy (is_ipv6 ? mp->entry.remote_address_stop.un.ip6 :
			      mp->entry.remote_address_stop.un.ip4,
	      dst_to.ptr, dst_to.len);
    }
  mp->entry.local_port_start = htons (id->src_ts->get_from_port (id->src_ts));
  mp->entry.local_port_stop = htons (id->src_ts->get_to_port (id->src_ts));
  mp->entry.remote_port_start = htons (id->dst_ts->get_from_port (id->dst_ts));
  mp->entry.remote_port_stop = htons (id->dst_ts->get_to_port (id->dst_ts));

  /* check if policy exists in SPD */
  mp_dump = vl_msg_api_alloc (sizeof (*mp_dump));
  memset (mp_dump, 0, sizeof (*mp_dump));

  msg_id = vl_msg_api_get_msg_index ((u8 *) "ipsec_spd_dump_afefbf7d");
  mp_dump->_vl_msg_id = htons (msg_id);
  mp_dump->spd_id = htonl (spd->spd_id);
  mp_dump->sa_id = htonl (sad_id);

  if (vac->send_dump (vac, (char *) mp_dump, sizeof (*mp_dump), &out,
		      &out_len))
    {
      DBG1 (DBG_KNL, "vac %s SPD lookup failed", add ? "adding" : "removing");
      goto error;
    }

  int num = out_len / sizeof (*rmp_dump);
  tmp = (void *) out;

  /* found existing policy */
  if (add && num)
    {
      int i;
      for (i = 0; i < num; i++)
	{
	  rmp_dump = tmp;
	  tmp += 1;
	  /* check if found entry equals the new one */
	  if (policy_equals (&mp->entry, &rmp_dump->entry))
	    goto next;
	}
    }
  else if (!add && num == 0)
    {
      /* VPP doesn't have any policy to delete */
      goto next;
    }

  free (out);

  if (vac->send (vac, (char *) mp, sizeof (*mp), &out, &out_len))
    {
      DBG1 (DBG_KNL, "vac %s SPD entry failed", add ? "adding" : "removing");
      goto error;
    }
  rmp = (void *) out;
  if (rmp->retval)
    {
      DBG1 (DBG_KNL, "%s SPD entry failed rv:%d", add ? "add" : "remove",
	    ntohl (rmp->retval));
      goto error;
    }

next:
  if (add)
    {
      ref_get (&spd->policy_num);
    }
  else
    {
      if (ref_put (&spd->policy_num))
	{
	  DBG1 (
	    DBG_KNL,
	    "policy_num's ref is 0, delete spd_id %d sw_if_index %d sad_id %x",
	    spd->spd_id, spd->sw_if_index, sad_id);
	  interface_add_del_spd (FALSE, spd->spd_id, spd->sw_if_index);
	  manage_bypass (FALSE, spd->spd_id, sad_id, priority);
	  spd_add_del (FALSE, spd->spd_id);
	  this->spds->remove (this->spds, interface);
	  if (spd->if_name)
	    {
	      free (spd->if_name);
	      spd->if_name = NULL;
	    }
	  if (spd)
	    {
	      free (spd);
	      spd = NULL;
	    }
	}
    }

  if (this->install_routes && id->dir == POLICY_OUT && !mp->entry.protocol)
    {
      if (data->type == POLICY_IPSEC && data->sa->mode != MODE_TRANSPORT)
	{
	  manage_route (this, add, id->dst_ts, data->src, data->dst);
	}
    }
  rv = SUCCESS;
error:
  if (out != NULL)
    free (out);
  if (mp_dump != NULL)
    vl_msg_api_free (mp_dump);
  if (mp != NULL)
    vl_msg_api_free (mp);
  if (src != NULL)
    src->destroy (src);
  if (dst != NULL)
    dst->destroy (dst);
  if (interface != NULL)
    free (interface);
  this->mutex->unlock (this->mutex);
  return rv;
}

METHOD (kernel_ipsec_t, get_features, kernel_feature_t,
	private_kernel_vpp_ipsec_t *this)
{
  return KERNEL_ESP_V3_TFC;
}

METHOD (kernel_ipsec_t, get_spi, status_t, private_kernel_vpp_ipsec_t *this,
	host_t *src, host_t *dst, uint8_t protocol, uint32_t *spi)
{
  static const u_int p = 268435399, offset = 0xc0000000;

  *spi = htonl (offset + permute (ref_get (&this->nextspi) ^ this->mixspi, p));
  return SUCCESS;
}

METHOD (kernel_ipsec_t, get_cpi, status_t, private_kernel_vpp_ipsec_t *this,
	host_t *src, host_t *dst, uint16_t *cpi)
{
  DBG1 (DBG_KNL, "get_cpi is not supported!!!!!!!!!!!!!!!!!!!!!!!!");
  return NOT_SUPPORTED;
}

/**
 * Helper struct for expiration events
 */
typedef struct
{

  private_kernel_vpp_ipsec_t *manager;

  kernel_ipsec_sa_id_t *sa_id;

  /**
   * 0 if this is a hard expire, otherwise the offset in s (soft->hard)
   */
  uint32_t hard_offset;

} vpp_sa_expired_t;

/**
 * Clean up expire data
 */
static void
expire_data_destroy (vpp_sa_expired_t *data)
{
  free (data);
}

/**
 * Callback for expiration events
 */
static job_requeue_t
sa_expired (vpp_sa_expired_t *expired)
{
  private_kernel_vpp_ipsec_t *this = expired->manager;
  sa_t *sa;
  kernel_ipsec_sa_id_t *id = expired->sa_id;

  this->mutex->lock (this->mutex);
  sa = this->sas->get (this->sas, id);

  if (sa)
    {
      charon->kernel->expire (charon->kernel, id->proto, id->spi, id->dst,
			      FALSE);
    }

  if (id->src)
    id->src->destroy (id->src);
  if (id->dst)
    id->dst->destroy (id->dst);
  free (id);
  this->mutex->unlock (this->mutex);
  return JOB_REQUEUE_NONE;
}

/**
 * Schedule a job to handle IPsec SA expiration
 */
static void
schedule_expiration (private_kernel_vpp_ipsec_t *this,
		     kernel_ipsec_add_sa_t *entry,
		     kernel_ipsec_sa_id_t *entry2)
{
  lifetime_cfg_t *lifetime = entry->lifetime;
  vpp_sa_expired_t *expired;
  callback_job_t *job;
  uint32_t timeout;
  kernel_ipsec_sa_id_t *id;

  if (!lifetime->time.life)
    { /* no expiration at all */
      return;
    }

  INIT (id, .src = entry2->src->clone (entry2->src),
	.dst = entry2->dst->clone (entry2->dst), .spi = entry2->spi,
	.proto = entry2->proto, );

  INIT (expired, .manager = this, .sa_id = id, );

  /* schedule a rekey first, a hard timeout will be scheduled then, if any */
  expired->hard_offset = lifetime->time.life - lifetime->time.rekey;
  timeout = lifetime->time.rekey;

  if (lifetime->time.life <= lifetime->time.rekey || lifetime->time.rekey == 0)
    { /* no rekey, schedule hard timeout */
      expired->hard_offset = 0;
      timeout = lifetime->time.life;
    }

  job =
    callback_job_create ((callback_job_cb_t) sa_expired, expired,
			 (callback_job_cleanup_t) expire_data_destroy, NULL);
  lib->scheduler->schedule_job (lib->scheduler, (job_t *) job, timeout);
}

/**
 * Delete an SA from VPP's SAD by sad_id (best-effort, no table state).
 *
 * Used by add_sa to clear a stale entry left over from a previous
 * charon instance before retrying the add — see the
 * ENTRY_ALREADY_EXISTS handling there.
 */
static void
delete_sad_entry_vpp (uint32_t sad_id)
{
  vl_api_ipsec_sad_entry_add_del_t *mp = NULL;
  vl_api_ipsec_sad_entry_add_del_reply_t *rmp = NULL;
  char *out = NULL;
  int out_len = 0;
  u16 msg_id;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  msg_id =
    vl_msg_api_get_msg_index ((u8 *) "ipsec_sad_entry_add_del_ab64b5c6");
  mp->_vl_msg_id = htons (msg_id);
  mp->is_add = 0;
  mp->entry.sad_id = htonl (sad_id);
  if (vac->send (vac, (char *) mp, sizeof (*mp), &out, &out_len))
    {
      DBG1 (DBG_KNL, "vac delete stale SA failed");
    }
  else
    {
      rmp = (void *) out;
      if (rmp->retval)
	DBG1 (DBG_KNL, "delete stale SA sad_id %u rv:%d", sad_id,
	      ntohl (rmp->retval));
      else
	DBG1 (DBG_KNL, "deleted stale SA sad_id %u", sad_id);
    }
  if (out)
    free (out);
  if (mp)
    vl_msg_api_free (mp);
}

METHOD (kernel_ipsec_t, add_sa, status_t, private_kernel_vpp_ipsec_t *this,
	kernel_ipsec_sa_id_t *id, kernel_ipsec_add_sa_t *data)
{
  char *out = NULL;
  int out_len;
  vl_api_ipsec_sad_entry_add_del_t *mp;
  vl_api_ipsec_sad_entry_add_del_reply_t *rmp;
  uint32_t sad_id = ref_get (&this->next_sad_id);
  uint8_t ca = 0, ia = 0;
  status_t rv = FAILED;
  chunk_t src, dst;
  kernel_ipsec_sa_id_t *sa_id;
  sa_t *sa;
  int key_len = data->enc_key.len;

  if ((data->enc_alg == ENCR_AES_CTR) ||
      (data->enc_alg == ENCR_AES_GCM_ICV8) ||
      (data->enc_alg == ENCR_AES_GCM_ICV12) ||
      (data->enc_alg == ENCR_AES_GCM_ICV16))
    {
      static const int SALT_SIZE =
	4; /* See how enc_size is calculated at keymat_v2.derive_child_keys */
      key_len = key_len - SALT_SIZE;
    }
  natt_port = lib->settings->get_int (
    lib->settings, "%s.plugins.socket-default.natt", IKEV2_NATT_PORT, lib->ns);
  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  u16 msg_id =
    vl_msg_api_get_msg_index ((u8 *) "ipsec_sad_entry_add_del_ab64b5c6");
  mp->_vl_msg_id = htons (msg_id);
  mp->is_add = 1;
  mp->entry.sad_id = htonl (sad_id);
  mp->entry.spi = id->spi;
  mp->entry.protocol = id->proto == IPPROTO_ESP ? htonl (IPSEC_API_PROTO_ESP) :
							htonl (IPSEC_API_PROTO_AH);

  switch (data->enc_alg)
    {
    case ENCR_NULL:
      ca = IPSEC_API_CRYPTO_ALG_NONE;
      break;
    case ENCR_AES_CBC:
      switch (key_len * 8)
	{
	case 128:
	  ca = IPSEC_API_CRYPTO_ALG_AES_CBC_128;
	  break;
	case 192:
	  ca = IPSEC_API_CRYPTO_ALG_AES_CBC_192;
	  break;
	case 256:
	  ca = IPSEC_API_CRYPTO_ALG_AES_CBC_256;
	  break;
	default:
	  DBG1 (DBG_KNL, "Key length %d is not supported by VPP!",
		key_len * 8);
	  goto error;
	}
      break;
    case ENCR_AES_CTR:
      switch (key_len * 8)
	{
	case 128:
	  ca = IPSEC_API_CRYPTO_ALG_AES_CTR_128;
	  break;
	case 192:
	  ca = IPSEC_API_CRYPTO_ALG_AES_CTR_192;
	  break;
	case 256:
	  ca = IPSEC_API_CRYPTO_ALG_AES_CTR_256;
	  break;
	default:
	  DBG1 (DBG_KNL, "Key length %d is not supported by VPP!",
		key_len * 8);
	  goto error;
	}
      break;
    case ENCR_AES_GCM_ICV8:
    case ENCR_AES_GCM_ICV12:
    case ENCR_AES_GCM_ICV16:
      switch (key_len * 8)
	{
	case 128:
	  ca = IPSEC_API_CRYPTO_ALG_AES_GCM_128;
	  break;
	case 192:
	  ca = IPSEC_API_CRYPTO_ALG_AES_GCM_192;
	  break;
	case 256:
	  ca = IPSEC_API_CRYPTO_ALG_AES_GCM_256;
	  break;
	default:
	  DBG1 (DBG_KNL, "Key length %d is not supported by VPP!",
		key_len * 8);
	  goto error;
	}
      break;
    case ENCR_DES:
      ca = IPSEC_API_CRYPTO_ALG_DES_CBC;
      break;
    case ENCR_3DES:
      ca = IPSEC_API_CRYPTO_ALG_3DES_CBC;
      break;
    default:
      DBG1 (DBG_KNL, "algorithm %N not supported by VPP!",
	    encryption_algorithm_names, data->enc_alg);
      goto error;
    }
  mp->entry.crypto_algorithm = htonl (ca);
  mp->entry.crypto_key.length = key_len < 128 ? key_len : 128;
  memcpy (mp->entry.crypto_key.data, data->enc_key.ptr,
	  mp->entry.crypto_key.length);

  /* copy salt for AEAD algorithms */
  if ((data->enc_alg == ENCR_AES_CTR) ||
      (data->enc_alg == ENCR_AES_GCM_ICV8) ||
      (data->enc_alg == ENCR_AES_GCM_ICV12) ||
      (data->enc_alg == ENCR_AES_GCM_ICV16))
    {
      memcpy (&mp->entry.salt, data->enc_key.ptr + mp->entry.crypto_key.length,
	      4);
    }

  switch (data->int_alg)
    {
    case AUTH_UNDEFINED:
      ia = IPSEC_API_INTEG_ALG_NONE;
      break;
    case AUTH_HMAC_MD5_96:
      ia = IPSEC_API_INTEG_ALG_MD5_96;
      break;
    case AUTH_HMAC_SHA1_96:
      ia = IPSEC_API_INTEG_ALG_SHA1_96;
      break;
    case AUTH_HMAC_SHA2_256_96:
      ia = IPSEC_API_INTEG_ALG_SHA_256_96;
      break;
    case AUTH_HMAC_SHA2_256_128:
      ia = IPSEC_API_INTEG_ALG_SHA_256_128;
      break;
    case AUTH_HMAC_SHA2_384_192:
      ia = IPSEC_API_INTEG_ALG_SHA_384_192;
      break;
    case AUTH_HMAC_SHA2_512_256:
      ia = IPSEC_API_INTEG_ALG_SHA_512_256;
      break;
    default:
      DBG1 (DBG_KNL, "algorithm %N not supported by VPP!",
	    integrity_algorithm_names, data->int_alg);
      goto error;
      break;
    }
  mp->entry.integrity_algorithm = htonl (ia);
  mp->entry.integrity_key.length =
    data->int_key.len < 128 ? data->int_key.len : 128;
  memcpy (mp->entry.integrity_key.data, data->int_key.ptr,
	  mp->entry.integrity_key.length);

  int flags = IPSEC_API_SAD_FLAG_NONE;
  if (data->inbound)
    flags |= IPSEC_API_SAD_FLAG_IS_INBOUND;
  /* like the kernel-netlink plugin, anti-replay can be disabled with zero
   * replay_window, but window size cannot be customized for vpp */
  if (data->replay_window)
    flags |= IPSEC_API_SAD_FLAG_USE_ANTI_REPLAY;
  if (data->esn)
    flags |= IPSEC_API_SAD_FLAG_USE_ESN;
  if (this->use_tunnel_mode_sa && data->mode == MODE_TUNNEL)
    {
      if (id->src->get_family (id->src) == AF_INET6)
	flags |= IPSEC_API_SAD_FLAG_IS_TUNNEL_V6;
      else
	flags |= IPSEC_API_SAD_FLAG_IS_TUNNEL;
    }
  if (data->encap)
    {
      /* NAT-T: the peer is reachable only on the port its NAT mapped
       * for us. Using the SA endpoint ports (id->src / id->dst) gives:
       *   inbound  SA: src=peer:<their ephemeral>  dst=us:4500
       *   outbound SA: src=us:4500                 dst=peer:<their ephemeral>
       * The old code hardcoded both to natt_port (4500), which works
       * only when the peer is also exactly on 4500. When the peer is
       * behind NAT with port translation (the common case), outbound
       * ESP went to port 4500 and the NAT box had no mapping for it
       * → replies were silently dropped at the NAT, the VPN client
       * saw IKE come up but no decrypted traffic flowed back. */
      uint16_t sport = id->src->get_port (id->src);
      uint16_t dport = id->dst->get_port (id->dst);
      if (sport == 0)
	sport = natt_port; /* fallback if charon didn't fill it */
      if (dport == 0)
	dport = natt_port;
      DBG1 (DBG_KNL, "UDP encap sport=%u dport=%u", sport, dport);
      flags |= IPSEC_API_SAD_FLAG_UDP_ENCAP;
      mp->entry.udp_src_port = htons (sport);
      mp->entry.udp_dst_port = htons (dport);
    }
  mp->entry.flags = htonl (flags);

  bool is_ipv6 = false;
  if (id->src->get_family (id->src) == AF_INET6)
    {
      is_ipv6 = true;
      mp->entry.tunnel_src.af = htonl (ADDRESS_IP6);
      mp->entry.tunnel_dst.af = htonl (ADDRESS_IP6);
    }
  else
    {
      mp->entry.tunnel_src.af = htonl (ADDRESS_IP4);
      mp->entry.tunnel_dst.af = htonl (ADDRESS_IP4);
    }
  src = id->src->get_address (id->src);
  memcpy (is_ipv6 ? mp->entry.tunnel_src.un.ip6 : mp->entry.tunnel_src.un.ip4,
	  src.ptr, src.len);
  dst = id->dst->get_address (id->dst);
  memcpy (is_ipv6 ? mp->entry.tunnel_dst.un.ip6 : mp->entry.tunnel_dst.un.ip4,
	  dst.ptr, dst.len);
  if (vac->send (vac, (char *) mp, sizeof (*mp), &out, &out_len))
    {
      DBG1 (DBG_KNL, "vac adding SA failed");
      goto error;
    }
  rmp = (void *) out;
  /* -116 = VNET_API_ERROR_ENTRY_ALREADY_EXISTS. The plugin resets
   * next_sad_id to 0 on every charon start, but VPP keeps SAs across a
   * charon restart (and a crashed charon never cleans up at all) — so
   * sad_id collides with a stale leftover.
   *
   * We try two things per collision:
   *   1. delete the colliding sad_id — frees it cleanly IF the leftover
   *      SA is unbound.
   *   2. move to a FRESH sad_id and retry — needed because a leftover SA
   *      that is still bound to a stale tunnel-protect is refcounted:
   *      the is_add=0 delete only unlocks it, the SA stays, and re-using
   *      the same id keeps failing. next_sad_id is monotonic, so a fresh
   *      id walks past the whole leaked range.
   * Bounded loop so a pathological VPP state can't spin forever. */
  {
    int tries = 0;
    while (rmp->retval && (int) ntohl (rmp->retval) == -116 && tries < 16)
      {
	tries++;
	DBG1 (DBG_KNL,
	      "add SA: sad_id %u already in VPP (stale leftover); freeing it "
	      "and retrying with a fresh id",
	      sad_id);
	delete_sad_entry_vpp (sad_id);
	sad_id = ref_get (&this->next_sad_id);
	mp->entry.sad_id = htonl (sad_id);
	free (out);
	out = NULL;
	if (vac->send (vac, (char *) mp, sizeof (*mp), &out, &out_len))
	  {
	    DBG1 (DBG_KNL, "vac adding SA failed (retry)");
	    goto error;
	  }
	rmp = (void *) out;
      }
  }
  if (rmp->retval)
    {
      DBG1 (DBG_KNL, "add SA failed rv:%d", ntohl (rmp->retval));
      goto error;
    }

  this->mutex->lock (this->mutex);
  INIT (sa_id, .src = id->src->clone (id->src),
	.dst = id->dst->clone (id->dst), .spi = id->spi, .proto = id->proto, );
  INIT (sa, .sa_id = sad_id, .stat_index = ntohl (rmp->stat_index),
	.sa_id_p = sa_id, .reqid = data->reqid, .inbound = data->inbound, );
  DBG4 (DBG_KNL, "put sa by its sa_id %x !!!!!!", sad_id);
  this->sas->put (this->sas, sa_id, sa);
  schedule_expiration (this, data, id);
  this->mutex->unlock (this->mutex);
  rv = SUCCESS;

error:
  free (out);
  vl_msg_api_free (mp);
  return rv;
}

METHOD (kernel_ipsec_t, update_sa, status_t, private_kernel_vpp_ipsec_t *this,
	kernel_ipsec_sa_id_t *id, kernel_ipsec_update_sa_t *data)
{
  DBG1 (DBG_KNL,
	"update sa not supported!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
  return NOT_SUPPORTED;
}

METHOD (kernel_ipsec_t, query_sa, status_t, private_kernel_vpp_ipsec_t *this,
	kernel_ipsec_sa_id_t *id, kernel_ipsec_query_sa_t *data,
	uint64_t *bytes, uint64_t *packets, time_t *time)
{
  status_t rv = FAILED;
  sa_t *sa;
  u32 *dir = NULL;
  int i, k;
  stat_segment_data_t *res = NULL;
  u8 **pattern = 0;
  uint64_t res_bytes = 0;
  uint64_t res_packets = 0;

  this->mutex->lock (this->mutex);
  sa = this->sas->get (this->sas, id);
  if (!sa)
    {
      this->mutex->unlock (this->mutex);
      DBG1 (DBG_KNL, "SA not found");
      return NOT_FOUND;
    }

  if (this->sm == NULL)
    {
      stat_client_main_t *sm = NULL;

      /* Stats segment already known unreachable — return silently
       * without retrying or logging (charon polls this often). */
      if (this->stats_unavailable)
	{
	  this->mutex->unlock (this->mutex);
	  return NOT_FOUND;
	}

      sm = stat_client_get ();
      if (!sm)
	{
	  this->stats_unavailable = TRUE;
	  DBG1 (DBG_KNL, "stats segment unavailable (per-SA byte counters "
			 "will read 0); not retrying");
	  this->mutex->unlock (this->mutex);
	  return NOT_FOUND;
	}
      this->sm = sm;
      int rv_stat = stat_segment_connect_r ("/run/vpp/stats.sock", this->sm);
      if (rv_stat != 0)
	{
	  stat_client_free (this->sm);
	  this->sm = NULL;
	  this->stats_unavailable = TRUE;
	  DBG1 (DBG_KNL, "stats segment unavailable at /run/vpp/stats.sock "
			 "(per-SA byte counters will read 0); not retrying");
	  this->mutex->unlock (this->mutex);
	  return NOT_FOUND;
	}
    }

  vec_add1 (pattern, (u8 *) "/net/ipsec/sa");
  dir = stat_segment_ls_r ((u8 **) pattern, this->sm);
  res = stat_segment_dump_r (dir, this->sm);
  /* i-loop for each results find by pattern - here two:
   * 1. /net/ipsec/sa
   * 2. /net/ipsec/sa/lost
   */
  for (i = 0; i < vec_len (res); i++)
    {
      switch (res[i].type)
	{
	/* type for how many packets are lost */
	case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
	  if (res[i].simple_counter_vec == 0)
	    continue;
	  break;
	/* type for counter for each SA */
	case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
	  if (res[i].combined_counter_vec == 0)
	    continue;
	  /* k-loop for each threads - that you run VPP */
	  for (k = 0; k < vec_len (res[i].combined_counter_vec); k++)
	    {
	      if (sa->stat_index <= vec_len (res[i].combined_counter_vec[k]))
		{
		  DBG4 (DBG_KNL, "Thread: %d, Packets: %lu, Bytes: %lu", k,
			res[i].combined_counter_vec[k][sa->stat_index].packets,
			res[i].combined_counter_vec[k][sa->stat_index].bytes);
		  res_bytes +=
		    res[i].combined_counter_vec[k][sa->stat_index].bytes;
		  res_packets +=
		    res[i].combined_counter_vec[k][sa->stat_index].packets;
		}
	    }
	  break;
	case STAT_DIR_TYPE_NAME_VECTOR:
	  if (res[i].name_vector == 0)
	    continue;
	  break;
	}
    }

  vec_free (pattern);
  vec_free (dir);
  stat_segment_data_free (res);

  if (bytes)
    {
      *bytes = res_bytes;
    }
  if (packets)
    {
      *packets = res_packets;
    }
  if (time)
    {
      *time = 0;
    }

  this->mutex->unlock (this->mutex);
  rv = SUCCESS;
  return rv;
}

METHOD (kernel_ipsec_t, del_sa, status_t, private_kernel_vpp_ipsec_t *this,
	kernel_ipsec_sa_id_t *id, kernel_ipsec_del_sa_t *data)
{
  char *out = NULL;
  int out_len;
  vl_api_ipsec_sad_entry_add_del_t *mp = NULL;
  vl_api_ipsec_sad_entry_add_del_reply_t *rmp = NULL;
  status_t rv = FAILED;
  sa_t *sa;

  this->mutex->lock (this->mutex);
  sa = this->sas->get (this->sas, id);
  if (!sa)
    {
      DBG1 (DBG_KNL, "SA not found");
      rv = NOT_FOUND;
      goto error;
    }
  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->is_add = 0;
  u16 msg_id =
    vl_msg_api_get_msg_index ((u8 *) "ipsec_sad_entry_add_del_ab64b5c6");
  mp->_vl_msg_id = htons (msg_id);
  mp->entry.sad_id = htonl (sa->sa_id);

  if (vac->send (vac, (char *) mp, sizeof (*mp), &out, &out_len))
    {
      DBG1 (DBG_KNL, "vac removing SA failed");
      goto error;
    }
  rmp = (void *) out;
  if (rmp->retval)
    {
      DBG1 (DBG_KNL, "del SA failed rv:%d", ntohl (rmp->retval));
      goto error;
    }

  void *temp = this->sas->remove (this->sas, id);
  if (sa->sa_id_p)
    {
      if (sa->sa_id_p->src)
	sa->sa_id_p->src->destroy (sa->sa_id_p->src);
      if (sa->sa_id_p->dst)
	sa->sa_id_p->dst->destroy (sa->sa_id_p->dst);
      free (sa->sa_id_p);
    }
  free (sa);
  rv = SUCCESS;
error:
  free (out);
  /* mp is NULL when we jumped here from the "SA not found" early-out
   * above (it is allocated only after that check). vl_msg_api_free()
   * does NOT null-check its argument — passing NULL dereferences a
   * bogus header and segfaults the whole charon process, which is
   * exactly what charon does while cleaning up after add_sa fails. */
  if (mp)
    vl_msg_api_free (mp);
  this->mutex->unlock (this->mutex);
  return rv;
}

METHOD (kernel_ipsec_t, flush_sas, status_t, private_kernel_vpp_ipsec_t *this)
{
  enumerator_t *enumerator;
  int out_len;
  char *out;
  vl_api_ipsec_sad_entry_add_del_t *mp = NULL;
  vl_api_ipsec_sad_entry_add_del_reply_t *rmp = NULL;
  sa_t *sa = NULL;
  status_t rv = FAILED;

  this->mutex->lock (this->mutex);
  enumerator = this->sas->create_enumerator (this->sas);
  while (enumerator->enumerate (enumerator, &sa))
    {
      mp = vl_msg_api_alloc (sizeof (*mp));
      memset (mp, 0, sizeof (*mp));
      u16 msg_id =
	vl_msg_api_get_msg_index ((u8 *) "ipsec_sad_entry_add_del_ab64b5c6");
      mp->_vl_msg_id = htons (msg_id);
      mp->entry.sad_id = htonl (sa->sa_id);
      mp->is_add = 0;
      if (vac->send (vac, (char *) mp, sizeof (*mp), &out, &out_len))
	{
	  DBG1 (DBG_KNL, "flush_sas failed!!!!");
	  goto error;
	}
      rmp = (void *) out;
      if (rmp->retval)
	{
	  DBG1 (DBG_KNL, "flush_sas failed!!!! rv: %d", ntohl (rmp->retval));
	  goto error;
	}
      if (sa->sa_id_p)
	{
	  if (sa->sa_id_p->src)
	    sa->sa_id_p->src->destroy (sa->sa_id_p->src);
	  if (sa->sa_id_p->dst)
	    sa->sa_id_p->dst->destroy (sa->sa_id_p->dst);
	}
      free (out);
      vl_msg_api_free (mp);
      this->sas->remove_at (this->sas, enumerator);
      free (sa->sa_id_p);
      free (sa);
    }
  rv = SUCCESS;
error:
  if (out != NULL)
    free (out);
  if (mp != NULL)
    vl_msg_api_free (mp);

  enumerator->destroy (enumerator);
  this->mutex->unlock (this->mutex);

  return rv;
}

METHOD (kernel_ipsec_t, add_policy, status_t, private_kernel_vpp_ipsec_t *this,
	kernel_ipsec_policy_id_t *id, kernel_ipsec_manage_policy_t *data)
{
  return manage_policy (this, TRUE, id, data);
}

METHOD (kernel_ipsec_t, query_policy, status_t,
	private_kernel_vpp_ipsec_t *this, kernel_ipsec_policy_id_t *id,
	kernel_ipsec_query_policy_t *data, time_t *use_time)
{
  return NOT_SUPPORTED;
}

METHOD (kernel_ipsec_t, del_policy, status_t, private_kernel_vpp_ipsec_t *this,
	kernel_ipsec_policy_id_t *id, kernel_ipsec_manage_policy_t *data)
{
  return manage_policy (this, FALSE, id, data);
}

METHOD (kernel_ipsec_t, flush_policies, status_t,
	private_kernel_vpp_ipsec_t *this)
{
  return NOT_SUPPORTED;
}

METHOD (kernel_ipsec_t, bypass_socket, bool, private_kernel_vpp_ipsec_t *this,
	int fd, int family)
{
  return FALSE;
}

METHOD (kernel_ipsec_t, enable_udp_decap, bool,
	private_kernel_vpp_ipsec_t *this, int fd, int family, u_int16_t port)
{
  DBG1 (DBG_KNL, "enable_udp_decap not supported!!!!!!!!!!!!!!!!!!!!!!!!!");
  return FALSE;
}

METHOD (kernel_ipsec_t, destroy, void, private_kernel_vpp_ipsec_t *this)
{
  this->mutex->destroy (this->mutex);
  this->sas->destroy (this->sas);
  this->spds->destroy (this->spds);
  this->routes->destroy (this->routes);
  /* Tear down every ipsec-itf we created before freeing the table.
   * hashtable->destroy() only frees the table structure — it does NOT
   * delete the VPP interfaces or free the entries. Without this loop
   * each ipsec-itf leaks in VPP across a charon restart (see
   * delete_ipsec_itf_vpp). This handles the graceful path (SIGTERM
   * from `systemctl restart`); crash/SIGKILL is swept by sarhad-guard
   * on the next gateway apply. */
  if (this->ipsec_itfs)
    {
      enumerator_t *e;
      char *key;
      ipsec_itf_t *itf;

      e = this->ipsec_itfs->create_enumerator (this->ipsec_itfs);
      while (e->enumerate (e, &key, &itf))
	{
	  delete_ipsec_itf_vpp (itf->sw_if_index);
	  free (itf->local_key);
	  free (itf);
	}
      e->destroy (e);
      this->ipsec_itfs->destroy (this->ipsec_itfs);
    }
  if (this->tunnel_protects)
    {
      enumerator_t *e;
      tp_key_t *key;
      tunnel_protect_t *tp;

      /* The VPP tunnel-protect objects are gone with their ipsec-itfs
       * above; just free the bookkeeping. Both the key and the value
       * own a cloned peer host_t (see manage_policy_route). */
      e = this->tunnel_protects->create_enumerator (this->tunnel_protects);
      while (e->enumerate (e, &key, &tp))
	{
	  if (tp->peer)
	    tp->peer->destroy (tp->peer);
	  free (tp);
	  if (key->peer)
	    key->peer->destroy (key->peer);
	  free (key);
	}
      e->destroy (e);
      this->tunnel_protects->destroy (this->tunnel_protects);
    }
  if (this->wan_interface)
    {
      free (this->wan_interface);
      this->wan_interface = NULL;
    }
  if (this->sm)
    {
      stat_segment_disconnect_r (this->sm);
      stat_client_free (this->sm);
      this->sm = NULL;
    }
  free (this);
}

kernel_vpp_ipsec_t *
kernel_vpp_ipsec_create ()
{
  private_kernel_vpp_ipsec_t *this;

  INIT(this,
        .public = {
            .interface = {
                .get_features = _get_features,
                .get_spi = _get_spi,
                .get_cpi = _get_cpi,
                .add_sa  = _add_sa,
                .update_sa = _update_sa,
                .query_sa = _query_sa,
                .del_sa = _del_sa,
                .flush_sas = _flush_sas,
                .add_policy = _add_policy,
                .query_policy = _query_policy,
                .del_policy = _del_policy,
                .flush_policies = _flush_policies,
                .bypass_socket = _bypass_socket,
                .enable_udp_decap = _enable_udp_decap,
                .destroy = _destroy,
            },
        },
        .next_sad_id = 0,
        .next_spd_id = 0,
        .mutex = mutex_create(MUTEX_TYPE_DEFAULT),
        .sas = hashtable_create((hashtable_hash_t)sa_hash,
                                (hashtable_equals_t)sa_equals, 32),
        .spds = hashtable_create((hashtable_hash_t)interface_hash,
                                 (hashtable_equals_t)interface_equals, 4),
        .routes = linked_list_create(),
        .install_routes = lib->settings->get_bool(lib->settings,
                            "%s.install_routes", TRUE, lib->ns),
        .use_tunnel_mode_sa = lib->settings->get_bool(lib->settings,
                            "%s.plugins.kernel-vpp.use_tunnel_mode_sa",
                            TRUE, lib->ns),
        .route_mode = lib->settings->get_bool(lib->settings,
                            "%s.plugins.kernel-vpp.route_mode",
                            FALSE, lib->ns),
        .ipsec_itfs = hashtable_create((hashtable_hash_t)itf_hash,
                                       (hashtable_equals_t)itf_equals, 4),
        .tunnel_protects = hashtable_create((hashtable_hash_t)tp_hash,
                                            (hashtable_equals_t)tp_equals, 16),
        .wan_interface = NULL,
        .sm = NULL,
    );

  {
    char *wan = lib->settings->get_str(lib->settings,
                  "%s.plugins.kernel-vpp.wan_interface", NULL, lib->ns);
    if (wan && *wan)
      this->wan_interface = strdup (wan);
  }

  if (this->route_mode)
    DBG1 (DBG_KNL, "kernel-vpp: route_mode ENABLED "
                   "(SPD bypassed, using ipsec-itf + tunnel-protect)%s%s",
                   this->wan_interface ? ", unnumber-to=" : "",
                   this->wan_interface ? this->wan_interface : "");

  if (!init_spi (this))
    {
      destroy (this);
      return NULL;
    }

  return &this->public;
}
