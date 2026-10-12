#ifndef __DP_LOG_H__
#define __DP_LOG_H__

#include <vppinfra/clib.h>
#include <vppinfra/types.h>
#include <vnet/ip/ip.h>

#ifdef __cplusplus
extern "C" {
#endif

/* An ACL tag as VPP stores it (acl_list_t.tag): NUL-terminated, at most 63
   characters. */
#define DP_LOG_TAG_MAX 64

/* Fixed-size POD event (NO pointers). */
typedef struct
{
  u64 ts_ns;   /* nanoseconds since VPP start */
  u8 is_ip6;
  u8 proto;
  u16 sport;
  u16 dport;

  u32 sw_if_index;
  u32 fib_index;

  u32 acl_index;
  u32 rule_index;

  u8 action;
  /* Which ACL matched: the interface's input policy or its output policy.
     They are different policies and a log that merges them cannot be read
     back into a decision. Fits in the existing padding, so the event stays
     the same size and the ring geometry is untouched. */
  u8 is_input;
  /* Bytes in this packet, clamped to 65535. The writer folds a flow's
     packets into one row, and this is what lets that row carry a volume the
     way a session row does. Takes the old padding, so the event stays the
     same size and the ring geometry is untouched. */
  u16 len;

  union {
    struct { ip4_address_t src, dst; } v4;
    struct { ip6_address_t src, dst; } v6;
  } ip;

  /* The matched ACL's tag (fw:pol:<id>, zone-auto:..., ...), copied when
     the packet is evaluated; empty for the implicit deny, where no ACL
     matched. acl_index alone cannot name a rule: VPP reassigns pool indices
     on restart and on re-apply, so an archived row would point at whatever
     ACL holds that index today. The tag is what the operator configured and
     does not move. */
  u8 tag[DP_LOG_TAG_MAX];
} dp_log_acl_event_t;

/* ------------------------------ DNS queries ------------------------------
 *
 * Which client asked for which name, and whether we answered it from a
 * block entry. Unlike the ACL event this is NOT aggregated: DNS query rate
 * is orders of magnitude below packet rate, and collapsing repeats would
 * destroy exactly the "who asked when" detail the log exists for.
 */

/* dp_log_dns_mode values */
#define DP_LOG_DNS_OFF	   0 /* log nothing */
#define DP_LOG_DNS_BLOCKED 1 /* log only queries answered from a block entry */
#define DP_LOG_DNS_ALL	   2 /* log every query */

/* DNS names are at most 253 characters (RFC 1035); 256 leaves room for the
 * terminator and keeps the struct a round size. */
#define DP_LOG_DNS_NAME_MAX 256

typedef struct
{
  u64 ts_ns; /* nanoseconds since VPP start */

  u8 is_ip6;	   /* client address family */
  u8 blocked;	   /* answered from a static (block) cache entry */
  u8 answer_is_ip6;/* answer address family */
  u8 has_answer;   /* 0 => resolution was still pending */

  union
  {
    ip4_address_t v4;
    ip6_address_t v6;
  } client; /* who asked */

  union
  {
    ip4_address_t v4;
    ip6_address_t v6;
  } answer; /* what we told them */

  u16 name_len;
  u8 name[DP_LOG_DNS_NAME_MAX];
} dp_log_dns_event_t;

/* ------------------------- Session close ---------------------------------
 *
 * One record per stateful flow, written when the session goes away.
 *
 * This is the only place the plugin can report volume. A permit+reflect rule
 * is evaluated once, on the first packet; everything after rides the session
 * and never reaches a rule, so neither the match log nor the per-rule
 * counters see it. The session does.
 *
 * Emitted only for sessions whose opening rule asked to be logged, which
 * keeps "what do I want logged" a single decision and keeps a busy box from
 * writing a record per connection.
 */
/* What a session record is reporting. A flow that lasts is described more
 * than once: periodically while it runs, and finally when it ends. The
 * reader keeps the newest row per flow, since the counters are cumulative. */
#define DP_LOG_SESS_OPEN  0 /* still running; counters so far */
#define DP_LOG_SESS_CLOSE 1 /* finished; final counters */

typedef struct
{
  u64 ts_ns;	   /* when the session closed */
  u64 duration_ns; /* how long it was open */

  u8 is_ip6;
  u8 proto;
  u8 is_input; /* the arc the opening rule sat on */
  u8 kind;     /* DP_LOG_SESS_OPEN or DP_LOG_SESS_CLOSE */

  u16 sport;
  u16 dport;

  u32 sw_if_index;
  u32 acl_index;
  u32 rule_index;

  /* Indexed the way the dataplane counts them: [1] is traffic arriving on
     the input arc, [0] traffic leaving on the output arc. The writer labels
     them in/out so a reader never has to know that. */
  u64 bytes[2];
  u32 packets[2];

  union
  {
    struct { ip4_address_t src, dst; } v4;
    struct { ip6_address_t src, dst; } v6;
  } ip;

  /* Tag of the ACL that opened the session; same reasoning as the match
     event. Read when the record is emitted, so an ACL deleted while the
     session lived leaves it empty rather than naming its successor. */
  u8 tag[DP_LOG_TAG_MAX];
} dp_log_sess_event_t;

/* ------------------------- ACL log scope ---------------------------------
 *
 * Which packets the ACL log covers, on top of the per-rule log flag.
 *
 * The per-rule flag is the primary control and needs nothing here: a rule
 * created with log=1 is logged whether it permits or denies. These two bits
 * cover the cases that have no rule to hang a flag on, or that predate the
 * flag:
 *
 *   UNMATCHED  the implicit deny at the end of every ACL. No rule matched,
 *              so no rule can carry a flag, yet "what is my firewall
 *              dropping that I never wrote a rule for" is the single most
 *              useful question the log answers.
 *   ALL_DENY   log every denied packet regardless of the rule's flag,
 *              INCLUDING the implicit deny. "Every" has to mean every: a
 *              spoofed-source flood matches no rule at all, so without
 *              this it falls through to the implicit deny and leaves no
 *              trace for the operator who asked to see every drop. So
 *              ALL_DENY implies UNMATCHED; UNMATCHED alone logs just the
 *              implicit deny.
 *
 * Shared by both halves below: the owner writes these bits, consumers read
 * them, and a value that meant different things on either side of the
 * boundary would be worse than no value at all.
 */
#define DP_LOG_ACL_F_UNMATCHED (1 << 0)
#define DP_LOG_ACL_F_ALL_DENY  (1 << 1)

/* ===================================================================== *
 *  Crossing the plugin boundary
 *
 *  VPP dlopen()s every plugin independently; they are NOT linked to one
 *  another. So a plugin that names dp_log_enabled, dp_log_acl_flags or
 *  dp_log_*_enq_export directly ends up with an undefined symbol, and the
 *  loader answers by refusing the whole plugin. For acl_plugin that means
 *  the acl-plugin-in-ip4-fa feature node ceases to exist, every NAT / ABF /
 *  cnat feature-arc registration anchored on it fails, and VPP exits during
 *  startup. A logging switch takes the entire data plane down.
 *
 *  This header therefore has two halves, and which one you get is decided
 *  by the compiler, not by discipline:
 *
 *    OWNER  (dp_log_plugin itself) sees the real symbols and reads them
 *           directly.
 *    CLIENT (every other plugin) sees only dp_log_client_t, which resolves
 *           the same things through vlib_get_plugin_symbol () at run time.
 *
 *  A client that reaches for the owner half now fails to COMPILE. That is
 *  the whole point: the mistake used to be a data plane that would not
 *  start, and it is now a build error in the file that made it.
 * ===================================================================== */

#ifdef dp_log_plugin_EXPORTS
/* ------------------------------- OWNER ------------------------------- */

#define DP_LOG_API __attribute__ ((visibility ("default")))

DP_LOG_API int dp_log_acl_enq_export (u32 thread_index,
				      const dp_log_acl_event_t *ev);
DP_LOG_API int dp_log_dns_enq_export (u32 thread_index,
				      const dp_log_dns_event_t *ev);
DP_LOG_API int dp_log_sess_enq_export (u32 thread_index,
				       const dp_log_sess_event_t *ev);

/* Exported switches: fast dataplane reads (use atomic ops).
 *
 * NB the DP_LOG_API marker is load-bearing: the plugin is built with
 * -fvisibility=hidden, so without it these are local symbols and
 * vlib_get_plugin_symbol () cannot find them from another plugin. */
DP_LOG_API extern u8 dp_log_enabled;

/* DNS log mode, separate from dp_log_enabled so DNS query logging and ACL
   logging are independently switchable -- an operator auditing DNS should
   not have to turn on the far higher-volume ACL log to do it. */
DP_LOG_API extern u8 dp_log_dns_mode;

/* Extra ACL scope beyond the per-rule flag: DP_LOG_ACL_F_*. */
DP_LOG_API extern u8 dp_log_acl_flags;

static inline int
dp_log_is_enabled (void)
{
  return __atomic_load_n (&dp_log_enabled, __ATOMIC_RELAXED);
}

static inline int
dp_log_acl_flags_get (void)
{
  return __atomic_load_n (&dp_log_acl_flags, __ATOMIC_RELAXED);
}

static inline int
dp_log_dns_mode_get (void)
{
  return __atomic_load_n (&dp_log_dns_mode, __ATOMIC_RELAXED);
}

#else
/* ------------------------------ CLIENT ------------------------------- */

#include <vlib/unix/plugin.h>

/* A resolved handle onto dp_log. Declare one static instance per consuming
 * plugin, zero-initialised, and call dp_log_client_resolve () on the hot
 * path -- it costs a predicted branch after the first packet.
 *
 * Header-only by design: nothing here creates a link-time dependency, which
 * is the property that makes the boundary safe. */
typedef struct
{
  int (*acl_enq) (u32, const dp_log_acl_event_t *);
  int (*dns_enq) (u32, const dp_log_dns_event_t *);
  int (*sess_enq) (u32, const dp_log_sess_event_t *);
  u8 *enabled;
  u8 *dns_mode;
  u8 *acl_flags;
  u8 resolved;
  u8 ok;
} dp_log_client_t;

/* Resolve everything, once. All or nothing: a half-resolved handle would
 * let a caller enqueue events through a switch it cannot read, i.e. logging
 * that cannot be turned off. */
static inline void
dp_log_client_resolve (dp_log_client_t *c)
{
  if (PREDICT_TRUE (c->resolved))
    return;
  c->resolved = 1;

  c->acl_enq = (int (*) (u32, const dp_log_acl_event_t *))
    vlib_get_plugin_symbol ("dp_log_plugin.so", "dp_log_acl_enq_export");
  c->dns_enq = (int (*) (u32, const dp_log_dns_event_t *))
    vlib_get_plugin_symbol ("dp_log_plugin.so", "dp_log_dns_enq_export");
  c->sess_enq = (int (*) (u32, const dp_log_sess_event_t *))
    vlib_get_plugin_symbol ("dp_log_plugin.so", "dp_log_sess_enq_export");
  c->enabled =
    (u8 *) vlib_get_plugin_symbol ("dp_log_plugin.so", "dp_log_enabled");
  c->dns_mode =
    (u8 *) vlib_get_plugin_symbol ("dp_log_plugin.so", "dp_log_dns_mode");
  c->acl_flags =
    (u8 *) vlib_get_plugin_symbol ("dp_log_plugin.so", "dp_log_acl_flags");

  c->ok = (c->acl_enq && c->dns_enq && c->sess_enq && c->enabled &&
	   c->dns_mode && c->acl_flags) != 0;
  if (!c->ok)
    clib_warning ("dp_log: logging unavailable (dp_log_plugin.so not loaded "
		  "or symbols missing)");
}

/* Every accessor below is false/zero on an unresolved or unavailable handle,
 * so a consumer never needs its own null checks. */

static inline int
dp_log_client_acl_on (const dp_log_client_t *c)
{
  return c->ok && __atomic_load_n (c->enabled, __ATOMIC_RELAXED) != 0;
}

static inline int
dp_log_client_acl_scope (const dp_log_client_t *c)
{
  return c->ok ? __atomic_load_n (c->acl_flags, __ATOMIC_RELAXED) : 0;
}

static inline int
dp_log_client_dns_mode (const dp_log_client_t *c)
{
  return c->ok ? __atomic_load_n (c->dns_mode, __ATOMIC_RELAXED)
	       : DP_LOG_DNS_OFF;
}

static inline int
dp_log_client_acl_enq (const dp_log_client_t *c, u32 thread_index,
		       const dp_log_acl_event_t *ev)
{
  return c->ok ? c->acl_enq (thread_index, ev) : 0;
}

static inline int
dp_log_client_dns_enq (const dp_log_client_t *c, u32 thread_index,
		       const dp_log_dns_event_t *ev)
{
  return c->ok ? c->dns_enq (thread_index, ev) : 0;
}

static inline int
dp_log_client_sess_enq (const dp_log_client_t *c, u32 thread_index,
			const dp_log_sess_event_t *ev)
{
  return c->ok ? c->sess_enq (thread_index, ev) : 0;
}

#endif /* dp_log_plugin_EXPORTS */

#ifdef __cplusplus
}
#endif

#endif /* __DP_LOG_H__ */
