#ifndef __DP_LOG_H__
#define __DP_LOG_H__

#include <vppinfra/clib.h>
#include <vppinfra/types.h>
#include <vnet/ip/ip.h>

#ifdef __cplusplus
extern "C" {
#endif

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
  u8 _pad[3];

  union {
    struct { ip4_address_t src, dst; } v4;
    struct { ip6_address_t src, dst; } v6;
  } ip;
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

/* Exported symbol from dp_log plugin (visible for vlib_plugin_get_symbol). */
#ifdef dp_log_plugin_EXPORTS
#define DP_LOG_API __attribute__((visibility("default")))
#else
#define DP_LOG_API
#endif

DP_LOG_API int dp_log_acl_enq_export (u32 thread_index, const dp_log_acl_event_t *ev);
DP_LOG_API int dp_log_dns_enq_export (u32 thread_index, const dp_log_dns_event_t *ev);

/* Exported enable flag: fast dataplane read (use atomic ops).
 *
 * NB the DP_LOG_API marker is load-bearing: the plugin is built with
 * -fvisibility=hidden, so without it these are local symbols and
 * vlib_get_plugin_symbol () cannot find them from another plugin. */
DP_LOG_API extern u8 dp_log_enabled;

/* Exported DNS log mode: one of DP_LOG_DNS_*. Separate from dp_log_enabled
   so DNS query logging and ACL drop logging are independently switchable --
   an operator auditing DNS should not have to turn on the far higher-volume
   ACL drop log to do it. */
DP_LOG_API extern u8 dp_log_dns_mode;

/* Check if dp_log is enabled. */
static inline int
dp_log_is_enabled (void)
{
  return __atomic_load_n (&dp_log_enabled, __ATOMIC_RELAXED);
}

/* Current DNS log mode. Read this in the dataplane BEFORE building an
   event: in the common (off) case it is one relaxed byte load. */
static inline int
dp_log_dns_mode_get (void)
{
  return __atomic_load_n (&dp_log_dns_mode, __ATOMIC_RELAXED);
}

#ifdef __cplusplus
}
#endif

#endif /* __DP_LOG_H__ */
