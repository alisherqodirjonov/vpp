#ifndef __DP_LOG_H__
#define __DP_LOG_H__

#include <vppinfra/clib.h>
#include <vnet/ip/ip.h>      /* ip4_address_t, ip6_address_t */
#include <vppinfra/types.h>  /* u8,u16,u32,u64 */

#ifdef __cplusplus
extern "C" {
#endif



/* Fast global enable flag (read on dataplane).
 * Written by config/CLI, read by workers.
 * Declared weak so ACL plugin can link even if dp_log isn't loaded.
 */
/* weak: ACL can link even if dp_log plugin isn't loaded */
extern u8 dp_log_enabled __attribute__((weak));

/* Fixed-size POD event (NO pointers, NO dynamic length). */
typedef struct
{
  /* Cheap timestamp for fast path: cycles (TSC) from clib_cpu_time_now(). */
  u64 ts_cycles;

  /* 0 = IPv4, 1 = IPv6 */
  u8 is_ip6;

  /* L4 */
  u8 proto;       /* ip protocol */
  u16 sport;      /* host order */
  u16 dport;      /* host order */

  /* Routing / interface context */
  u32 sw_if_index;
  u32 fib_index;

  /* ACL context */
  u32 acl_index;
  u32 rule_index;

  /* Action: 0=unknown, 1=deny (extend later if you want) */
  u8 action;

  /* Padding for alignment/future fields */
  u8 _pad[3];

  /* Addresses */
  union {
    struct {
      ip4_address_t src;
      ip4_address_t dst;
    } v4;
    struct {
      ip6_address_t src;
      ip6_address_t dst;
    } v6;
  } ip;
} dp_log_acl_event_t;

/* Worker API: enqueue one event to ring[thread_index].
 * Returns 1 on success, 0 on drop/full/disabled/out-of-range.
 */
int dp_log_acl_enq (u32 thread_index, const dp_log_acl_event_t *ev) __attribute__((weak));

/* Very fast enabled check for callers that want to short-circuit earlier. */
static inline u8
dp_log_is_enabled (void)
{
  /* if dp_log isn't loaded, weak var resolves to 0 */
  return __atomic_load_n (&dp_log_enabled, __ATOMIC_RELAXED);
}

static inline void
dp_log_acl_enq_safe (u32 thread_index, const dp_log_acl_event_t *ev)
{
  /* if dp_log isn't loaded, weak fn pointer is NULL */
  if (PREDICT_TRUE (dp_log_acl_enq && dp_log_is_enabled ()))
    (void) dp_log_acl_enq (thread_index, ev);
}

#ifdef __cplusplus
}
#endif

#endif /* __DP_LOG_H__ */
