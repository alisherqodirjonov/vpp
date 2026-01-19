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

/* Exported symbol from dp_log plugin (visible for vlib_plugin_get_symbol). */
#ifdef dp_log_plugin_EXPORTS
#define DP_LOG_API __attribute__((visibility("default")))
#else
#define DP_LOG_API
#endif

DP_LOG_API int dp_log_acl_enq_export (u32 thread_index, const dp_log_acl_event_t *ev);

/* Exported enable flag: fast dataplane read (use atomic ops). */
extern u8 dp_log_enabled;

/* Check if dp_log is enabled. */
static inline int
dp_log_is_enabled (void)
{
  return __atomic_load_n (&dp_log_enabled, __ATOMIC_RELAXED);
}

#ifdef __cplusplus
}
#endif

#endif /* __DP_LOG_H__ */
