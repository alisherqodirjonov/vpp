#define _GNU_SOURCE
#include <vlib/vlib.h>
#include <vppinfra/clib.h>
#include <vppinfra/format.h>

#include <pthread.h>
#include <sched.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <vnet/plugin/plugin.h>

#include "dp_log.h"



#include <vpp/app/version.h>

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "dp_log: dataplane ACL deny logger",
};




/* Exported enable flag (fast dataplane read). */
u8 dp_log_enabled = 0;

// typedef struct
// {
//   u32 size;
//   u32 mask;

//   /* head: producer writes, tail: consumer writes (SPSC pattern per ring) */
//   u32 head __clib_cache_aligned;
//   u32 tail __clib_cache_aligned;

//   dp_log_acl_event_t *elts;

//   /* drops from full ring */
//   u64 drops;
// } dp_log_ring_t;

typedef struct {
  u32 size;
  u32 mask;

  /* Ensures head starts on its own cache line */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  u32 head;

  /* Ensures tail starts on a DIFFERENT cache line */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline2);
  u32 tail;

  dp_log_acl_event_t *elts;
  u64 drops;
} dp_log_ring_t;

typedef struct
{
  /* config */
  u32 ring_size;       /* power-of-2 */
  int writer_core;     /* linux cpu id, -1 means no pin */
  u8 *path;            /* null-terminated C string (vec) */

  /* runtime */
  int fd;
  u32 n_threads;
  dp_log_ring_t *rings;

  pthread_t writer_thread;
  volatile int stop;
} dp_log_main_t;

static dp_log_main_t dp_log_main;

/* ----------------------- Ring ops (no locks) ----------------------- */

static inline uword
dp_log_ring_try_enq (dp_log_ring_t *r, const dp_log_acl_event_t *ev)
{
  /* Single producer for this ring (the VPP thread indexed by thread_index). */
  u32 head = __atomic_load_n (&r->head, __ATOMIC_RELAXED);
  u32 tail = __atomic_load_n (&r->tail, __ATOMIC_ACQUIRE);
  u32 next = (head + 1) & r->mask;

  if (PREDICT_FALSE (next == tail))
    {
      __atomic_add_fetch (&r->drops, 1, __ATOMIC_RELAXED);
      return 0;
    }

  r->elts[head] = *ev;

  /* publish */
  __atomic_store_n (&r->head, next, __ATOMIC_RELEASE);
  return 1;
}

static inline uword
dp_log_ring_try_deq (dp_log_ring_t *r, dp_log_acl_event_t *out)
{
  /* Single consumer per ring (writer thread). */
  u32 tail = __atomic_load_n (&r->tail, __ATOMIC_RELAXED);
  u32 head = __atomic_load_n (&r->head, __ATOMIC_ACQUIRE);

  if (tail == head)
    return 0;

  *out = r->elts[tail];

  __atomic_store_n (&r->tail, (tail + 1) & r->mask, __ATOMIC_RELEASE);
  return 1;
}

/* ----------------------- Worker API ----------------------- */

int
dp_log_acl_enq (u32 thread_index, const dp_log_acl_event_t *ev)
{
  dp_log_main_t *lm = &dp_log_main;

  if (PREDICT_FALSE (!dp_log_is_enabled ()))
    return 0;

  if (PREDICT_FALSE (lm->rings == 0 || thread_index >= lm->n_threads))
    return 0;

  return (int) dp_log_ring_try_enq (&lm->rings[thread_index], ev);
}

/* ----------------------- Writer thread ----------------------- */

static void
dp_log_pin_to_core (int core)
{
  if (core < 0)
    return;

  cpu_set_t cs;
  CPU_ZERO (&cs);
  CPU_SET (core, &cs);
  (void) pthread_setaffinity_np (pthread_self (), sizeof (cs), &cs);
}

static int
dp_log_open_file (dp_log_main_t *lm)
{
  if (lm->fd >= 0)
    return 0;

  const char *p = (const char *) lm->path;
  if (!p || !p[0])
    return -1;

  lm->fd = open (p, O_CREAT | O_WRONLY | O_APPEND, 0644);
  if (lm->fd < 0)
    {
      clib_warning ("dp_log: open(%s) failed: %s", p, strerror (errno));
      return -1;
    }

  /* Optional header (write once if file is empty is more complex; keep simple). */
  const char *hdr =
    "ts_cycles,is_ip6,proto,sport,dport,sw_if_index,fib_index,acl_index,rule_index,action,src,dst\n";
  (void) write (lm->fd, hdr, (int) strlen (hdr));

  return 0;
}

static inline int
dp_log_format_ip (char *dst, size_t dst_sz, const dp_log_acl_event_t *ev, int is_src)
{
  if (!dst || dst_sz == 0)
    return 0;

  if (!ev->is_ip6)
    {
      struct in_addr a;
      if (is_src)
        clib_memcpy_fast (&a, &ev->ip.v4.src, sizeof (a));
      else
        clib_memcpy_fast (&a, &ev->ip.v4.dst, sizeof (a));

      return inet_ntop (AF_INET, &a, dst, (socklen_t) dst_sz) != 0;
    }
  else
    {
      struct in6_addr a6;
      if (is_src)
        clib_memcpy_fast (&a6, &ev->ip.v6.src, sizeof (a6));
      else
        clib_memcpy_fast (&a6, &ev->ip.v6.dst, sizeof (a6));

      return inet_ntop (AF_INET6, &a6, dst, (socklen_t) dst_sz) != 0;
    }
}

static void *
dp_log_writer_thread_fn (void *arg)
{
  dp_log_main_t *lm = arg;

  dp_log_pin_to_core (lm->writer_core);

  /* Big batching buffer: one write() per chunk */
  enum { OUTBUF_SZ = 1 << 20 }; /* 1MB */
  char *out = clib_mem_alloc (OUTBUF_SZ);
  int out_len = 0;

  /* Flush pacing */
  struct timespec last_flush;
  clock_gettime (CLOCK_MONOTONIC, &last_flush);

  while (!lm->stop)
    {
      if (!dp_log_is_enabled ())
        {
          usleep (10 * 1000);
          continue;
        }

      if (lm->fd < 0)
        {
          if (dp_log_open_file (lm) < 0)
            {
              /* If can't open, disable to avoid burning CPU */
              __atomic_store_n (&dp_log_enabled, 0, __ATOMIC_RELAXED);
              usleep (100 * 1000);
              continue;
            }
        }

      int did_work = 0;

      for (u32 ti = 0; ti < lm->n_threads; ti++)
        {
          dp_log_ring_t *r = &lm->rings[ti];
          dp_log_acl_event_t ev;
          int n = 0;

          while (n < 1024 && dp_log_ring_try_deq (r, &ev))
            {
              did_work = 1;
              n++;

              char src[INET6_ADDRSTRLEN];
              char dst[INET6_ADDRSTRLEN];
              if (!dp_log_format_ip (src, sizeof (src), &ev, 1))
                clib_strncpy (src, "?", sizeof (src));
              if (!dp_log_format_ip (dst, sizeof (dst), &ev, 0))
                clib_strncpy (dst, "?", sizeof (dst));

              /* CSV line */
              char line[512];
              int len = snprintf (
                line, sizeof (line),
                "%llu,%u,%u,%u,%u,%u,%u,%u,%u,%u,%s,%s\n",
                (unsigned long long) ev.ts_cycles,
                (unsigned) ev.is_ip6,
                (unsigned) ev.proto,
                (unsigned) ev.sport,
                (unsigned) ev.dport,
                (unsigned) ev.sw_if_index,
                (unsigned) ev.fib_index,
                (unsigned) ev.acl_index,
                (unsigned) ev.rule_index,
                (unsigned) ev.action,
                src, dst);

              if (len <= 0)
                continue;

              /* If buffer would overflow, flush first */
              if (out_len + len > OUTBUF_SZ)
                {
                  (void) write (lm->fd, out, out_len);
                  out_len = 0;
                  clock_gettime (CLOCK_MONOTONIC, &last_flush);
                }

              clib_memcpy_fast (out + out_len, line, len);
              out_len += len;
            }
        }

      /* Time-based flush ~ every 100ms (and also if we did work) */
      struct timespec now;
      clock_gettime (CLOCK_MONOTONIC, &now);

      long dt_ms =
        (now.tv_sec - last_flush.tv_sec) * 1000L +
        (now.tv_nsec - last_flush.tv_nsec) / 1000000L;

      if (out_len > 0 && (dt_ms >= 100 || did_work))
        {
          (void) write (lm->fd, out, out_len);
          out_len = 0;
          last_flush = now;
        }

      if (!did_work)
        usleep (1000); /* 1ms */
    }

  /* Final flush */
  if (lm->fd >= 0 && out_len > 0)
    (void) write (lm->fd, out, out_len);

  clib_mem_free (out);
  return 0;
}

/* ----------------------- Config & init ----------------------- */

static u32
dp_log_pow2_or_default (u32 x, u32 def)
{
  if (x == 0)
    return def;
  /* require power-of-two */
  if ((x & (x - 1)) != 0)
    return def;
  return x;
}

static clib_error_t *
dp_log_config (vlib_main_t *vm, unformat_input_t *input)
{
  dp_log_main_t *lm = &dp_log_main;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "enable"))
        __atomic_store_n (&dp_log_enabled, 1, __ATOMIC_RELAXED);
      else if (unformat (input, "disable"))
        __atomic_store_n (&dp_log_enabled, 0, __ATOMIC_RELAXED);
      else if (unformat (input, "writer-core %d", &lm->writer_core))
        ;
      else if (unformat (input, "ring-size %u", &lm->ring_size))
        ;
      else if (unformat (input, "path %s", &lm->path))
        ;
      else
        return clib_error_return (0, "unknown dp-log config");
    }

  return 0;
}
VLIB_CONFIG_FUNCTION (dp_log_config, "dp-log");

static clib_error_t *
dp_log_init (vlib_main_t *vm)
{
  dp_log_main_t *lm = &dp_log_main;

  lm->fd = -1;
  if (!lm->path)
    lm->path = format (0, "/tmp/vpp-dp-log.csv%c", 0);

  lm->ring_size = dp_log_pow2_or_default (lm->ring_size, 1 << 16);
  lm->writer_core = (lm->writer_core == 0 && lm->writer_core == 0) ? -1 : lm->writer_core;
  /* (above line effectively keeps default -1 if not set; harmless) */

  lm->n_threads = vlib_get_n_threads ();
  lm->rings =
    clib_mem_alloc_aligned (sizeof (*lm->rings) * lm->n_threads,
                            CLIB_CACHE_LINE_BYTES);
  clib_memset (lm->rings, 0, sizeof (*lm->rings) * lm->n_threads);

  for (u32 i = 0; i < lm->n_threads; i++)
    {
      dp_log_ring_t *r = &lm->rings[i];
      r->size = lm->ring_size;
      r->mask = r->size - 1;

      r->elts =
        clib_mem_alloc_aligned (r->size * sizeof (dp_log_acl_event_t),
                                CLIB_CACHE_LINE_BYTES);
      clib_memset (r->elts, 0, r->size * sizeof (dp_log_acl_event_t));

      __atomic_store_n (&r->head, 0, __ATOMIC_RELAXED);
      __atomic_store_n (&r->tail, 0, __ATOMIC_RELAXED);
      __atomic_store_n (&r->drops, 0, __ATOMIC_RELAXED);
    }

  lm->stop = 0;
  if (pthread_create (&lm->writer_thread, 0, dp_log_writer_thread_fn, lm) != 0)
    {
      return clib_error_return (0, "dp_log: pthread_create failed");
    }

  return 0;
}
VLIB_INIT_FUNCTION (dp_log_init);
