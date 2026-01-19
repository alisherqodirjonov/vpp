#define _GNU_SOURCE
#include <vlib/vlib.h>
#include <vppinfra/clib.h>
#include <vppinfra/format.h>

#include <pthread.h>
#include <sched.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <vnet/plugin/plugin.h>

#include "dp_log.h"

/* Forward declaration for internal use */
static int dp_log_acl_enq (u32 thread_index, const dp_log_acl_event_t *ev);

#include <vpp/app/version.h>

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "dp_log: dataplane ACL deny logger",
};

DP_LOG_API int
dp_log_acl_enq_export (u32 thread_index, const dp_log_acl_event_t *ev)
{
  return dp_log_acl_enq (thread_index, ev);
}

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

typedef struct
{
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

  u64 wall_base_ns; /* CLOCK_REALTIME at base (ns) */
  u64 ts_base_ns;   /* clib_time_now() at same base (ns since VPP start) */

  /* config */
  u32 ring_size;   /* power-of-2 */
  int writer_core; /* linux cpu id, -1 means no pin */
  u8 *path;	   /* null-terminated C string (vec) */

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

  if (PREDICT_FALSE (lm->rings == 0))
    return 0;

  /* Handle thread_index >= n_threads by allocating more rings on demand */
  if (PREDICT_FALSE (thread_index >= lm->n_threads))
    {
      //   clib_warning ("dp_log: thread_index %u >= n_threads %u, dropping
      //   event",
      //                 thread_index, lm->n_threads);
      return 0;
    }

  return (int) dp_log_ring_try_enq (&lm->rings[thread_index], ev);
}

static inline void
dp_log_format_wall_time_ms (char *dst, size_t dst_sz, const dp_log_main_t *lm,
			    u64 ev_ts_ns)
{
  /* Convert event ts (ns since VPP start) into wall-clock ns */
  u64 wall_ns = lm->wall_base_ns;
  if (ev_ts_ns >= lm->ts_base_ns)
    wall_ns += (ev_ts_ns - lm->ts_base_ns);

  time_t sec = (time_t) (wall_ns / 1000000000ULL);
  u32 msec = (u32) ((wall_ns % 1000000000ULL) / 1000000ULL);

  struct tm tm;
  localtime_r (&sec, &tm);

  /* "YYYY-MM-DD HH:MM:SS.mmm" */
  (void) snprintf (dst, dst_sz, "%04d-%02d-%02d %02d:%02d:%02d.%03u",
		   tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
		   tm.tm_min, tm.tm_sec, msec);
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

  /* Check if file exists and is non-empty to decide if we should write header
   */
  //   int file_exists = 0;
  off_t file_size = 0;
  struct stat st;
  if (stat (p, &st) == 0)
    {
      //   file_exists = 1;
      file_size = st.st_size;
    }

  lm->fd = open (p, O_CREAT | O_WRONLY | O_APPEND, 0644);
  if (lm->fd < 0)
    {
      clib_warning ("dp_log: open(%s) failed: %s", p, strerror (errno));
      return -1;
    }

  //   clib_warning ("dp_log: opened file %s (exists=%d, size=%ld)", p,
  //   file_exists, file_size);

  /* Write header only if file is empty (new file) */
  if (file_size == 0)
    {
      const char *hdr = "ts,is_ip6,proto,sport,dport,sw_if_index,fib_index,"
			"acl_index,rule_index,action,src,dst,count\n";
      /*ssize_t hdr_written = */
      (void) write (lm->fd, hdr, (int) strlen (hdr));
      //   clib_warning ("dp_log: wrote header, %ld bytes", hdr_written);
    }

  return 0;
}

static inline int
dp_log_format_ip (char *dst, size_t dst_sz, const dp_log_acl_event_t *ev,
		  int is_src)
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

/* Event aggregation key - for counting same 5-tuple + ACL rule hits */
typedef struct
{
  u64 src_dst_tuple; /* Combined source/dest for quick comparison */
  u32 sport_dport;   /* Combined ports */
  u8 proto;
  u8 is_ip6;
  u16 _pad;

  u32 acl_index;
  u32 rule_index;
} dp_log_agg_key_t;

/* Aggregated event with count */
typedef struct
{
  dp_log_agg_key_t key;
  u64 count;
  dp_log_acl_event_t last_event; /* Keep last event for full logging */
} dp_log_agg_event_t;

static void *
dp_log_writer_thread_fn (void *arg)
{
  dp_log_main_t *lm = arg;

  dp_log_pin_to_core (lm->writer_core);

  /* Big batching buffer: one write() per chunk */
  enum
  {
    OUTBUF_SZ = 1 << 20
  }; /* 1MB */
  char *out = clib_mem_alloc (OUTBUF_SZ);
  int out_len = 0;

  /* Aggregation: hash table for counting events per second */
  uword *agg_hash =
    0; /* hash table: key = fingerprint, value = ptr to dp_log_agg_event_t */
  dp_log_agg_event_t *agg_events = 0;
  u32 agg_count = 0;

  /* Flush pacing */
  struct timespec last_flush;
  clock_gettime (CLOCK_MONOTONIC, &last_flush);
  enum
  {
    FLUSH_INTERVAL_MS = 1000
  }; /* 1 second aggregation window */

  int loop_count = 0;

  while (!lm->stop)
    {
      loop_count++;
      if (!dp_log_is_enabled ())
	{
	  if (loop_count == 1)
	    //   clib_warning ("dp_log: writer thread waiting for enable");

	    usleep (10 * 1000);
	  continue;
	}

      //   if (loop_count % 100000 == 0)  /* Log every 100k loops ~= 1 second
      //   */
      //     clib_warning ("dp_log: writer thread ENABLED (loops=%d)",
      //     loop_count);

      if (lm->fd < 0)
	{
	  //   clib_warning ("dp_log: writer thread opening file, path=%s",
	  //   (const char *)lm->path);
	  if (dp_log_open_file (lm) < 0)
	    {
	      /* If can't open, disable to avoid burning CPU */
	      //   clib_warning ("dp_log: failed to open file (path=%s),
	      //   disabling", (const char *)lm->path);
	      __atomic_store_n (&dp_log_enabled, 0, __ATOMIC_RELAXED);
	      usleep (100 * 1000);
	      continue;
	    }
	  //   clib_warning ("dp_log: file opened successfully, fd=%d",
	  //   lm->fd);
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

	      /* Create aggregation key */
	      dp_log_agg_key_t key;
	      clib_memset (&key, 0, sizeof (key));
	      key.proto = ev.proto;
	      key.is_ip6 = ev.is_ip6;
	      key.acl_index = ev.acl_index;
	      key.rule_index = ev.rule_index;

	      if (!ev.is_ip6)
		{
		  clib_memcpy_fast (&key.src_dst_tuple, &ev.ip.v4.src, 8);
		}
	      else
		{
		  /* For IPv6, use first 64 bits of src + dst */
		  key.src_dst_tuple = *(u64 *) &ev.ip.v6.src;
		}
	      key.sport_dport = ((u32) ev.sport << 16) | ev.dport;

	      /* Calculate hash of key - simple djb2 hash */
	      u64 hash_val = 5381;
	      u8 *ptr = (u8 *) &key;
	      for (u32 j = 0; j < sizeof (key); j++)
		hash_val = ((hash_val << 5) + hash_val) + ptr[j];

	      /* Look up in aggregation hash */
	      uword *p = hash_get (agg_hash, hash_val);
	      dp_log_agg_event_t *agg_event = 0;

	      if (p)
		{
		  agg_event = (dp_log_agg_event_t *) (*p);
		}
	      else
		{
		  /* New event - add to aggregation */
		  vec_add2 (agg_events, agg_event, 1);
		  agg_event->key = key;
		  agg_event->count = 0;
		  hash_set (agg_hash, hash_val, (uword) agg_event);
		  agg_count++;
		}

	      agg_event->count++;
	      agg_event->last_event = ev;
	    }
	}

      /* Check if we should flush aggregated results (every 1 second) */
      struct timespec now;
      clock_gettime (CLOCK_MONOTONIC, &now);

      long dt_ms = (now.tv_sec - last_flush.tv_sec) * 1000L +
		   (now.tv_nsec - last_flush.tv_nsec) / 1000000L;

      if (dt_ms >= FLUSH_INTERVAL_MS && agg_count > 0)
	{
	  /* Write all aggregated events */
	  for (u32 i = 0; i < vec_len (agg_events); i++)
	    {
	      dp_log_agg_event_t *agg = &agg_events[i];
	      dp_log_acl_event_t *ev = &agg->last_event;

	      char src[INET6_ADDRSTRLEN];
	      char dst[INET6_ADDRSTRLEN];
	      if (!dp_log_format_ip (src, sizeof (src), ev, 1))
		clib_strncpy (src, "?", sizeof (src));
	      if (!dp_log_format_ip (dst, sizeof (dst), ev, 0))
		clib_strncpy (dst, "?", sizeof (dst));

	      /* CSV line with count */
	      char ts[32];
	      dp_log_format_wall_time_ms (ts, sizeof (ts), lm, ev->ts_ns);

	      char line[512];
	      int len =
		snprintf (line, sizeof (line),
			  "%s,%u,%u,%u,%u,%u,%u,%u,%u,%u,%s,%s,%llu\n", ts,
			  (unsigned) ev->is_ip6, (unsigned) ev->proto,
			  (unsigned) ev->sport, (unsigned) ev->dport,
			  (unsigned) ev->sw_if_index, (unsigned) ev->fib_index,
			  (unsigned) ev->acl_index, (unsigned) ev->rule_index,
			  (unsigned) ev->action, src, dst,
			  (unsigned long long) agg->count);

	      if (len <= 0)
		continue;

	      /* If buffer would overflow, flush first */
	      if (out_len + len > OUTBUF_SZ)
		{
		  (void) write (lm->fd, out, out_len);
		  out_len = 0;
		}

	      clib_memcpy_fast (out + out_len, line, len);
	      out_len += len;
	    }

	  /* Flush buffer */
	  if (out_len > 0)
	    {
	      (void) write (lm->fd, out, out_len);
	      out_len = 0;
	    }

	  /* Clear aggregation for next window */
	  hash_free (agg_hash);
	  agg_hash = 0;
	  vec_free (agg_events);
	  agg_count = 0;

	  last_flush = now;
	  //   clib_warning ("dp_log: flushed %ld aggregated results at %ld ms
	  //   interval", vec_len(agg_events), dt_ms);
	}

      if (!did_work)
	usleep (10 * 1000); // sleep 10ms if no work done
    }

  /* Final flush */
  if (lm->fd >= 0 && out_len > 0)
    (void) write (lm->fd, out, out_len);

  /* Clean up */
  hash_free (agg_hash);
  vec_free (agg_events);
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

  //   clib_warning ("dp_log_config: called, parsing config");

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "enable"))
	{
	  //   clib_warning ("dp_log_config: found 'enable' keyword, setting
	  //   enabled=1");
	  __atomic_store_n (&dp_log_enabled, 1, __ATOMIC_RELAXED);
	}
      else if (unformat (input, "disable"))
	{
	  //   clib_warning ("dp_log_config: found 'disable' keyword");
	  __atomic_store_n (&dp_log_enabled, 0, __ATOMIC_RELAXED);
	}
      else if (unformat (input, "writer-core %d", &lm->writer_core))
	{
	  //   clib_warning ("dp_log_config: writer-core=%d", lm->writer_core);
	}
      else if (unformat (input, "ring-size %u", &lm->ring_size))
	{
	  //   clib_warning ("dp_log_config: ring-size=%u", lm->ring_size);
	}
      else if (unformat (input, "path %s", &lm->path))
	{
	  //   clib_warning ("dp_log_config: path=%s", (char *)lm->path);
	}
      else
	{
	  //   clib_warning ("dp_log_config: unknown option");
	  return clib_error_return (0, "unknown dp-log config");
	}
    }

  //   clib_warning ("dp_log_config: done, enabled=%d", __atomic_load_n
  //   (&dp_log_enabled, __ATOMIC_RELAXED));
  return 0;
}
VLIB_CONFIG_FUNCTION (dp_log_config, "dp-log");

static clib_error_t *
dp_log_init (vlib_main_t *vm)
{
  dp_log_main_t *lm = &dp_log_main;

  lm->fd = -1;
  if (!lm->path)
    lm->path = format (0, "/etc/sarhad-guard/acl_logs/acl_logs.log");

  lm->ring_size = dp_log_pow2_or_default (lm->ring_size, 1 << 16);
  lm->writer_core =
    (lm->writer_core == 0 && lm->writer_core == 0) ? -1 : lm->writer_core;
  /* (above line effectively keeps default -1 if not set; harmless) */

  /* Allocate rings for all possible threads - use max of current threads +
   * overhead */
  u32 n_threads_allocated = vlib_get_n_threads ();
  if (n_threads_allocated < 16)
    n_threads_allocated =
      16; /* Allocate for at least 16 threads to handle worker threads */

  lm->n_threads = n_threads_allocated;

  //   clib_warning ("dp_log_init: BEFORE config: path=%s, ring_size=%u,
  //   n_threads=%u (allocated for %u), enabled=%d, writer_core=%d",
  //                 (const char *)lm->path, lm->ring_size,
  //                 vlib_get_n_threads(), lm->n_threads, dp_log_enabled,
  //                 lm->writer_core);

  /* Ensure we check the config at this point */
  //   int enabled_after_config = __atomic_load_n (&dp_log_enabled,
  //   __ATOMIC_RELAXED);
  __atomic_load_n (&dp_log_enabled, __ATOMIC_RELAXED);
  //   clib_warning ("dp_log_init: AFTER config: enabled=%d, path=%s",
  //                 enabled_after_config, (const char *)lm->path);

  lm->rings = clib_mem_alloc_aligned (sizeof (*lm->rings) * lm->n_threads,
				      CLIB_CACHE_LINE_BYTES);
  clib_memset (lm->rings, 0, sizeof (*lm->rings) * lm->n_threads);

  for (u32 i = 0; i < lm->n_threads; i++)
    {
      dp_log_ring_t *r = &lm->rings[i];
      r->size = lm->ring_size;
      r->mask = r->size - 1;

      r->elts = clib_mem_alloc_aligned (r->size * sizeof (dp_log_acl_event_t),
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

  //   clib_warning ("dp_log_init: writer thread started");

  /* Anchor VPP monotonic time to wall clock once */
  {
    struct timespec rt;
    clock_gettime (CLOCK_REALTIME, &rt);
    dp_log_main.wall_base_ns =
      (u64) rt.tv_sec * 1000000000ULL + (u64) rt.tv_nsec;

    dp_log_main.ts_base_ns = (u64) (clib_time_now (&vm->clib_time) * 1e9);
  }

  return 0;
}
VLIB_INIT_FUNCTION (dp_log_init);
