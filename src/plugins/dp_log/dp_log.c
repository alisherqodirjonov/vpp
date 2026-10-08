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
static int dp_log_dns_enq (u32 thread_index, const dp_log_dns_event_t *ev);
static int dp_log_sess_enq (u32 thread_index, const dp_log_sess_event_t *ev);

#include <vpp/app/version.h>

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "dp_log: dataplane ACL match, session close and DNS query logger",
};

DP_LOG_API int
dp_log_acl_enq_export (u32 thread_index, const dp_log_acl_event_t *ev)
{
  return dp_log_acl_enq (thread_index, ev);
}

DP_LOG_API int
dp_log_dns_enq_export (u32 thread_index, const dp_log_dns_event_t *ev)
{
  return dp_log_dns_enq (thread_index, ev);
}

DP_LOG_API int
dp_log_sess_enq_export (u32 thread_index, const dp_log_sess_event_t *ev)
{
  return dp_log_sess_enq (thread_index, ev);
}

/* Exported enable flag (fast dataplane read). */
DP_LOG_API u8 dp_log_enabled = 0;

/* Exported DNS log mode, one of DP_LOG_DNS_*. */
DP_LOG_API u8 dp_log_dns_mode = DP_LOG_DNS_OFF;
DP_LOG_API u8 dp_log_acl_flags = 0;

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

/* Same SPSC discipline as dp_log_ring_t, carrying DNS events. Kept as a
   separate type rather than made generic: the ring ops are inlined into the
   dataplane enqueue path, and a generic version taking an untyped element
   pointer plus a size would cost a multiply and lose the fixed-size copy the
   compiler emits here. */
typedef struct
{
  u32 size;
  u32 mask;

  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  u32 head;

  CLIB_CACHE_LINE_ALIGN_MARK (cacheline2);
  u32 tail;

  dp_log_dns_event_t *elts;
  u64 drops;
} dp_log_dns_ring_t;

typedef struct
{
  u32 size;
  u32 mask;

  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  u32 head;

  CLIB_CACHE_LINE_ALIGN_MARK (cacheline2);
  u32 tail;

  dp_log_sess_event_t *elts;
  u64 drops;
} dp_log_sess_ring_t;

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

  /* DNS query log: its own rings, file and ring size. The ring is far
     smaller than the ACL one because each event carries a 256-byte name and
     query rate is orders of magnitude below packet rate -- sizing it like
     the ACL ring would cost hundreds of MB for no benefit. */
  int dns_fd;
  u8 *dns_path;
  u32 dns_ring_size;
  dp_log_dns_ring_t *dns_rings;

  /* Session close log: one record per stateful flow, not per packet, so the
     rate is bounded by connections per second rather than by pps. It shares
     the ACL file -- one log, one row per event -- so it needs a ring and a
     size but no descriptor or path of its own. */
  u32 sess_ring_size;
  dp_log_sess_ring_t *sess_rings;

  pthread_t writer_thread;
  volatile int stop;
} dp_log_main_t;

static dp_log_main_t dp_log_main;

/* Diagnostics from the writer thread go to stderr, never clib_warning.
 *
 * clib_warning () formats through VPP's vector machinery, which allocates
 * on the per-thread heap -- and this thread has no heap of its own, so it
 * would use the main thread's unlocked. That is the same fault that took
 * the data plane down under an hping3 flood; an error path is a worse place
 * to hide it than the hot path, because it only fires when something is
 * already wrong. stderr is libc, thread-safe, and lands in the journal. */
#define dp_log_warn(...)                                                      \
  do                                                                          \
    {                                                                         \
      fprintf (stderr, "dp_log: ");                                           \
      fprintf (stderr, __VA_ARGS__);                                          \
      fprintf (stderr, "\n");                                                 \
    }                                                                         \
  while (0)


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

static inline uword
dp_log_dns_ring_try_enq (dp_log_dns_ring_t *r, const dp_log_dns_event_t *ev)
{
  u32 head = __atomic_load_n (&r->head, __ATOMIC_RELAXED);
  u32 tail = __atomic_load_n (&r->tail, __ATOMIC_ACQUIRE);
  u32 next = (head + 1) & r->mask;

  if (PREDICT_FALSE (next == tail))
    {
      __atomic_add_fetch (&r->drops, 1, __ATOMIC_RELAXED);
      return 0;
    }

  r->elts[head] = *ev;

  __atomic_store_n (&r->head, next, __ATOMIC_RELEASE);
  return 1;
}

static inline uword
dp_log_dns_ring_try_deq (dp_log_dns_ring_t *r, dp_log_dns_event_t *out)
{
  u32 tail = __atomic_load_n (&r->tail, __ATOMIC_RELAXED);
  u32 head = __atomic_load_n (&r->head, __ATOMIC_ACQUIRE);

  if (tail == head)
    return 0;

  *out = r->elts[tail];

  __atomic_store_n (&r->tail, (tail + 1) & r->mask, __ATOMIC_RELEASE);
  return 1;
}

static inline uword
dp_log_sess_ring_try_enq (dp_log_sess_ring_t *r, const dp_log_sess_event_t *ev)
{
  u32 head = __atomic_load_n (&r->head, __ATOMIC_RELAXED);
  u32 tail = __atomic_load_n (&r->tail, __ATOMIC_ACQUIRE);
  u32 next = (head + 1) & r->mask;

  if (PREDICT_FALSE (next == tail))
    {
      __atomic_add_fetch (&r->drops, 1, __ATOMIC_RELAXED);
      return 0;
    }

  r->elts[head] = *ev;

  __atomic_store_n (&r->head, next, __ATOMIC_RELEASE);
  return 1;
}

static inline uword
dp_log_sess_ring_try_deq (dp_log_sess_ring_t *r, dp_log_sess_event_t *out)
{
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

static int
dp_log_dns_enq (u32 thread_index, const dp_log_dns_event_t *ev)
{
  dp_log_main_t *lm = &dp_log_main;

  if (PREDICT_FALSE (dp_log_dns_mode_get () == DP_LOG_DNS_OFF))
    return 0;

  if (PREDICT_FALSE (lm->dns_rings == 0))
    return 0;

  if (PREDICT_FALSE (thread_index >= lm->n_threads))
    return 0;

  return (int) dp_log_dns_ring_try_enq (&lm->dns_rings[thread_index], ev);
}

static int
dp_log_sess_enq (u32 thread_index, const dp_log_sess_event_t *ev)
{
  dp_log_main_t *lm = &dp_log_main;

  /* Follows the ACL master switch: the session log is the volume half of the
     same picture, and a per-rule flag already decided that this flow is one
     the operator asked about. */
  if (PREDICT_FALSE (!dp_log_is_enabled ()))
    return 0;

  if (PREDICT_FALSE (lm->sess_rings == 0))
    return 0;

  if (PREDICT_FALSE (thread_index >= lm->n_threads))
    return 0;

  return (int) dp_log_sess_ring_try_enq (&lm->sess_rings[thread_index], ev);
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

/* Close the descriptor if the file it points at is no longer the one at
 * path, so the next loop reopens it.
 *
 * The writer holds every log open with O_APPEND. An operator who deletes or
 * moves one -- "rm acl_sessions.log" to start clean -- only unlinks the
 * directory entry: the descriptor stays valid and the writer keeps appending
 * to an inode nothing can open any more. The log then looks permanently
 * empty, with no error anywhere, until VPP is restarted. That is a silent
 * data-loss mode and it is not obvious from the outside, so the writer
 * checks rather than assumes.
 *
 * Two stats per file per second; it is called on the flush tick, never per
 * record.
 */
static void
dp_log_reopen_if_replaced (int *fd, const u8 *path)
{
  struct stat on_disk, open_now;

  if (*fd < 0 || !path || !path[0])
    return;

  if (fstat (*fd, &open_now) != 0)
    {
      close (*fd);
      *fd = -1;
      return;
    }

  if (stat ((const char *) path, &on_disk) != 0 ||
      on_disk.st_ino != open_now.st_ino || on_disk.st_dev != open_now.st_dev)
    {
      /* Deleted, moved, or replaced by a new file at the same path. */
      close (*fd);
      *fd = -1;
    }
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
      dp_log_warn ("open(%s) failed: %s", p, strerror (errno));
      return -1;
    }

  //   clib_warning ("dp_log: opened file %s (exists=%d, size=%ld)", p,
  //   file_exists, file_size);

  /* Write header only if file is empty (new file) */
  if (file_size == 0)
    {
      /* One file, one row per event, with kind saying which kind of event.
	 Splitting match records and session records into two files was an
	 implementation detail leaking into the operator's view: nobody asks
	 "was this a rule evaluation or a flow summary", they ask what
	 happened. The union is sparse -- a match row has no volume, a
	 session row has no count -- and empty fields cost a byte each. */
      const char *hdr =
	"ts,kind,is_ip6,proto,sport,dport,sw_if_index,fib_index,acl_index,"
	"rule_index,action,dir,src,dst,count,duration_ms,bytes_in,bytes_out,"
	"pkts_in,pkts_out\n";
      /*ssize_t hdr_written = */
      (void) write (lm->fd, hdr, (int) strlen (hdr));
      //   clib_warning ("dp_log: wrote header, %ld bytes", hdr_written);
    }

  return 0;
}

static int
dp_log_open_dns_file (dp_log_main_t *lm)
{
  if (lm->dns_fd >= 0)
    return 0;

  const char *p = (const char *) lm->dns_path;
  if (!p || !p[0])
    return -1;

  off_t file_size = 0;
  struct stat st;
  if (stat (p, &st) == 0)
    file_size = st.st_size;

  lm->dns_fd = open (p, O_CREAT | O_WRONLY | O_APPEND, 0644);
  if (lm->dns_fd < 0)
    {
      dp_log_warn ("open(%s) failed: %s", p, strerror (errno));
      return -1;
    }

  if (file_size == 0)
    {
      const char *hdr = "ts,client,name,blocked,answer\n";
      (void) write (lm->dns_fd, hdr, (int) strlen (hdr));
    }

  return 0;
}

/* Copy a DNS name into a CSV field, dropping anything that would break the
   row or inject markup downstream. Names come off the wire, so treating
   them as trusted text would let a crafted query forge log columns. */
static int
dp_log_copy_dns_name (char *dst, size_t dst_sz, const dp_log_dns_event_t *ev)
{
  size_t n = ev->name_len;
  size_t o = 0;

  if (dst_sz == 0)
    return 0;
  if (n > sizeof (ev->name))
    n = sizeof (ev->name);

  for (size_t i = 0; i < n && o + 1 < dst_sz; i++)
    {
      u8 c = ev->name[i];
      /* printable ASCII only, minus the CSV metacharacters */
      if (c < 0x20 || c > 0x7e || c == ',' || c == '"')
	c = '_';
      dst[o++] = (char) c;
    }
  dst[o] = 0;
  return (int) o;
}

/* Same formatting for a session record. Kept separate rather than made
   generic over a union member: the two event types are independent wire
   formats and quietly coupling them would make a change to one silently
   reinterpret the other. */
static inline int
dp_log_format_sess_ip (char *dst, size_t dst_sz, const dp_log_sess_event_t *ev,
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
  u8 is_input;
  u8 _pad;

  u32 acl_index;
  u32 rule_index;
  /* Same 5-tuple arriving on two interfaces is two distinct events, not one
     with a doubled count -- and with permit logging on, that case is normal
     rather than exotic. */
  u32 sw_if_index;
} dp_log_agg_key_t;

/* Aggregated event with count */
typedef struct
{
  dp_log_agg_key_t key;
  u64 count; /* 0 means the slot is free */
  dp_log_acl_event_t last_event; /* Keep last event for full logging */
} dp_log_agg_event_t;

/* Append one ACL match row to the batching buffer, flushing it to disk if
 * the row would not fit. Shared by the per-second aggregate flush and the
 * overflow path, so a row written while the table is full looks identical
 * to one that went through aggregation -- it simply carries count=1. */
static void
dp_log_write_acl_row (dp_log_main_t *lm, char *out, int *out_len, int cap,
		      const dp_log_acl_event_t *ev, u64 count)
{
  char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN], ts[32], line[512];
  int len;

  if (!dp_log_format_ip (src, sizeof (src), ev, 1))
    clib_strncpy (src, "?", sizeof (src));
  if (!dp_log_format_ip (dst, sizeof (dst), ev, 0))
    clib_strncpy (dst, "?", sizeof (dst));
  dp_log_format_wall_time_ms (ts, sizeof (ts), lm, ev->ts_ns);

  len = snprintf (line, sizeof (line),
		  "%s,match,%u,%u,%u,%u,%u,%u,%u,%u,%u,%s,%s,%s,%llu,,,,,\n",
		  ts, (unsigned) ev->is_ip6, (unsigned) ev->proto,
		  (unsigned) ev->sport, (unsigned) ev->dport,
		  (unsigned) ev->sw_if_index, (unsigned) ev->fib_index,
		  (unsigned) ev->acl_index, (unsigned) ev->rule_index,
		  (unsigned) ev->action, ev->is_input ? "in" : "out", src, dst,
		  (unsigned long long) count);
  if (len <= 0)
    return;

  if (*out_len + len > cap)
    {
      (void) write (lm->fd, out, *out_len);
      *out_len = 0;
    }
  clib_memcpy_fast (out + *out_len, line, len);
  *out_len += len;
}

static void *
dp_log_writer_thread_fn (void *arg)
{
  dp_log_main_t *lm = arg;

  dp_log_pin_to_core (lm->writer_core);

  /* Big batching buffer: one write() per chunk.
   *
   * malloc, not clib_mem_alloc. This is a plain pthread, not a VPP worker,
   * so os_get_thread_index () answers 0 for it and every clib_mem call here
   * would operate on the MAIN thread's heap with no lock. That raced
   * harmlessly for months because a quiet box produces few distinct flows
   * per second and the aggregation table almost never grew -- and then an
   * hping3 flood produced thousands, hash_set called clib_mem_realloc
   * concurrently with the main thread, and VPP died in the allocator.
   * Nothing in this thread may touch the VPP heap. */
  enum
  {
    OUTBUF_SZ = 1 << 20
  }; /* 1MB */
  char *out = malloc (OUTBUF_SZ);
  int out_len = 0;

  /* Aggregation table: open-addressed, power-of-two, allocated once.
   *
   * Fixed capacity on purpose. A log aggregator must not grow without bound
   * while being flooded -- that is precisely when it must stay cheap and
   * predictable. When the table fills, events are written through
   * unaggregated rather than dropped, so a flood costs disk rather than
   * visibility. */
  enum
  {
    AGG_CAP = 1 << 13
  }; /* 8192 distinct flows per second before falling through */
  dp_log_agg_event_t *agg_slots = calloc (AGG_CAP, sizeof (*agg_slots));
  u32 agg_count = 0;
  u64 overflow_events = 0;

  if (!out || !agg_slots)
    {
      dp_log_warn ("writer thread could not allocate; logging off");
      free (out);
      free (agg_slots);
      return 0;
    }

  /* Flush pacing */
  struct timespec last_flush;
  clock_gettime (CLOCK_MONOTONIC, &last_flush);
  struct timespec last_stat = last_flush;
  enum
  {
    FLUSH_INTERVAL_MS = 1000
  }; /* 1 second aggregation window */

  int loop_count = 0;

  while (!lm->stop)
    {
      loop_count++;

      /* The two logs are switched independently, so the writer runs when
	 EITHER is on and drains only the rings that are actually enabled. */
      int acl_on = dp_log_is_enabled ();
      int dns_on = dp_log_dns_mode_get () != DP_LOG_DNS_OFF;

      /* Once a second, notice if any of our files was deleted or replaced
	 under us and drop the stale descriptor; the opens below recreate it. */
      {
	struct timespec tnow;
	clock_gettime (CLOCK_MONOTONIC, &tnow);
	long since_ms = (tnow.tv_sec - last_stat.tv_sec) * 1000L +
			(tnow.tv_nsec - last_stat.tv_nsec) / 1000000L;
	if (since_ms >= 1000)
	  {
	    dp_log_reopen_if_replaced (&lm->fd, lm->path);
	    dp_log_reopen_if_replaced (&lm->dns_fd, lm->dns_path);
	    last_stat = tnow;
	  }
      }

      if (!acl_on && !dns_on)
	{
	  usleep (10 * 1000);
	  continue;
	}

      //   if (loop_count % 100000 == 0)  /* Log every 100k loops ~= 1 second
      //   */
      //     clib_warning ("dp_log: writer thread ENABLED (loops=%d)",
      //     loop_count);

      if (acl_on && lm->fd < 0)
	{
	  if (dp_log_open_file (lm) < 0)
	    {
	      /* If can't open, disable to avoid burning CPU */
	      __atomic_store_n (&dp_log_enabled, 0, __ATOMIC_RELAXED);
	      acl_on = 0;
	      usleep (100 * 1000);
	    }
	}

      if (dns_on && lm->dns_fd < 0)
	{
	  if (dp_log_open_dns_file (lm) < 0)
	    {
	      __atomic_store_n (&dp_log_dns_mode, DP_LOG_DNS_OFF,
				__ATOMIC_RELAXED);
	      dns_on = 0;
	      usleep (100 * 1000);
	    }
	}

      /* Session records go to the same file as match records -- one log,
	 one row per event, told apart by the kind column. */
      int sess_on = acl_on;

      if (!acl_on && !dns_on)
	continue;

      int did_work = 0;

      /* ---- Session closes: one row per flow, written straight through.
	 No aggregation: each record is already a whole flow, and collapsing
	 two of them would destroy the volume figure they exist to carry. */
      if (sess_on)
	{
	  char sess_out[8192];
	  int sess_len = 0;

	  for (u32 ti = 0; ti < lm->n_threads; ti++)
	    {
	      dp_log_sess_ring_t *r = &lm->sess_rings[ti];
	      dp_log_sess_event_t ev;
	      int n = 0;

	      while (n < 1024 && dp_log_sess_ring_try_deq (r, &ev))
		{
		  char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
		  char ts[32];
		  char line[512];

		  did_work = 1;
		  n++;

		  if (!dp_log_format_sess_ip (src, sizeof (src), &ev, 1))
		    clib_strncpy (src, "?", sizeof (src));
		  if (!dp_log_format_sess_ip (dst, sizeof (dst), &ev, 0))
		    clib_strncpy (dst, "?", sizeof (dst));
		  dp_log_format_wall_time_ms (ts, sizeof (ts), lm, ev.ts_ns);

		  /* Milliseconds with three decimals rather than a whole
		     number. A LAN exchange that opens and closes inside one
		     millisecond is normal -- an hping3 SYN/RST pair takes
		     microseconds -- and rounding those to "0" threw away the
		     only timing the record carried. Keeping the unit and
		     adding precision means rows written before this change
		     still read correctly as whole milliseconds. */
		  /* Same columns as a match row, filled from the other end:
		     no count, but a duration and the volume each way. action
		     is always permit+reflect, because that is the only verdict
		     that creates a session. */
		  int len = snprintf (
		    line, sizeof (line),
		    "%s,%s,%u,%u,%u,%u,%u,0,%u,%u,2,%s,%s,%s,,%.3f,%llu,%llu,"
		    "%u,%u\n",
		    ts,
		    ev.kind == DP_LOG_SESS_CLOSE ? "close" : "open",
		    (unsigned) ev.is_ip6, (unsigned) ev.proto,
		    (unsigned) ev.sport, (unsigned) ev.dport,
		    (unsigned) ev.sw_if_index, (unsigned) ev.acl_index,
		    (unsigned) ev.rule_index, ev.is_input ? "in" : "out", src,
		    dst, (double) ev.duration_ns / 1e6,
		    (unsigned long long) ev.bytes[1],
		    (unsigned long long) ev.bytes[0], (unsigned) ev.packets[1],
		    (unsigned) ev.packets[0]);
		  if (len <= 0)
		    continue;

		  if (sess_len + len > (int) sizeof (sess_out))
		    {
		      (void) write (lm->fd, sess_out, sess_len);
		      sess_len = 0;
		    }
		  clib_memcpy_fast (sess_out + sess_len, line, len);
		  sess_len += len;
		}
	    }

	  if (sess_len > 0)
	    (void) write (lm->fd, sess_out, sess_len);
	}

      /* ---- DNS queries: written straight through, no aggregation ---- */
      if (dns_on)
	{
	  char dns_out[4096];
	  int dns_len = 0;

	  for (u32 ti = 0; ti < lm->n_threads; ti++)
	    {
	      dp_log_dns_ring_t *r = &lm->dns_rings[ti];
	      dp_log_dns_event_t ev;
	      int n = 0;

	      while (n < 1024 && dp_log_dns_ring_try_deq (r, &ev))
		{
		  did_work = 1;
		  n++;

		  char ts[32];
		  dp_log_format_wall_time_ms (ts, sizeof (ts), lm, ev.ts_ns);

		  char client[INET6_ADDRSTRLEN] = "?";
		  char answer[INET6_ADDRSTRLEN] = "";
		  char name[DP_LOG_DNS_NAME_MAX];

		  if (!ev.is_ip6)
		    {
		      struct in_addr a;
		      clib_memcpy_fast (&a, &ev.client.v4, sizeof (a));
		      (void) inet_ntop (AF_INET, &a, client, sizeof (client));
		    }
		  else
		    {
		      struct in6_addr a6;
		      clib_memcpy_fast (&a6, &ev.client.v6, sizeof (a6));
		      (void) inet_ntop (AF_INET6, &a6, client, sizeof (client));
		    }

		  if (ev.has_answer)
		    {
		      if (!ev.answer_is_ip6)
			{
			  struct in_addr a;
			  clib_memcpy_fast (&a, &ev.answer.v4, sizeof (a));
			  (void) inet_ntop (AF_INET, &a, answer,
					    sizeof (answer));
			}
		      else
			{
			  struct in6_addr a6;
			  clib_memcpy_fast (&a6, &ev.answer.v6, sizeof (a6));
			  (void) inet_ntop (AF_INET6, &a6, answer,
					    sizeof (answer));
			}
		    }

		  (void) dp_log_copy_dns_name (name, sizeof (name), &ev);

		  char line[512];
		  int len = snprintf (line, sizeof (line), "%s,%s,%s,%u,%s\n",
				      ts, client, name,
				      (unsigned) (ev.blocked ? 1 : 0), answer);
		  if (len <= 0)
		    continue;
		  if (len > (int) sizeof (line) - 1)
		    len = (int) sizeof (line) - 1;

		  if (dns_len + len > (int) sizeof (dns_out))
		    {
		      (void) write (lm->dns_fd, dns_out, dns_len);
		      dns_len = 0;
		    }
		  clib_memcpy_fast (dns_out + dns_len, line, len);
		  dns_len += len;
		}
	    }

	  if (dns_len > 0)
	    (void) write (lm->dns_fd, dns_out, dns_len);
	}

      if (!acl_on)
	{
	  if (!did_work)
	    usleep (10 * 1000);
	  continue;
	}

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
	      key.sw_if_index = ev.sw_if_index;
	      key.is_input = ev.is_input;

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

	      /* Linear probe. The table is never more than half full before
		 the overflow path below takes over, so the probe is short. */
	      dp_log_agg_event_t *agg_event = 0;
	      u32 slot = (u32) (hash_val & (AGG_CAP - 1));
	      for (u32 probe = 0; probe < AGG_CAP; probe++)
		{
		  dp_log_agg_event_t *cand =
		    &agg_slots[(slot + probe) & (AGG_CAP - 1)];
		  if (cand->count == 0)
		    {
		      /* Free slot: claim it, unless the table is already
			 carrying as much as it should. */
		      if (agg_count >= AGG_CAP / 2)
			break;
		      cand->key = key;
		      agg_count++;
		      agg_event = cand;
		      break;
		    }
		  if (0 == memcmp (&cand->key, &key, sizeof (key)))
		    {
		      agg_event = cand;
		      break;
		    }
		}

	      if (PREDICT_FALSE (agg_event == 0))
		{
		  /* Overflowing: write this one through on its own rather
		     than lose it. A flood should cost disk, not visibility. */
		  overflow_events++;
		  dp_log_write_acl_row (lm, out, &out_len, OUTBUF_SZ, &ev, 1);
		  continue;
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
	  for (u32 i = 0; i < AGG_CAP; i++)
	    {
	      if (agg_slots[i].count == 0)
		continue;
	      dp_log_write_acl_row (lm, out, &out_len, OUTBUF_SZ,
				    &agg_slots[i].last_event,
				    agg_slots[i].count);
	    }

	  /* Flush buffer */
	  if (out_len > 0)
	    {
	      (void) write (lm->fd, out, out_len);
	      out_len = 0;
	    }

	  if (overflow_events)
	    {
	      dp_log_warn ("%llu ACL events in the last window exceeded the "
			   "%u-flow aggregation table and were written "
			   "individually",
			   (unsigned long long) overflow_events,
			   (unsigned) (AGG_CAP / 2));
	      overflow_events = 0;
	    }

	  /* Clear the window. memset, not free: the table is allocated once
	     for the life of the thread. */
	  memset (agg_slots, 0, AGG_CAP * sizeof (*agg_slots));
	  agg_count = 0;

	  last_flush = now;
	}

      if (!did_work)
	usleep (10 * 1000); // sleep 10ms if no work done
    }

  /* Final flush */
  if (lm->fd >= 0 && out_len > 0)
    (void) write (lm->fd, out, out_len);

  /* Clean up */
  free (agg_slots);
  free (out);
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
      else if (unformat (input, "session-ring-size %u", &lm->sess_ring_size))
	;
      else if (unformat (input, "dns-path %s", &lm->dns_path))
	;
      else if (unformat (input, "dns-ring-size %u", &lm->dns_ring_size))
	;
      else if (unformat (input, "acl-log-unmatched"))
	__atomic_fetch_or (&dp_log_acl_flags, DP_LOG_ACL_F_UNMATCHED,
			   __ATOMIC_RELAXED);
      else if (unformat (input, "acl-log-all-deny"))
	__atomic_fetch_or (&dp_log_acl_flags, DP_LOG_ACL_F_ALL_DENY,
			   __ATOMIC_RELAXED);
      else if (unformat (input, "dns-log-all"))
	__atomic_store_n (&dp_log_dns_mode, DP_LOG_DNS_ALL, __ATOMIC_RELAXED);
      else if (unformat (input, "dns-log-blocked"))
	__atomic_store_n (&dp_log_dns_mode, DP_LOG_DNS_BLOCKED,
			  __ATOMIC_RELAXED);
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

  lm->dns_fd = -1;
  if (!lm->dns_path)
    lm->dns_path = format (0, "/etc/sarhad-guard/dns_logs/dns_logs.log");

  lm->ring_size = dp_log_pow2_or_default (lm->ring_size, 1 << 16);
  /* 2048 entries x ~300 bytes x n_threads. Sizing this like the ACL ring
     (65536) would reserve hundreds of MB to buffer a few queries a second. */
  lm->dns_ring_size = dp_log_pow2_or_default (lm->dns_ring_size, 1 << 11);
  /* One record per flow rather than per packet, so the arrival rate is
     connections per second. 4096 absorbs a burst of short-lived connections
     without reserving the ACL ring's footprint. */
  lm->sess_ring_size = dp_log_pow2_or_default (lm->sess_ring_size, 1 << 12);
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

  lm->sess_rings = clib_mem_alloc_aligned (
    sizeof (*lm->sess_rings) * lm->n_threads, CLIB_CACHE_LINE_BYTES);
  clib_memset (lm->sess_rings, 0, sizeof (*lm->sess_rings) * lm->n_threads);

  for (u32 i = 0; i < lm->n_threads; i++)
    {
      dp_log_sess_ring_t *r = &lm->sess_rings[i];
      r->size = lm->sess_ring_size;
      r->mask = r->size - 1;

      r->elts = clib_mem_alloc_aligned (
	r->size * sizeof (dp_log_sess_event_t), CLIB_CACHE_LINE_BYTES);
      clib_memset (r->elts, 0, r->size * sizeof (dp_log_sess_event_t));

      __atomic_store_n (&r->head, 0, __ATOMIC_RELAXED);
      __atomic_store_n (&r->tail, 0, __ATOMIC_RELAXED);
      __atomic_store_n (&r->drops, 0, __ATOMIC_RELAXED);
    }

  lm->dns_rings = clib_mem_alloc_aligned (
    sizeof (*lm->dns_rings) * lm->n_threads, CLIB_CACHE_LINE_BYTES);
  clib_memset (lm->dns_rings, 0, sizeof (*lm->dns_rings) * lm->n_threads);

  for (u32 i = 0; i < lm->n_threads; i++)
    {
      dp_log_dns_ring_t *r = &lm->dns_rings[i];
      r->size = lm->dns_ring_size;
      r->mask = r->size - 1;

      r->elts = clib_mem_alloc_aligned (
	r->size * sizeof (dp_log_dns_event_t), CLIB_CACHE_LINE_BYTES);
      clib_memset (r->elts, 0, r->size * sizeof (dp_log_dns_event_t));

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
