/*
 * dns_blocklist.c - large-scale name blocklist for the DNS resolver
 *
 * Blocked names used to be static entries in the resolver cache. That cache
 * is a pool capped at max-cache-size (1000 by default) and SHARED with normal
 * answers: a few hundred blocks starved ordinary resolution, and at the cap
 * every non-blocked lookup failed outright because delete_random_entry ()
 * cannot evict a static entry. Feeds of malicious domains run to 10^5..10^7
 * names, so blocking needs its own structure.
 *
 * Design
 *  - One clib_bihash_8_8 keyed by a 64-bit hash of the normalized name;
 *    the value carries flags (exact vs. name-and-subdomains). Names are not
 *    stored: at 10^7 entries the false-positive probability per lookup is
 *    ~10^-12, and the control plane keeps the authoritative list anyway.
 *  - Suffix matching: a lookup for a.b.example.com probes the full name,
 *    then b.example.com, then example.com; parents only match entries
 *    flagged SUBDOMAINS. At most one probe per label, ~100ns each.
 *  - Each table lives in its own clib heap sized for the configured maximum.
 *    The main heap is never touched, the table can never outgrow its heap
 *    (adds are refused at the entry limit, and the heap is sized well above
 *    what that many entries can use), and freeing a table is destroying its
 *    heap -- no per-chunk frees, no fragmentation.
 *  - Bulk load builds a complete new table off to the side and swaps the
 *    pointer under the worker barrier, so a reload of millions of names
 *    never stalls the data plane for more than the swap. The load handler
 *    is marked thread-safe (mp-safe) for exactly this reason.
 *  - A blocked lookup is answered from one sentinel cache entry that is
 *    NOT in the cache pool: the existing reply path, per-segment redirect
 *    and query log all key off DNS_CACHE_ENTRY_FLAG_STATIC and work on it
 *    unchanged, while the cache itself goes back to caching real answers.
 */

#include <stdio.h>
#include <dns/dns.h>
#include <vlib/vlib.h>
#include <vlib/stats/stats.h>
#include <vppinfra/bihash_8_8.h>
#include <vppinfra/bihash_template.h>

/* Per-entry heap budget. Measured with this file's sizing (buckets =
   max-entries / 8, 1M random names): ~35 bytes per entry. With buckets at
   N/2 it was 63, and a table grown from 1024 buckets reached 142 -- which
   is why the bucket count is fixed from max-entries, not from the load.
   128 bytes is ~3.5x the measured figure, which keeps "heap exhausted" (an
   abort inside clib_mem_alloc) unreachable below the entry limit. */
#define DNS_BLOCKLIST_BYTES_PER_ENTRY 128
#define DNS_BLOCKLIST_HEAP_BASE	      (32ULL << 20)

dns_blocklist_main_t dns_blocklist_main;

/* FNV-1a 64 over the lower-cased bytes. Deterministic and cheap; the key
   only needs to be stable inside this process. */
static_always_inline u64
dns_blocklist_hash (const u8 *s, uword len)
{
  u64 h = 0xcbf29ce484222325ULL;
  uword i;

  for (i = 0; i < len; i++)
    {
      u8 c = s[i];
      if (c >= 'A' && c <= 'Z')
	c += 'a' - 'A';
      h ^= c;
      h *= 0x100000001b3ULL;
    }
  return h;
}

static uword
dns_blocklist_heap_size (u32 max_entries)
{
  return DNS_BLOCKLIST_HEAP_BASE +
	 (uword) max_entries * DNS_BLOCKLIST_BYTES_PER_ENTRY;
}

static dns_blocklist_table_t *
dns_blocklist_table_create (void)
{
  dns_blocklist_main_t *bm = &dns_blocklist_main;
  dns_blocklist_table_t *t;
  clib_bihash_init2_args_8_8_t a = {};
  u32 nbuckets;

  t = clib_mem_alloc (sizeof (*t));
  clib_memset (t, 0, sizeof (*t));

  t->heap = clib_mem_create_heap (0, dns_blocklist_heap_size (bm->max_entries),
				  1 /* locked */, "dns-blocklist");
  if (!t->heap)
    {
      clib_mem_free (t);
      return 0;
    }

  /* Sized from the capacity, not the current load: a table that starts
     small and grows by single adds otherwise piles names into long linear
     pages (measured 4x the memory). ~1MB of buckets per 1M capacity. */
  nbuckets = clib_max (bm->max_entries / 8, 1024);

  /* bihash_8_8 is built with BIHASH_USE_HEAP: instantiate records the
     CURRENT heap as h->heap, and the alloc lock and working-copy vectors
     come from the current heap too. Make the private heap current for
     init and for every add/del (dns_blocklist_table_add_del), so that every
     byte the table owns lives in it and freeing the table is destroying
     the heap. */
  a.h = &t->hash;
  a.name = "dns-blocklist";
  a.nbuckets = nbuckets;
  a.dont_add_to_all_bihash_list = 1;
  {
    void *oldheap = clib_mem_set_heap (t->heap);
    clib_bihash_init2_8_8 (&a);
    clib_mem_set_heap (oldheap);
  }
  return t;
}

/* Never clib_bihash_free_8_8 (): it frees the alloc lock on whatever heap
   is current. Everything is in t->heap, so destroying it is the free. */
static void
dns_blocklist_table_free (dns_blocklist_table_t *t)
{
  if (!t)
    return;
  clib_mem_destroy_heap (t->heap);
  clib_mem_free (t);
}

static void
dns_blocklist_table_add_del (dns_blocklist_table_t *t,
			     clib_bihash_kv_8_8_t *kv, int is_add)
{
  void *oldheap = clib_mem_set_heap (t->heap);
  clib_bihash_add_del_8_8 (&t->hash, kv, is_add);
  clib_mem_set_heap (oldheap);
}

/* Normalize in place: lower-case, strip one trailing dot. Returns the new
   length, or 0 if the name is not something a resolver would ask for. */
static uword
dns_blocklist_normalize (u8 *s, uword len)
{
  uword i;

  while (len && (s[len - 1] == '.' || s[len - 1] == '\r' ||
		 s[len - 1] == ' ' || s[len - 1] == '\t'))
    len--;
  if (len == 0 || len > 253)
    return 0;
  for (i = 0; i < len; i++)
    {
      u8 c = s[i];
      if (c >= 'A' && c <= 'Z')
	s[i] = c + ('a' - 'A');
      else if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
		 c == '-' || c == '.' || c == '_'))
	return 0;
    }
  return len;
}

/* Insert into t, merging flags on a (vanishingly rare) key collision.
   Returns 1 if a new key was added. */
static int
dns_blocklist_table_add (dns_blocklist_table_t *t, const u8 *name, uword len,
			 u8 flags)
{
  clib_bihash_kv_8_8_t kv;

  kv.key = dns_blocklist_hash (name, len);
  if (clib_bihash_search_8_8 (&t->hash, &kv, &kv) == 0)
    {
      kv.value |= flags;
      dns_blocklist_table_add_del (t, &kv, 1);
      return 0;
    }
  kv.value = flags;
  dns_blocklist_table_add_del (t, &kv, 1);
  t->count++;
  return 1;
}

static void
dns_blocklist_publish_stats (void)
{
  dns_blocklist_main_t *bm = &dns_blocklist_main;
  dns_blocklist_table_t *t = bm->table;

  vlib_stats_set_gauge (bm->entries_idx, t ? t->count : 0);
  vlib_stats_set_gauge (bm->limit_idx, bm->max_entries);
}

/* Swap in a new table under the barrier and free the old one after. */
static void
dns_blocklist_install (dns_blocklist_table_t *t)
{
  dns_blocklist_main_t *bm = &dns_blocklist_main;
  vlib_main_t *vm = vlib_get_main ();
  dns_blocklist_table_t *old;

  vlib_worker_thread_barrier_sync (vm);
  old = bm->table;
  bm->table = t;
  vlib_worker_thread_barrier_release (vm);

  dns_blocklist_table_free (old);
  dns_blocklist_publish_stats ();
}

int
dns_blocklist_load_file (const char *path, u32 *n_entries, u32 *n_skipped)
{
  dns_blocklist_main_t *bm = &dns_blocklist_main;
  dns_blocklist_table_t *t;
  FILE *f;
  char *line = 0;
  size_t cap = 0;
  ssize_t n;
  u32 skipped = 0;
  int rv = 0;

  *n_entries = 0;
  *n_skipped = 0;

  f = fopen (path, "r");
  if (!f)
    return VNET_API_ERROR_SYSCALL_ERROR_1;

  t = dns_blocklist_table_create ();
  if (!t)
    {
      fclose (f);
      free (line);
      return VNET_API_ERROR_INIT_FAILED;
    }

  /*
   * One entry per line: "<flag> <name>", flag 'S' = name and every
   * subdomain, 'E' = exact name only. '#' starts a comment line. The
   * control plane writes this file; anything malformed is counted and
   * skipped rather than failing the whole load.
   */
  while ((n = getline (&line, &cap, f)) > 0)
    {
      u8 flags, *name;
      uword len;

      if (line[0] == '#' || line[0] == '\n')
	continue;
      if (n < 3 || line[1] != ' ' || (line[0] != 'S' && line[0] != 'E'))
	{
	  skipped++;
	  continue;
	}
      flags = DNS_BLOCKLIST_F_BLOCK;
      if (line[0] == 'S')
	flags |= DNS_BLOCKLIST_F_SUBDOMAINS;

      name = (u8 *) line + 2;
      len = n - 2;
      if (len && name[len - 1] == '\n')
	len--;
      len = dns_blocklist_normalize (name, len);
      if (!len)
	{
	  skipped++;
	  continue;
	}

      if (t->count >= bm->max_entries)
	{
	  /* All-or-nothing: a half-loaded list would silently leave the
	     tail of a threat feed unenforced. */
	  rv = VNET_API_ERROR_LIMIT_EXCEEDED;
	  break;
	}
      dns_blocklist_table_add (t, name, len, flags);
    }

  fclose (f);
  free (line);

  *n_entries = t->count;
  *n_skipped = skipped;

  if (rv)
    {
      dns_blocklist_table_free (t);
      return rv;
    }

  dns_blocklist_install (t);
  return 0;
}

int
dns_blocklist_add_del (u8 *name, int is_add, int subdomains)
{
  dns_blocklist_main_t *bm = &dns_blocklist_main;
  dns_blocklist_table_t *t = bm->table;
  clib_bihash_kv_8_8_t kv;
  uword len;
  u8 *copy;
  int rv = 0;

  copy = format (0, "%s", name);
  len = dns_blocklist_normalize (copy, vec_len (copy));
  if (!len)
    {
      vec_free (copy);
      return VNET_API_ERROR_INVALID_VALUE;
    }

  if (!t)
    {
      /* First edit before any load: start an empty table. */
      t = dns_blocklist_table_create ();
      if (!t)
	{
	  vec_free (copy);
	  return VNET_API_ERROR_INIT_FAILED;
	}
      dns_blocklist_install (t);
    }

  /*
   * bihash add/del is safe against concurrent readers on the workers, so
   * single edits go straight into the live table: no rebuild, no barrier.
   */
  if (is_add)
    {
      if (t->count >= bm->max_entries)
	rv = VNET_API_ERROR_LIMIT_EXCEEDED;
      else
	dns_blocklist_table_add (
	  t, copy, len,
	  DNS_BLOCKLIST_F_BLOCK | (subdomains ? DNS_BLOCKLIST_F_SUBDOMAINS : 0));
    }
  else
    {
      kv.key = dns_blocklist_hash (copy, len);
      if (clib_bihash_search_8_8 (&t->hash, &kv, &kv) == 0)
	{
	  dns_blocklist_table_add_del (t, &kv, 0);
	  t->count--;
	}
      else
	rv = VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  vec_free (copy);
  dns_blocklist_publish_stats ();
  return rv;
}

void
dns_blocklist_clear (void)
{
  dns_blocklist_install (0);
}

int
dns_blocklist_set_answer (ip4_address_t *a4, ip6_address_t *a6)
{
  dns_blocklist_main_t *bm = &dns_blocklist_main;
  vlib_main_t *vm = vlib_get_main ();
  u8 *reply, *old, *name;

  if (!a4 && !a6)
    return VNET_API_ERROR_INVALID_VALUE;

  /* Any syntactically valid name will do: the reply path takes the
     question from the client's request and only reads the address out of
     this response.
     It MUST be a vppinfra vector: name_to_labels () starts with vec_dup,
     which reads the length from a vector header. A C string literal has
     none, so the "length" was whatever bytes sit in front of it in
     .rodata -- a multi-GB allocation and an os_out_of_memory abort on
     every call, i.e. on every VPP start. */
  name = format (0, "blocked.invalid");
  /* Short TTL: clients cache the block answer, and an unblocked name
     should start resolving again within a minute, not a day. */
  reply = dns_build_static_reply_ttl (name, a4, a6, 60);
  vec_free (name);
  if (!reply)
    return VNET_API_ERROR_INVALID_VALUE;

  vlib_worker_thread_barrier_sync (vm);
  old = bm->sentinel.dns_response;
  bm->sentinel.dns_response = reply;
  bm->sentinel.flags = DNS_CACHE_ENTRY_FLAG_VALID | DNS_CACHE_ENTRY_FLAG_STATIC;
  vlib_worker_thread_barrier_release (vm);

  vec_free (old);
  return 0;
}

dns_cache_entry_t *
dns_blocklist_match (u8 *name)
{
  dns_blocklist_main_t *bm = &dns_blocklist_main;
  dns_blocklist_table_t *t = bm->table;
  clib_bihash_kv_8_8_t kv;
  u8 *p, *end;
  int first = 1;

  if (PREDICT_TRUE (!t || t->count == 0 || !bm->sentinel.dns_response))
    return 0;

  /* name is the normalized, NUL-terminated cache key */
  end = name + strlen ((char *) name);
  while (end > name && end[-1] == '.')
    end--;

  for (p = name; p < end;)
    {
      kv.key = dns_blocklist_hash (p, end - p);
      if (clib_bihash_search_8_8 (&t->hash, &kv, &kv) == 0 &&
	  (first || (kv.value & DNS_BLOCKLIST_F_SUBDOMAINS)))
	{
	  clib_atomic_fetch_add_relax (&bm->hits, 1);
	  return &bm->sentinel;
	}
      p = memchr (p, '.', end - p);
      if (!p)
	break;
      p++;
      first = 0;
    }
  return 0;
}

void
dns_blocklist_status (u32 *entries, u32 *limit, u64 *hits)
{
  dns_blocklist_main_t *bm = &dns_blocklist_main;

  *entries = bm->table ? bm->table->count : 0;
  *limit = bm->max_entries;
  *hits = bm->hits;
}

/* ---------------------------------------------------------------- config */

static clib_error_t *
dns_blocklist_config_fn (vlib_main_t *vm, unformat_input_t *input)
{
  dns_blocklist_main_t *bm = &dns_blocklist_main;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "max-entries %u", &bm->max_entries))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  if (bm->max_entries == 0)
    return clib_error_return (0, "max-entries must be at least 1");
  return 0;
}

VLIB_CONFIG_FUNCTION (dns_blocklist_config_fn, "dns-blocklist");

static clib_error_t *
dns_blocklist_init (vlib_main_t *vm)
{
  dns_blocklist_main_t *bm = &dns_blocklist_main;

  if (bm->max_entries == 0)
    bm->max_entries = 1000000;
  bm->entries_idx = vlib_stats_add_gauge ("/dns/blocklist/entries");
  bm->limit_idx = vlib_stats_add_gauge ("/dns/blocklist/limit");
  dns_blocklist_publish_stats ();
  return 0;
}

VLIB_INIT_FUNCTION (dns_blocklist_init);

/* ------------------------------------------------------------------- CLI */

static clib_error_t *
show_dns_blocklist_command_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{
  dns_blocklist_main_t *bm = &dns_blocklist_main;
  dns_blocklist_table_t *t = bm->table;
  u8 *name = 0;

  if (unformat (input, "%s", &name))
    {
      dns_cache_entry_t *ep;

      vec_add1 (name, 0);
      dns_normalize_name (name);
      ep = dns_blocklist_match (name);
      vlib_cli_output (vm, "%s: %s", name, ep ? "BLOCKED" : "not blocked");
      vec_free (name);
      return 0;
    }

  vlib_cli_output (vm, "entries %u / limit %u, hits %llu",
		   t ? t->count : 0, bm->max_entries, bm->hits);
  vlib_cli_output (vm, "answer %s", bm->sentinel.dns_response ? "set" :
						       "NOT SET (blocking off)");
  if (t)
    {
      clib_mem_usage_t usage;
      clib_mem_get_heap_usage (t->heap, &usage);
      vlib_cli_output (vm, "heap %U used of %U", format_memory_size,
		       usage.bytes_used, format_memory_size,
		       usage.bytes_total);
    }
  return 0;
}

VLIB_CLI_COMMAND (show_dns_blocklist_command) = {
  .path = "show dns blocklist",
  .short_help = "show dns blocklist [<name>]",
  .function = show_dns_blocklist_command_fn,
};

static clib_error_t *
dns_blocklist_command_fn (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  u8 *arg = 0;
  u32 entries, skipped;
  int rv, subdomains = 0;

  if (unformat (input, "load %s", &arg))
    {
      vec_add1 (arg, 0);
      rv = dns_blocklist_load_file ((char *) arg, &entries, &skipped);
      vec_free (arg);
      if (rv)
	return clib_error_return (0, "load failed: %d (read %u entries)", rv,
				  entries);
      vlib_cli_output (vm, "loaded %u entries, skipped %u", entries,
		       skipped);
      return 0;
    }
  if (unformat (input, "add %s", &arg))
    {
      if (unformat (input, "subdomains"))
	subdomains = 1;
      vec_add1 (arg, 0);
      rv = dns_blocklist_add_del (arg, 1, subdomains);
      vec_free (arg);
      return rv ? clib_error_return (0, "add failed: %d", rv) : 0;
    }
  if (unformat (input, "del %s", &arg))
    {
      vec_add1 (arg, 0);
      rv = dns_blocklist_add_del (arg, 0, 0);
      vec_free (arg);
      return rv ? clib_error_return (0, "del failed: %d", rv) : 0;
    }
  if (unformat (input, "clear"))
    {
      dns_blocklist_clear ();
      return 0;
    }
  return clib_error_return (0, "unknown input `%U'", format_unformat_error,
			    input);
}

VLIB_CLI_COMMAND (dns_blocklist_command) = {
  .path = "dns blocklist",
  .short_help =
    "dns blocklist load <file> | add <name> [subdomains] | del <name> | clear",
  .function = dns_blocklist_command_fn,
};
