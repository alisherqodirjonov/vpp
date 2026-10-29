/*
 * http_certmint.c - per-name server certificates, minted on demand
 *
 * A TLS listener with no certificate of its own (ckpair index 0) asks the
 * application that owns it for one, per handshake, naming the server the
 * client asked for (SNI): see openssl_server_cert_callback and
 * app_crypto_async_req. For HTTP-over-TLS that application is this plugin.
 * When a minting CA is configured, the answer is a certificate for exactly
 * that name, signed by the CA:
 *
 *   subject CN = SAN = the requested name, nothing else
 *   one shared EC P-256 leaf key (generated when the CA is set), so minting
 *   is a single CA signature, not a key generation
 *   validity: 397 days, never past the CA's own expiry
 *
 * This is what lets the DNS-filtering block page answer HTTPS for a blocked
 * name without a browser warning (clients trust the TLS-inspection CA), and
 * without a certificate that lists every blocked domain or has to be
 * reissued when the blocklist changes. It is equally what a TLS-inspecting
 * proxy needs, which is why it lives here and not in http_static.
 *
 * Threading. The request arrives on the worker running the handshake. The
 * work is done on the main thread, because registering a cert/key pair
 * grows a pool workers read without locks (app_cert_key_pair_alloc), so it
 * happens under the worker barrier. The answer is posted back to the
 * requesting worker, which is where app_crypto_async_reply must run.
 *
 * Bounds. Results are cached per name (oldest evicted beyond the cache
 * size), and new mints are rate-limited: every miss is a barrier, and the
 * name is chosen by whoever opens the connection, so an unbounded rate
 * would let one LAN client stall the data plane by asking for random
 * names. A refused or failed request fails that handshake, nothing more.
 */

#include <vnet/session/session.h>
#include <vnet/session/application.h>
#include <vnet/session/application_crypto.h>
#include <http/http_certmint.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define CERTMINT_CACHE_SIZE  4096
#define CERTMINT_RATE	     50.0  /* new mints per second, sustained */
#define CERTMINT_BURST	     200.0 /* ... and in a burst */
#define CERTMINT_VALID_DAYS  397

typedef struct
{
  X509 *ca_cert;
  EVP_PKEY *ca_key;
  EVP_PKEY *leaf_key;
  u8 *leaf_key_pem; /**< NUL-terminated */

  uword *ckpair_by_name; /**< name (NUL-terminated vec) -> ckpair index */
  u8 **fifo;		 /**< insertion order, for eviction */
  u32 fifo_head;

  f64 tokens;
  f64 tokens_at;

  u64 minted, cache_hits, refused, failed;
} http_certmint_main_t;

static http_certmint_main_t certmint_main;

typedef struct
{
  u32 app_index;
  u32 req_index;
  app_crypto_async_req_handle_t handle;
  u8 *name;
  u32 ckpair_index;
} certmint_rpc_t;

/* ---------------------------------------------------------------- minting */

static int
certmint_add_ext (X509 *x, X509V3_CTX *ctx, int nid, const char *value)
{
  X509_EXTENSION *ex = X509V3_EXT_conf_nid (NULL, ctx, nid, value);
  int ok;

  if (!ex)
    return 0;
  ok = X509_add_ext (x, ex, -1);
  X509_EXTENSION_free (ex);
  return ok;
}

static u8 *
certmint_pem_of_x509 (X509 *x)
{
  BIO *b = BIO_new (BIO_s_mem ());
  char *data;
  long len;
  u8 *pem = 0;

  if (b && PEM_write_bio_X509 (b, x))
    {
      len = BIO_get_mem_data (b, &data);
      vec_add (pem, data, len);
      vec_add1 (pem, 0);
    }
  BIO_free (b);
  return pem;
}

/* Hostname characters only. The name goes into an X509V3 config string,
   so anything else (a comma, a colon) must never get that far. */
static int
certmint_valid_name (const u8 *n, uword len)
{
  uword i;

  if (len == 0 || len > 253 || n[0] == '.' || n[0] == '-')
    return 0;
  for (i = 0; i < len; i++)
    {
      u8 c = n[i];
      if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' ||
	    c == '.' || c == '_'))
	return 0;
    }
  return 1;
}

static X509 *
certmint_mint (const char *name)
{
  http_certmint_main_t *cm = &certmint_main;
  X509 *x = X509_new ();
  X509V3_CTX v3;
  BIGNUM *bn = BN_new ();
  ASN1_INTEGER *serial = 0;
  char cn[65], san[300];
  int ok = 0;

  if (!x || !bn)
    goto done;

  X509_set_version (x, 2);
  if (!BN_rand (bn, 127, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) ||
      !(serial = BN_to_ASN1_INTEGER (bn, NULL)) ||
      !X509_set_serialNumber (x, serial))
    goto done;

  X509_gmtime_adj (X509_getm_notBefore (x), -3600); /* client clock skew */
  X509_gmtime_adj (X509_getm_notAfter (x),
		   (long) CERTMINT_VALID_DAYS * 24 * 3600);
  if (ASN1_TIME_compare (X509_get0_notAfter (x),
			 X509_get0_notAfter (cm->ca_cert)) > 0)
    X509_set1_notAfter (x, X509_get0_notAfter (cm->ca_cert));

  /* CN is limited to 64 characters; the SAN carries the full name and is
     what browsers check. */
  snprintf (cn, sizeof (cn), "%s", name);
  if (!X509_NAME_add_entry_by_txt (X509_get_subject_name (x), "CN",
				   MBSTRING_ASC, (u8 *) cn, -1, -1, 0) ||
      !X509_set_issuer_name (x, X509_get_subject_name (cm->ca_cert)) ||
      !X509_set_pubkey (x, cm->leaf_key))
    goto done;

  X509V3_set_ctx (&v3, cm->ca_cert, x, NULL, NULL, 0);
  snprintf (san, sizeof (san), "DNS:%s", name);
  if (!certmint_add_ext (x, &v3, NID_subject_alt_name, san) ||
      !certmint_add_ext (x, &v3, NID_basic_constraints, "critical,CA:FALSE") ||
      !certmint_add_ext (x, &v3, NID_key_usage,
			 "critical,digitalSignature") ||
      !certmint_add_ext (x, &v3, NID_ext_key_usage, "serverAuth") ||
      !certmint_add_ext (x, &v3, NID_subject_key_identifier, "hash") ||
      !certmint_add_ext (x, &v3, NID_authority_key_identifier,
			 "keyid:always"))
    goto done;

  if (!X509_sign (x, cm->ca_key, EVP_sha256 ()))
    goto done;
  ok = 1;

done:
  BN_free (bn);
  ASN1_INTEGER_free (serial);
  if (!ok)
    {
      X509_free (x);
      x = 0;
    }
  return x;
}

/* ------------------------------------------------------------------ cache */

static void
certmint_del_ckpair (u32 index)
{
  vlib_main_t *vm = vlib_get_main ();

  vlib_worker_thread_barrier_sync (vm);
  vnet_app_del_cert_key_pair (index);
  vlib_worker_thread_barrier_release (vm);
}

static void
certmint_cache_flush (void)
{
  http_certmint_main_t *cm = &certmint_main;
  u8 **np;
  uword *p;

  vec_foreach (np, cm->fifo)
    {
      if (!*np)
	continue;
      if ((p = hash_get_mem (cm->ckpair_by_name, *np)))
	certmint_del_ckpair (p[0]);
      vec_free (*np);
    }
  vec_free (cm->fifo);
  cm->fifo_head = 0;
  hash_free (cm->ckpair_by_name);
  cm->ckpair_by_name = hash_create_string (0, sizeof (uword));
}

/* Main thread. Returns a ckpair index, or ~0. */
static u32
certmint_get (u8 *name)
{
  http_certmint_main_t *cm = &certmint_main;
  vlib_main_t *vm = vlib_get_main ();
  vnet_app_add_cert_key_pair_args_t a = {};
  uword *p;
  X509 *x;
  u8 *pem, *key;
  f64 now;

  if (!cm->ca_cert)
    return ~0;

  if ((p = hash_get_mem (cm->ckpair_by_name, name)))
    {
      cm->cache_hits++;
      return p[0];
    }

  /* Token bucket. */
  now = vlib_time_now (vm);
  cm->tokens = clib_min (CERTMINT_BURST,
			 cm->tokens + (now - cm->tokens_at) * CERTMINT_RATE);
  cm->tokens_at = now;
  if (cm->tokens < 1.0)
    {
      cm->refused++;
      return ~0;
    }
  cm->tokens -= 1.0;

  x = certmint_mint ((char *) name);
  if (!x)
    {
      cm->failed++;
      return ~0;
    }
  pem = certmint_pem_of_x509 (x);
  X509_free (x);
  if (!pem)
    {
      cm->failed++;
      return ~0;
    }

  /* vnet_app_add_cert_key_pair copies both buffers. */
  key = cm->leaf_key_pem;
  a.cert = pem;
  a.cert_len = vec_len (pem);
  a.key = key;
  a.key_len = vec_len (key);
  vlib_worker_thread_barrier_sync (vm);
  vnet_app_add_cert_key_pair (&a);
  vlib_worker_thread_barrier_release (vm);
  vec_free (pem);
  cm->minted++;

  /* Remember it; evict the oldest once the cache is full. */
  if (vec_len (cm->fifo) < CERTMINT_CACHE_SIZE)
    vec_add1 (cm->fifo, 0);
  {
    u8 **slot = vec_elt_at_index (cm->fifo, cm->fifo_head);
    if (*slot)
      {
	if ((p = hash_get_mem (cm->ckpair_by_name, *slot)))
	  certmint_del_ckpair (p[0]);
	hash_unset_mem (cm->ckpair_by_name, *slot);
	vec_free (*slot);
      }
    *slot = vec_dup (name);
    hash_set_mem (cm->ckpair_by_name, *slot, a.index);
    cm->fifo_head = (cm->fifo_head + 1) % CERTMINT_CACHE_SIZE;
  }
  return a.index;
}

/* ------------------------------------------------------------ async path */

/* On the requesting worker. */
static void
certmint_reply_rpc (void *arg)
{
  certmint_rpc_t *r = arg;
  app_crypto_async_reply_t reply = {
    .app_index = r->app_index,
    .req_index = r->req_index,
    .handle = r->handle,
    .req_type = APP_CRYPTO_ASYNC_REQ_TYPE_CERT,
    .async_cert = { .ckpair_index = r->ckpair_index },
  };

  app_crypto_async_reply (&reply);
  vec_free (r->name);
  clib_mem_free (r);
}

/* On the main thread. */
static void
certmint_work_rpc (void *arg)
{
  certmint_rpc_t *r = arg;

  r->ckpair_index = certmint_get (r->name);
  session_send_rpc_evt_to_thread_force (r->handle.thread_index,
					certmint_reply_rpc, r);
}

/* app_crypto_async callback for the HTTP transport app. Runs on the
   worker doing the handshake; returns non-zero to refuse (the handshake
   then fails), zero once the request has been taken. */
int
http_certmint_async_req (app_crypto_async_req_t *req)
{
  http_certmint_main_t *cm = &certmint_main;
  certmint_rpc_t *r;
  app_worker_t *app_wrk;
  const u8 *sn;
  uword len;
  u8 *name;

  if (req->req_type != APP_CRYPTO_ASYNC_REQ_TYPE_CERT || !cm->ca_cert)
    return -1;

  sn = req->async_cert.servername;
  if (!sn)
    return -1;
  len = strnlen ((char *) sn, 254);
  name = 0;
  vec_add (name, sn, len);
  {
    uword i;
    for (i = 0; i < len; i++)
      if (name[i] >= 'A' && name[i] <= 'Z')
	name[i] += 'a' - 'A';
  }
  if (len && name[len - 1] == '.')
    vec_dec_len (name, 1);
  if (!certmint_valid_name (name, vec_len (name)))
    {
      vec_free (name);
      return -1;
    }
  vec_add1 (name, 0);

  /* The request lives in a per-worker pool that may move; copy what the
     reply needs, never keep the pointer. */
  app_wrk = app_worker_get (req->app_wrk_index);
  r = clib_mem_alloc (sizeof (*r));
  r->app_index = app_wrk->app_index;
  r->req_index = req->req_index;
  r->handle = req->handle;
  r->name = name;
  r->ckpair_index = ~0;
  session_send_rpc_evt_to_thread_force (0, certmint_work_rpc, r);
  return 0;
}

/* ---------------------------------------------------------------- config */

__clib_export int
http_certmint_set_ca (u8 *cert_pem, u32 cert_len, u8 *key_pem, u32 key_len)
{
  http_certmint_main_t *cm = &certmint_main;
  BIO *b;
  X509 *ca = 0;
  EVP_PKEY *key = 0, *leaf = 0;
  char *data;
  long len;

  if (!cm->ckpair_by_name)
    cm->ckpair_by_name = hash_create_string (0, sizeof (uword));

  /* No PEM at all: switch minting off. */
  if (!cert_len && !key_len)
    goto install;

  b = BIO_new_mem_buf (cert_pem, cert_len);
  ca = PEM_read_bio_X509 (b, NULL, NULL, NULL);
  BIO_free (b);
  b = BIO_new_mem_buf (key_pem, key_len);
  key = PEM_read_bio_PrivateKey (b, NULL, NULL, NULL);
  BIO_free (b);
  if (!ca || !key || !X509_check_private_key (ca, key) ||
      X509_check_ca (ca) == 0)
    goto bad;

  leaf = EVP_EC_gen ("P-256");
  if (!leaf)
    goto bad;

install:
  /* Every cached certificate was signed by the old CA. */
  certmint_cache_flush ();
  X509_free (cm->ca_cert);
  EVP_PKEY_free (cm->ca_key);
  EVP_PKEY_free (cm->leaf_key);
  vec_free (cm->leaf_key_pem);
  cm->ca_cert = ca;
  cm->ca_key = key;
  cm->leaf_key = leaf;
  if (leaf)
    {
      b = BIO_new (BIO_s_mem ());
      PEM_write_bio_PrivateKey (b, leaf, NULL, NULL, 0, NULL, NULL);
      len = BIO_get_mem_data (b, &data);
      vec_add (cm->leaf_key_pem, data, len);
      vec_add1 (cm->leaf_key_pem, 0);
      BIO_free (b);
    }
  cm->tokens = CERTMINT_BURST;
  cm->tokens_at = vlib_time_now (vlib_get_main ());
  return 0;

bad:
  X509_free (ca);
  EVP_PKEY_free (key);
  EVP_PKEY_free (leaf);
  return VNET_API_ERROR_INVALID_VALUE;
}

/* ------------------------------------------------------------------- CLI */

static clib_error_t *
show_http_certmint_fn (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
{
  http_certmint_main_t *cm = &certmint_main;
  char subj[256] = "";

  if (cm->ca_cert)
    X509_NAME_oneline (X509_get_subject_name (cm->ca_cert), subj,
		       sizeof (subj));
  vlib_cli_output (vm, "minting %s%s%s", cm->ca_cert ? "on, CA " : "off",
		   subj, "");
  vlib_cli_output (vm,
		   "cached %u, minted %llu, cache hits %llu, refused (rate) "
		   "%llu, failed %llu",
		   cm->ckpair_by_name ? hash_elts (cm->ckpair_by_name) : 0,
		   cm->minted, cm->cache_hits, cm->refused, cm->failed);
  return 0;
}

VLIB_CLI_COMMAND (show_http_certmint_command) = {
  .path = "show http certmint",
  .short_help = "show http certmint",
  .function = show_http_certmint_fn,
};
