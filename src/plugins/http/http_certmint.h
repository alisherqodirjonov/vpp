/*
 * http_certmint.h - per-name server certificates, minted on demand
 * (see http_certmint.c)
 */

#ifndef SRC_PLUGINS_HTTP_HTTP_CERTMINT_H_
#define SRC_PLUGINS_HTTP_HTTP_CERTMINT_H_

#include <vnet/session/application_crypto.h>

/** app_crypto_async callback for the HTTP transport app */
int http_certmint_async_req (app_crypto_async_req_t *req);

/** Configure the minting CA from PEM (main thread). Both lengths zero
    switches minting off. Other plugins reach it through
    vlib_get_plugin_symbol ("http_plugin.so", "http_certmint_set_ca"). */
int http_certmint_set_ca (u8 *cert_pem, u32 cert_len, u8 *key_pem,
			  u32 key_len);

typedef int (http_certmint_set_ca_fn) (u8 *, u32, u8 *, u32);

#endif /* SRC_PLUGINS_HTTP_HTTP_CERTMINT_H_ */
