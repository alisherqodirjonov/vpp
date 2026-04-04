/* Imported API files */
#ifndef included_tls_openssl_api_fromjson_h
#define included_tls_openssl_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_tls_openssl_set_engine_t *vl_api_tls_openssl_set_engine_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_tls_openssl_set_engine_t);
    vl_api_tls_openssl_set_engine_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "async_enable");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->async_enable);

    item = cJSON_GetObjectItem(o, "engine");
    if (!item) goto error;
    if (u8string_fromjson2(o, "engine", a->engine) < 0) goto error;

    item = cJSON_GetObjectItem(o, "algorithm");
    if (!item) goto error;
    if (u8string_fromjson2(o, "algorithm", a->algorithm) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ciphers");
    if (!item) goto error;
    if (u8string_fromjson2(o, "ciphers", a->ciphers) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_tls_openssl_set_engine_reply_t *vl_api_tls_openssl_set_engine_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_tls_openssl_set_engine_reply_t);
    vl_api_tls_openssl_set_engine_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
