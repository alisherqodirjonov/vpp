/* Imported API files */
#ifndef included_crypto_api_fromjson_h
#define included_crypto_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_crypto_dispatch_mode_t_fromjson(void **mp, int *len, cJSON *o, vl_api_crypto_dispatch_mode_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "CRYPTO_ASYNC_DISPATCH_POLLING") == 0) {*a = 0; return 0;}
    if (strcmp(p, "CRYPTO_ASYNC_DISPATCH_INTERRUPT") == 0) {*a = 1; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_crypto_op_class_type_t_fromjson(void **mp, int *len, cJSON *o, vl_api_crypto_op_class_type_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "CRYPTO_API_OP_SIMPLE") == 0) {*a = 0; return 0;}
    if (strcmp(p, "CRYPTO_API_OP_CHAINED") == 0) {*a = 1; return 0;}
    if (strcmp(p, "CRYPTO_API_OP_BOTH") == 0) {*a = 2; return 0;}
    *a = 0;
    return -1;
}
static inline vl_api_crypto_set_async_dispatch_t *vl_api_crypto_set_async_dispatch_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_crypto_set_async_dispatch_t);
    vl_api_crypto_set_async_dispatch_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "mode");
    if (!item) goto error;
    if (vl_api_crypto_dispatch_mode_t_fromjson((void **)&a, &l, item, &a->mode) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_crypto_set_async_dispatch_reply_t *vl_api_crypto_set_async_dispatch_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_crypto_set_async_dispatch_reply_t);
    vl_api_crypto_set_async_dispatch_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_crypto_set_async_dispatch_v2_t *vl_api_crypto_set_async_dispatch_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_crypto_set_async_dispatch_v2_t);
    vl_api_crypto_set_async_dispatch_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "mode");
    if (!item) goto error;
    if (vl_api_crypto_dispatch_mode_t_fromjson((void **)&a, &l, item, &a->mode) < 0) goto error;

    item = cJSON_GetObjectItem(o, "adaptive");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->adaptive);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_crypto_set_async_dispatch_v2_reply_t *vl_api_crypto_set_async_dispatch_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_crypto_set_async_dispatch_v2_reply_t);
    vl_api_crypto_set_async_dispatch_v2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_crypto_set_handler_t *vl_api_crypto_set_handler_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_crypto_set_handler_t);
    vl_api_crypto_set_handler_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "alg_name");
    if (!item) goto error;
    strncpy_s((char *)a->alg_name, sizeof(a->alg_name), cJSON_GetStringValue(item), sizeof(a->alg_name) - 1);

    item = cJSON_GetObjectItem(o, "engine");
    if (!item) goto error;
    strncpy_s((char *)a->engine, sizeof(a->engine), cJSON_GetStringValue(item), sizeof(a->engine) - 1);

    item = cJSON_GetObjectItem(o, "oct");
    if (!item) goto error;
    if (vl_api_crypto_op_class_type_t_fromjson((void **)&a, &l, item, &a->oct) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_async");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->is_async);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_crypto_set_handler_reply_t *vl_api_crypto_set_handler_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_crypto_set_handler_reply_t);
    vl_api_crypto_set_handler_reply_t *a = cJSON_malloc(l);

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
