/* Imported API files */
#ifndef included_crypto_sw_scheduler_api_fromjson_h
#define included_crypto_sw_scheduler_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_crypto_sw_scheduler_set_worker_t *vl_api_crypto_sw_scheduler_set_worker_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_crypto_sw_scheduler_set_worker_t);
    vl_api_crypto_sw_scheduler_set_worker_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "worker_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->worker_index);

    item = cJSON_GetObjectItem(o, "crypto_enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->crypto_enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_crypto_sw_scheduler_set_worker_reply_t *vl_api_crypto_sw_scheduler_set_worker_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_crypto_sw_scheduler_set_worker_reply_t);
    vl_api_crypto_sw_scheduler_set_worker_reply_t *a = cJSON_malloc(l);

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
