/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#ifndef included_adl_api_fromjson_h
#define included_adl_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_adl_interface_enable_disable_t *vl_api_adl_interface_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_adl_interface_enable_disable_t);
    vl_api_adl_interface_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "enable_disable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable_disable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_adl_interface_enable_disable_reply_t *vl_api_adl_interface_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_adl_interface_enable_disable_reply_t);
    vl_api_adl_interface_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_adl_allowlist_enable_disable_t *vl_api_adl_allowlist_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_adl_allowlist_enable_disable_t);
    vl_api_adl_allowlist_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "fib_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->fib_id);

    item = cJSON_GetObjectItem(o, "ip4");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->ip4);

    item = cJSON_GetObjectItem(o, "ip6");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->ip6);

    item = cJSON_GetObjectItem(o, "default_adl");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->default_adl);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_adl_allowlist_enable_disable_reply_t *vl_api_adl_allowlist_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_adl_allowlist_enable_disable_reply_t);
    vl_api_adl_allowlist_enable_disable_reply_t *a = cJSON_malloc(l);

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
