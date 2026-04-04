/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/ip/ip_types.api_fromjson.h>
#include <vnet/srv6/sr_types.api_fromjson.h>
#include <vnet/srv6/sr.api_fromjson.h>
#include <srv6-mobile/sr_mobile_types.api_fromjson.h>
#ifndef included_sr_mobile_api_fromjson_h
#define included_sr_mobile_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_sr_mobile_localsid_add_del_t *vl_api_sr_mobile_localsid_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_mobile_localsid_add_del_t);
    vl_api_sr_mobile_localsid_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_del");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_del);

    item = cJSON_GetObjectItem(o, "localsid_prefix");
    if (!item) goto error;
    if (vl_api_ip6_prefix_t_fromjson((void **)&a, &l, item, &a->localsid_prefix) < 0) goto error;

    item = cJSON_GetObjectItem(o, "behavior");
    if (!item) goto error;
    strncpy_s((char *)a->behavior, sizeof(a->behavior), cJSON_GetStringValue(item), sizeof(a->behavior) - 1);

    item = cJSON_GetObjectItem(o, "fib_table");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->fib_table);

    item = cJSON_GetObjectItem(o, "local_fib_table");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->local_fib_table);

    item = cJSON_GetObjectItem(o, "drop_in");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->drop_in);

    item = cJSON_GetObjectItem(o, "nhtype");
    if (!item) goto error;
    if (vl_api_sr_mobile_nhtype_t_fromjson((void **)&a, &l, item, &a->nhtype) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sr_prefix");
    if (!item) goto error;
    if (vl_api_ip6_prefix_t_fromjson((void **)&a, &l, item, &a->sr_prefix) < 0) goto error;

    item = cJSON_GetObjectItem(o, "v4src_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->v4src_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "v4src_position");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->v4src_position);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_mobile_localsid_add_del_reply_t *vl_api_sr_mobile_localsid_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_mobile_localsid_add_del_reply_t);
    vl_api_sr_mobile_localsid_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_mobile_policy_add_t *vl_api_sr_mobile_policy_add_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_mobile_policy_add_t);
    vl_api_sr_mobile_policy_add_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bsid_addr");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->bsid_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sr_prefix");
    if (!item) goto error;
    if (vl_api_ip6_prefix_t_fromjson((void **)&a, &l, item, &a->sr_prefix) < 0) goto error;

    item = cJSON_GetObjectItem(o, "v6src_prefix");
    if (!item) goto error;
    if (vl_api_ip6_prefix_t_fromjson((void **)&a, &l, item, &a->v6src_prefix) < 0) goto error;

    item = cJSON_GetObjectItem(o, "behavior");
    if (!item) goto error;
    strncpy_s((char *)a->behavior, sizeof(a->behavior), cJSON_GetStringValue(item), sizeof(a->behavior) - 1);

    item = cJSON_GetObjectItem(o, "fib_table");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->fib_table);

    item = cJSON_GetObjectItem(o, "local_fib_table");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->local_fib_table);

    item = cJSON_GetObjectItem(o, "encap_src");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->encap_src) < 0) goto error;

    item = cJSON_GetObjectItem(o, "drop_in");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->drop_in);

    item = cJSON_GetObjectItem(o, "nhtype");
    if (!item) goto error;
    if (vl_api_sr_mobile_nhtype_t_fromjson((void **)&a, &l, item, &a->nhtype) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_mobile_policy_add_reply_t *vl_api_sr_mobile_policy_add_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_mobile_policy_add_reply_t);
    vl_api_sr_mobile_policy_add_reply_t *a = cJSON_malloc(l);

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
