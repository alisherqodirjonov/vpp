/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/ip/ip_types.api_fromjson.h>
#include <vnet/ethernet/ethernet_types.api_fromjson.h>
#ifndef included_arping_api_fromjson_h
#define included_arping_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_arping_t *vl_api_arping_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_arping_t);
    vl_api_arping_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_garp");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_garp);

    item = cJSON_GetObjectItem(o, "repeat");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->repeat);

    item = cJSON_GetObjectItem(o, "interval");
    if (!item) goto error;
    vl_api_f64_fromjson(item, &a->interval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_arping_reply_t *vl_api_arping_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_arping_reply_t);
    vl_api_arping_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "reply_count");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->reply_count);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_arping_acd_t *vl_api_arping_acd_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_arping_acd_t);
    vl_api_arping_acd_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_garp");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_garp);

    item = cJSON_GetObjectItem(o, "repeat");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->repeat);

    item = cJSON_GetObjectItem(o, "interval");
    if (!item) goto error;
    vl_api_f64_fromjson(item, &a->interval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_arping_acd_reply_t *vl_api_arping_acd_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_arping_acd_reply_t);
    vl_api_arping_acd_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "reply_count");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->reply_count);

    item = cJSON_GetObjectItem(o, "mac_address");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->mac_address) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
