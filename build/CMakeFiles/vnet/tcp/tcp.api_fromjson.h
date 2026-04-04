/* Imported API files */
#include <vnet/ip/ip_types.api_fromjson.h>
#ifndef included_tcp_api_fromjson_h
#define included_tcp_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_tcp_configure_src_addresses_t *vl_api_tcp_configure_src_addresses_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_tcp_configure_src_addresses_t);
    vl_api_tcp_configure_src_addresses_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    item = cJSON_GetObjectItem(o, "first_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->first_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "last_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->last_address) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_tcp_configure_src_addresses_reply_t *vl_api_tcp_configure_src_addresses_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_tcp_configure_src_addresses_reply_t);
    vl_api_tcp_configure_src_addresses_reply_t *a = cJSON_malloc(l);

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
