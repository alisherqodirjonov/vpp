/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/ethernet/ethernet_types.api_fromjson.h>
#ifndef included_p2p_ethernet_api_fromjson_h
#define included_p2p_ethernet_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_p2p_ethernet_add_t *vl_api_p2p_ethernet_add_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_p2p_ethernet_add_t);
    vl_api_p2p_ethernet_add_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "parent_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->parent_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "subif_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->subif_id);

    item = cJSON_GetObjectItem(o, "remote_mac");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->remote_mac) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_p2p_ethernet_add_reply_t *vl_api_p2p_ethernet_add_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_p2p_ethernet_add_reply_t);
    vl_api_p2p_ethernet_add_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_p2p_ethernet_del_t *vl_api_p2p_ethernet_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_p2p_ethernet_del_t);
    vl_api_p2p_ethernet_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "parent_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->parent_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "remote_mac");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->remote_mac) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_p2p_ethernet_del_reply_t *vl_api_p2p_ethernet_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_p2p_ethernet_del_reply_t);
    vl_api_p2p_ethernet_del_reply_t *a = cJSON_malloc(l);

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
