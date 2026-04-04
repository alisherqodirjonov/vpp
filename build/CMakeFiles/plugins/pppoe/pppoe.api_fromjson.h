/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/ethernet/ethernet_types.api_fromjson.h>
#include <vnet/ip/ip_types.api_fromjson.h>
#ifndef included_pppoe_api_fromjson_h
#define included_pppoe_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_pppoe_add_del_session_t *vl_api_pppoe_add_del_session_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pppoe_add_del_session_t);
    vl_api_pppoe_add_del_session_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "session_id");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->session_id);

    item = cJSON_GetObjectItem(o, "client_ip");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->client_ip) < 0) goto error;

    item = cJSON_GetObjectItem(o, "decap_vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->decap_vrf_id);

    item = cJSON_GetObjectItem(o, "client_mac");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->client_mac) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pppoe_add_del_session_reply_t *vl_api_pppoe_add_del_session_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pppoe_add_del_session_reply_t);
    vl_api_pppoe_add_del_session_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_pppoe_session_dump_t *vl_api_pppoe_session_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pppoe_session_dump_t);
    vl_api_pppoe_session_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pppoe_session_details_t *vl_api_pppoe_session_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pppoe_session_details_t);
    vl_api_pppoe_session_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "session_id");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->session_id);

    item = cJSON_GetObjectItem(o, "client_ip");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->client_ip) < 0) goto error;

    item = cJSON_GetObjectItem(o, "encap_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->encap_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "decap_vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->decap_vrf_id);

    item = cJSON_GetObjectItem(o, "local_mac");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->local_mac) < 0) goto error;

    item = cJSON_GetObjectItem(o, "client_mac");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->client_mac) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pppoe_add_del_cp_t *vl_api_pppoe_add_del_cp_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pppoe_add_del_cp_t);
    vl_api_pppoe_add_del_cp_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->is_add);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pppoe_add_del_cp_reply_t *vl_api_pppoe_add_del_cp_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pppoe_add_del_cp_reply_t);
    vl_api_pppoe_add_del_cp_reply_t *a = cJSON_malloc(l);

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
