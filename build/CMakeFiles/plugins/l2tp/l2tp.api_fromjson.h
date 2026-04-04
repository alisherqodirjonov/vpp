/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/ethernet/ethernet_types.api_fromjson.h>
#include <vnet/ip/ip_types.api_fromjson.h>
#ifndef included_l2tp_api_fromjson_h
#define included_l2tp_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_l2t_lookup_key_t_fromjson(void **mp, int *len, cJSON *o, vl_api_l2t_lookup_key_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "L2T_LOOKUP_KEY_API_SRC_ADDR") == 0) {*a = 0; return 0;}
    if (strcmp(p, "L2T_LOOKUP_KEY_API_DST_ADDR") == 0) {*a = 1; return 0;}
    if (strcmp(p, "L2T_LOOKUP_KEY_API_SESSION_ID") == 0) {*a = 2; return 0;}
    *a = 0;
    return -1;
}
static inline vl_api_l2tpv3_create_tunnel_t *vl_api_l2tpv3_create_tunnel_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_l2tpv3_create_tunnel_t);
    vl_api_l2tpv3_create_tunnel_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "client_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->client_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "our_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->our_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "local_session_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->local_session_id);

    item = cJSON_GetObjectItem(o, "remote_session_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->remote_session_id);

    item = cJSON_GetObjectItem(o, "local_cookie");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->local_cookie);

    item = cJSON_GetObjectItem(o, "remote_cookie");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->remote_cookie);

    item = cJSON_GetObjectItem(o, "l2_sublayer_present");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->l2_sublayer_present);

    item = cJSON_GetObjectItem(o, "encap_vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->encap_vrf_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_l2tpv3_create_tunnel_reply_t *vl_api_l2tpv3_create_tunnel_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_l2tpv3_create_tunnel_reply_t);
    vl_api_l2tpv3_create_tunnel_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_l2tpv3_set_tunnel_cookies_t *vl_api_l2tpv3_set_tunnel_cookies_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_l2tpv3_set_tunnel_cookies_t);
    vl_api_l2tpv3_set_tunnel_cookies_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "new_local_cookie");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->new_local_cookie);

    item = cJSON_GetObjectItem(o, "new_remote_cookie");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->new_remote_cookie);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_l2tpv3_set_tunnel_cookies_reply_t *vl_api_l2tpv3_set_tunnel_cookies_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_l2tpv3_set_tunnel_cookies_reply_t);
    vl_api_l2tpv3_set_tunnel_cookies_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_if_l2tpv3_tunnel_details_t *vl_api_sw_if_l2tpv3_tunnel_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_if_l2tpv3_tunnel_details_t);
    vl_api_sw_if_l2tpv3_tunnel_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "interface_name");
    if (!item) goto error;
    strncpy_s((char *)a->interface_name, sizeof(a->interface_name), cJSON_GetStringValue(item), sizeof(a->interface_name) - 1);

    item = cJSON_GetObjectItem(o, "client_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->client_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "our_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->our_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "local_session_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->local_session_id);

    item = cJSON_GetObjectItem(o, "remote_session_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->remote_session_id);

    item = cJSON_GetObjectItem(o, "local_cookie");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "local_cookie");
        int size = cJSON_GetArraySize(array);
        if (size != 2) goto error;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_u64_fromjson(e, &a->local_cookie[i]);
        }
    }

    item = cJSON_GetObjectItem(o, "remote_cookie");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->remote_cookie);

    item = cJSON_GetObjectItem(o, "l2_sublayer_present");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->l2_sublayer_present);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_if_l2tpv3_tunnel_dump_t *vl_api_sw_if_l2tpv3_tunnel_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_if_l2tpv3_tunnel_dump_t);
    vl_api_sw_if_l2tpv3_tunnel_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_l2tpv3_interface_enable_disable_t *vl_api_l2tpv3_interface_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_l2tpv3_interface_enable_disable_t);
    vl_api_l2tpv3_interface_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "enable_disable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable_disable);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_l2tpv3_interface_enable_disable_reply_t *vl_api_l2tpv3_interface_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_l2tpv3_interface_enable_disable_reply_t);
    vl_api_l2tpv3_interface_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_l2tpv3_set_lookup_key_t *vl_api_l2tpv3_set_lookup_key_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_l2tpv3_set_lookup_key_t);
    vl_api_l2tpv3_set_lookup_key_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "key");
    if (!item) goto error;
    if (vl_api_l2t_lookup_key_t_fromjson((void **)&a, &l, item, &a->key) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_l2tpv3_set_lookup_key_reply_t *vl_api_l2tpv3_set_lookup_key_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_l2tpv3_set_lookup_key_reply_t);
    vl_api_l2tpv3_set_lookup_key_reply_t *a = cJSON_malloc(l);

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
