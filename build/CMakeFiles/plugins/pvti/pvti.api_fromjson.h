/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/ip/ip_types.api_fromjson.h>
#ifndef included_pvti_api_fromjson_h
#define included_pvti_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_pvti_tunnel_t_fromjson (void **mp, int *len, cJSON *o, vl_api_pvti_tunnel_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson(mp, len, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "local_ip");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->local_ip) < 0) goto error;

    item = cJSON_GetObjectItem(o, "local_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->local_port);

    item = cJSON_GetObjectItem(o, "remote_ip");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->remote_ip) < 0) goto error;

    item = cJSON_GetObjectItem(o, "peer_address_from_payload");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->peer_address_from_payload);

    item = cJSON_GetObjectItem(o, "remote_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->remote_port);

    item = cJSON_GetObjectItem(o, "underlay_mtu");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->underlay_mtu);

    item = cJSON_GetObjectItem(o, "underlay_fib_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->underlay_fib_index);

    return 0;

  error:
    return -1;
}
static inline vl_api_pvti_interface_create_t *vl_api_pvti_interface_create_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pvti_interface_create_t);
    vl_api_pvti_interface_create_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "interface");
    if (!item) goto error;
    if (vl_api_pvti_tunnel_t_fromjson((void **)&a, &l, item, &a->interface) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pvti_interface_create_reply_t *vl_api_pvti_interface_create_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pvti_interface_create_reply_t);
    vl_api_pvti_interface_create_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_pvti_interface_delete_t *vl_api_pvti_interface_delete_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pvti_interface_delete_t);
    vl_api_pvti_interface_delete_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pvti_interface_delete_reply_t *vl_api_pvti_interface_delete_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pvti_interface_delete_reply_t);
    vl_api_pvti_interface_delete_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pvti_interface_dump_t *vl_api_pvti_interface_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pvti_interface_dump_t);
    vl_api_pvti_interface_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pvti_interface_details_t *vl_api_pvti_interface_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pvti_interface_details_t);
    vl_api_pvti_interface_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "interface");
    if (!item) goto error;
    if (vl_api_pvti_tunnel_t_fromjson((void **)&a, &l, item, &a->interface) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
