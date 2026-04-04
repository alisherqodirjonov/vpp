/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/ip/ip_types.api_fromjson.h>
#ifndef included_wireguard_api_fromjson_h
#define included_wireguard_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_wireguard_interface_t_fromjson (void **mp, int *len, cJSON *o, vl_api_wireguard_interface_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "user_instance");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->user_instance);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson(mp, len, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "private_key");
    if (!item) goto error;
    if (u8string_fromjson2(o, "private_key", a->private_key) < 0) goto error;

    item = cJSON_GetObjectItem(o, "public_key");
    if (!item) goto error;
    if (u8string_fromjson2(o, "public_key", a->public_key) < 0) goto error;

    item = cJSON_GetObjectItem(o, "port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->port);

    item = cJSON_GetObjectItem(o, "src_ip");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->src_ip) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_wireguard_peer_flags_t_fromjson(void **mp, int *len, cJSON *o, vl_api_wireguard_peer_flags_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "WIREGUARD_PEER_STATUS_DEAD") == 0) {*a = 1; return 0;}
    if (strcmp(p, "WIREGUARD_PEER_ESTABLISHED") == 0) {*a = 2; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_wireguard_peer_t_fromjson (void **mp, int *len, cJSON *o, vl_api_wireguard_peer_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "peer_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->peer_index);

    item = cJSON_GetObjectItem(o, "public_key");
    if (!item) goto error;
    if (u8string_fromjson2(o, "public_key", a->public_key) < 0) goto error;

    item = cJSON_GetObjectItem(o, "port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->port);

    item = cJSON_GetObjectItem(o, "persistent_keepalive");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->persistent_keepalive);

    item = cJSON_GetObjectItem(o, "table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_id);

    item = cJSON_GetObjectItem(o, "endpoint");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->endpoint) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson(mp, len, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_wireguard_peer_flags_t_fromjson(mp, len, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "allowed_ips");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "allowed_ips");
        int size = cJSON_GetArraySize(array);
        a->n_allowed_ips = size;
        *mp = cJSON_realloc(*mp, *len + sizeof(vl_api_prefix_t) * size);
        vl_api_prefix_t *d = (void *)*mp + *len;
        *len += sizeof(vl_api_prefix_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_prefix_t_fromjson(mp, len, e, &d[i]) < 0) goto error; 
        }
    }

    return 0;

  error:
    return -1;
}
static inline vl_api_wireguard_interface_create_t *vl_api_wireguard_interface_create_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_wireguard_interface_create_t);
    vl_api_wireguard_interface_create_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "interface");
    if (!item) goto error;
    if (vl_api_wireguard_interface_t_fromjson((void **)&a, &l, item, &a->interface) < 0) goto error;

    item = cJSON_GetObjectItem(o, "generate_key");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->generate_key);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_wireguard_interface_create_reply_t *vl_api_wireguard_interface_create_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_wireguard_interface_create_reply_t);
    vl_api_wireguard_interface_create_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_wireguard_interface_delete_t *vl_api_wireguard_interface_delete_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_wireguard_interface_delete_t);
    vl_api_wireguard_interface_delete_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_wireguard_interface_delete_reply_t *vl_api_wireguard_interface_delete_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_wireguard_interface_delete_reply_t);
    vl_api_wireguard_interface_delete_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_wireguard_interface_dump_t *vl_api_wireguard_interface_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_wireguard_interface_dump_t);
    vl_api_wireguard_interface_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "show_private_key");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->show_private_key);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_wireguard_interface_details_t *vl_api_wireguard_interface_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_wireguard_interface_details_t);
    vl_api_wireguard_interface_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "interface");
    if (!item) goto error;
    if (vl_api_wireguard_interface_t_fromjson((void **)&a, &l, item, &a->interface) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_want_wireguard_peer_events_t *vl_api_want_wireguard_peer_events_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_want_wireguard_peer_events_t);
    vl_api_want_wireguard_peer_events_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "peer_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->peer_index);

    item = cJSON_GetObjectItem(o, "enable_disable");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->enable_disable);

    item = cJSON_GetObjectItem(o, "pid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->pid);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_want_wireguard_peer_events_reply_t *vl_api_want_wireguard_peer_events_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_want_wireguard_peer_events_reply_t);
    vl_api_want_wireguard_peer_events_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_wireguard_peer_event_t *vl_api_wireguard_peer_event_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_wireguard_peer_event_t);
    vl_api_wireguard_peer_event_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "pid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->pid);

    item = cJSON_GetObjectItem(o, "peer_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->peer_index);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_wireguard_peer_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_wireguard_peer_add_t *vl_api_wireguard_peer_add_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_wireguard_peer_add_t);
    vl_api_wireguard_peer_add_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "peer");
    if (!item) goto error;
    if (vl_api_wireguard_peer_t_fromjson((void **)&a, &l, item, &a->peer) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_wireguard_peer_add_reply_t *vl_api_wireguard_peer_add_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_wireguard_peer_add_reply_t);
    vl_api_wireguard_peer_add_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "peer_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->peer_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_wireguard_peer_remove_t *vl_api_wireguard_peer_remove_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_wireguard_peer_remove_t);
    vl_api_wireguard_peer_remove_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "peer_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->peer_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_wireguard_peer_remove_reply_t *vl_api_wireguard_peer_remove_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_wireguard_peer_remove_reply_t);
    vl_api_wireguard_peer_remove_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_wireguard_peers_dump_t *vl_api_wireguard_peers_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_wireguard_peers_dump_t);
    vl_api_wireguard_peers_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "peer_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->peer_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_wireguard_peers_details_t *vl_api_wireguard_peers_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_wireguard_peers_details_t);
    vl_api_wireguard_peers_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "peer");
    if (!item) goto error;
    if (vl_api_wireguard_peer_t_fromjson((void **)&a, &l, item, &a->peer) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_wg_set_async_mode_t *vl_api_wg_set_async_mode_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_wg_set_async_mode_t);
    vl_api_wg_set_async_mode_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "async_enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->async_enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_wg_set_async_mode_reply_t *vl_api_wg_set_async_mode_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_wg_set_async_mode_reply_t);
    vl_api_wg_set_async_mode_reply_t *a = cJSON_malloc(l);

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
