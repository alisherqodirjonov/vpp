/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/ip/ip_types.api_fromjson.h>
#include <vnet/ethernet/ethernet_types.api_fromjson.h>
#ifndef included_vrrp_api_fromjson_h
#define included_vrrp_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_vrrp_vr_key_t_fromjson (void **mp, int *len, cJSON *o, vl_api_vrrp_vr_key_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson(mp, len, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vr_id");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->vr_id);

    item = cJSON_GetObjectItem(o, "is_ipv6");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->is_ipv6);

    return 0;

  error:
    return -1;
}
static inline int vl_api_vrrp_vr_flags_t_fromjson(void **mp, int *len, cJSON *o, vl_api_vrrp_vr_flags_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "VRRP_API_VR_PREEMPT") == 0) {*a = 1; return 0;}
    if (strcmp(p, "VRRP_API_VR_ACCEPT") == 0) {*a = 2; return 0;}
    if (strcmp(p, "VRRP_API_VR_UNICAST") == 0) {*a = 4; return 0;}
    if (strcmp(p, "VRRP_API_VR_IPV6") == 0) {*a = 8; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_vrrp_vr_conf_t_fromjson (void **mp, int *len, cJSON *o, vl_api_vrrp_vr_conf_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson(mp, len, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vr_id");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->vr_id);

    item = cJSON_GetObjectItem(o, "priority");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->priority);

    item = cJSON_GetObjectItem(o, "interval");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->interval);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_vrrp_vr_flags_t_fromjson(mp, len, item, &a->flags) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_vrrp_vr_state_t_fromjson(void **mp, int *len, cJSON *o, vl_api_vrrp_vr_state_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "VRRP_API_VR_STATE_INIT") == 0) {*a = 0; return 0;}
    if (strcmp(p, "VRRP_API_VR_STATE_BACKUP") == 0) {*a = 1; return 0;}
    if (strcmp(p, "VRRP_API_VR_STATE_MASTER") == 0) {*a = 2; return 0;}
    if (strcmp(p, "VRRP_API_VR_STATE_INTF_DOWN") == 0) {*a = 3; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_vrrp_vr_tracking_t_fromjson (void **mp, int *len, cJSON *o, vl_api_vrrp_vr_tracking_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "interfaces_dec");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->interfaces_dec);

    item = cJSON_GetObjectItem(o, "priority");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->priority);

    return 0;

  error:
    return -1;
}
static inline int vl_api_vrrp_vr_runtime_t_fromjson (void **mp, int *len, cJSON *o, vl_api_vrrp_vr_runtime_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "state");
    if (!item) goto error;
    if (vl_api_vrrp_vr_state_t_fromjson(mp, len, item, &a->state) < 0) goto error;

    item = cJSON_GetObjectItem(o, "master_adv_int");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->master_adv_int);

    item = cJSON_GetObjectItem(o, "skew");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->skew);

    item = cJSON_GetObjectItem(o, "master_down_int");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->master_down_int);

    item = cJSON_GetObjectItem(o, "mac");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson(mp, len, item, &a->mac) < 0) goto error;

    item = cJSON_GetObjectItem(o, "tracking");
    if (!item) goto error;
    if (vl_api_vrrp_vr_tracking_t_fromjson(mp, len, item, &a->tracking) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_vrrp_vr_track_if_t_fromjson (void **mp, int *len, cJSON *o, vl_api_vrrp_vr_track_if_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson(mp, len, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "priority");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->priority);

    return 0;

  error:
    return -1;
}
static inline vl_api_vrrp_vr_add_del_t *vl_api_vrrp_vr_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vrrp_vr_add_del_t);
    vl_api_vrrp_vr_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vr_id");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->vr_id);

    item = cJSON_GetObjectItem(o, "priority");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->priority);

    item = cJSON_GetObjectItem(o, "interval");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->interval);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_vrrp_vr_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "addrs");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "addrs");
        int size = cJSON_GetArraySize(array);
        a->n_addrs = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_address_t) * size);
        vl_api_address_t *d = (void *)a + l;
        l += sizeof(vl_api_address_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_address_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vrrp_vr_add_del_reply_t *vl_api_vrrp_vr_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vrrp_vr_add_del_reply_t);
    vl_api_vrrp_vr_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vrrp_vr_update_t *vl_api_vrrp_vr_update_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vrrp_vr_update_t);
    vl_api_vrrp_vr_update_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "vrrp_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrrp_index);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vr_id");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->vr_id);

    item = cJSON_GetObjectItem(o, "priority");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->priority);

    item = cJSON_GetObjectItem(o, "interval");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->interval);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_vrrp_vr_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "addrs");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "addrs");
        int size = cJSON_GetArraySize(array);
        a->n_addrs = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_address_t) * size);
        vl_api_address_t *d = (void *)a + l;
        l += sizeof(vl_api_address_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_address_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vrrp_vr_update_reply_t *vl_api_vrrp_vr_update_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vrrp_vr_update_reply_t);
    vl_api_vrrp_vr_update_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "vrrp_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrrp_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vrrp_vr_del_t *vl_api_vrrp_vr_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vrrp_vr_del_t);
    vl_api_vrrp_vr_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "vrrp_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrrp_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vrrp_vr_del_reply_t *vl_api_vrrp_vr_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vrrp_vr_del_reply_t);
    vl_api_vrrp_vr_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vrrp_vr_dump_t *vl_api_vrrp_vr_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vrrp_vr_dump_t);
    vl_api_vrrp_vr_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vrrp_vr_details_t *vl_api_vrrp_vr_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vrrp_vr_details_t);
    vl_api_vrrp_vr_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "config");
    if (!item) goto error;
    if (vl_api_vrrp_vr_conf_t_fromjson((void **)&a, &l, item, &a->config) < 0) goto error;

    item = cJSON_GetObjectItem(o, "runtime");
    if (!item) goto error;
    if (vl_api_vrrp_vr_runtime_t_fromjson((void **)&a, &l, item, &a->runtime) < 0) goto error;

    item = cJSON_GetObjectItem(o, "addrs");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "addrs");
        int size = cJSON_GetArraySize(array);
        a->n_addrs = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_address_t) * size);
        vl_api_address_t *d = (void *)a + l;
        l += sizeof(vl_api_address_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_address_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vrrp_vr_start_stop_t *vl_api_vrrp_vr_start_stop_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vrrp_vr_start_stop_t);
    vl_api_vrrp_vr_start_stop_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vr_id");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->vr_id);

    item = cJSON_GetObjectItem(o, "is_ipv6");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->is_ipv6);

    item = cJSON_GetObjectItem(o, "is_start");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->is_start);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vrrp_vr_start_stop_reply_t *vl_api_vrrp_vr_start_stop_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vrrp_vr_start_stop_reply_t);
    vl_api_vrrp_vr_start_stop_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vrrp_vr_set_peers_t *vl_api_vrrp_vr_set_peers_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vrrp_vr_set_peers_t);
    vl_api_vrrp_vr_set_peers_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vr_id");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->vr_id);

    item = cJSON_GetObjectItem(o, "is_ipv6");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->is_ipv6);

    item = cJSON_GetObjectItem(o, "addrs");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "addrs");
        int size = cJSON_GetArraySize(array);
        a->n_addrs = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_address_t) * size);
        vl_api_address_t *d = (void *)a + l;
        l += sizeof(vl_api_address_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_address_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vrrp_vr_set_peers_reply_t *vl_api_vrrp_vr_set_peers_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vrrp_vr_set_peers_reply_t);
    vl_api_vrrp_vr_set_peers_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vrrp_vr_peer_dump_t *vl_api_vrrp_vr_peer_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vrrp_vr_peer_dump_t);
    vl_api_vrrp_vr_peer_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_ipv6");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->is_ipv6);

    item = cJSON_GetObjectItem(o, "vr_id");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->vr_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vrrp_vr_peer_details_t *vl_api_vrrp_vr_peer_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vrrp_vr_peer_details_t);
    vl_api_vrrp_vr_peer_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vr_id");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->vr_id);

    item = cJSON_GetObjectItem(o, "is_ipv6");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->is_ipv6);

    item = cJSON_GetObjectItem(o, "peer_addrs");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "peer_addrs");
        int size = cJSON_GetArraySize(array);
        a->n_peer_addrs = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_address_t) * size);
        vl_api_address_t *d = (void *)a + l;
        l += sizeof(vl_api_address_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_address_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vrrp_vr_track_if_add_del_t *vl_api_vrrp_vr_track_if_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vrrp_vr_track_if_add_del_t);
    vl_api_vrrp_vr_track_if_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_ipv6");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->is_ipv6);

    item = cJSON_GetObjectItem(o, "vr_id");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->vr_id);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "ifs");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "ifs");
        int size = cJSON_GetArraySize(array);
        a->n_ifs = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_vrrp_vr_track_if_t) * size);
        vl_api_vrrp_vr_track_if_t *d = (void *)a + l;
        l += sizeof(vl_api_vrrp_vr_track_if_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_vrrp_vr_track_if_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vrrp_vr_track_if_add_del_reply_t *vl_api_vrrp_vr_track_if_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vrrp_vr_track_if_add_del_reply_t);
    vl_api_vrrp_vr_track_if_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vrrp_vr_track_if_dump_t *vl_api_vrrp_vr_track_if_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vrrp_vr_track_if_dump_t);
    vl_api_vrrp_vr_track_if_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_ipv6");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->is_ipv6);

    item = cJSON_GetObjectItem(o, "vr_id");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->vr_id);

    item = cJSON_GetObjectItem(o, "dump_all");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->dump_all);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vrrp_vr_track_if_details_t *vl_api_vrrp_vr_track_if_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vrrp_vr_track_if_details_t);
    vl_api_vrrp_vr_track_if_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vr_id");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->vr_id);

    item = cJSON_GetObjectItem(o, "is_ipv6");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->is_ipv6);

    item = cJSON_GetObjectItem(o, "ifs");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "ifs");
        int size = cJSON_GetArraySize(array);
        a->n_ifs = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_vrrp_vr_track_if_t) * size);
        vl_api_vrrp_vr_track_if_t *d = (void *)a + l;
        l += sizeof(vl_api_vrrp_vr_track_if_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_vrrp_vr_track_if_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vrrp_vr_event_t *vl_api_vrrp_vr_event_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vrrp_vr_event_t);
    vl_api_vrrp_vr_event_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "pid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->pid);

    item = cJSON_GetObjectItem(o, "vr");
    if (!item) goto error;
    if (vl_api_vrrp_vr_key_t_fromjson((void **)&a, &l, item, &a->vr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "old_state");
    if (!item) goto error;
    if (vl_api_vrrp_vr_state_t_fromjson((void **)&a, &l, item, &a->old_state) < 0) goto error;

    item = cJSON_GetObjectItem(o, "new_state");
    if (!item) goto error;
    if (vl_api_vrrp_vr_state_t_fromjson((void **)&a, &l, item, &a->new_state) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_want_vrrp_vr_events_t *vl_api_want_vrrp_vr_events_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_want_vrrp_vr_events_t);
    vl_api_want_vrrp_vr_events_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "enable_disable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable_disable);

    item = cJSON_GetObjectItem(o, "pid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->pid);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_want_vrrp_vr_events_reply_t *vl_api_want_vrrp_vr_events_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_want_vrrp_vr_events_reply_t);
    vl_api_want_vrrp_vr_events_reply_t *a = cJSON_malloc(l);

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
