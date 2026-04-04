/* Imported API files */
#include <vnet/ipsec/ipsec_types.api_fromjson.h>
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/ip/ip_types.api_fromjson.h>
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/tunnel/tunnel_types.api_fromjson.h>
#ifndef included_ipsec_api_fromjson_h
#define included_ipsec_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_ipsec_tunnel_protect_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ipsec_tunnel_protect_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson(mp, len, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "nh");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->nh) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sa_out");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sa_out);

    item = cJSON_GetObjectItem(o, "sa_in");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "sa_in");
        int size = cJSON_GetArraySize(array);
        a->n_sa_in = size;
        *mp = cJSON_realloc(*mp, *len + sizeof(u32) * size);
        u32 *d = (void *)*mp + *len;
        *len += sizeof(u32) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_u32_fromjson(e, &d[i]);
        }
    }

    return 0;

  error:
    return -1;
}
static inline int vl_api_ipsec_itf_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ipsec_itf_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "user_instance");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->user_instance);

    item = cJSON_GetObjectItem(o, "mode");
    if (!item) goto error;
    if (vl_api_tunnel_mode_t_fromjson(mp, len, item, &a->mode) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson(mp, len, item, &a->sw_if_index) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline vl_api_ipsec_spd_add_del_t *vl_api_ipsec_spd_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_spd_add_del_t);
    vl_api_ipsec_spd_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "spd_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->spd_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_spd_add_del_reply_t *vl_api_ipsec_spd_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_spd_add_del_reply_t);
    vl_api_ipsec_spd_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_interface_add_del_spd_t *vl_api_ipsec_interface_add_del_spd_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_interface_add_del_spd_t);
    vl_api_ipsec_interface_add_del_spd_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "spd_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->spd_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_interface_add_del_spd_reply_t *vl_api_ipsec_interface_add_del_spd_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_interface_add_del_spd_reply_t);
    vl_api_ipsec_interface_add_del_spd_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_spd_entry_add_del_t *vl_api_ipsec_spd_entry_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_spd_entry_add_del_t);
    vl_api_ipsec_spd_entry_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "entry");
    if (!item) goto error;
    if (vl_api_ipsec_spd_entry_t_fromjson((void **)&a, &l, item, &a->entry) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_spd_entry_add_del_v2_t *vl_api_ipsec_spd_entry_add_del_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_spd_entry_add_del_v2_t);
    vl_api_ipsec_spd_entry_add_del_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "entry");
    if (!item) goto error;
    if (vl_api_ipsec_spd_entry_v2_t_fromjson((void **)&a, &l, item, &a->entry) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_spd_entry_add_del_reply_t *vl_api_ipsec_spd_entry_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_spd_entry_add_del_reply_t);
    vl_api_ipsec_spd_entry_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "stat_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->stat_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_spd_entry_add_del_v2_reply_t *vl_api_ipsec_spd_entry_add_del_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_spd_entry_add_del_v2_reply_t);
    vl_api_ipsec_spd_entry_add_del_v2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "stat_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->stat_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_spds_dump_t *vl_api_ipsec_spds_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_spds_dump_t);
    vl_api_ipsec_spds_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_ipsec_spds_details_t *vl_api_ipsec_spds_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_spds_details_t);
    vl_api_ipsec_spds_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "spd_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->spd_id);

    item = cJSON_GetObjectItem(o, "npolicies");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->npolicies);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_spd_dump_t *vl_api_ipsec_spd_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_spd_dump_t);
    vl_api_ipsec_spd_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "spd_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->spd_id);

    item = cJSON_GetObjectItem(o, "sa_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sa_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_spd_details_t *vl_api_ipsec_spd_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_spd_details_t);
    vl_api_ipsec_spd_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "entry");
    if (!item) goto error;
    if (vl_api_ipsec_spd_entry_t_fromjson((void **)&a, &l, item, &a->entry) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_sad_entry_add_del_t *vl_api_ipsec_sad_entry_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_sad_entry_add_del_t);
    vl_api_ipsec_sad_entry_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "entry");
    if (!item) goto error;
    if (vl_api_ipsec_sad_entry_t_fromjson((void **)&a, &l, item, &a->entry) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_sad_entry_add_del_v2_t *vl_api_ipsec_sad_entry_add_del_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_sad_entry_add_del_v2_t);
    vl_api_ipsec_sad_entry_add_del_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "entry");
    if (!item) goto error;
    if (vl_api_ipsec_sad_entry_v2_t_fromjson((void **)&a, &l, item, &a->entry) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_sad_entry_add_del_v3_t *vl_api_ipsec_sad_entry_add_del_v3_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_sad_entry_add_del_v3_t);
    vl_api_ipsec_sad_entry_add_del_v3_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "entry");
    if (!item) goto error;
    if (vl_api_ipsec_sad_entry_v3_t_fromjson((void **)&a, &l, item, &a->entry) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_sad_entry_add_t *vl_api_ipsec_sad_entry_add_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_sad_entry_add_t);
    vl_api_ipsec_sad_entry_add_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "entry");
    if (!item) goto error;
    if (vl_api_ipsec_sad_entry_v3_t_fromjson((void **)&a, &l, item, &a->entry) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_sad_entry_add_v2_t *vl_api_ipsec_sad_entry_add_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_sad_entry_add_v2_t);
    vl_api_ipsec_sad_entry_add_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "entry");
    if (!item) goto error;
    if (vl_api_ipsec_sad_entry_v4_t_fromjson((void **)&a, &l, item, &a->entry) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_sad_entry_del_t *vl_api_ipsec_sad_entry_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_sad_entry_del_t);
    vl_api_ipsec_sad_entry_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_sad_entry_del_reply_t *vl_api_ipsec_sad_entry_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_sad_entry_del_reply_t);
    vl_api_ipsec_sad_entry_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_sad_bind_t *vl_api_ipsec_sad_bind_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_sad_bind_t);
    vl_api_ipsec_sad_bind_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sa_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sa_id);

    item = cJSON_GetObjectItem(o, "worker");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->worker);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_sad_bind_reply_t *vl_api_ipsec_sad_bind_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_sad_bind_reply_t);
    vl_api_ipsec_sad_bind_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_sad_unbind_t *vl_api_ipsec_sad_unbind_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_sad_unbind_t);
    vl_api_ipsec_sad_unbind_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sa_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sa_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_sad_unbind_reply_t *vl_api_ipsec_sad_unbind_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_sad_unbind_reply_t);
    vl_api_ipsec_sad_unbind_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_sad_entry_update_t *vl_api_ipsec_sad_entry_update_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_sad_entry_update_t);
    vl_api_ipsec_sad_entry_update_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sad_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sad_id);

    item = cJSON_GetObjectItem(o, "is_tun");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_tun);

    item = cJSON_GetObjectItem(o, "tunnel");
    if (!item) goto error;
    if (vl_api_tunnel_t_fromjson((void **)&a, &l, item, &a->tunnel) < 0) goto error;

    item = cJSON_GetObjectItem(o, "udp_src_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->udp_src_port);

    item = cJSON_GetObjectItem(o, "udp_dst_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->udp_dst_port);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_sad_entry_update_reply_t *vl_api_ipsec_sad_entry_update_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_sad_entry_update_reply_t);
    vl_api_ipsec_sad_entry_update_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_sad_entry_add_del_reply_t *vl_api_ipsec_sad_entry_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_sad_entry_add_del_reply_t);
    vl_api_ipsec_sad_entry_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "stat_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->stat_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_sad_entry_add_del_v2_reply_t *vl_api_ipsec_sad_entry_add_del_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_sad_entry_add_del_v2_reply_t);
    vl_api_ipsec_sad_entry_add_del_v2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "stat_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->stat_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_sad_entry_add_del_v3_reply_t *vl_api_ipsec_sad_entry_add_del_v3_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_sad_entry_add_del_v3_reply_t);
    vl_api_ipsec_sad_entry_add_del_v3_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "stat_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->stat_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_sad_entry_add_reply_t *vl_api_ipsec_sad_entry_add_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_sad_entry_add_reply_t);
    vl_api_ipsec_sad_entry_add_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "stat_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->stat_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_sad_entry_add_v2_reply_t *vl_api_ipsec_sad_entry_add_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_sad_entry_add_v2_reply_t);
    vl_api_ipsec_sad_entry_add_v2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "stat_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->stat_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_tunnel_protect_update_t *vl_api_ipsec_tunnel_protect_update_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_tunnel_protect_update_t);
    vl_api_ipsec_tunnel_protect_update_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "tunnel");
    if (!item) goto error;
    if (vl_api_ipsec_tunnel_protect_t_fromjson((void **)&a, &l, item, &a->tunnel) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_tunnel_protect_update_reply_t *vl_api_ipsec_tunnel_protect_update_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_tunnel_protect_update_reply_t);
    vl_api_ipsec_tunnel_protect_update_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_tunnel_protect_del_t *vl_api_ipsec_tunnel_protect_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_tunnel_protect_del_t);
    vl_api_ipsec_tunnel_protect_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "nh");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->nh) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_tunnel_protect_del_reply_t *vl_api_ipsec_tunnel_protect_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_tunnel_protect_del_reply_t);
    vl_api_ipsec_tunnel_protect_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_tunnel_protect_dump_t *vl_api_ipsec_tunnel_protect_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_tunnel_protect_dump_t);
    vl_api_ipsec_tunnel_protect_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_tunnel_protect_details_t *vl_api_ipsec_tunnel_protect_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_tunnel_protect_details_t);
    vl_api_ipsec_tunnel_protect_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "tun");
    if (!item) goto error;
    if (vl_api_ipsec_tunnel_protect_t_fromjson((void **)&a, &l, item, &a->tun) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_spd_interface_dump_t *vl_api_ipsec_spd_interface_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_spd_interface_dump_t);
    vl_api_ipsec_spd_interface_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "spd_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->spd_index);

    item = cJSON_GetObjectItem(o, "spd_index_valid");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->spd_index_valid);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_spd_interface_details_t *vl_api_ipsec_spd_interface_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_spd_interface_details_t);
    vl_api_ipsec_spd_interface_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "spd_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->spd_index);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_itf_create_t *vl_api_ipsec_itf_create_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_itf_create_t);
    vl_api_ipsec_itf_create_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "itf");
    if (!item) goto error;
    if (vl_api_ipsec_itf_t_fromjson((void **)&a, &l, item, &a->itf) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_itf_create_reply_t *vl_api_ipsec_itf_create_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_itf_create_reply_t);
    vl_api_ipsec_itf_create_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_ipsec_itf_delete_t *vl_api_ipsec_itf_delete_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_itf_delete_t);
    vl_api_ipsec_itf_delete_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_itf_delete_reply_t *vl_api_ipsec_itf_delete_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_itf_delete_reply_t);
    vl_api_ipsec_itf_delete_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_itf_dump_t *vl_api_ipsec_itf_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_itf_dump_t);
    vl_api_ipsec_itf_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_itf_details_t *vl_api_ipsec_itf_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_itf_details_t);
    vl_api_ipsec_itf_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "itf");
    if (!item) goto error;
    if (vl_api_ipsec_itf_t_fromjson((void **)&a, &l, item, &a->itf) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_sa_dump_t *vl_api_ipsec_sa_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_sa_dump_t);
    vl_api_ipsec_sa_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sa_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sa_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_sa_v2_dump_t *vl_api_ipsec_sa_v2_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_sa_v2_dump_t);
    vl_api_ipsec_sa_v2_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sa_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sa_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_sa_v3_dump_t *vl_api_ipsec_sa_v3_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_sa_v3_dump_t);
    vl_api_ipsec_sa_v3_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sa_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sa_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_sa_v4_dump_t *vl_api_ipsec_sa_v4_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_sa_v4_dump_t);
    vl_api_ipsec_sa_v4_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sa_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sa_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_sa_v5_dump_t *vl_api_ipsec_sa_v5_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_sa_v5_dump_t);
    vl_api_ipsec_sa_v5_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sa_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sa_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_sa_details_t *vl_api_ipsec_sa_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_sa_details_t);
    vl_api_ipsec_sa_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "entry");
    if (!item) goto error;
    if (vl_api_ipsec_sad_entry_t_fromjson((void **)&a, &l, item, &a->entry) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "salt");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->salt);

    item = cJSON_GetObjectItem(o, "seq_outbound");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->seq_outbound);

    item = cJSON_GetObjectItem(o, "last_seq_inbound");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->last_seq_inbound);

    item = cJSON_GetObjectItem(o, "replay_window");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->replay_window);

    item = cJSON_GetObjectItem(o, "stat_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->stat_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_sa_v2_details_t *vl_api_ipsec_sa_v2_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_sa_v2_details_t);
    vl_api_ipsec_sa_v2_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "entry");
    if (!item) goto error;
    if (vl_api_ipsec_sad_entry_v2_t_fromjson((void **)&a, &l, item, &a->entry) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "salt");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->salt);

    item = cJSON_GetObjectItem(o, "seq_outbound");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->seq_outbound);

    item = cJSON_GetObjectItem(o, "last_seq_inbound");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->last_seq_inbound);

    item = cJSON_GetObjectItem(o, "replay_window");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->replay_window);

    item = cJSON_GetObjectItem(o, "stat_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->stat_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_sa_v3_details_t *vl_api_ipsec_sa_v3_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_sa_v3_details_t);
    vl_api_ipsec_sa_v3_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "entry");
    if (!item) goto error;
    if (vl_api_ipsec_sad_entry_v3_t_fromjson((void **)&a, &l, item, &a->entry) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "seq_outbound");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->seq_outbound);

    item = cJSON_GetObjectItem(o, "last_seq_inbound");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->last_seq_inbound);

    item = cJSON_GetObjectItem(o, "replay_window");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->replay_window);

    item = cJSON_GetObjectItem(o, "stat_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->stat_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_sa_v4_details_t *vl_api_ipsec_sa_v4_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_sa_v4_details_t);
    vl_api_ipsec_sa_v4_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "entry");
    if (!item) goto error;
    if (vl_api_ipsec_sad_entry_v3_t_fromjson((void **)&a, &l, item, &a->entry) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "seq_outbound");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->seq_outbound);

    item = cJSON_GetObjectItem(o, "last_seq_inbound");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->last_seq_inbound);

    item = cJSON_GetObjectItem(o, "replay_window");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->replay_window);

    item = cJSON_GetObjectItem(o, "thread_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->thread_index);

    item = cJSON_GetObjectItem(o, "stat_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->stat_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_sa_v5_details_t *vl_api_ipsec_sa_v5_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_sa_v5_details_t);
    vl_api_ipsec_sa_v5_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "entry");
    if (!item) goto error;
    if (vl_api_ipsec_sad_entry_v4_t_fromjson((void **)&a, &l, item, &a->entry) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "seq_outbound");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->seq_outbound);

    item = cJSON_GetObjectItem(o, "last_seq_inbound");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->last_seq_inbound);

    item = cJSON_GetObjectItem(o, "replay_window");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->replay_window);

    item = cJSON_GetObjectItem(o, "thread_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->thread_index);

    item = cJSON_GetObjectItem(o, "stat_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->stat_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_backend_dump_t *vl_api_ipsec_backend_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_backend_dump_t);
    vl_api_ipsec_backend_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_ipsec_backend_details_t *vl_api_ipsec_backend_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_backend_details_t);
    vl_api_ipsec_backend_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    strncpy_s((char *)a->name, sizeof(a->name), cJSON_GetStringValue(item), sizeof(a->name) - 1);

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    if (vl_api_ipsec_proto_t_fromjson((void **)&a, &l, item, &a->protocol) < 0) goto error;

    item = cJSON_GetObjectItem(o, "index");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->index);

    item = cJSON_GetObjectItem(o, "active");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->active);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_select_backend_t *vl_api_ipsec_select_backend_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_select_backend_t);
    vl_api_ipsec_select_backend_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    if (vl_api_ipsec_proto_t_fromjson((void **)&a, &l, item, &a->protocol) < 0) goto error;

    item = cJSON_GetObjectItem(o, "index");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_select_backend_reply_t *vl_api_ipsec_select_backend_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_select_backend_reply_t);
    vl_api_ipsec_select_backend_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_set_async_mode_t *vl_api_ipsec_set_async_mode_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_set_async_mode_t);
    vl_api_ipsec_set_async_mode_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "async_enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->async_enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipsec_set_async_mode_reply_t *vl_api_ipsec_set_async_mode_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipsec_set_async_mode_reply_t);
    vl_api_ipsec_set_async_mode_reply_t *a = cJSON_malloc(l);

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
