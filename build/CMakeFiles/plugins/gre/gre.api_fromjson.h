/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/tunnel/tunnel_types.api_fromjson.h>
#include <vnet/ip/ip_types.api_fromjson.h>
#ifndef included_gre_api_fromjson_h
#define included_gre_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_gre_tunnel_type_t_fromjson(void **mp, int *len, cJSON *o, vl_api_gre_tunnel_type_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "GRE_API_TUNNEL_TYPE_L3") == 0) {*a = 0; return 0;}
    if (strcmp(p, "GRE_API_TUNNEL_TYPE_TEB") == 0) {*a = 1; return 0;}
    if (strcmp(p, "GRE_API_TUNNEL_TYPE_ERSPAN") == 0) {*a = 2; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_gre_tunnel_t_fromjson (void **mp, int *len, cJSON *o, vl_api_gre_tunnel_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "type");
    if (!item) goto error;
    if (vl_api_gre_tunnel_type_t_fromjson(mp, len, item, &a->type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "mode");
    if (!item) goto error;
    if (vl_api_tunnel_mode_t_fromjson(mp, len, item, &a->mode) < 0) goto error;

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_tunnel_encap_decap_flags_t_fromjson(mp, len, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "session_id");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->session_id);

    item = cJSON_GetObjectItem(o, "instance");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->instance);

    item = cJSON_GetObjectItem(o, "outer_table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->outer_table_id);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson(mp, len, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "src");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->src) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dst");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->dst) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_gre_tunnel_v2_t_fromjson (void **mp, int *len, cJSON *o, vl_api_gre_tunnel_v2_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "type");
    if (!item) goto error;
    if (vl_api_gre_tunnel_type_t_fromjson(mp, len, item, &a->type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "mode");
    if (!item) goto error;
    if (vl_api_tunnel_mode_t_fromjson(mp, len, item, &a->mode) < 0) goto error;

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_tunnel_encap_decap_flags_t_fromjson(mp, len, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "session_id");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->session_id);

    item = cJSON_GetObjectItem(o, "instance");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->instance);

    item = cJSON_GetObjectItem(o, "outer_table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->outer_table_id);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson(mp, len, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "src");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->src) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dst");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->dst) < 0) goto error;

    item = cJSON_GetObjectItem(o, "key");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->key);

    return 0;

  error:
    return -1;
}
static inline vl_api_gre_tunnel_add_del_t *vl_api_gre_tunnel_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gre_tunnel_add_del_t);
    vl_api_gre_tunnel_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "tunnel");
    if (!item) goto error;
    if (vl_api_gre_tunnel_t_fromjson((void **)&a, &l, item, &a->tunnel) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_gre_tunnel_add_del_reply_t *vl_api_gre_tunnel_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gre_tunnel_add_del_reply_t);
    vl_api_gre_tunnel_add_del_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_gre_tunnel_add_del_v2_t *vl_api_gre_tunnel_add_del_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gre_tunnel_add_del_v2_t);
    vl_api_gre_tunnel_add_del_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "tunnel");
    if (!item) goto error;
    if (vl_api_gre_tunnel_v2_t_fromjson((void **)&a, &l, item, &a->tunnel) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_gre_tunnel_add_del_v2_reply_t *vl_api_gre_tunnel_add_del_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gre_tunnel_add_del_v2_reply_t);
    vl_api_gre_tunnel_add_del_v2_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_gre_tunnel_dump_t *vl_api_gre_tunnel_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gre_tunnel_dump_t);
    vl_api_gre_tunnel_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_gre_tunnel_dump_reply_t *vl_api_gre_tunnel_dump_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gre_tunnel_dump_reply_t);
    vl_api_gre_tunnel_dump_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_gre_tunnel_dump_v2_t *vl_api_gre_tunnel_dump_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gre_tunnel_dump_v2_t);
    vl_api_gre_tunnel_dump_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_gre_tunnel_dump_v2_reply_t *vl_api_gre_tunnel_dump_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gre_tunnel_dump_v2_reply_t);
    vl_api_gre_tunnel_dump_v2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_gre_tunnel_details_t *vl_api_gre_tunnel_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gre_tunnel_details_t);
    vl_api_gre_tunnel_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "tunnel");
    if (!item) goto error;
    if (vl_api_gre_tunnel_t_fromjson((void **)&a, &l, item, &a->tunnel) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_gre_tunnel_details_v2_t *vl_api_gre_tunnel_details_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gre_tunnel_details_v2_t);
    vl_api_gre_tunnel_details_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "tunnel");
    if (!item) goto error;
    if (vl_api_gre_tunnel_v2_t_fromjson((void **)&a, &l, item, &a->tunnel) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
