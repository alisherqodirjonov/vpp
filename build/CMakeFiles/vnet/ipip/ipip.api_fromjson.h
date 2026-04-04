/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/ip/ip_types.api_fromjson.h>
#include <vnet/tunnel/tunnel_types.api_fromjson.h>
#ifndef included_ipip_api_fromjson_h
#define included_ipip_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_ipip_tunnel_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ipip_tunnel_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "instance");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->instance);

    item = cJSON_GetObjectItem(o, "src");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->src) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dst");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->dst) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson(mp, len, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_id);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_tunnel_encap_decap_flags_t_fromjson(mp, len, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "mode");
    if (!item) goto error;
    if (vl_api_tunnel_mode_t_fromjson(mp, len, item, &a->mode) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dscp");
    if (!item) goto error;
    if (vl_api_ip_dscp_t_fromjson(mp, len, item, &a->dscp) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline vl_api_ipip_add_tunnel_t *vl_api_ipip_add_tunnel_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipip_add_tunnel_t);
    vl_api_ipip_add_tunnel_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "tunnel");
    if (!item) goto error;
    if (vl_api_ipip_tunnel_t_fromjson((void **)&a, &l, item, &a->tunnel) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipip_add_tunnel_reply_t *vl_api_ipip_add_tunnel_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipip_add_tunnel_reply_t);
    vl_api_ipip_add_tunnel_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_ipip_del_tunnel_t *vl_api_ipip_del_tunnel_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipip_del_tunnel_t);
    vl_api_ipip_del_tunnel_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipip_del_tunnel_reply_t *vl_api_ipip_del_tunnel_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipip_del_tunnel_reply_t);
    vl_api_ipip_del_tunnel_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipip_6rd_add_tunnel_t *vl_api_ipip_6rd_add_tunnel_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipip_6rd_add_tunnel_t);
    vl_api_ipip_6rd_add_tunnel_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "ip6_table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ip6_table_id);

    item = cJSON_GetObjectItem(o, "ip4_table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ip4_table_id);

    item = cJSON_GetObjectItem(o, "ip6_prefix");
    if (!item) goto error;
    if (vl_api_ip6_prefix_t_fromjson((void **)&a, &l, item, &a->ip6_prefix) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ip4_prefix");
    if (!item) goto error;
    if (vl_api_ip4_prefix_t_fromjson((void **)&a, &l, item, &a->ip4_prefix) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ip4_src");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->ip4_src) < 0) goto error;

    item = cJSON_GetObjectItem(o, "security_check");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->security_check);

    item = cJSON_GetObjectItem(o, "tc_tos");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->tc_tos);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipip_6rd_add_tunnel_reply_t *vl_api_ipip_6rd_add_tunnel_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipip_6rd_add_tunnel_reply_t);
    vl_api_ipip_6rd_add_tunnel_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_ipip_6rd_del_tunnel_t *vl_api_ipip_6rd_del_tunnel_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipip_6rd_del_tunnel_t);
    vl_api_ipip_6rd_del_tunnel_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipip_6rd_del_tunnel_reply_t *vl_api_ipip_6rd_del_tunnel_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipip_6rd_del_tunnel_reply_t);
    vl_api_ipip_6rd_del_tunnel_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipip_tunnel_dump_t *vl_api_ipip_tunnel_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipip_tunnel_dump_t);
    vl_api_ipip_tunnel_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipip_tunnel_details_t *vl_api_ipip_tunnel_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipip_tunnel_details_t);
    vl_api_ipip_tunnel_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "tunnel");
    if (!item) goto error;
    if (vl_api_ipip_tunnel_t_fromjson((void **)&a, &l, item, &a->tunnel) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
