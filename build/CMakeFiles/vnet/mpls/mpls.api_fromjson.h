/* Imported API files */
#include <vnet/fib/fib_types.api_fromjson.h>
#include <vnet/ip/ip_types.api_fromjson.h>
#include <vnet/interface_types.api_fromjson.h>
#ifndef included_mpls_api_fromjson_h
#define included_mpls_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_mpls_tunnel_t_fromjson (void **mp, int *len, cJSON *o, vl_api_mpls_tunnel_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "mt_sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson(mp, len, item, &a->mt_sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "mt_tunnel_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->mt_tunnel_index);

    item = cJSON_GetObjectItem(o, "mt_l2_only");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->mt_l2_only);

    item = cJSON_GetObjectItem(o, "mt_is_multicast");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->mt_is_multicast);

    item = cJSON_GetObjectItem(o, "mt_tag");
    if (!item) goto error;
    strncpy_s((char *)a->mt_tag, sizeof(a->mt_tag), cJSON_GetStringValue(item), sizeof(a->mt_tag) - 1);

    item = cJSON_GetObjectItem(o, "mt_paths");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "mt_paths");
        int size = cJSON_GetArraySize(array);
        a->mt_n_paths = size;
        *mp = cJSON_realloc(*mp, *len + sizeof(vl_api_fib_path_t) * size);
        vl_api_fib_path_t *d = (void *)*mp + *len;
        *len += sizeof(vl_api_fib_path_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_fib_path_t_fromjson(mp, len, e, &d[i]) < 0) goto error; 
        }
    }

    return 0;

  error:
    return -1;
}
static inline int vl_api_mpls_table_t_fromjson (void **mp, int *len, cJSON *o, vl_api_mpls_table_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "mt_table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->mt_table_id);

    item = cJSON_GetObjectItem(o, "mt_name");
    if (!item) goto error;
    strncpy_s((char *)a->mt_name, sizeof(a->mt_name), cJSON_GetStringValue(item), sizeof(a->mt_name) - 1);

    return 0;

  error:
    return -1;
}
static inline int vl_api_mpls_route_t_fromjson (void **mp, int *len, cJSON *o, vl_api_mpls_route_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "mr_table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->mr_table_id);

    item = cJSON_GetObjectItem(o, "mr_label");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->mr_label);

    item = cJSON_GetObjectItem(o, "mr_eos");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->mr_eos);

    item = cJSON_GetObjectItem(o, "mr_eos_proto");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->mr_eos_proto);

    item = cJSON_GetObjectItem(o, "mr_is_multicast");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->mr_is_multicast);

    item = cJSON_GetObjectItem(o, "mr_paths");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "mr_paths");
        int size = cJSON_GetArraySize(array);
        a->mr_n_paths = size;
        *mp = cJSON_realloc(*mp, *len + sizeof(vl_api_fib_path_t) * size);
        vl_api_fib_path_t *d = (void *)*mp + *len;
        *len += sizeof(vl_api_fib_path_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_fib_path_t_fromjson(mp, len, e, &d[i]) < 0) goto error; 
        }
    }

    return 0;

  error:
    return -1;
}
static inline vl_api_mpls_ip_bind_unbind_t *vl_api_mpls_ip_bind_unbind_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_mpls_ip_bind_unbind_t);
    vl_api_mpls_ip_bind_unbind_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "mb_mpls_table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->mb_mpls_table_id);

    item = cJSON_GetObjectItem(o, "mb_label");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->mb_label);

    item = cJSON_GetObjectItem(o, "mb_ip_table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->mb_ip_table_id);

    item = cJSON_GetObjectItem(o, "mb_is_bind");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->mb_is_bind);

    item = cJSON_GetObjectItem(o, "mb_prefix");
    if (!item) goto error;
    if (vl_api_prefix_t_fromjson((void **)&a, &l, item, &a->mb_prefix) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_mpls_ip_bind_unbind_reply_t *vl_api_mpls_ip_bind_unbind_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_mpls_ip_bind_unbind_reply_t);
    vl_api_mpls_ip_bind_unbind_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_mpls_tunnel_add_del_t *vl_api_mpls_tunnel_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_mpls_tunnel_add_del_t);
    vl_api_mpls_tunnel_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "mt_is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->mt_is_add);

    item = cJSON_GetObjectItem(o, "mt_tunnel");
    if (!item) goto error;
    if (vl_api_mpls_tunnel_t_fromjson((void **)&a, &l, item, &a->mt_tunnel) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_mpls_tunnel_add_del_reply_t *vl_api_mpls_tunnel_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_mpls_tunnel_add_del_reply_t);
    vl_api_mpls_tunnel_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "tunnel_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->tunnel_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_mpls_tunnel_dump_t *vl_api_mpls_tunnel_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_mpls_tunnel_dump_t);
    vl_api_mpls_tunnel_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_mpls_tunnel_details_t *vl_api_mpls_tunnel_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_mpls_tunnel_details_t);
    vl_api_mpls_tunnel_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "mt_tunnel");
    if (!item) goto error;
    if (vl_api_mpls_tunnel_t_fromjson((void **)&a, &l, item, &a->mt_tunnel) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_mpls_interface_dump_t *vl_api_mpls_interface_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_mpls_interface_dump_t);
    vl_api_mpls_interface_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_mpls_interface_details_t *vl_api_mpls_interface_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_mpls_interface_details_t);
    vl_api_mpls_interface_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_mpls_table_add_del_t *vl_api_mpls_table_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_mpls_table_add_del_t);
    vl_api_mpls_table_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "mt_is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->mt_is_add);

    item = cJSON_GetObjectItem(o, "mt_table");
    if (!item) goto error;
    if (vl_api_mpls_table_t_fromjson((void **)&a, &l, item, &a->mt_table) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_mpls_table_add_del_reply_t *vl_api_mpls_table_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_mpls_table_add_del_reply_t);
    vl_api_mpls_table_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_mpls_table_dump_t *vl_api_mpls_table_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_mpls_table_dump_t);
    vl_api_mpls_table_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_mpls_table_details_t *vl_api_mpls_table_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_mpls_table_details_t);
    vl_api_mpls_table_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "mt_table");
    if (!item) goto error;
    if (vl_api_mpls_table_t_fromjson((void **)&a, &l, item, &a->mt_table) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_mpls_route_add_del_t *vl_api_mpls_route_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_mpls_route_add_del_t);
    vl_api_mpls_route_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "mr_is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->mr_is_add);

    item = cJSON_GetObjectItem(o, "mr_is_multipath");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->mr_is_multipath);

    item = cJSON_GetObjectItem(o, "mr_route");
    if (!item) goto error;
    if (vl_api_mpls_route_t_fromjson((void **)&a, &l, item, &a->mr_route) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_mpls_route_add_del_reply_t *vl_api_mpls_route_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_mpls_route_add_del_reply_t);
    vl_api_mpls_route_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "stats_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->stats_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_mpls_route_dump_t *vl_api_mpls_route_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_mpls_route_dump_t);
    vl_api_mpls_route_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "table");
    if (!item) goto error;
    if (vl_api_mpls_table_t_fromjson((void **)&a, &l, item, &a->table) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_mpls_route_details_t *vl_api_mpls_route_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_mpls_route_details_t);
    vl_api_mpls_route_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "mr_route");
    if (!item) goto error;
    if (vl_api_mpls_route_t_fromjson((void **)&a, &l, item, &a->mr_route) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_set_mpls_enable_t *vl_api_sw_interface_set_mpls_enable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_mpls_enable_t);
    vl_api_sw_interface_set_mpls_enable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_set_mpls_enable_reply_t *vl_api_sw_interface_set_mpls_enable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_mpls_enable_reply_t);
    vl_api_sw_interface_set_mpls_enable_reply_t *a = cJSON_malloc(l);

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
