/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/fib/fib_types.api_fromjson.h>
#include <vnet/ethernet/ethernet_types.api_fromjson.h>
#include <vnet/mfib/mfib_types.api_fromjson.h>
#include <vnet/interface_types.api_fromjson.h>
#ifndef included_ip_api_fromjson_h
#define included_ip_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_ip_table_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ip_table_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_id);

    item = cJSON_GetObjectItem(o, "is_ip6");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_ip6);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    strncpy_s((char *)a->name, sizeof(a->name), cJSON_GetStringValue(item), sizeof(a->name) - 1);

    return 0;

  error:
    return -1;
}
static inline int vl_api_ip_route_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ip_route_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_id);

    item = cJSON_GetObjectItem(o, "stats_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->stats_index);

    item = cJSON_GetObjectItem(o, "prefix");
    if (!item) goto error;
    if (vl_api_prefix_t_fromjson(mp, len, item, &a->prefix) < 0) goto error;

    item = cJSON_GetObjectItem(o, "paths");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "paths");
        int size = cJSON_GetArraySize(array);
        a->n_paths = size;
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
static inline int vl_api_ip_route_v2_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ip_route_v2_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_id);

    item = cJSON_GetObjectItem(o, "stats_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->stats_index);

    item = cJSON_GetObjectItem(o, "prefix");
    if (!item) goto error;
    if (vl_api_prefix_t_fromjson(mp, len, item, &a->prefix) < 0) goto error;

    item = cJSON_GetObjectItem(o, "src");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->src);

    item = cJSON_GetObjectItem(o, "paths");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "paths");
        int size = cJSON_GetArraySize(array);
        a->n_paths = size;
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
static inline int vl_api_ip_flow_hash_config_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ip_flow_hash_config_t *a) {
   int i;
   *a = 0;
   for (i = 0; i < cJSON_GetArraySize(o); i++) {
       cJSON *e = cJSON_GetArrayItem(o, i);
       char *p = cJSON_GetStringValue(e);
       if (!p) return -1;
       if (strcmp(p, "IP_API_FLOW_HASH_SRC_IP") == 0) *a |= 1;
       if (strcmp(p, "IP_API_FLOW_HASH_DST_IP") == 0) *a |= 2;
       if (strcmp(p, "IP_API_FLOW_HASH_SRC_PORT") == 0) *a |= 4;
       if (strcmp(p, "IP_API_FLOW_HASH_DST_PORT") == 0) *a |= 8;
       if (strcmp(p, "IP_API_FLOW_HASH_PROTO") == 0) *a |= 16;
       if (strcmp(p, "IP_API_FLOW_HASH_REVERSE") == 0) *a |= 32;
       if (strcmp(p, "IP_API_FLOW_HASH_SYMETRIC") == 0) *a |= 64;
       if (strcmp(p, "IP_API_FLOW_HASH_FLOW_LABEL") == 0) *a |= 128;
    }
   return 0;
}
static inline int vl_api_ip_flow_hash_config_v2_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ip_flow_hash_config_v2_t *a) {
   int i;
   *a = 0;
   for (i = 0; i < cJSON_GetArraySize(o); i++) {
       cJSON *e = cJSON_GetArrayItem(o, i);
       char *p = cJSON_GetStringValue(e);
       if (!p) return -1;
       if (strcmp(p, "IP_API_V2_FLOW_HASH_SRC_IP") == 0) *a |= 1;
       if (strcmp(p, "IP_API_V2_FLOW_HASH_DST_IP") == 0) *a |= 2;
       if (strcmp(p, "IP_API_V2_FLOW_HASH_SRC_PORT") == 0) *a |= 4;
       if (strcmp(p, "IP_API_V2_FLOW_HASH_DST_PORT") == 0) *a |= 8;
       if (strcmp(p, "IP_API_V2_FLOW_HASH_PROTO") == 0) *a |= 16;
       if (strcmp(p, "IP_API_V2_FLOW_HASH_REVERSE") == 0) *a |= 32;
       if (strcmp(p, "IP_API_V2_FLOW_HASH_SYMETRIC") == 0) *a |= 64;
       if (strcmp(p, "IP_API_V2_FLOW_HASH_FLOW_LABEL") == 0) *a |= 128;
       if (strcmp(p, "IP_API_V2_FLOW_HASH_GTPV1_TEID") == 0) *a |= 256;
    }
   return 0;
}
static inline int vl_api_ip_mroute_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ip_mroute_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_id);

    item = cJSON_GetObjectItem(o, "entry_flags");
    if (!item) goto error;
    if (vl_api_mfib_entry_flags_t_fromjson(mp, len, item, &a->entry_flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "rpf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->rpf_id);

    item = cJSON_GetObjectItem(o, "prefix");
    if (!item) goto error;
    if (vl_api_mprefix_t_fromjson(mp, len, item, &a->prefix) < 0) goto error;

    item = cJSON_GetObjectItem(o, "paths");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "paths");
        int size = cJSON_GetArraySize(array);
        a->n_paths = size;
        *mp = cJSON_realloc(*mp, *len + sizeof(vl_api_mfib_path_t) * size);
        vl_api_mfib_path_t *d = (void *)*mp + *len;
        *len += sizeof(vl_api_mfib_path_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_mfib_path_t_fromjson(mp, len, e, &d[i]) < 0) goto error; 
        }
    }

    return 0;

  error:
    return -1;
}
static inline int vl_api_punt_redirect_t_fromjson (void **mp, int *len, cJSON *o, vl_api_punt_redirect_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "rx_sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson(mp, len, item, &a->rx_sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "tx_sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson(mp, len, item, &a->tx_sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "nh");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->nh) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_punt_redirect_v2_t_fromjson (void **mp, int *len, cJSON *o, vl_api_punt_redirect_v2_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "rx_sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson(mp, len, item, &a->rx_sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "af");
    if (!item) goto error;
    if (vl_api_address_family_t_fromjson(mp, len, item, &a->af) < 0) goto error;

    item = cJSON_GetObjectItem(o, "paths");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "paths");
        int size = cJSON_GetArraySize(array);
        a->n_paths = size;
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
static inline int vl_api_ip_reass_type_t_fromjson(void **mp, int *len, cJSON *o, vl_api_ip_reass_type_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "IP_REASS_TYPE_FULL") == 0) {*a = 0; return 0;}
    if (strcmp(p, "IP_REASS_TYPE_SHALLOW_VIRTUAL") == 0) {*a = 1; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_ip_path_mtu_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ip_path_mtu_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "client_index");
    if (!item) goto error;

    item = cJSON_GetObjectItem(o, "context");
    if (!item) goto error;

    item = cJSON_GetObjectItem(o, "table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_id);

    item = cJSON_GetObjectItem(o, "nh");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->nh) < 0) goto error;

    item = cJSON_GetObjectItem(o, "path_mtu");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->path_mtu);

    return 0;

  error:
    return -1;
}
static inline vl_api_ip_table_add_del_t *vl_api_ip_table_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_table_add_del_t);
    vl_api_ip_table_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "table");
    if (!item) goto error;
    if (vl_api_ip_table_t_fromjson((void **)&a, &l, item, &a->table) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_table_add_del_reply_t *vl_api_ip_table_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_table_add_del_reply_t);
    vl_api_ip_table_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_table_add_del_v2_t *vl_api_ip_table_add_del_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_table_add_del_v2_t);
    vl_api_ip_table_add_del_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "table");
    if (!item) goto error;
    if (vl_api_ip_table_t_fromjson((void **)&a, &l, item, &a->table) < 0) goto error;

    item = cJSON_GetObjectItem(o, "create_mfib");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->create_mfib);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_table_add_del_v2_reply_t *vl_api_ip_table_add_del_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_table_add_del_v2_reply_t);
    vl_api_ip_table_add_del_v2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_table_allocate_t *vl_api_ip_table_allocate_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_table_allocate_t);
    vl_api_ip_table_allocate_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "table");
    if (!item) goto error;
    if (vl_api_ip_table_t_fromjson((void **)&a, &l, item, &a->table) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_table_allocate_reply_t *vl_api_ip_table_allocate_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_table_allocate_reply_t);
    vl_api_ip_table_allocate_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "table");
    if (!item) goto error;
    if (vl_api_ip_table_t_fromjson((void **)&a, &l, item, &a->table) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_table_dump_t *vl_api_ip_table_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_table_dump_t);
    vl_api_ip_table_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_ip_table_replace_begin_t *vl_api_ip_table_replace_begin_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_table_replace_begin_t);
    vl_api_ip_table_replace_begin_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "table");
    if (!item) goto error;
    if (vl_api_ip_table_t_fromjson((void **)&a, &l, item, &a->table) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_table_replace_begin_reply_t *vl_api_ip_table_replace_begin_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_table_replace_begin_reply_t);
    vl_api_ip_table_replace_begin_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_table_replace_end_t *vl_api_ip_table_replace_end_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_table_replace_end_t);
    vl_api_ip_table_replace_end_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "table");
    if (!item) goto error;
    if (vl_api_ip_table_t_fromjson((void **)&a, &l, item, &a->table) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_table_replace_end_reply_t *vl_api_ip_table_replace_end_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_table_replace_end_reply_t);
    vl_api_ip_table_replace_end_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_table_flush_t *vl_api_ip_table_flush_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_table_flush_t);
    vl_api_ip_table_flush_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "table");
    if (!item) goto error;
    if (vl_api_ip_table_t_fromjson((void **)&a, &l, item, &a->table) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_table_flush_reply_t *vl_api_ip_table_flush_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_table_flush_reply_t);
    vl_api_ip_table_flush_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_table_details_t *vl_api_ip_table_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_table_details_t);
    vl_api_ip_table_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "table");
    if (!item) goto error;
    if (vl_api_ip_table_t_fromjson((void **)&a, &l, item, &a->table) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_route_add_del_t *vl_api_ip_route_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_route_add_del_t);
    vl_api_ip_route_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "is_multipath");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_multipath);

    item = cJSON_GetObjectItem(o, "route");
    if (!item) goto error;
    if (vl_api_ip_route_t_fromjson((void **)&a, &l, item, &a->route) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_route_add_del_v2_t *vl_api_ip_route_add_del_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_route_add_del_v2_t);
    vl_api_ip_route_add_del_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "is_multipath");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_multipath);

    item = cJSON_GetObjectItem(o, "route");
    if (!item) goto error;
    if (vl_api_ip_route_v2_t_fromjson((void **)&a, &l, item, &a->route) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_route_add_del_reply_t *vl_api_ip_route_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_route_add_del_reply_t);
    vl_api_ip_route_add_del_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_ip_route_add_del_v2_reply_t *vl_api_ip_route_add_del_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_route_add_del_v2_reply_t);
    vl_api_ip_route_add_del_v2_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_ip_route_dump_t *vl_api_ip_route_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_route_dump_t);
    vl_api_ip_route_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "table");
    if (!item) goto error;
    if (vl_api_ip_table_t_fromjson((void **)&a, &l, item, &a->table) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_route_v2_dump_t *vl_api_ip_route_v2_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_route_v2_dump_t);
    vl_api_ip_route_v2_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "src");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->src);

    item = cJSON_GetObjectItem(o, "table");
    if (!item) goto error;
    if (vl_api_ip_table_t_fromjson((void **)&a, &l, item, &a->table) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_route_details_t *vl_api_ip_route_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_route_details_t);
    vl_api_ip_route_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "route");
    if (!item) goto error;
    if (vl_api_ip_route_t_fromjson((void **)&a, &l, item, &a->route) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_route_v2_details_t *vl_api_ip_route_v2_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_route_v2_details_t);
    vl_api_ip_route_v2_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "route");
    if (!item) goto error;
    if (vl_api_ip_route_v2_t_fromjson((void **)&a, &l, item, &a->route) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_route_lookup_t *vl_api_ip_route_lookup_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_route_lookup_t);
    vl_api_ip_route_lookup_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_id);

    item = cJSON_GetObjectItem(o, "exact");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->exact);

    item = cJSON_GetObjectItem(o, "prefix");
    if (!item) goto error;
    if (vl_api_prefix_t_fromjson((void **)&a, &l, item, &a->prefix) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_route_lookup_v2_t *vl_api_ip_route_lookup_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_route_lookup_v2_t);
    vl_api_ip_route_lookup_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_id);

    item = cJSON_GetObjectItem(o, "exact");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->exact);

    item = cJSON_GetObjectItem(o, "prefix");
    if (!item) goto error;
    if (vl_api_prefix_t_fromjson((void **)&a, &l, item, &a->prefix) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_route_lookup_reply_t *vl_api_ip_route_lookup_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_route_lookup_reply_t);
    vl_api_ip_route_lookup_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "route");
    if (!item) goto error;
    if (vl_api_ip_route_t_fromjson((void **)&a, &l, item, &a->route) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_route_lookup_v2_reply_t *vl_api_ip_route_lookup_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_route_lookup_v2_reply_t);
    vl_api_ip_route_lookup_v2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "route");
    if (!item) goto error;
    if (vl_api_ip_route_v2_t_fromjson((void **)&a, &l, item, &a->route) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_set_ip_flow_hash_t *vl_api_set_ip_flow_hash_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_set_ip_flow_hash_t);
    vl_api_set_ip_flow_hash_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    item = cJSON_GetObjectItem(o, "is_ipv6");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_ipv6);

    item = cJSON_GetObjectItem(o, "src");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->src);

    item = cJSON_GetObjectItem(o, "dst");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->dst);

    item = cJSON_GetObjectItem(o, "sport");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->sport);

    item = cJSON_GetObjectItem(o, "dport");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->dport);

    item = cJSON_GetObjectItem(o, "proto");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->proto);

    item = cJSON_GetObjectItem(o, "reverse");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->reverse);

    item = cJSON_GetObjectItem(o, "symmetric");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->symmetric);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_set_ip_flow_hash_reply_t *vl_api_set_ip_flow_hash_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_set_ip_flow_hash_reply_t);
    vl_api_set_ip_flow_hash_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_set_ip_flow_hash_v2_t *vl_api_set_ip_flow_hash_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_set_ip_flow_hash_v2_t);
    vl_api_set_ip_flow_hash_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_id);

    item = cJSON_GetObjectItem(o, "af");
    if (!item) goto error;
    if (vl_api_address_family_t_fromjson((void **)&a, &l, item, &a->af) < 0) goto error;

    item = cJSON_GetObjectItem(o, "flow_hash_config");
    if (!item) goto error;
    if (vl_api_ip_flow_hash_config_t_fromjson((void **)&a, &l, item, &a->flow_hash_config) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_set_ip_flow_hash_v2_reply_t *vl_api_set_ip_flow_hash_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_set_ip_flow_hash_v2_reply_t);
    vl_api_set_ip_flow_hash_v2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_set_ip_flow_hash_v3_t *vl_api_set_ip_flow_hash_v3_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_set_ip_flow_hash_v3_t);
    vl_api_set_ip_flow_hash_v3_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_id);

    item = cJSON_GetObjectItem(o, "af");
    if (!item) goto error;
    if (vl_api_address_family_t_fromjson((void **)&a, &l, item, &a->af) < 0) goto error;

    item = cJSON_GetObjectItem(o, "flow_hash_config");
    if (!item) goto error;
    if (vl_api_ip_flow_hash_config_v2_t_fromjson((void **)&a, &l, item, &a->flow_hash_config) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_set_ip_flow_hash_v3_reply_t *vl_api_set_ip_flow_hash_v3_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_set_ip_flow_hash_v3_reply_t);
    vl_api_set_ip_flow_hash_v3_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_set_ip_flow_hash_router_id_t *vl_api_set_ip_flow_hash_router_id_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_set_ip_flow_hash_router_id_t);
    vl_api_set_ip_flow_hash_router_id_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "router_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->router_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_set_ip_flow_hash_router_id_reply_t *vl_api_set_ip_flow_hash_router_id_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_set_ip_flow_hash_router_id_reply_t);
    vl_api_set_ip_flow_hash_router_id_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_ip6_enable_disable_t *vl_api_sw_interface_ip6_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_ip6_enable_disable_t);
    vl_api_sw_interface_ip6_enable_disable_t *a = cJSON_malloc(l);

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
static inline vl_api_sw_interface_ip6_enable_disable_reply_t *vl_api_sw_interface_ip6_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_ip6_enable_disable_reply_t);
    vl_api_sw_interface_ip6_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_ip4_enable_disable_t *vl_api_sw_interface_ip4_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_ip4_enable_disable_t);
    vl_api_sw_interface_ip4_enable_disable_t *a = cJSON_malloc(l);

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
static inline vl_api_sw_interface_ip4_enable_disable_reply_t *vl_api_sw_interface_ip4_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_ip4_enable_disable_reply_t);
    vl_api_sw_interface_ip4_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_mtable_dump_t *vl_api_ip_mtable_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_mtable_dump_t);
    vl_api_ip_mtable_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_ip_mtable_details_t *vl_api_ip_mtable_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_mtable_details_t);
    vl_api_ip_mtable_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "table");
    if (!item) goto error;
    if (vl_api_ip_table_t_fromjson((void **)&a, &l, item, &a->table) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_mroute_add_del_t *vl_api_ip_mroute_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_mroute_add_del_t);
    vl_api_ip_mroute_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "is_multipath");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_multipath);

    item = cJSON_GetObjectItem(o, "route");
    if (!item) goto error;
    if (vl_api_ip_mroute_t_fromjson((void **)&a, &l, item, &a->route) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_mroute_add_del_reply_t *vl_api_ip_mroute_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_mroute_add_del_reply_t);
    vl_api_ip_mroute_add_del_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_ip_mroute_dump_t *vl_api_ip_mroute_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_mroute_dump_t);
    vl_api_ip_mroute_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "table");
    if (!item) goto error;
    if (vl_api_ip_table_t_fromjson((void **)&a, &l, item, &a->table) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_mroute_details_t *vl_api_ip_mroute_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_mroute_details_t);
    vl_api_ip_mroute_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "route");
    if (!item) goto error;
    if (vl_api_ip_mroute_t_fromjson((void **)&a, &l, item, &a->route) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_address_details_t *vl_api_ip_address_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_address_details_t);
    vl_api_ip_address_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "prefix");
    if (!item) goto error;
    if (vl_api_address_with_prefix_t_fromjson((void **)&a, &l, item, &a->prefix) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_address_dump_t *vl_api_ip_address_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_address_dump_t);
    vl_api_ip_address_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_ipv6");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_ipv6);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_unnumbered_details_t *vl_api_ip_unnumbered_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_unnumbered_details_t);
    vl_api_ip_unnumbered_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ip_sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->ip_sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_unnumbered_dump_t *vl_api_ip_unnumbered_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_unnumbered_dump_t);
    vl_api_ip_unnumbered_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_details_t *vl_api_ip_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_details_t);
    vl_api_ip_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_ipv6");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_ipv6);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_dump_t *vl_api_ip_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_dump_t);
    vl_api_ip_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_ipv6");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_ipv6);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_mfib_signal_dump_t *vl_api_mfib_signal_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_mfib_signal_dump_t);
    vl_api_mfib_signal_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_mfib_signal_details_t *vl_api_mfib_signal_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_mfib_signal_details_t);
    vl_api_mfib_signal_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_id);

    item = cJSON_GetObjectItem(o, "prefix");
    if (!item) goto error;
    if (vl_api_mprefix_t_fromjson((void **)&a, &l, item, &a->prefix) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ip_packet_len");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->ip_packet_len);

    item = cJSON_GetObjectItem(o, "ip_packet_data");
    if (!item) goto error;
    if (u8string_fromjson2(o, "ip_packet_data", a->ip_packet_data) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_punt_police_t *vl_api_ip_punt_police_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_punt_police_t);
    vl_api_ip_punt_police_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "policer_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->policer_index);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "is_ip6");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_ip6);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_punt_police_reply_t *vl_api_ip_punt_police_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_punt_police_reply_t);
    vl_api_ip_punt_police_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_punt_redirect_t *vl_api_ip_punt_redirect_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_punt_redirect_t);
    vl_api_ip_punt_redirect_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "punt");
    if (!item) goto error;
    if (vl_api_punt_redirect_t_fromjson((void **)&a, &l, item, &a->punt) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_punt_redirect_reply_t *vl_api_ip_punt_redirect_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_punt_redirect_reply_t);
    vl_api_ip_punt_redirect_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_punt_redirect_dump_t *vl_api_ip_punt_redirect_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_punt_redirect_dump_t);
    vl_api_ip_punt_redirect_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_ipv6");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_ipv6);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_punt_redirect_details_t *vl_api_ip_punt_redirect_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_punt_redirect_details_t);
    vl_api_ip_punt_redirect_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "punt");
    if (!item) goto error;
    if (vl_api_punt_redirect_t_fromjson((void **)&a, &l, item, &a->punt) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_add_del_ip_punt_redirect_v2_t *vl_api_add_del_ip_punt_redirect_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_add_del_ip_punt_redirect_v2_t);
    vl_api_add_del_ip_punt_redirect_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "punt");
    if (!item) goto error;
    if (vl_api_punt_redirect_v2_t_fromjson((void **)&a, &l, item, &a->punt) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_add_del_ip_punt_redirect_v2_reply_t *vl_api_add_del_ip_punt_redirect_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_add_del_ip_punt_redirect_v2_reply_t);
    vl_api_add_del_ip_punt_redirect_v2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_punt_redirect_v2_dump_t *vl_api_ip_punt_redirect_v2_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_punt_redirect_v2_dump_t);
    vl_api_ip_punt_redirect_v2_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "af");
    if (!item) goto error;
    if (vl_api_address_family_t_fromjson((void **)&a, &l, item, &a->af) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_punt_redirect_v2_details_t *vl_api_ip_punt_redirect_v2_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_punt_redirect_v2_details_t);
    vl_api_ip_punt_redirect_v2_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "punt");
    if (!item) goto error;
    if (vl_api_punt_redirect_v2_t_fromjson((void **)&a, &l, item, &a->punt) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_container_proxy_add_del_t *vl_api_ip_container_proxy_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_container_proxy_add_del_t);
    vl_api_ip_container_proxy_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "pfx");
    if (!item) goto error;
    if (vl_api_prefix_t_fromjson((void **)&a, &l, item, &a->pfx) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_container_proxy_add_del_reply_t *vl_api_ip_container_proxy_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_container_proxy_add_del_reply_t);
    vl_api_ip_container_proxy_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_container_proxy_dump_t *vl_api_ip_container_proxy_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_container_proxy_dump_t);
    vl_api_ip_container_proxy_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_ip_container_proxy_details_t *vl_api_ip_container_proxy_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_container_proxy_details_t);
    vl_api_ip_container_proxy_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "prefix");
    if (!item) goto error;
    if (vl_api_prefix_t_fromjson((void **)&a, &l, item, &a->prefix) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_source_and_port_range_check_add_del_t *vl_api_ip_source_and_port_range_check_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_source_and_port_range_check_add_del_t);
    vl_api_ip_source_and_port_range_check_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "prefix");
    if (!item) goto error;
    if (vl_api_prefix_t_fromjson((void **)&a, &l, item, &a->prefix) < 0) goto error;

    item = cJSON_GetObjectItem(o, "number_of_ranges");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->number_of_ranges);

    item = cJSON_GetObjectItem(o, "low_ports");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "low_ports");
        int size = cJSON_GetArraySize(array);
        if (size != 32) goto error;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_u16_fromjson(e, &a->low_ports[i]);
        }
    }

    item = cJSON_GetObjectItem(o, "high_ports");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "high_ports");
        int size = cJSON_GetArraySize(array);
        if (size != 32) goto error;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_u16_fromjson(e, &a->high_ports[i]);
        }
    }

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_source_and_port_range_check_add_del_reply_t *vl_api_ip_source_and_port_range_check_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_source_and_port_range_check_add_del_reply_t);
    vl_api_ip_source_and_port_range_check_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_source_and_port_range_check_interface_add_del_t *vl_api_ip_source_and_port_range_check_interface_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_source_and_port_range_check_interface_add_del_t);
    vl_api_ip_source_and_port_range_check_interface_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "tcp_in_vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->tcp_in_vrf_id);

    item = cJSON_GetObjectItem(o, "tcp_out_vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->tcp_out_vrf_id);

    item = cJSON_GetObjectItem(o, "udp_in_vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->udp_in_vrf_id);

    item = cJSON_GetObjectItem(o, "udp_out_vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->udp_out_vrf_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_source_and_port_range_check_interface_add_del_reply_t *vl_api_ip_source_and_port_range_check_interface_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_source_and_port_range_check_interface_add_del_reply_t);
    vl_api_ip_source_and_port_range_check_interface_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_ip6_set_link_local_address_t *vl_api_sw_interface_ip6_set_link_local_address_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_ip6_set_link_local_address_t);
    vl_api_sw_interface_ip6_set_link_local_address_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ip");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->ip) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_ip6_set_link_local_address_reply_t *vl_api_sw_interface_ip6_set_link_local_address_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_ip6_set_link_local_address_reply_t);
    vl_api_sw_interface_ip6_set_link_local_address_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_ip6_get_link_local_address_t *vl_api_sw_interface_ip6_get_link_local_address_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_ip6_get_link_local_address_t);
    vl_api_sw_interface_ip6_get_link_local_address_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_ip6_get_link_local_address_reply_t *vl_api_sw_interface_ip6_get_link_local_address_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_ip6_get_link_local_address_reply_t);
    vl_api_sw_interface_ip6_get_link_local_address_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "ip");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->ip) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ioam_enable_t *vl_api_ioam_enable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ioam_enable_t);
    vl_api_ioam_enable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->id);

    item = cJSON_GetObjectItem(o, "seqno");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->seqno);

    item = cJSON_GetObjectItem(o, "analyse");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->analyse);

    item = cJSON_GetObjectItem(o, "pot_enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->pot_enable);

    item = cJSON_GetObjectItem(o, "trace_enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->trace_enable);

    item = cJSON_GetObjectItem(o, "node_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->node_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ioam_enable_reply_t *vl_api_ioam_enable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ioam_enable_reply_t);
    vl_api_ioam_enable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ioam_disable_t *vl_api_ioam_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ioam_disable_t);
    vl_api_ioam_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ioam_disable_reply_t *vl_api_ioam_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ioam_disable_reply_t);
    vl_api_ioam_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_reassembly_set_t *vl_api_ip_reassembly_set_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_reassembly_set_t);
    vl_api_ip_reassembly_set_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "timeout_ms");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->timeout_ms);

    item = cJSON_GetObjectItem(o, "max_reassemblies");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->max_reassemblies);

    item = cJSON_GetObjectItem(o, "max_reassembly_length");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->max_reassembly_length);

    item = cJSON_GetObjectItem(o, "expire_walk_interval_ms");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->expire_walk_interval_ms);

    item = cJSON_GetObjectItem(o, "is_ip6");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_ip6);

    item = cJSON_GetObjectItem(o, "type");
    if (!item) goto error;
    if (vl_api_ip_reass_type_t_fromjson((void **)&a, &l, item, &a->type) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_reassembly_set_reply_t *vl_api_ip_reassembly_set_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_reassembly_set_reply_t);
    vl_api_ip_reassembly_set_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_reassembly_get_t *vl_api_ip_reassembly_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_reassembly_get_t);
    vl_api_ip_reassembly_get_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_ip6");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_ip6);

    item = cJSON_GetObjectItem(o, "type");
    if (!item) goto error;
    if (vl_api_ip_reass_type_t_fromjson((void **)&a, &l, item, &a->type) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_reassembly_get_reply_t *vl_api_ip_reassembly_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_reassembly_get_reply_t);
    vl_api_ip_reassembly_get_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "timeout_ms");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->timeout_ms);

    item = cJSON_GetObjectItem(o, "max_reassemblies");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->max_reassemblies);

    item = cJSON_GetObjectItem(o, "max_reassembly_length");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->max_reassembly_length);

    item = cJSON_GetObjectItem(o, "expire_walk_interval_ms");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->expire_walk_interval_ms);

    item = cJSON_GetObjectItem(o, "is_ip6");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_ip6);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_reassembly_enable_disable_t *vl_api_ip_reassembly_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_reassembly_enable_disable_t);
    vl_api_ip_reassembly_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "enable_ip4");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable_ip4);

    item = cJSON_GetObjectItem(o, "enable_ip6");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable_ip6);

    item = cJSON_GetObjectItem(o, "type");
    if (!item) goto error;
    if (vl_api_ip_reass_type_t_fromjson((void **)&a, &l, item, &a->type) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_reassembly_enable_disable_reply_t *vl_api_ip_reassembly_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_reassembly_enable_disable_reply_t);
    vl_api_ip_reassembly_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_local_reass_enable_disable_t *vl_api_ip_local_reass_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_local_reass_enable_disable_t);
    vl_api_ip_local_reass_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "enable_ip4");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable_ip4);

    item = cJSON_GetObjectItem(o, "enable_ip6");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable_ip6);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_local_reass_enable_disable_reply_t *vl_api_ip_local_reass_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_local_reass_enable_disable_reply_t);
    vl_api_ip_local_reass_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_local_reass_get_t *vl_api_ip_local_reass_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_local_reass_get_t);
    vl_api_ip_local_reass_get_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_ip_local_reass_get_reply_t *vl_api_ip_local_reass_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_local_reass_get_reply_t);
    vl_api_ip_local_reass_get_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "ip4_is_enabled");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->ip4_is_enabled);

    item = cJSON_GetObjectItem(o, "ip6_is_enabled");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->ip6_is_enabled);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_path_mtu_update_t *vl_api_ip_path_mtu_update_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_path_mtu_update_t);
    vl_api_ip_path_mtu_update_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "pmtu");
    if (!item) goto error;
    if (vl_api_ip_path_mtu_t_fromjson((void **)&a, &l, item, &a->pmtu) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_path_mtu_update_reply_t *vl_api_ip_path_mtu_update_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_path_mtu_update_reply_t);
    vl_api_ip_path_mtu_update_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_path_mtu_get_t *vl_api_ip_path_mtu_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_path_mtu_get_t);
    vl_api_ip_path_mtu_get_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "cursor");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->cursor);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_path_mtu_get_reply_t *vl_api_ip_path_mtu_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_path_mtu_get_reply_t);
    vl_api_ip_path_mtu_get_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "cursor");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->cursor);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_path_mtu_details_t *vl_api_ip_path_mtu_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_path_mtu_details_t);
    vl_api_ip_path_mtu_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "pmtu");
    if (!item) goto error;
    if (vl_api_ip_path_mtu_t_fromjson((void **)&a, &l, item, &a->pmtu) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_path_mtu_replace_begin_t *vl_api_ip_path_mtu_replace_begin_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_path_mtu_replace_begin_t);
    vl_api_ip_path_mtu_replace_begin_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_ip_path_mtu_replace_begin_reply_t *vl_api_ip_path_mtu_replace_begin_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_path_mtu_replace_begin_reply_t);
    vl_api_ip_path_mtu_replace_begin_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_path_mtu_replace_end_t *vl_api_ip_path_mtu_replace_end_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_path_mtu_replace_end_t);
    vl_api_ip_path_mtu_replace_end_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_ip_path_mtu_replace_end_reply_t *vl_api_ip_path_mtu_replace_end_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_path_mtu_replace_end_reply_t);
    vl_api_ip_path_mtu_replace_end_reply_t *a = cJSON_malloc(l);

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
