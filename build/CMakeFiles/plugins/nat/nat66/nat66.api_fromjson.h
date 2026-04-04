/* Imported API files */
#include <vnet/ip/ip_types.api_fromjson.h>
#include <vnet/interface_types.api_fromjson.h>
#include <nat/lib/nat_types.api_fromjson.h>
#ifndef included_nat66_api_fromjson_h
#define included_nat66_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_nat66_plugin_enable_disable_t *vl_api_nat66_plugin_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat66_plugin_enable_disable_t);
    vl_api_nat66_plugin_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "outside_vrf");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->outside_vrf);

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat66_plugin_enable_disable_reply_t *vl_api_nat66_plugin_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat66_plugin_enable_disable_reply_t);
    vl_api_nat66_plugin_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat66_add_del_interface_t *vl_api_nat66_add_del_interface_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat66_add_del_interface_t);
    vl_api_nat66_add_del_interface_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_nat_config_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat66_add_del_interface_reply_t *vl_api_nat66_add_del_interface_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat66_add_del_interface_reply_t);
    vl_api_nat66_add_del_interface_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat66_interface_dump_t *vl_api_nat66_interface_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat66_interface_dump_t);
    vl_api_nat66_interface_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_nat66_interface_details_t *vl_api_nat66_interface_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat66_interface_details_t);
    vl_api_nat66_interface_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_nat_config_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat66_add_del_static_mapping_t *vl_api_nat66_add_del_static_mapping_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat66_add_del_static_mapping_t);
    vl_api_nat66_add_del_static_mapping_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "local_ip_address");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->local_ip_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "external_ip_address");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->external_ip_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat66_add_del_static_mapping_reply_t *vl_api_nat66_add_del_static_mapping_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat66_add_del_static_mapping_reply_t);
    vl_api_nat66_add_del_static_mapping_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat66_static_mapping_dump_t *vl_api_nat66_static_mapping_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat66_static_mapping_dump_t);
    vl_api_nat66_static_mapping_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_nat66_static_mapping_details_t *vl_api_nat66_static_mapping_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat66_static_mapping_details_t);
    vl_api_nat66_static_mapping_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "local_ip_address");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->local_ip_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "external_ip_address");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->external_ip_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    item = cJSON_GetObjectItem(o, "total_bytes");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->total_bytes);

    item = cJSON_GetObjectItem(o, "total_pkts");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->total_pkts);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
