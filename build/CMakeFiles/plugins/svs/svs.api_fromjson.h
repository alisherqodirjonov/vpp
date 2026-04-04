/* Imported API files */
#include <vnet/ip/ip_types.api_fromjson.h>
#include <vnet/interface_types.api_fromjson.h>
#ifndef included_svs_api_fromjson_h
#define included_svs_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_svs_plugin_get_version_t *vl_api_svs_plugin_get_version_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_svs_plugin_get_version_t);
    vl_api_svs_plugin_get_version_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_svs_plugin_get_version_reply_t *vl_api_svs_plugin_get_version_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_svs_plugin_get_version_reply_t);
    vl_api_svs_plugin_get_version_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "major");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->major);

    item = cJSON_GetObjectItem(o, "minor");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->minor);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_svs_table_add_del_t *vl_api_svs_table_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_svs_table_add_del_t);
    vl_api_svs_table_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "af");
    if (!item) goto error;
    if (vl_api_address_family_t_fromjson((void **)&a, &l, item, &a->af) < 0) goto error;

    item = cJSON_GetObjectItem(o, "table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_svs_table_add_del_reply_t *vl_api_svs_table_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_svs_table_add_del_reply_t);
    vl_api_svs_table_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_svs_route_add_del_t *vl_api_svs_route_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_svs_route_add_del_t);
    vl_api_svs_route_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "prefix");
    if (!item) goto error;
    if (vl_api_prefix_t_fromjson((void **)&a, &l, item, &a->prefix) < 0) goto error;

    item = cJSON_GetObjectItem(o, "table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_id);

    item = cJSON_GetObjectItem(o, "source_table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->source_table_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_svs_route_add_del_reply_t *vl_api_svs_route_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_svs_route_add_del_reply_t);
    vl_api_svs_route_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_svs_enable_disable_t *vl_api_svs_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_svs_enable_disable_t);
    vl_api_svs_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_enable);

    item = cJSON_GetObjectItem(o, "af");
    if (!item) goto error;
    if (vl_api_address_family_t_fromjson((void **)&a, &l, item, &a->af) < 0) goto error;

    item = cJSON_GetObjectItem(o, "table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_id);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_svs_enable_disable_reply_t *vl_api_svs_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_svs_enable_disable_reply_t);
    vl_api_svs_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_svs_dump_t *vl_api_svs_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_svs_dump_t);
    vl_api_svs_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_svs_details_t *vl_api_svs_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_svs_details_t);
    vl_api_svs_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_id);

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
#endif
