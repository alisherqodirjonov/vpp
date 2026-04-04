/* Imported API files */
#include <vnet/ip/ip_types.api_tojson.h>
#include <vnet/interface_types.api_tojson.h>
#ifndef included_svs_api_tojson_h
#define included_svs_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_svs_plugin_get_version_t_tojson (vl_api_svs_plugin_get_version_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "svs_plugin_get_version");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_svs_plugin_get_version_reply_t_tojson (vl_api_svs_plugin_get_version_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "svs_plugin_get_version_reply");
    cJSON_AddStringToObject(o, "_crc", "9b32cf86");
    cJSON_AddNumberToObject(o, "major", a->major);
    cJSON_AddNumberToObject(o, "minor", a->minor);
    return o;
}
static inline cJSON *vl_api_svs_table_add_del_t_tojson (vl_api_svs_table_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "svs_table_add_del");
    cJSON_AddStringToObject(o, "_crc", "7d21cb2a");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "af", vl_api_address_family_t_tojson(a->af));
    cJSON_AddNumberToObject(o, "table_id", a->table_id);
    return o;
}
static inline cJSON *vl_api_svs_table_add_del_reply_t_tojson (vl_api_svs_table_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "svs_table_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_svs_route_add_del_t_tojson (vl_api_svs_route_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "svs_route_add_del");
    cJSON_AddStringToObject(o, "_crc", "e49bc63c");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "prefix", vl_api_prefix_t_tojson(&a->prefix));
    cJSON_AddNumberToObject(o, "table_id", a->table_id);
    cJSON_AddNumberToObject(o, "source_table_id", a->source_table_id);
    return o;
}
static inline cJSON *vl_api_svs_route_add_del_reply_t_tojson (vl_api_svs_route_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "svs_route_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_svs_enable_disable_t_tojson (vl_api_svs_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "svs_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "634b89d2");
    cJSON_AddBoolToObject(o, "is_enable", a->is_enable);
    cJSON_AddItemToObject(o, "af", vl_api_address_family_t_tojson(a->af));
    cJSON_AddNumberToObject(o, "table_id", a->table_id);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_svs_enable_disable_reply_t_tojson (vl_api_svs_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "svs_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_svs_dump_t_tojson (vl_api_svs_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "svs_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_svs_details_t_tojson (vl_api_svs_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "svs_details");
    cJSON_AddStringToObject(o, "_crc", "6282cd55");
    cJSON_AddNumberToObject(o, "table_id", a->table_id);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "af", vl_api_address_family_t_tojson(a->af));
    return o;
}
#endif
