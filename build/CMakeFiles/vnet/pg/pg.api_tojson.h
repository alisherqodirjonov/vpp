/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#ifndef included_pg_api_tojson_h
#define included_pg_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_pg_interface_mode_t_tojson (vl_api_pg_interface_mode_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("PG_API_MODE_ETHERNET");
    case 1:
        return cJSON_CreateString("PG_API_MODE_IP4");
    case 2:
        return cJSON_CreateString("PG_API_MODE_IP6");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_pg_interface_flags_t_tojson (vl_api_pg_interface_flags_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("PG_API_FLAG_NONE");
    case 1:
        return cJSON_CreateString("PG_API_FLAG_CSUM_OFFLOAD");
    case 2:
        return cJSON_CreateString("PG_API_FLAG_GSO");
    case 4:
        return cJSON_CreateString("PG_API_FLAG_GRO_COALESCE");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_pg_create_interface_t_tojson (vl_api_pg_create_interface_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pg_create_interface");
    cJSON_AddStringToObject(o, "_crc", "b7c893d7");
    cJSON_AddNumberToObject(o, "interface_id", a->interface_id);
    cJSON_AddBoolToObject(o, "gso_enabled", a->gso_enabled);
    cJSON_AddNumberToObject(o, "gso_size", a->gso_size);
    return o;
}
static inline cJSON *vl_api_pg_create_interface_v2_t_tojson (vl_api_pg_create_interface_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pg_create_interface_v2");
    cJSON_AddStringToObject(o, "_crc", "8657466a");
    cJSON_AddNumberToObject(o, "interface_id", a->interface_id);
    cJSON_AddBoolToObject(o, "gso_enabled", a->gso_enabled);
    cJSON_AddNumberToObject(o, "gso_size", a->gso_size);
    cJSON_AddItemToObject(o, "mode", vl_api_pg_interface_mode_t_tojson(a->mode));
    return o;
}
static inline cJSON *vl_api_pg_create_interface_v3_t_tojson (vl_api_pg_create_interface_v3_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pg_create_interface_v3");
    cJSON_AddStringToObject(o, "_crc", "b2aac653");
    cJSON_AddNumberToObject(o, "interface_id", a->interface_id);
    cJSON_AddItemToObject(o, "pg_flags", vl_api_pg_interface_flags_t_tojson(a->pg_flags));
    cJSON_AddNumberToObject(o, "gso_size", a->gso_size);
    cJSON_AddItemToObject(o, "mode", vl_api_pg_interface_mode_t_tojson(a->mode));
    return o;
}
static inline cJSON *vl_api_pg_create_interface_reply_t_tojson (vl_api_pg_create_interface_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pg_create_interface_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_pg_create_interface_v2_reply_t_tojson (vl_api_pg_create_interface_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pg_create_interface_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_pg_create_interface_v3_reply_t_tojson (vl_api_pg_create_interface_v3_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pg_create_interface_v3_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_pg_delete_interface_t_tojson (vl_api_pg_delete_interface_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pg_delete_interface");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_pg_delete_interface_reply_t_tojson (vl_api_pg_delete_interface_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pg_delete_interface_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_pg_interface_enable_disable_coalesce_t_tojson (vl_api_pg_interface_enable_disable_coalesce_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pg_interface_enable_disable_coalesce");
    cJSON_AddStringToObject(o, "_crc", "a2ef99e7");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "coalesce_enabled", a->coalesce_enabled);
    return o;
}
static inline cJSON *vl_api_pg_interface_enable_disable_coalesce_reply_t_tojson (vl_api_pg_interface_enable_disable_coalesce_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pg_interface_enable_disable_coalesce_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_pg_capture_t_tojson (vl_api_pg_capture_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pg_capture");
    cJSON_AddStringToObject(o, "_crc", "3712fb6c");
    cJSON_AddNumberToObject(o, "interface_id", a->interface_id);
    cJSON_AddBoolToObject(o, "is_enabled", a->is_enabled);
    cJSON_AddNumberToObject(o, "count", a->count);
    vl_api_string_cJSON_AddToObject(o, "pcap_file_name", &a->pcap_file_name);
    return o;
}
static inline cJSON *vl_api_pg_capture_reply_t_tojson (vl_api_pg_capture_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pg_capture_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_pg_enable_disable_t_tojson (vl_api_pg_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pg_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "01f94f3a");
    cJSON_AddBoolToObject(o, "is_enabled", a->is_enabled);
    vl_api_string_cJSON_AddToObject(o, "stream_name", &a->stream_name);
    return o;
}
static inline cJSON *vl_api_pg_enable_disable_reply_t_tojson (vl_api_pg_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pg_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
