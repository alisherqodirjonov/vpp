/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/tunnel/tunnel_types.api_tojson.h>
#include <vnet/ip/ip_types.api_tojson.h>
#ifndef included_gre_api_tojson_h
#define included_gre_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_gre_tunnel_type_t_tojson (vl_api_gre_tunnel_type_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("GRE_API_TUNNEL_TYPE_L3");
    case 1:
        return cJSON_CreateString("GRE_API_TUNNEL_TYPE_TEB");
    case 2:
        return cJSON_CreateString("GRE_API_TUNNEL_TYPE_ERSPAN");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_gre_tunnel_t_tojson (vl_api_gre_tunnel_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "type", vl_api_gre_tunnel_type_t_tojson(a->type));
    cJSON_AddItemToObject(o, "mode", vl_api_tunnel_mode_t_tojson(a->mode));
    cJSON_AddItemToObject(o, "flags", vl_api_tunnel_encap_decap_flags_t_tojson(a->flags));
    cJSON_AddNumberToObject(o, "session_id", a->session_id);
    cJSON_AddNumberToObject(o, "instance", a->instance);
    cJSON_AddNumberToObject(o, "outer_table_id", a->outer_table_id);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "src", vl_api_address_t_tojson(&a->src));
    cJSON_AddItemToObject(o, "dst", vl_api_address_t_tojson(&a->dst));
    return o;
}
static inline cJSON *vl_api_gre_tunnel_v2_t_tojson (vl_api_gre_tunnel_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "type", vl_api_gre_tunnel_type_t_tojson(a->type));
    cJSON_AddItemToObject(o, "mode", vl_api_tunnel_mode_t_tojson(a->mode));
    cJSON_AddItemToObject(o, "flags", vl_api_tunnel_encap_decap_flags_t_tojson(a->flags));
    cJSON_AddNumberToObject(o, "session_id", a->session_id);
    cJSON_AddNumberToObject(o, "instance", a->instance);
    cJSON_AddNumberToObject(o, "outer_table_id", a->outer_table_id);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "src", vl_api_address_t_tojson(&a->src));
    cJSON_AddItemToObject(o, "dst", vl_api_address_t_tojson(&a->dst));
    cJSON_AddNumberToObject(o, "key", a->key);
    return o;
}
static inline cJSON *vl_api_gre_tunnel_add_del_t_tojson (vl_api_gre_tunnel_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gre_tunnel_add_del");
    cJSON_AddStringToObject(o, "_crc", "a27d7f17");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "tunnel", vl_api_gre_tunnel_t_tojson(&a->tunnel));
    return o;
}
static inline cJSON *vl_api_gre_tunnel_add_del_reply_t_tojson (vl_api_gre_tunnel_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gre_tunnel_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_gre_tunnel_add_del_v2_t_tojson (vl_api_gre_tunnel_add_del_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gre_tunnel_add_del_v2");
    cJSON_AddStringToObject(o, "_crc", "7d9576de");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "tunnel", vl_api_gre_tunnel_v2_t_tojson(&a->tunnel));
    return o;
}
static inline cJSON *vl_api_gre_tunnel_add_del_v2_reply_t_tojson (vl_api_gre_tunnel_add_del_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gre_tunnel_add_del_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_gre_tunnel_dump_t_tojson (vl_api_gre_tunnel_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gre_tunnel_dump");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_gre_tunnel_dump_reply_t_tojson (vl_api_gre_tunnel_dump_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gre_tunnel_dump_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_gre_tunnel_dump_v2_t_tojson (vl_api_gre_tunnel_dump_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gre_tunnel_dump_v2");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_gre_tunnel_dump_v2_reply_t_tojson (vl_api_gre_tunnel_dump_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gre_tunnel_dump_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_gre_tunnel_details_t_tojson (vl_api_gre_tunnel_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gre_tunnel_details");
    cJSON_AddStringToObject(o, "_crc", "24435433");
    cJSON_AddItemToObject(o, "tunnel", vl_api_gre_tunnel_t_tojson(&a->tunnel));
    return o;
}
static inline cJSON *vl_api_gre_tunnel_details_v2_t_tojson (vl_api_gre_tunnel_details_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gre_tunnel_details_v2");
    cJSON_AddStringToObject(o, "_crc", "65521177");
    cJSON_AddItemToObject(o, "tunnel", vl_api_gre_tunnel_v2_t_tojson(&a->tunnel));
    return o;
}
#endif
