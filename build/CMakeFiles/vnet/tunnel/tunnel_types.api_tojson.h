/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ip/ip_types.api_tojson.h>
#ifndef included_tunnel_types_api_tojson_h
#define included_tunnel_types_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_tunnel_encap_decap_flags_t_tojson (vl_api_tunnel_encap_decap_flags_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("TUNNEL_API_ENCAP_DECAP_FLAG_NONE");
    case 1:
        return cJSON_CreateString("TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_DF");
    case 2:
        return cJSON_CreateString("TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_SET_DF");
    case 4:
        return cJSON_CreateString("TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_DSCP");
    case 8:
        return cJSON_CreateString("TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_ECN");
    case 16:
        return cJSON_CreateString("TUNNEL_API_ENCAP_DECAP_FLAG_DECAP_COPY_ECN");
    case 32:
        return cJSON_CreateString("TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_INNER_HASH");
    case 64:
        return cJSON_CreateString("TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_HOP_LIMIT");
    case 128:
        return cJSON_CreateString("TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_FLOW_LABEL");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_tunnel_mode_t_tojson (vl_api_tunnel_mode_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("TUNNEL_API_MODE_P2P");
    case 1:
        return cJSON_CreateString("TUNNEL_API_MODE_MP");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_tunnel_flags_t_tojson (vl_api_tunnel_flags_t a) {
    cJSON *array = cJSON_CreateArray();
    if (a & TUNNEL_API_FLAG_TRACK_MTU)
       cJSON_AddItemToArray(array, cJSON_CreateString("TUNNEL_API_FLAG_TRACK_MTU"));
    return array;
}
static inline cJSON *vl_api_tunnel_t_tojson (vl_api_tunnel_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "instance", a->instance);
    cJSON_AddItemToObject(o, "src", vl_api_address_t_tojson(&a->src));
    cJSON_AddItemToObject(o, "dst", vl_api_address_t_tojson(&a->dst));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "table_id", a->table_id);
    cJSON_AddItemToObject(o, "encap_decap_flags", vl_api_tunnel_encap_decap_flags_t_tojson(a->encap_decap_flags));
    cJSON_AddItemToObject(o, "mode", vl_api_tunnel_mode_t_tojson(a->mode));
    cJSON_AddItemToObject(o, "flags", vl_api_tunnel_flags_t_tojson(a->flags));
    cJSON_AddItemToObject(o, "dscp", vl_api_ip_dscp_t_tojson(a->dscp));
    cJSON_AddNumberToObject(o, "hop_limit", a->hop_limit);
    return o;
}
#endif
