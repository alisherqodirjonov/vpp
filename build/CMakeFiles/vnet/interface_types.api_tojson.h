/* Imported API files */
#ifndef included_interface_types_api_tojson_h
#define included_interface_types_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#define vl_printfun
#include <vnet/interface_types.api.h>

static inline cJSON *vl_api_interface_index_t_tojson (vl_api_interface_index_t *a) {
    char *s = format_c_string(0, "%U", format_vl_api_interface_index_t, a);
    cJSON *o = cJSON_CreateString(s);
    vec_free(s);
    return o;
}
static inline cJSON *vl_api_if_status_flags_t_tojson (vl_api_if_status_flags_t a) {
    switch(a) {
    case 1:
        return cJSON_CreateString("IF_STATUS_API_FLAG_ADMIN_UP");
    case 2:
        return cJSON_CreateString("IF_STATUS_API_FLAG_LINK_UP");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_mtu_proto_t_tojson (vl_api_mtu_proto_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("MTU_PROTO_API_L3");
    case 1:
        return cJSON_CreateString("MTU_PROTO_API_IP4");
    case 2:
        return cJSON_CreateString("MTU_PROTO_API_IP6");
    case 3:
        return cJSON_CreateString("MTU_PROTO_API_MPLS");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_link_duplex_t_tojson (vl_api_link_duplex_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("LINK_DUPLEX_API_UNKNOWN");
    case 1:
        return cJSON_CreateString("LINK_DUPLEX_API_HALF");
    case 2:
        return cJSON_CreateString("LINK_DUPLEX_API_FULL");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_sub_if_flags_t_tojson (vl_api_sub_if_flags_t a) {
    switch(a) {
    case 1:
        return cJSON_CreateString("SUB_IF_API_FLAG_NO_TAGS");
    case 2:
        return cJSON_CreateString("SUB_IF_API_FLAG_ONE_TAG");
    case 4:
        return cJSON_CreateString("SUB_IF_API_FLAG_TWO_TAGS");
    case 8:
        return cJSON_CreateString("SUB_IF_API_FLAG_DOT1AD");
    case 16:
        return cJSON_CreateString("SUB_IF_API_FLAG_EXACT_MATCH");
    case 32:
        return cJSON_CreateString("SUB_IF_API_FLAG_DEFAULT");
    case 64:
        return cJSON_CreateString("SUB_IF_API_FLAG_OUTER_VLAN_ID_ANY");
    case 128:
        return cJSON_CreateString("SUB_IF_API_FLAG_INNER_VLAN_ID_ANY");
    case 254:
        return cJSON_CreateString("SUB_IF_API_FLAG_MASK_VNET");
    case 256:
        return cJSON_CreateString("SUB_IF_API_FLAG_DOT1AH");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_rx_mode_t_tojson (vl_api_rx_mode_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("RX_MODE_API_UNKNOWN");
    case 1:
        return cJSON_CreateString("RX_MODE_API_POLLING");
    case 2:
        return cJSON_CreateString("RX_MODE_API_INTERRUPT");
    case 3:
        return cJSON_CreateString("RX_MODE_API_ADAPTIVE");
    case 4:
        return cJSON_CreateString("RX_MODE_API_DEFAULT");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_if_type_t_tojson (vl_api_if_type_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("IF_API_TYPE_HARDWARE");
    case 1:
        return cJSON_CreateString("IF_API_TYPE_SUB");
    case 2:
        return cJSON_CreateString("IF_API_TYPE_P2P");
    case 3:
        return cJSON_CreateString("IF_API_TYPE_PIPE");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_direction_t_tojson (vl_api_direction_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("RX");
    case 1:
        return cJSON_CreateString("TX");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
#endif
