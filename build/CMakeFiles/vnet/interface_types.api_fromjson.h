/* Imported API files */
#ifndef included_interface_types_api_fromjson_h
#define included_interface_types_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_interface_index_t_fromjson (void **mp, int *len, cJSON *o, vl_api_interface_index_t *a) {
    vl_api_u32_fromjson(o, (u32 *)a);
    return 0;
}
static inline int vl_api_if_status_flags_t_fromjson(void **mp, int *len, cJSON *o, vl_api_if_status_flags_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "IF_STATUS_API_FLAG_ADMIN_UP") == 0) {*a = 1; return 0;}
    if (strcmp(p, "IF_STATUS_API_FLAG_LINK_UP") == 0) {*a = 2; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_mtu_proto_t_fromjson(void **mp, int *len, cJSON *o, vl_api_mtu_proto_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "MTU_PROTO_API_L3") == 0) {*a = 0; return 0;}
    if (strcmp(p, "MTU_PROTO_API_IP4") == 0) {*a = 1; return 0;}
    if (strcmp(p, "MTU_PROTO_API_IP6") == 0) {*a = 2; return 0;}
    if (strcmp(p, "MTU_PROTO_API_MPLS") == 0) {*a = 3; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_link_duplex_t_fromjson(void **mp, int *len, cJSON *o, vl_api_link_duplex_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "LINK_DUPLEX_API_UNKNOWN") == 0) {*a = 0; return 0;}
    if (strcmp(p, "LINK_DUPLEX_API_HALF") == 0) {*a = 1; return 0;}
    if (strcmp(p, "LINK_DUPLEX_API_FULL") == 0) {*a = 2; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_sub_if_flags_t_fromjson(void **mp, int *len, cJSON *o, vl_api_sub_if_flags_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "SUB_IF_API_FLAG_NO_TAGS") == 0) {*a = 1; return 0;}
    if (strcmp(p, "SUB_IF_API_FLAG_ONE_TAG") == 0) {*a = 2; return 0;}
    if (strcmp(p, "SUB_IF_API_FLAG_TWO_TAGS") == 0) {*a = 4; return 0;}
    if (strcmp(p, "SUB_IF_API_FLAG_DOT1AD") == 0) {*a = 8; return 0;}
    if (strcmp(p, "SUB_IF_API_FLAG_EXACT_MATCH") == 0) {*a = 16; return 0;}
    if (strcmp(p, "SUB_IF_API_FLAG_DEFAULT") == 0) {*a = 32; return 0;}
    if (strcmp(p, "SUB_IF_API_FLAG_OUTER_VLAN_ID_ANY") == 0) {*a = 64; return 0;}
    if (strcmp(p, "SUB_IF_API_FLAG_INNER_VLAN_ID_ANY") == 0) {*a = 128; return 0;}
    if (strcmp(p, "SUB_IF_API_FLAG_MASK_VNET") == 0) {*a = 254; return 0;}
    if (strcmp(p, "SUB_IF_API_FLAG_DOT1AH") == 0) {*a = 256; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_rx_mode_t_fromjson(void **mp, int *len, cJSON *o, vl_api_rx_mode_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "RX_MODE_API_UNKNOWN") == 0) {*a = 0; return 0;}
    if (strcmp(p, "RX_MODE_API_POLLING") == 0) {*a = 1; return 0;}
    if (strcmp(p, "RX_MODE_API_INTERRUPT") == 0) {*a = 2; return 0;}
    if (strcmp(p, "RX_MODE_API_ADAPTIVE") == 0) {*a = 3; return 0;}
    if (strcmp(p, "RX_MODE_API_DEFAULT") == 0) {*a = 4; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_if_type_t_fromjson(void **mp, int *len, cJSON *o, vl_api_if_type_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "IF_API_TYPE_HARDWARE") == 0) {*a = 0; return 0;}
    if (strcmp(p, "IF_API_TYPE_SUB") == 0) {*a = 1; return 0;}
    if (strcmp(p, "IF_API_TYPE_P2P") == 0) {*a = 2; return 0;}
    if (strcmp(p, "IF_API_TYPE_PIPE") == 0) {*a = 3; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_direction_t_fromjson(void **mp, int *len, cJSON *o, vl_api_direction_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "RX") == 0) {*a = 0; return 0;}
    if (strcmp(p, "TX") == 0) {*a = 1; return 0;}
    *a = 0;
    return -1;
}
#endif
