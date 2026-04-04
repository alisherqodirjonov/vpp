/* Imported API files */
#include <vnet/ip/ip_types.api_tojson.h>
#ifndef included_lb_types_api_tojson_h
#define included_lb_types_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_lb_srv_type_t_tojson (vl_api_lb_srv_type_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("LB_API_SRV_TYPE_CLUSTERIP");
    case 1:
        return cJSON_CreateString("LB_API_SRV_TYPE_NODEPORT");
    case 2:
        return cJSON_CreateString("LB_API_SRV_N_TYPES");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_lb_encap_type_t_tojson (vl_api_lb_encap_type_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("LB_API_ENCAP_TYPE_GRE4");
    case 1:
        return cJSON_CreateString("LB_API_ENCAP_TYPE_GRE6");
    case 2:
        return cJSON_CreateString("LB_API_ENCAP_TYPE_L3DSR");
    case 3:
        return cJSON_CreateString("LB_API_ENCAP_TYPE_NAT4");
    case 4:
        return cJSON_CreateString("LB_API_ENCAP_TYPE_NAT6");
    case 5:
        return cJSON_CreateString("LB_API_ENCAP_N_TYPES");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_lb_lkp_type_t_t_tojson (vl_api_lb_lkp_type_t_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("LB_API_LKP_SAME_IP_PORT");
    case 1:
        return cJSON_CreateString("LB_API_LKP_DIFF_IP_PORT");
    case 2:
        return cJSON_CreateString("LB_API_LKP_ALL_PORT_IP");
    case 3:
        return cJSON_CreateString("LB_API_LKP_N_TYPES");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_lb_vip_type_t_tojson (vl_api_lb_vip_type_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("LB_API_VIP_TYPE_IP6_GRE6");
    case 1:
        return cJSON_CreateString("LB_API_VIP_TYPE_IP6_GRE4");
    case 2:
        return cJSON_CreateString("LB_API_VIP_TYPE_IP4_GRE6");
    case 3:
        return cJSON_CreateString("LB_API_VIP_TYPE_IP4_GRE4");
    case 4:
        return cJSON_CreateString("LB_API_VIP_TYPE_IP4_L3DSR");
    case 5:
        return cJSON_CreateString("LB_API_VIP_TYPE_IP4_NAT4");
    case 6:
        return cJSON_CreateString("LB_API_VIP_TYPE_IP6_NAT6");
    case 7:
        return cJSON_CreateString("LB_API_VIP_N_TYPES");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_lb_nat_protocol_t_tojson (vl_api_lb_nat_protocol_t a) {
    switch(a) {
    case 6:
        return cJSON_CreateString("LB_API_NAT_PROTOCOL_UDP");
    case 23:
        return cJSON_CreateString("LB_API_NAT_PROTOCOL_TCP");
    case 4294967295:
        return cJSON_CreateString("LB_API_NAT_PROTOCOL_ANY");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_lb_vip_t_tojson (vl_api_lb_vip_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "pfx", vl_api_address_with_prefix_t_tojson(&a->pfx));
    cJSON_AddItemToObject(o, "protocol", vl_api_ip_proto_t_tojson(a->protocol));
    cJSON_AddNumberToObject(o, "port", a->port);
    return o;
}
#endif
