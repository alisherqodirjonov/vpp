/* Imported API files */
#ifndef included_ip_types_api_tojson_h
#define included_ip_types_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

/* Manual print ip4_address */
/* Manual print ip6_address */
static inline cJSON *vl_api_address_family_t_tojson (vl_api_address_family_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("ADDRESS_IP4");
    case 1:
        return cJSON_CreateString("ADDRESS_IP6");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_ip_feature_location_t_tojson (vl_api_ip_feature_location_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("IP_API_FEATURE_INPUT");
    case 1:
        return cJSON_CreateString("IP_API_FEATURE_OUTPUT");
    case 2:
        return cJSON_CreateString("IP_API_FEATURE_LOCAL");
    case 3:
        return cJSON_CreateString("IP_API_FEATURE_PUNT");
    case 4:
        return cJSON_CreateString("IP_API_FEATURE_DROP");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_ip_ecn_t_tojson (vl_api_ip_ecn_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("IP_API_ECN_NONE");
    case 1:
        return cJSON_CreateString("IP_API_ECN_ECT0");
    case 2:
        return cJSON_CreateString("IP_API_ECN_ECT1");
    case 3:
        return cJSON_CreateString("IP_API_ECN_CE");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_ip_dscp_t_tojson (vl_api_ip_dscp_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("IP_API_DSCP_CS0");
    case 8:
        return cJSON_CreateString("IP_API_DSCP_CS1");
    case 10:
        return cJSON_CreateString("IP_API_DSCP_AF11");
    case 12:
        return cJSON_CreateString("IP_API_DSCP_AF12");
    case 14:
        return cJSON_CreateString("IP_API_DSCP_AF13");
    case 16:
        return cJSON_CreateString("IP_API_DSCP_CS2");
    case 18:
        return cJSON_CreateString("IP_API_DSCP_AF21");
    case 20:
        return cJSON_CreateString("IP_API_DSCP_AF22");
    case 22:
        return cJSON_CreateString("IP_API_DSCP_AF23");
    case 24:
        return cJSON_CreateString("IP_API_DSCP_CS3");
    case 26:
        return cJSON_CreateString("IP_API_DSCP_AF31");
    case 28:
        return cJSON_CreateString("IP_API_DSCP_AF32");
    case 30:
        return cJSON_CreateString("IP_API_DSCP_AF33");
    case 32:
        return cJSON_CreateString("IP_API_DSCP_CS4");
    case 34:
        return cJSON_CreateString("IP_API_DSCP_AF41");
    case 36:
        return cJSON_CreateString("IP_API_DSCP_AF42");
    case 38:
        return cJSON_CreateString("IP_API_DSCP_AF43");
    case 40:
        return cJSON_CreateString("IP_API_DSCP_CS5");
    case 46:
        return cJSON_CreateString("IP_API_DSCP_EF");
    case 48:
        return cJSON_CreateString("IP_API_DSCP_CS6");
    case 50:
        return cJSON_CreateString("IP_API_DSCP_CS7");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_ip_proto_t_tojson (vl_api_ip_proto_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("IP_API_PROTO_HOPOPT");
    case 1:
        return cJSON_CreateString("IP_API_PROTO_ICMP");
    case 2:
        return cJSON_CreateString("IP_API_PROTO_IGMP");
    case 6:
        return cJSON_CreateString("IP_API_PROTO_TCP");
    case 17:
        return cJSON_CreateString("IP_API_PROTO_UDP");
    case 47:
        return cJSON_CreateString("IP_API_PROTO_GRE");
    case 50:
        return cJSON_CreateString("IP_API_PROTO_ESP");
    case 51:
        return cJSON_CreateString("IP_API_PROTO_AH");
    case 58:
        return cJSON_CreateString("IP_API_PROTO_ICMP6");
    case 88:
        return cJSON_CreateString("IP_API_PROTO_EIGRP");
    case 89:
        return cJSON_CreateString("IP_API_PROTO_OSPF");
    case 132:
        return cJSON_CreateString("IP_API_PROTO_SCTP");
    case 255:
        return cJSON_CreateString("IP_API_PROTO_RESERVED");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_address_union_t_tojson (vl_api_address_union_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "ip4", vl_api_ip4_address_t_tojson(&a->ip4));
    cJSON_AddItemToObject(o, "ip6", vl_api_ip6_address_t_tojson(&a->ip6));
    return o;
}
/* Manual print address */
/* Manual print prefix */
static inline cJSON *vl_api_ip4_address_and_mask_t_tojson (vl_api_ip4_address_and_mask_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "addr", vl_api_ip4_address_t_tojson(&a->addr));
    cJSON_AddItemToObject(o, "mask", vl_api_ip4_address_t_tojson(&a->mask));
    return o;
}
static inline cJSON *vl_api_ip6_address_and_mask_t_tojson (vl_api_ip6_address_and_mask_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "addr", vl_api_ip6_address_t_tojson(&a->addr));
    cJSON_AddItemToObject(o, "mask", vl_api_ip6_address_t_tojson(&a->mask));
    return o;
}
static inline cJSON *vl_api_mprefix_t_tojson (vl_api_mprefix_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "af", vl_api_address_family_t_tojson(a->af));
    cJSON_AddNumberToObject(o, "grp_address_length", a->grp_address_length);
    cJSON_AddItemToObject(o, "grp_address", vl_api_address_union_t_tojson(&a->grp_address));
    cJSON_AddItemToObject(o, "src_address", vl_api_address_union_t_tojson(&a->src_address));
    return o;
}
/* Manual print ip6_prefix */
/* Manual print ip4_prefix */
/* Manual print address_with_prefix */
/* Manual print ip4_address_with_prefix */
/* Manual print ip6_address_with_prefix */
static inline cJSON *vl_api_prefix_matcher_t_tojson (vl_api_prefix_matcher_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "le", a->le);
    cJSON_AddNumberToObject(o, "ge", a->ge);
    return o;
}
#endif
