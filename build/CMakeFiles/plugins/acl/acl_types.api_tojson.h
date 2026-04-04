/* Imported API files */
#include <vnet/ip/ip_types.api_tojson.h>
#include <vnet/ethernet/ethernet_types.api_tojson.h>
#ifndef included_acl_types_api_tojson_h
#define included_acl_types_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_acl_action_t_tojson (vl_api_acl_action_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("ACL_ACTION_API_DENY");
    case 1:
        return cJSON_CreateString("ACL_ACTION_API_PERMIT");
    case 2:
        return cJSON_CreateString("ACL_ACTION_API_PERMIT_REFLECT");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_acl_rule_t_tojson (vl_api_acl_rule_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "is_permit", vl_api_acl_action_t_tojson(a->is_permit));
    cJSON_AddItemToObject(o, "src_prefix", vl_api_prefix_t_tojson(&a->src_prefix));
    cJSON_AddItemToObject(o, "dst_prefix", vl_api_prefix_t_tojson(&a->dst_prefix));
    cJSON_AddItemToObject(o, "proto", vl_api_ip_proto_t_tojson(a->proto));
    cJSON_AddNumberToObject(o, "srcport_or_icmptype_first", a->srcport_or_icmptype_first);
    cJSON_AddNumberToObject(o, "srcport_or_icmptype_last", a->srcport_or_icmptype_last);
    cJSON_AddNumberToObject(o, "dstport_or_icmpcode_first", a->dstport_or_icmpcode_first);
    cJSON_AddNumberToObject(o, "dstport_or_icmpcode_last", a->dstport_or_icmpcode_last);
    cJSON_AddNumberToObject(o, "tcp_flags_mask", a->tcp_flags_mask);
    cJSON_AddNumberToObject(o, "tcp_flags_value", a->tcp_flags_value);
    return o;
}
static inline cJSON *vl_api_macip_acl_rule_t_tojson (vl_api_macip_acl_rule_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "is_permit", vl_api_acl_action_t_tojson(a->is_permit));
    cJSON_AddItemToObject(o, "src_mac", vl_api_mac_address_t_tojson(&a->src_mac));
    cJSON_AddItemToObject(o, "src_mac_mask", vl_api_mac_address_t_tojson(&a->src_mac_mask));
    cJSON_AddItemToObject(o, "src_prefix", vl_api_prefix_t_tojson(&a->src_prefix));
    return o;
}
#endif
