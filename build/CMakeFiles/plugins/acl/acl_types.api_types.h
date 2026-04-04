#ifndef included_acl_types_api_types_h
#define included_acl_types_api_types_h
#define VL_API_ACL_TYPES_API_VERSION_MAJOR 1
#define VL_API_ACL_TYPES_API_VERSION_MINOR 0
#define VL_API_ACL_TYPES_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/ip/ip_types.api_types.h>
#include <vnet/ethernet/ethernet_types.api_types.h>
typedef enum __attribute__((packed)) {
    ACL_ACTION_API_DENY = 0,
    ACL_ACTION_API_PERMIT = 1,
    ACL_ACTION_API_PERMIT_REFLECT = 2,
} vl_api_acl_action_t;
STATIC_ASSERT(sizeof(vl_api_acl_action_t) == sizeof(u8), "size of API enum acl_action is wrong");
typedef struct __attribute__ ((packed)) _vl_api_acl_rule {
    vl_api_acl_action_t is_permit;
    vl_api_prefix_t src_prefix;
    vl_api_prefix_t dst_prefix;
    vl_api_ip_proto_t proto;
    u16 srcport_or_icmptype_first;
    u16 srcport_or_icmptype_last;
    u16 dstport_or_icmpcode_first;
    u16 dstport_or_icmpcode_last;
    u8 tcp_flags_mask;
    u8 tcp_flags_value;
} vl_api_acl_rule_t;
#define VL_API_ACL_RULE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_macip_acl_rule {
    vl_api_acl_action_t is_permit;
    vl_api_mac_address_t src_mac;
    vl_api_mac_address_t src_mac_mask;
    vl_api_prefix_t src_prefix;
} vl_api_macip_acl_rule_t;
#define VL_API_MACIP_ACL_RULE_IS_CONSTANT_SIZE (1)


#endif
