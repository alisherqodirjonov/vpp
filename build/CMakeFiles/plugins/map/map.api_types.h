#ifndef included_map_api_types_h
#define included_map_api_types_h
#define VL_API_MAP_API_VERSION_MAJOR 4
#define VL_API_MAP_API_VERSION_MINOR 2
#define VL_API_MAP_API_VERSION_PATCH 1
/* Imported API files */
#include <vnet/ip/ip_types.api_types.h>
#include <vnet/interface_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_map_add_domain {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_ip6_prefix_t ip6_prefix;
    vl_api_ip4_prefix_t ip4_prefix;
    vl_api_ip6_prefix_t ip6_src;
    u8 ea_bits_len;
    u8 psid_offset;
    u8 psid_length;
    u16 mtu;
    u8 tag[64];
} vl_api_map_add_domain_t;
#define VL_API_MAP_ADD_DOMAIN_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_map_add_domain_reply {
    u16 _vl_msg_id;
    u32 context;
    u32 index;
    i32 retval;
} vl_api_map_add_domain_reply_t;
#define VL_API_MAP_ADD_DOMAIN_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_map_del_domain {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 index;
} vl_api_map_del_domain_t;
#define VL_API_MAP_DEL_DOMAIN_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_map_del_domain_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_map_del_domain_reply_t;
#define VL_API_MAP_DEL_DOMAIN_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_map_add_del_rule {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 index;
    bool is_add;
    vl_api_ip6_address_t ip6_dst;
    u16 psid;
} vl_api_map_add_del_rule_t;
#define VL_API_MAP_ADD_DEL_RULE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_map_add_del_rule_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_map_add_del_rule_reply_t;
#define VL_API_MAP_ADD_DEL_RULE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_map_domains_get {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 cursor;
} vl_api_map_domains_get_t;
#define VL_API_MAP_DOMAINS_GET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_map_domains_get_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 cursor;
} vl_api_map_domains_get_reply_t;
#define VL_API_MAP_DOMAINS_GET_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_map_domain_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_map_domain_dump_t;
#define VL_API_MAP_DOMAIN_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_map_domain_details {
    u16 _vl_msg_id;
    u32 context;
    u32 domain_index;
    vl_api_ip6_prefix_t ip6_prefix;
    vl_api_ip4_prefix_t ip4_prefix;
    vl_api_ip6_prefix_t ip6_src;
    u8 ea_bits_len;
    u8 psid_offset;
    u8 psid_length;
    u8 flags;
    u16 mtu;
    u8 tag[64];
} vl_api_map_domain_details_t;
#define VL_API_MAP_DOMAIN_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_map_rule_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 domain_index;
} vl_api_map_rule_dump_t;
#define VL_API_MAP_RULE_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_map_rule_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_ip6_address_t ip6_dst;
    u16 psid;
} vl_api_map_rule_details_t;
#define VL_API_MAP_RULE_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_map_if_enable_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    bool is_enable;
    bool is_translation;
} vl_api_map_if_enable_disable_t;
#define VL_API_MAP_IF_ENABLE_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_map_if_enable_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_map_if_enable_disable_reply_t;
#define VL_API_MAP_IF_ENABLE_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_map_summary_stats {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_map_summary_stats_t;
#define VL_API_MAP_SUMMARY_STATS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_map_summary_stats_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u64 total_bindings;
    u64 total_pkts[2];
    u64 total_bytes[2];
    u64 total_ip4_fragments;
    u64 total_security_check[2];
} vl_api_map_summary_stats_reply_t;
#define VL_API_MAP_SUMMARY_STATS_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_map_param_set_fragmentation {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool inner;
    bool ignore_df;
} vl_api_map_param_set_fragmentation_t;
#define VL_API_MAP_PARAM_SET_FRAGMENTATION_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_map_param_set_fragmentation_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_map_param_set_fragmentation_reply_t;
#define VL_API_MAP_PARAM_SET_FRAGMENTATION_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_map_param_set_icmp {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_ip4_address_t ip4_err_relay_src;
} vl_api_map_param_set_icmp_t;
#define VL_API_MAP_PARAM_SET_ICMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_map_param_set_icmp_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_map_param_set_icmp_reply_t;
#define VL_API_MAP_PARAM_SET_ICMP_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_map_param_set_icmp6 {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool enable_unreachable;
} vl_api_map_param_set_icmp6_t;
#define VL_API_MAP_PARAM_SET_ICMP6_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_map_param_set_icmp6_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_map_param_set_icmp6_reply_t;
#define VL_API_MAP_PARAM_SET_ICMP6_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_map_param_add_del_pre_resolve {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_ip4_address_t ip4_nh_address;
    vl_api_ip6_address_t ip6_nh_address;
} vl_api_map_param_add_del_pre_resolve_t;
#define VL_API_MAP_PARAM_ADD_DEL_PRE_RESOLVE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_map_param_add_del_pre_resolve_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_map_param_add_del_pre_resolve_reply_t;
#define VL_API_MAP_PARAM_ADD_DEL_PRE_RESOLVE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_map_param_set_security_check {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool enable;
    bool fragments;
} vl_api_map_param_set_security_check_t;
#define VL_API_MAP_PARAM_SET_SECURITY_CHECK_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_map_param_set_security_check_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_map_param_set_security_check_reply_t;
#define VL_API_MAP_PARAM_SET_SECURITY_CHECK_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_map_param_set_traffic_class {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool copy;
    u8 tc_class;
} vl_api_map_param_set_traffic_class_t;
#define VL_API_MAP_PARAM_SET_TRAFFIC_CLASS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_map_param_set_traffic_class_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_map_param_set_traffic_class_reply_t;
#define VL_API_MAP_PARAM_SET_TRAFFIC_CLASS_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_map_param_set_tcp {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u16 tcp_mss;
} vl_api_map_param_set_tcp_t;
#define VL_API_MAP_PARAM_SET_TCP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_map_param_set_tcp_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_map_param_set_tcp_reply_t;
#define VL_API_MAP_PARAM_SET_TCP_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_map_param_get {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_map_param_get_t;
#define VL_API_MAP_PARAM_GET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_map_param_get_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u8 frag_inner;
    u8 frag_ignore_df;
    vl_api_ip4_address_t icmp_ip4_err_relay_src;
    bool icmp6_enable_unreachable;
    vl_api_ip4_address_t ip4_nh_address;
    vl_api_ip6_address_t ip6_nh_address;
    u16 ip4_lifetime_ms;
    u16 ip4_pool_size;
    u32 ip4_buffers;
    f64 ip4_ht_ratio;
    bool sec_check_enable;
    bool sec_check_fragments;
    bool tc_copy;
    u8 tc_class;
} vl_api_map_param_get_reply_t;
#define VL_API_MAP_PARAM_GET_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_MAP_ADD_DOMAIN_CRC "map_add_domain_249f195c"
#define VL_API_MAP_ADD_DOMAIN_REPLY_CRC "map_add_domain_reply_3e6d4e2c"
#define VL_API_MAP_DEL_DOMAIN_CRC "map_del_domain_8ac76db6"
#define VL_API_MAP_DEL_DOMAIN_REPLY_CRC "map_del_domain_reply_e8d4e804"
#define VL_API_MAP_ADD_DEL_RULE_CRC "map_add_del_rule_c65b32f7"
#define VL_API_MAP_ADD_DEL_RULE_REPLY_CRC "map_add_del_rule_reply_e8d4e804"
#define VL_API_MAP_DOMAINS_GET_CRC "map_domains_get_f75ba505"
#define VL_API_MAP_DOMAINS_GET_REPLY_CRC "map_domains_get_reply_53b48f5d"
#define VL_API_MAP_DOMAIN_DUMP_CRC "map_domain_dump_51077d14"
#define VL_API_MAP_DOMAIN_DETAILS_CRC "map_domain_details_796edb50"
#define VL_API_MAP_RULE_DUMP_CRC "map_rule_dump_e43e6ff6"
#define VL_API_MAP_RULE_DETAILS_CRC "map_rule_details_c7cbeea5"
#define VL_API_MAP_IF_ENABLE_DISABLE_CRC "map_if_enable_disable_59bb32f4"
#define VL_API_MAP_IF_ENABLE_DISABLE_REPLY_CRC "map_if_enable_disable_reply_e8d4e804"
#define VL_API_MAP_SUMMARY_STATS_CRC "map_summary_stats_51077d14"
#define VL_API_MAP_SUMMARY_STATS_REPLY_CRC "map_summary_stats_reply_0e4ace0e"
#define VL_API_MAP_PARAM_SET_FRAGMENTATION_CRC "map_param_set_fragmentation_9ff54d90"
#define VL_API_MAP_PARAM_SET_FRAGMENTATION_REPLY_CRC "map_param_set_fragmentation_reply_e8d4e804"
#define VL_API_MAP_PARAM_SET_ICMP_CRC "map_param_set_icmp_58210cbf"
#define VL_API_MAP_PARAM_SET_ICMP_REPLY_CRC "map_param_set_icmp_reply_e8d4e804"
#define VL_API_MAP_PARAM_SET_ICMP6_CRC "map_param_set_icmp6_5d01f8c1"
#define VL_API_MAP_PARAM_SET_ICMP6_REPLY_CRC "map_param_set_icmp6_reply_e8d4e804"
#define VL_API_MAP_PARAM_ADD_DEL_PRE_RESOLVE_CRC "map_param_add_del_pre_resolve_dae5af03"
#define VL_API_MAP_PARAM_ADD_DEL_PRE_RESOLVE_REPLY_CRC "map_param_add_del_pre_resolve_reply_e8d4e804"
#define VL_API_MAP_PARAM_SET_SECURITY_CHECK_CRC "map_param_set_security_check_6abe9836"
#define VL_API_MAP_PARAM_SET_SECURITY_CHECK_REPLY_CRC "map_param_set_security_check_reply_e8d4e804"
#define VL_API_MAP_PARAM_SET_TRAFFIC_CLASS_CRC "map_param_set_traffic_class_9cac455c"
#define VL_API_MAP_PARAM_SET_TRAFFIC_CLASS_REPLY_CRC "map_param_set_traffic_class_reply_e8d4e804"
#define VL_API_MAP_PARAM_SET_TCP_CRC "map_param_set_tcp_87a825d9"
#define VL_API_MAP_PARAM_SET_TCP_REPLY_CRC "map_param_set_tcp_reply_e8d4e804"
#define VL_API_MAP_PARAM_GET_CRC "map_param_get_51077d14"
#define VL_API_MAP_PARAM_GET_REPLY_CRC "map_param_get_reply_26272c90"

#endif
