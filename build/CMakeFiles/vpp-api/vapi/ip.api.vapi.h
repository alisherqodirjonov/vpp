#ifndef __included_ip_api_json
#define __included_ip_api_json

#include <stdlib.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <vapi/vapi_internal.h>
#include <vapi/vapi.h>
#include <vapi/vapi_dbg.h>

#ifdef __cplusplus
extern "C" {
#endif
#ifndef __vl_api_string_swap_fns_defined__
#define __vl_api_string_swap_fns_defined__

#include <vlibapi/api_types.h>

static inline void vl_api_string_t_hton(vl_api_string_t *msg)
{
  msg->length = htobe32(msg->length);
}

static inline void vl_api_string_t_ntoh(vl_api_string_t *msg)
{
  msg->length = be32toh(msg->length);
}

#endif //__vl_api_string_swap_fns_defined__
#include <vapi/vlib.api.vapi.h>

extern vapi_msg_id_t vapi_msg_id_ip_table_add_del;
extern vapi_msg_id_t vapi_msg_id_ip_table_add_del_reply;
extern vapi_msg_id_t vapi_msg_id_ip_table_add_del_v2;
extern vapi_msg_id_t vapi_msg_id_ip_table_add_del_v2_reply;
extern vapi_msg_id_t vapi_msg_id_ip_table_allocate;
extern vapi_msg_id_t vapi_msg_id_ip_table_allocate_reply;
extern vapi_msg_id_t vapi_msg_id_ip_table_dump;
extern vapi_msg_id_t vapi_msg_id_ip_table_replace_begin;
extern vapi_msg_id_t vapi_msg_id_ip_table_replace_begin_reply;
extern vapi_msg_id_t vapi_msg_id_ip_table_replace_end;
extern vapi_msg_id_t vapi_msg_id_ip_table_replace_end_reply;
extern vapi_msg_id_t vapi_msg_id_ip_table_flush;
extern vapi_msg_id_t vapi_msg_id_ip_table_flush_reply;
extern vapi_msg_id_t vapi_msg_id_ip_table_details;
extern vapi_msg_id_t vapi_msg_id_ip_route_add_del;
extern vapi_msg_id_t vapi_msg_id_ip_route_add_del_v2;
extern vapi_msg_id_t vapi_msg_id_ip_route_add_del_reply;
extern vapi_msg_id_t vapi_msg_id_ip_route_add_del_v2_reply;
extern vapi_msg_id_t vapi_msg_id_ip_route_dump;
extern vapi_msg_id_t vapi_msg_id_ip_route_v2_dump;
extern vapi_msg_id_t vapi_msg_id_ip_route_details;
extern vapi_msg_id_t vapi_msg_id_ip_route_v2_details;
extern vapi_msg_id_t vapi_msg_id_ip_route_lookup;
extern vapi_msg_id_t vapi_msg_id_ip_route_lookup_v2;
extern vapi_msg_id_t vapi_msg_id_ip_route_lookup_reply;
extern vapi_msg_id_t vapi_msg_id_ip_route_lookup_v2_reply;
extern vapi_msg_id_t vapi_msg_id_set_ip_flow_hash;
extern vapi_msg_id_t vapi_msg_id_set_ip_flow_hash_reply;
extern vapi_msg_id_t vapi_msg_id_set_ip_flow_hash_v2;
extern vapi_msg_id_t vapi_msg_id_set_ip_flow_hash_v2_reply;
extern vapi_msg_id_t vapi_msg_id_set_ip_flow_hash_v3;
extern vapi_msg_id_t vapi_msg_id_set_ip_flow_hash_v3_reply;
extern vapi_msg_id_t vapi_msg_id_set_ip_flow_hash_router_id;
extern vapi_msg_id_t vapi_msg_id_set_ip_flow_hash_router_id_reply;
extern vapi_msg_id_t vapi_msg_id_sw_interface_ip6_enable_disable;
extern vapi_msg_id_t vapi_msg_id_sw_interface_ip6_enable_disable_reply;
extern vapi_msg_id_t vapi_msg_id_sw_interface_ip4_enable_disable;
extern vapi_msg_id_t vapi_msg_id_sw_interface_ip4_enable_disable_reply;
extern vapi_msg_id_t vapi_msg_id_ip_mtable_dump;
extern vapi_msg_id_t vapi_msg_id_ip_mtable_details;
extern vapi_msg_id_t vapi_msg_id_ip_mroute_add_del;
extern vapi_msg_id_t vapi_msg_id_ip_mroute_add_del_reply;
extern vapi_msg_id_t vapi_msg_id_ip_mroute_dump;
extern vapi_msg_id_t vapi_msg_id_ip_mroute_details;
extern vapi_msg_id_t vapi_msg_id_ip_address_details;
extern vapi_msg_id_t vapi_msg_id_ip_address_dump;
extern vapi_msg_id_t vapi_msg_id_ip_unnumbered_details;
extern vapi_msg_id_t vapi_msg_id_ip_unnumbered_dump;
extern vapi_msg_id_t vapi_msg_id_ip_details;
extern vapi_msg_id_t vapi_msg_id_ip_dump;
extern vapi_msg_id_t vapi_msg_id_mfib_signal_dump;
extern vapi_msg_id_t vapi_msg_id_mfib_signal_details;
extern vapi_msg_id_t vapi_msg_id_ip_punt_police;
extern vapi_msg_id_t vapi_msg_id_ip_punt_police_reply;
extern vapi_msg_id_t vapi_msg_id_ip_punt_redirect;
extern vapi_msg_id_t vapi_msg_id_ip_punt_redirect_reply;
extern vapi_msg_id_t vapi_msg_id_ip_punt_redirect_dump;
extern vapi_msg_id_t vapi_msg_id_ip_punt_redirect_details;
extern vapi_msg_id_t vapi_msg_id_add_del_ip_punt_redirect_v2;
extern vapi_msg_id_t vapi_msg_id_add_del_ip_punt_redirect_v2_reply;
extern vapi_msg_id_t vapi_msg_id_ip_punt_redirect_v2_dump;
extern vapi_msg_id_t vapi_msg_id_ip_punt_redirect_v2_details;
extern vapi_msg_id_t vapi_msg_id_ip_container_proxy_add_del;
extern vapi_msg_id_t vapi_msg_id_ip_container_proxy_add_del_reply;
extern vapi_msg_id_t vapi_msg_id_ip_container_proxy_dump;
extern vapi_msg_id_t vapi_msg_id_ip_container_proxy_details;
extern vapi_msg_id_t vapi_msg_id_ip_source_and_port_range_check_add_del;
extern vapi_msg_id_t vapi_msg_id_ip_source_and_port_range_check_add_del_reply;
extern vapi_msg_id_t vapi_msg_id_ip_source_and_port_range_check_interface_add_del;
extern vapi_msg_id_t vapi_msg_id_ip_source_and_port_range_check_interface_add_del_reply;
extern vapi_msg_id_t vapi_msg_id_sw_interface_ip6_set_link_local_address;
extern vapi_msg_id_t vapi_msg_id_sw_interface_ip6_set_link_local_address_reply;
extern vapi_msg_id_t vapi_msg_id_sw_interface_ip6_get_link_local_address;
extern vapi_msg_id_t vapi_msg_id_sw_interface_ip6_get_link_local_address_reply;
extern vapi_msg_id_t vapi_msg_id_ioam_enable;
extern vapi_msg_id_t vapi_msg_id_ioam_enable_reply;
extern vapi_msg_id_t vapi_msg_id_ioam_disable;
extern vapi_msg_id_t vapi_msg_id_ioam_disable_reply;
extern vapi_msg_id_t vapi_msg_id_ip_reassembly_set;
extern vapi_msg_id_t vapi_msg_id_ip_reassembly_set_reply;
extern vapi_msg_id_t vapi_msg_id_ip_reassembly_get;
extern vapi_msg_id_t vapi_msg_id_ip_reassembly_get_reply;
extern vapi_msg_id_t vapi_msg_id_ip_reassembly_enable_disable;
extern vapi_msg_id_t vapi_msg_id_ip_reassembly_enable_disable_reply;
extern vapi_msg_id_t vapi_msg_id_ip_local_reass_enable_disable;
extern vapi_msg_id_t vapi_msg_id_ip_local_reass_enable_disable_reply;
extern vapi_msg_id_t vapi_msg_id_ip_local_reass_get;
extern vapi_msg_id_t vapi_msg_id_ip_local_reass_get_reply;
extern vapi_msg_id_t vapi_msg_id_ip_path_mtu_update;
extern vapi_msg_id_t vapi_msg_id_ip_path_mtu_update_reply;
extern vapi_msg_id_t vapi_msg_id_ip_path_mtu_get;
extern vapi_msg_id_t vapi_msg_id_ip_path_mtu_get_reply;
extern vapi_msg_id_t vapi_msg_id_ip_path_mtu_details;
extern vapi_msg_id_t vapi_msg_id_ip_path_mtu_replace_begin;
extern vapi_msg_id_t vapi_msg_id_ip_path_mtu_replace_begin_reply;
extern vapi_msg_id_t vapi_msg_id_ip_path_mtu_replace_end;
extern vapi_msg_id_t vapi_msg_id_ip_path_mtu_replace_end_reply;

#define DEFINE_VAPI_MSG_IDS_IP_API_JSON\
  vapi_msg_id_t vapi_msg_id_ip_table_add_del;\
  vapi_msg_id_t vapi_msg_id_ip_table_add_del_reply;\
  vapi_msg_id_t vapi_msg_id_ip_table_add_del_v2;\
  vapi_msg_id_t vapi_msg_id_ip_table_add_del_v2_reply;\
  vapi_msg_id_t vapi_msg_id_ip_table_allocate;\
  vapi_msg_id_t vapi_msg_id_ip_table_allocate_reply;\
  vapi_msg_id_t vapi_msg_id_ip_table_dump;\
  vapi_msg_id_t vapi_msg_id_ip_table_replace_begin;\
  vapi_msg_id_t vapi_msg_id_ip_table_replace_begin_reply;\
  vapi_msg_id_t vapi_msg_id_ip_table_replace_end;\
  vapi_msg_id_t vapi_msg_id_ip_table_replace_end_reply;\
  vapi_msg_id_t vapi_msg_id_ip_table_flush;\
  vapi_msg_id_t vapi_msg_id_ip_table_flush_reply;\
  vapi_msg_id_t vapi_msg_id_ip_table_details;\
  vapi_msg_id_t vapi_msg_id_ip_route_add_del;\
  vapi_msg_id_t vapi_msg_id_ip_route_add_del_v2;\
  vapi_msg_id_t vapi_msg_id_ip_route_add_del_reply;\
  vapi_msg_id_t vapi_msg_id_ip_route_add_del_v2_reply;\
  vapi_msg_id_t vapi_msg_id_ip_route_dump;\
  vapi_msg_id_t vapi_msg_id_ip_route_v2_dump;\
  vapi_msg_id_t vapi_msg_id_ip_route_details;\
  vapi_msg_id_t vapi_msg_id_ip_route_v2_details;\
  vapi_msg_id_t vapi_msg_id_ip_route_lookup;\
  vapi_msg_id_t vapi_msg_id_ip_route_lookup_v2;\
  vapi_msg_id_t vapi_msg_id_ip_route_lookup_reply;\
  vapi_msg_id_t vapi_msg_id_ip_route_lookup_v2_reply;\
  vapi_msg_id_t vapi_msg_id_set_ip_flow_hash;\
  vapi_msg_id_t vapi_msg_id_set_ip_flow_hash_reply;\
  vapi_msg_id_t vapi_msg_id_set_ip_flow_hash_v2;\
  vapi_msg_id_t vapi_msg_id_set_ip_flow_hash_v2_reply;\
  vapi_msg_id_t vapi_msg_id_set_ip_flow_hash_v3;\
  vapi_msg_id_t vapi_msg_id_set_ip_flow_hash_v3_reply;\
  vapi_msg_id_t vapi_msg_id_set_ip_flow_hash_router_id;\
  vapi_msg_id_t vapi_msg_id_set_ip_flow_hash_router_id_reply;\
  vapi_msg_id_t vapi_msg_id_sw_interface_ip6_enable_disable;\
  vapi_msg_id_t vapi_msg_id_sw_interface_ip6_enable_disable_reply;\
  vapi_msg_id_t vapi_msg_id_sw_interface_ip4_enable_disable;\
  vapi_msg_id_t vapi_msg_id_sw_interface_ip4_enable_disable_reply;\
  vapi_msg_id_t vapi_msg_id_ip_mtable_dump;\
  vapi_msg_id_t vapi_msg_id_ip_mtable_details;\
  vapi_msg_id_t vapi_msg_id_ip_mroute_add_del;\
  vapi_msg_id_t vapi_msg_id_ip_mroute_add_del_reply;\
  vapi_msg_id_t vapi_msg_id_ip_mroute_dump;\
  vapi_msg_id_t vapi_msg_id_ip_mroute_details;\
  vapi_msg_id_t vapi_msg_id_ip_address_details;\
  vapi_msg_id_t vapi_msg_id_ip_address_dump;\
  vapi_msg_id_t vapi_msg_id_ip_unnumbered_details;\
  vapi_msg_id_t vapi_msg_id_ip_unnumbered_dump;\
  vapi_msg_id_t vapi_msg_id_ip_details;\
  vapi_msg_id_t vapi_msg_id_ip_dump;\
  vapi_msg_id_t vapi_msg_id_mfib_signal_dump;\
  vapi_msg_id_t vapi_msg_id_mfib_signal_details;\
  vapi_msg_id_t vapi_msg_id_ip_punt_police;\
  vapi_msg_id_t vapi_msg_id_ip_punt_police_reply;\
  vapi_msg_id_t vapi_msg_id_ip_punt_redirect;\
  vapi_msg_id_t vapi_msg_id_ip_punt_redirect_reply;\
  vapi_msg_id_t vapi_msg_id_ip_punt_redirect_dump;\
  vapi_msg_id_t vapi_msg_id_ip_punt_redirect_details;\
  vapi_msg_id_t vapi_msg_id_add_del_ip_punt_redirect_v2;\
  vapi_msg_id_t vapi_msg_id_add_del_ip_punt_redirect_v2_reply;\
  vapi_msg_id_t vapi_msg_id_ip_punt_redirect_v2_dump;\
  vapi_msg_id_t vapi_msg_id_ip_punt_redirect_v2_details;\
  vapi_msg_id_t vapi_msg_id_ip_container_proxy_add_del;\
  vapi_msg_id_t vapi_msg_id_ip_container_proxy_add_del_reply;\
  vapi_msg_id_t vapi_msg_id_ip_container_proxy_dump;\
  vapi_msg_id_t vapi_msg_id_ip_container_proxy_details;\
  vapi_msg_id_t vapi_msg_id_ip_source_and_port_range_check_add_del;\
  vapi_msg_id_t vapi_msg_id_ip_source_and_port_range_check_add_del_reply;\
  vapi_msg_id_t vapi_msg_id_ip_source_and_port_range_check_interface_add_del;\
  vapi_msg_id_t vapi_msg_id_ip_source_and_port_range_check_interface_add_del_reply;\
  vapi_msg_id_t vapi_msg_id_sw_interface_ip6_set_link_local_address;\
  vapi_msg_id_t vapi_msg_id_sw_interface_ip6_set_link_local_address_reply;\
  vapi_msg_id_t vapi_msg_id_sw_interface_ip6_get_link_local_address;\
  vapi_msg_id_t vapi_msg_id_sw_interface_ip6_get_link_local_address_reply;\
  vapi_msg_id_t vapi_msg_id_ioam_enable;\
  vapi_msg_id_t vapi_msg_id_ioam_enable_reply;\
  vapi_msg_id_t vapi_msg_id_ioam_disable;\
  vapi_msg_id_t vapi_msg_id_ioam_disable_reply;\
  vapi_msg_id_t vapi_msg_id_ip_reassembly_set;\
  vapi_msg_id_t vapi_msg_id_ip_reassembly_set_reply;\
  vapi_msg_id_t vapi_msg_id_ip_reassembly_get;\
  vapi_msg_id_t vapi_msg_id_ip_reassembly_get_reply;\
  vapi_msg_id_t vapi_msg_id_ip_reassembly_enable_disable;\
  vapi_msg_id_t vapi_msg_id_ip_reassembly_enable_disable_reply;\
  vapi_msg_id_t vapi_msg_id_ip_local_reass_enable_disable;\
  vapi_msg_id_t vapi_msg_id_ip_local_reass_enable_disable_reply;\
  vapi_msg_id_t vapi_msg_id_ip_local_reass_get;\
  vapi_msg_id_t vapi_msg_id_ip_local_reass_get_reply;\
  vapi_msg_id_t vapi_msg_id_ip_path_mtu_update;\
  vapi_msg_id_t vapi_msg_id_ip_path_mtu_update_reply;\
  vapi_msg_id_t vapi_msg_id_ip_path_mtu_get;\
  vapi_msg_id_t vapi_msg_id_ip_path_mtu_get_reply;\
  vapi_msg_id_t vapi_msg_id_ip_path_mtu_details;\
  vapi_msg_id_t vapi_msg_id_ip_path_mtu_replace_begin;\
  vapi_msg_id_t vapi_msg_id_ip_path_mtu_replace_begin_reply;\
  vapi_msg_id_t vapi_msg_id_ip_path_mtu_replace_end;\
  vapi_msg_id_t vapi_msg_id_ip_path_mtu_replace_end_reply;


#ifndef defined_vapi_enum_if_status_flags
#define defined_vapi_enum_if_status_flags
typedef enum {
  IF_STATUS_API_FLAG_ADMIN_UP = 1,
  IF_STATUS_API_FLAG_LINK_UP = 2,
}  vapi_enum_if_status_flags;

#endif

#ifndef defined_vapi_enum_mtu_proto
#define defined_vapi_enum_mtu_proto
typedef enum {
  MTU_PROTO_API_L3 = 0,
  MTU_PROTO_API_IP4 = 1,
  MTU_PROTO_API_IP6 = 2,
  MTU_PROTO_API_MPLS = 3,
}  vapi_enum_mtu_proto;

#endif

#ifndef defined_vapi_enum_link_duplex
#define defined_vapi_enum_link_duplex
typedef enum {
  LINK_DUPLEX_API_UNKNOWN = 0,
  LINK_DUPLEX_API_HALF = 1,
  LINK_DUPLEX_API_FULL = 2,
}  vapi_enum_link_duplex;

#endif

#ifndef defined_vapi_enum_sub_if_flags
#define defined_vapi_enum_sub_if_flags
typedef enum {
  SUB_IF_API_FLAG_NO_TAGS = 1,
  SUB_IF_API_FLAG_ONE_TAG = 2,
  SUB_IF_API_FLAG_TWO_TAGS = 4,
  SUB_IF_API_FLAG_DOT1AD = 8,
  SUB_IF_API_FLAG_EXACT_MATCH = 16,
  SUB_IF_API_FLAG_DEFAULT = 32,
  SUB_IF_API_FLAG_OUTER_VLAN_ID_ANY = 64,
  SUB_IF_API_FLAG_INNER_VLAN_ID_ANY = 128,
  SUB_IF_API_FLAG_MASK_VNET = 254,
  SUB_IF_API_FLAG_DOT1AH = 256,
}  vapi_enum_sub_if_flags;

#endif

#ifndef defined_vapi_enum_rx_mode
#define defined_vapi_enum_rx_mode
typedef enum {
  RX_MODE_API_UNKNOWN = 0,
  RX_MODE_API_POLLING = 1,
  RX_MODE_API_INTERRUPT = 2,
  RX_MODE_API_ADAPTIVE = 3,
  RX_MODE_API_DEFAULT = 4,
}  vapi_enum_rx_mode;

#endif

#ifndef defined_vapi_enum_if_type
#define defined_vapi_enum_if_type
typedef enum {
  IF_API_TYPE_HARDWARE = 0,
  IF_API_TYPE_SUB = 1,
  IF_API_TYPE_P2P = 2,
  IF_API_TYPE_PIPE = 3,
}  vapi_enum_if_type;

#endif

#ifndef defined_vapi_enum_direction
#define defined_vapi_enum_direction
typedef enum {
  RX = 0,
  TX = 1,
} __attribute__((packed)) vapi_enum_direction;

#endif

#ifndef defined_vapi_enum_address_family
#define defined_vapi_enum_address_family
typedef enum {
  ADDRESS_IP4 = 0,
  ADDRESS_IP6 = 1,
} __attribute__((packed)) vapi_enum_address_family;

#endif

#ifndef defined_vapi_enum_ip_feature_location
#define defined_vapi_enum_ip_feature_location
typedef enum {
  IP_API_FEATURE_INPUT = 0,
  IP_API_FEATURE_OUTPUT = 1,
  IP_API_FEATURE_LOCAL = 2,
  IP_API_FEATURE_PUNT = 3,
  IP_API_FEATURE_DROP = 4,
} __attribute__((packed)) vapi_enum_ip_feature_location;

#endif

#ifndef defined_vapi_enum_ip_ecn
#define defined_vapi_enum_ip_ecn
typedef enum {
  IP_API_ECN_NONE = 0,
  IP_API_ECN_ECT0 = 1,
  IP_API_ECN_ECT1 = 2,
  IP_API_ECN_CE = 3,
} __attribute__((packed)) vapi_enum_ip_ecn;

#endif

#ifndef defined_vapi_enum_ip_dscp
#define defined_vapi_enum_ip_dscp
typedef enum {
  IP_API_DSCP_CS0 = 0,
  IP_API_DSCP_CS1 = 8,
  IP_API_DSCP_AF11 = 10,
  IP_API_DSCP_AF12 = 12,
  IP_API_DSCP_AF13 = 14,
  IP_API_DSCP_CS2 = 16,
  IP_API_DSCP_AF21 = 18,
  IP_API_DSCP_AF22 = 20,
  IP_API_DSCP_AF23 = 22,
  IP_API_DSCP_CS3 = 24,
  IP_API_DSCP_AF31 = 26,
  IP_API_DSCP_AF32 = 28,
  IP_API_DSCP_AF33 = 30,
  IP_API_DSCP_CS4 = 32,
  IP_API_DSCP_AF41 = 34,
  IP_API_DSCP_AF42 = 36,
  IP_API_DSCP_AF43 = 38,
  IP_API_DSCP_CS5 = 40,
  IP_API_DSCP_EF = 46,
  IP_API_DSCP_CS6 = 48,
  IP_API_DSCP_CS7 = 50,
} __attribute__((packed)) vapi_enum_ip_dscp;

#endif

#ifndef defined_vapi_enum_ip_proto
#define defined_vapi_enum_ip_proto
typedef enum {
  IP_API_PROTO_HOPOPT = 0,
  IP_API_PROTO_ICMP = 1,
  IP_API_PROTO_IGMP = 2,
  IP_API_PROTO_TCP = 6,
  IP_API_PROTO_UDP = 17,
  IP_API_PROTO_GRE = 47,
  IP_API_PROTO_ESP = 50,
  IP_API_PROTO_AH = 51,
  IP_API_PROTO_ICMP6 = 58,
  IP_API_PROTO_EIGRP = 88,
  IP_API_PROTO_OSPF = 89,
  IP_API_PROTO_SCTP = 132,
  IP_API_PROTO_RESERVED = 255,
} __attribute__((packed)) vapi_enum_ip_proto;

#endif

#ifndef defined_vapi_enum_fib_path_nh_proto
#define defined_vapi_enum_fib_path_nh_proto
typedef enum {
  FIB_API_PATH_NH_PROTO_IP4 = 0,
  FIB_API_PATH_NH_PROTO_IP6 = 1,
  FIB_API_PATH_NH_PROTO_MPLS = 2,
  FIB_API_PATH_NH_PROTO_ETHERNET = 3,
  FIB_API_PATH_NH_PROTO_BIER = 4,
}  vapi_enum_fib_path_nh_proto;

#endif

#ifndef defined_vapi_enum_fib_path_flags
#define defined_vapi_enum_fib_path_flags
typedef enum {
  FIB_API_PATH_FLAG_NONE = 0,
  FIB_API_PATH_FLAG_RESOLVE_VIA_ATTACHED = 1,
  FIB_API_PATH_FLAG_RESOLVE_VIA_HOST = 2,
  FIB_API_PATH_FLAG_POP_PW_CW = 4,
}  vapi_enum_fib_path_flags;

#endif

#ifndef defined_vapi_enum_fib_path_type
#define defined_vapi_enum_fib_path_type
typedef enum {
  FIB_API_PATH_TYPE_NORMAL = 0,
  FIB_API_PATH_TYPE_LOCAL = 1,
  FIB_API_PATH_TYPE_DROP = 2,
  FIB_API_PATH_TYPE_UDP_ENCAP = 3,
  FIB_API_PATH_TYPE_BIER_IMP = 4,
  FIB_API_PATH_TYPE_ICMP_UNREACH = 5,
  FIB_API_PATH_TYPE_ICMP_PROHIBIT = 6,
  FIB_API_PATH_TYPE_SOURCE_LOOKUP = 7,
  FIB_API_PATH_TYPE_DVR = 8,
  FIB_API_PATH_TYPE_INTERFACE_RX = 9,
  FIB_API_PATH_TYPE_CLASSIFY = 10,
}  vapi_enum_fib_path_type;

#endif

#ifndef defined_vapi_enum_address_family
#define defined_vapi_enum_address_family
typedef enum {
  ADDRESS_IP4 = 0,
  ADDRESS_IP6 = 1,
} __attribute__((packed)) vapi_enum_address_family;

#endif

#ifndef defined_vapi_enum_ip_feature_location
#define defined_vapi_enum_ip_feature_location
typedef enum {
  IP_API_FEATURE_INPUT = 0,
  IP_API_FEATURE_OUTPUT = 1,
  IP_API_FEATURE_LOCAL = 2,
  IP_API_FEATURE_PUNT = 3,
  IP_API_FEATURE_DROP = 4,
} __attribute__((packed)) vapi_enum_ip_feature_location;

#endif

#ifndef defined_vapi_enum_ip_ecn
#define defined_vapi_enum_ip_ecn
typedef enum {
  IP_API_ECN_NONE = 0,
  IP_API_ECN_ECT0 = 1,
  IP_API_ECN_ECT1 = 2,
  IP_API_ECN_CE = 3,
} __attribute__((packed)) vapi_enum_ip_ecn;

#endif

#ifndef defined_vapi_enum_ip_dscp
#define defined_vapi_enum_ip_dscp
typedef enum {
  IP_API_DSCP_CS0 = 0,
  IP_API_DSCP_CS1 = 8,
  IP_API_DSCP_AF11 = 10,
  IP_API_DSCP_AF12 = 12,
  IP_API_DSCP_AF13 = 14,
  IP_API_DSCP_CS2 = 16,
  IP_API_DSCP_AF21 = 18,
  IP_API_DSCP_AF22 = 20,
  IP_API_DSCP_AF23 = 22,
  IP_API_DSCP_CS3 = 24,
  IP_API_DSCP_AF31 = 26,
  IP_API_DSCP_AF32 = 28,
  IP_API_DSCP_AF33 = 30,
  IP_API_DSCP_CS4 = 32,
  IP_API_DSCP_AF41 = 34,
  IP_API_DSCP_AF42 = 36,
  IP_API_DSCP_AF43 = 38,
  IP_API_DSCP_CS5 = 40,
  IP_API_DSCP_EF = 46,
  IP_API_DSCP_CS6 = 48,
  IP_API_DSCP_CS7 = 50,
} __attribute__((packed)) vapi_enum_ip_dscp;

#endif

#ifndef defined_vapi_enum_ip_proto
#define defined_vapi_enum_ip_proto
typedef enum {
  IP_API_PROTO_HOPOPT = 0,
  IP_API_PROTO_ICMP = 1,
  IP_API_PROTO_IGMP = 2,
  IP_API_PROTO_TCP = 6,
  IP_API_PROTO_UDP = 17,
  IP_API_PROTO_GRE = 47,
  IP_API_PROTO_ESP = 50,
  IP_API_PROTO_AH = 51,
  IP_API_PROTO_ICMP6 = 58,
  IP_API_PROTO_EIGRP = 88,
  IP_API_PROTO_OSPF = 89,
  IP_API_PROTO_SCTP = 132,
  IP_API_PROTO_RESERVED = 255,
} __attribute__((packed)) vapi_enum_ip_proto;

#endif

#ifndef defined_vapi_enum_fib_path_nh_proto
#define defined_vapi_enum_fib_path_nh_proto
typedef enum {
  FIB_API_PATH_NH_PROTO_IP4 = 0,
  FIB_API_PATH_NH_PROTO_IP6 = 1,
  FIB_API_PATH_NH_PROTO_MPLS = 2,
  FIB_API_PATH_NH_PROTO_ETHERNET = 3,
  FIB_API_PATH_NH_PROTO_BIER = 4,
}  vapi_enum_fib_path_nh_proto;

#endif

#ifndef defined_vapi_enum_fib_path_flags
#define defined_vapi_enum_fib_path_flags
typedef enum {
  FIB_API_PATH_FLAG_NONE = 0,
  FIB_API_PATH_FLAG_RESOLVE_VIA_ATTACHED = 1,
  FIB_API_PATH_FLAG_RESOLVE_VIA_HOST = 2,
  FIB_API_PATH_FLAG_POP_PW_CW = 4,
}  vapi_enum_fib_path_flags;

#endif

#ifndef defined_vapi_enum_fib_path_type
#define defined_vapi_enum_fib_path_type
typedef enum {
  FIB_API_PATH_TYPE_NORMAL = 0,
  FIB_API_PATH_TYPE_LOCAL = 1,
  FIB_API_PATH_TYPE_DROP = 2,
  FIB_API_PATH_TYPE_UDP_ENCAP = 3,
  FIB_API_PATH_TYPE_BIER_IMP = 4,
  FIB_API_PATH_TYPE_ICMP_UNREACH = 5,
  FIB_API_PATH_TYPE_ICMP_PROHIBIT = 6,
  FIB_API_PATH_TYPE_SOURCE_LOOKUP = 7,
  FIB_API_PATH_TYPE_DVR = 8,
  FIB_API_PATH_TYPE_INTERFACE_RX = 9,
  FIB_API_PATH_TYPE_CLASSIFY = 10,
}  vapi_enum_fib_path_type;

#endif

#ifndef defined_vapi_enum_address_family
#define defined_vapi_enum_address_family
typedef enum {
  ADDRESS_IP4 = 0,
  ADDRESS_IP6 = 1,
} __attribute__((packed)) vapi_enum_address_family;

#endif

#ifndef defined_vapi_enum_ip_feature_location
#define defined_vapi_enum_ip_feature_location
typedef enum {
  IP_API_FEATURE_INPUT = 0,
  IP_API_FEATURE_OUTPUT = 1,
  IP_API_FEATURE_LOCAL = 2,
  IP_API_FEATURE_PUNT = 3,
  IP_API_FEATURE_DROP = 4,
} __attribute__((packed)) vapi_enum_ip_feature_location;

#endif

#ifndef defined_vapi_enum_ip_ecn
#define defined_vapi_enum_ip_ecn
typedef enum {
  IP_API_ECN_NONE = 0,
  IP_API_ECN_ECT0 = 1,
  IP_API_ECN_ECT1 = 2,
  IP_API_ECN_CE = 3,
} __attribute__((packed)) vapi_enum_ip_ecn;

#endif

#ifndef defined_vapi_enum_ip_dscp
#define defined_vapi_enum_ip_dscp
typedef enum {
  IP_API_DSCP_CS0 = 0,
  IP_API_DSCP_CS1 = 8,
  IP_API_DSCP_AF11 = 10,
  IP_API_DSCP_AF12 = 12,
  IP_API_DSCP_AF13 = 14,
  IP_API_DSCP_CS2 = 16,
  IP_API_DSCP_AF21 = 18,
  IP_API_DSCP_AF22 = 20,
  IP_API_DSCP_AF23 = 22,
  IP_API_DSCP_CS3 = 24,
  IP_API_DSCP_AF31 = 26,
  IP_API_DSCP_AF32 = 28,
  IP_API_DSCP_AF33 = 30,
  IP_API_DSCP_CS4 = 32,
  IP_API_DSCP_AF41 = 34,
  IP_API_DSCP_AF42 = 36,
  IP_API_DSCP_AF43 = 38,
  IP_API_DSCP_CS5 = 40,
  IP_API_DSCP_EF = 46,
  IP_API_DSCP_CS6 = 48,
  IP_API_DSCP_CS7 = 50,
} __attribute__((packed)) vapi_enum_ip_dscp;

#endif

#ifndef defined_vapi_enum_ip_proto
#define defined_vapi_enum_ip_proto
typedef enum {
  IP_API_PROTO_HOPOPT = 0,
  IP_API_PROTO_ICMP = 1,
  IP_API_PROTO_IGMP = 2,
  IP_API_PROTO_TCP = 6,
  IP_API_PROTO_UDP = 17,
  IP_API_PROTO_GRE = 47,
  IP_API_PROTO_ESP = 50,
  IP_API_PROTO_AH = 51,
  IP_API_PROTO_ICMP6 = 58,
  IP_API_PROTO_EIGRP = 88,
  IP_API_PROTO_OSPF = 89,
  IP_API_PROTO_SCTP = 132,
  IP_API_PROTO_RESERVED = 255,
} __attribute__((packed)) vapi_enum_ip_proto;

#endif

#ifndef defined_vapi_enum_mfib_entry_flags
#define defined_vapi_enum_mfib_entry_flags
typedef enum {
  MFIB_API_ENTRY_FLAG_NONE = 0,
  MFIB_API_ENTRY_FLAG_SIGNAL = 1,
  MFIB_API_ENTRY_FLAG_DROP = 2,
  MFIB_API_ENTRY_FLAG_CONNECTED = 4,
  MFIB_API_ENTRY_FLAG_ACCEPT_ALL_ITF = 8,
}  vapi_enum_mfib_entry_flags;

#endif

#ifndef defined_vapi_enum_mfib_itf_flags
#define defined_vapi_enum_mfib_itf_flags
typedef enum {
  MFIB_API_ITF_FLAG_NONE = 0,
  MFIB_API_ITF_FLAG_NEGATE_SIGNAL = 1,
  MFIB_API_ITF_FLAG_ACCEPT = 2,
  MFIB_API_ITF_FLAG_FORWARD = 4,
  MFIB_API_ITF_FLAG_SIGNAL_PRESENT = 8,
  MFIB_API_ITF_FLAG_DONT_PRESERVE = 16,
}  vapi_enum_mfib_itf_flags;

#endif

#ifndef defined_vapi_enum_if_status_flags
#define defined_vapi_enum_if_status_flags
typedef enum {
  IF_STATUS_API_FLAG_ADMIN_UP = 1,
  IF_STATUS_API_FLAG_LINK_UP = 2,
}  vapi_enum_if_status_flags;

#endif

#ifndef defined_vapi_enum_mtu_proto
#define defined_vapi_enum_mtu_proto
typedef enum {
  MTU_PROTO_API_L3 = 0,
  MTU_PROTO_API_IP4 = 1,
  MTU_PROTO_API_IP6 = 2,
  MTU_PROTO_API_MPLS = 3,
}  vapi_enum_mtu_proto;

#endif

#ifndef defined_vapi_enum_link_duplex
#define defined_vapi_enum_link_duplex
typedef enum {
  LINK_DUPLEX_API_UNKNOWN = 0,
  LINK_DUPLEX_API_HALF = 1,
  LINK_DUPLEX_API_FULL = 2,
}  vapi_enum_link_duplex;

#endif

#ifndef defined_vapi_enum_sub_if_flags
#define defined_vapi_enum_sub_if_flags
typedef enum {
  SUB_IF_API_FLAG_NO_TAGS = 1,
  SUB_IF_API_FLAG_ONE_TAG = 2,
  SUB_IF_API_FLAG_TWO_TAGS = 4,
  SUB_IF_API_FLAG_DOT1AD = 8,
  SUB_IF_API_FLAG_EXACT_MATCH = 16,
  SUB_IF_API_FLAG_DEFAULT = 32,
  SUB_IF_API_FLAG_OUTER_VLAN_ID_ANY = 64,
  SUB_IF_API_FLAG_INNER_VLAN_ID_ANY = 128,
  SUB_IF_API_FLAG_MASK_VNET = 254,
  SUB_IF_API_FLAG_DOT1AH = 256,
}  vapi_enum_sub_if_flags;

#endif

#ifndef defined_vapi_enum_rx_mode
#define defined_vapi_enum_rx_mode
typedef enum {
  RX_MODE_API_UNKNOWN = 0,
  RX_MODE_API_POLLING = 1,
  RX_MODE_API_INTERRUPT = 2,
  RX_MODE_API_ADAPTIVE = 3,
  RX_MODE_API_DEFAULT = 4,
}  vapi_enum_rx_mode;

#endif

#ifndef defined_vapi_enum_if_type
#define defined_vapi_enum_if_type
typedef enum {
  IF_API_TYPE_HARDWARE = 0,
  IF_API_TYPE_SUB = 1,
  IF_API_TYPE_P2P = 2,
  IF_API_TYPE_PIPE = 3,
}  vapi_enum_if_type;

#endif

#ifndef defined_vapi_enum_direction
#define defined_vapi_enum_direction
typedef enum {
  RX = 0,
  TX = 1,
} __attribute__((packed)) vapi_enum_direction;

#endif

#ifndef defined_vapi_enum_ip_reass_type
#define defined_vapi_enum_ip_reass_type
typedef enum {
  IP_REASS_TYPE_FULL = 0,
  IP_REASS_TYPE_SHALLOW_VIRTUAL = 1,
}  vapi_enum_ip_reass_type;

#endif

#ifndef defined_vapi_enum_ip_flow_hash_config
#define defined_vapi_enum_ip_flow_hash_config
typedef enum {
  IP_API_FLOW_HASH_SRC_IP = 1,
  IP_API_FLOW_HASH_DST_IP = 2,
  IP_API_FLOW_HASH_SRC_PORT = 4,
  IP_API_FLOW_HASH_DST_PORT = 8,
  IP_API_FLOW_HASH_PROTO = 16,
  IP_API_FLOW_HASH_REVERSE = 32,
  IP_API_FLOW_HASH_SYMETRIC = 64,
  IP_API_FLOW_HASH_FLOW_LABEL = 128,
}  vapi_enum_ip_flow_hash_config;

#endif

#ifndef defined_vapi_enum_ip_flow_hash_config_v2
#define defined_vapi_enum_ip_flow_hash_config_v2
typedef enum {
  IP_API_V2_FLOW_HASH_SRC_IP = 1,
  IP_API_V2_FLOW_HASH_DST_IP = 2,
  IP_API_V2_FLOW_HASH_SRC_PORT = 4,
  IP_API_V2_FLOW_HASH_DST_PORT = 8,
  IP_API_V2_FLOW_HASH_PROTO = 16,
  IP_API_V2_FLOW_HASH_REVERSE = 32,
  IP_API_V2_FLOW_HASH_SYMETRIC = 64,
  IP_API_V2_FLOW_HASH_FLOW_LABEL = 128,
  IP_API_V2_FLOW_HASH_GTPV1_TEID = 256,
}  vapi_enum_ip_flow_hash_config_v2;

#endif

#ifndef defined_vapi_type_ip4_address
#define defined_vapi_type_ip4_address
typedef u8 vapi_type_ip4_address[4];

#endif

#ifndef defined_vapi_type_ip6_address
#define defined_vapi_type_ip6_address
typedef u8 vapi_type_ip6_address[16];

#endif

#ifndef defined_vapi_union_address_union
#define defined_vapi_union_address_union
typedef union {
  vapi_type_ip4_address ip4;
  vapi_type_ip6_address ip6;
} vapi_union_address_union;

#endif

#ifndef defined_vapi_type_prefix_matcher
#define defined_vapi_type_prefix_matcher
typedef struct __attribute__((__packed__)) {
  u8 le;
  u8 ge;
} vapi_type_prefix_matcher;

static inline void vapi_type_prefix_matcher_hton(vapi_type_prefix_matcher *msg)
{

}

static inline void vapi_type_prefix_matcher_ntoh(vapi_type_prefix_matcher *msg)
{

}
#endif

#ifndef defined_vapi_type_fib_mpls_label
#define defined_vapi_type_fib_mpls_label
typedef struct __attribute__((__packed__)) {
  u8 is_uniform;
  u32 label;
  u8 ttl;
  u8 exp;
} vapi_type_fib_mpls_label;

static inline void vapi_type_fib_mpls_label_hton(vapi_type_fib_mpls_label *msg)
{
  msg->label = htobe32(msg->label);
}

static inline void vapi_type_fib_mpls_label_ntoh(vapi_type_fib_mpls_label *msg)
{
  msg->label = be32toh(msg->label);
}
#endif

#ifndef defined_vapi_type_ip_table
#define defined_vapi_type_ip_table
typedef struct __attribute__((__packed__)) {
  u32 table_id;
  bool is_ip6;
  u8 name[64];
} vapi_type_ip_table;

static inline void vapi_type_ip_table_hton(vapi_type_ip_table *msg)
{
  msg->table_id = htobe32(msg->table_id);
}

static inline void vapi_type_ip_table_ntoh(vapi_type_ip_table *msg)
{
  msg->table_id = be32toh(msg->table_id);
}
#endif

#ifndef defined_vapi_type_address
#define defined_vapi_type_address
typedef struct __attribute__((__packed__)) {
  vapi_enum_address_family af;
  vapi_union_address_union un;
} vapi_type_address;

static inline void vapi_type_address_hton(vapi_type_address *msg)
{

}

static inline void vapi_type_address_ntoh(vapi_type_address *msg)
{

}
#endif

#ifndef defined_vapi_type_prefix
#define defined_vapi_type_prefix
typedef struct __attribute__((__packed__)) {
  vapi_type_address address;
  u8 len;
} vapi_type_prefix;

static inline void vapi_type_prefix_hton(vapi_type_prefix *msg)
{

}

static inline void vapi_type_prefix_ntoh(vapi_type_prefix *msg)
{

}
#endif

#ifndef defined_vapi_type_ip4_address_and_mask
#define defined_vapi_type_ip4_address_and_mask
typedef struct __attribute__((__packed__)) {
  vapi_type_ip4_address addr;
  vapi_type_ip4_address mask;
} vapi_type_ip4_address_and_mask;

static inline void vapi_type_ip4_address_and_mask_hton(vapi_type_ip4_address_and_mask *msg)
{

}

static inline void vapi_type_ip4_address_and_mask_ntoh(vapi_type_ip4_address_and_mask *msg)
{

}
#endif

#ifndef defined_vapi_type_ip6_address_and_mask
#define defined_vapi_type_ip6_address_and_mask
typedef struct __attribute__((__packed__)) {
  vapi_type_ip6_address addr;
  vapi_type_ip6_address mask;
} vapi_type_ip6_address_and_mask;

static inline void vapi_type_ip6_address_and_mask_hton(vapi_type_ip6_address_and_mask *msg)
{

}

static inline void vapi_type_ip6_address_and_mask_ntoh(vapi_type_ip6_address_and_mask *msg)
{

}
#endif

#ifndef defined_vapi_type_mprefix
#define defined_vapi_type_mprefix
typedef struct __attribute__((__packed__)) {
  vapi_enum_address_family af;
  u16 grp_address_length;
  vapi_union_address_union grp_address;
  vapi_union_address_union src_address;
} vapi_type_mprefix;

static inline void vapi_type_mprefix_hton(vapi_type_mprefix *msg)
{
  msg->grp_address_length = htobe16(msg->grp_address_length);
}

static inline void vapi_type_mprefix_ntoh(vapi_type_mprefix *msg)
{
  msg->grp_address_length = be16toh(msg->grp_address_length);
}
#endif

#ifndef defined_vapi_type_ip6_prefix
#define defined_vapi_type_ip6_prefix
typedef struct __attribute__((__packed__)) {
  vapi_type_ip6_address address;
  u8 len;
} vapi_type_ip6_prefix;

static inline void vapi_type_ip6_prefix_hton(vapi_type_ip6_prefix *msg)
{

}

static inline void vapi_type_ip6_prefix_ntoh(vapi_type_ip6_prefix *msg)
{

}
#endif

#ifndef defined_vapi_type_ip4_prefix
#define defined_vapi_type_ip4_prefix
typedef struct __attribute__((__packed__)) {
  vapi_type_ip4_address address;
  u8 len;
} vapi_type_ip4_prefix;

static inline void vapi_type_ip4_prefix_hton(vapi_type_ip4_prefix *msg)
{

}

static inline void vapi_type_ip4_prefix_ntoh(vapi_type_ip4_prefix *msg)
{

}
#endif

#ifndef defined_vapi_type_fib_path_nh
#define defined_vapi_type_fib_path_nh
typedef struct __attribute__((__packed__)) {
  vapi_union_address_union address;
  u32 via_label;
  u32 obj_id;
  u32 classify_table_index;
} vapi_type_fib_path_nh;

static inline void vapi_type_fib_path_nh_hton(vapi_type_fib_path_nh *msg)
{
  msg->via_label = htobe32(msg->via_label);
  msg->obj_id = htobe32(msg->obj_id);
  msg->classify_table_index = htobe32(msg->classify_table_index);
}

static inline void vapi_type_fib_path_nh_ntoh(vapi_type_fib_path_nh *msg)
{
  msg->via_label = be32toh(msg->via_label);
  msg->obj_id = be32toh(msg->obj_id);
  msg->classify_table_index = be32toh(msg->classify_table_index);
}
#endif

#ifndef defined_vapi_type_fib_path
#define defined_vapi_type_fib_path
typedef struct __attribute__((__packed__)) {
  u32 sw_if_index;
  u32 table_id;
  u32 rpf_id;
  u8 weight;
  u8 preference;
  vapi_enum_fib_path_type type;
  vapi_enum_fib_path_flags flags;
  vapi_enum_fib_path_nh_proto proto;
  vapi_type_fib_path_nh nh;
  u8 n_labels;
  vapi_type_fib_mpls_label label_stack[16];
} vapi_type_fib_path;

static inline void vapi_type_fib_path_hton(vapi_type_fib_path *msg)
{
  msg->sw_if_index = htobe32(msg->sw_if_index);
  msg->table_id = htobe32(msg->table_id);
  msg->rpf_id = htobe32(msg->rpf_id);
  msg->type = (vapi_enum_fib_path_type)htobe32(msg->type);
  msg->flags = (vapi_enum_fib_path_flags)htobe32(msg->flags);
  msg->proto = (vapi_enum_fib_path_nh_proto)htobe32(msg->proto);
  vapi_type_fib_path_nh_hton(&msg->nh);
  do { unsigned i; for (i = 0; i < 16; ++i) { vapi_type_fib_mpls_label_hton(&msg->label_stack[i]); } } while(0);
}

static inline void vapi_type_fib_path_ntoh(vapi_type_fib_path *msg)
{
  msg->sw_if_index = be32toh(msg->sw_if_index);
  msg->table_id = be32toh(msg->table_id);
  msg->rpf_id = be32toh(msg->rpf_id);
  msg->type = (vapi_enum_fib_path_type)be32toh(msg->type);
  msg->flags = (vapi_enum_fib_path_flags)be32toh(msg->flags);
  msg->proto = (vapi_enum_fib_path_nh_proto)be32toh(msg->proto);
  vapi_type_fib_path_nh_ntoh(&msg->nh);
  do { unsigned i; for (i = 0; i < 16; ++i) { vapi_type_fib_mpls_label_ntoh(&msg->label_stack[i]); } } while(0);
}
#endif

#ifndef defined_vapi_type_mfib_path
#define defined_vapi_type_mfib_path
typedef struct __attribute__((__packed__)) {
  vapi_enum_mfib_itf_flags itf_flags;
  vapi_type_fib_path path;
} vapi_type_mfib_path;

static inline void vapi_type_mfib_path_hton(vapi_type_mfib_path *msg)
{
  msg->itf_flags = (vapi_enum_mfib_itf_flags)htobe32(msg->itf_flags);
  vapi_type_fib_path_hton(&msg->path);
}

static inline void vapi_type_mfib_path_ntoh(vapi_type_mfib_path *msg)
{
  msg->itf_flags = (vapi_enum_mfib_itf_flags)be32toh(msg->itf_flags);
  vapi_type_fib_path_ntoh(&msg->path);
}
#endif

#ifndef defined_vapi_type_ip_route
#define defined_vapi_type_ip_route
typedef struct __attribute__((__packed__)) {
  u32 table_id;
  u32 stats_index;
  vapi_type_prefix prefix;
  u8 n_paths;
  vapi_type_fib_path paths[0];
} vapi_type_ip_route;

static inline void vapi_type_ip_route_hton(vapi_type_ip_route *msg)
{
  msg->table_id = htobe32(msg->table_id);
  msg->stats_index = htobe32(msg->stats_index);
  do { unsigned i; for (i = 0; i < msg->n_paths; ++i) { vapi_type_fib_path_hton(&msg->paths[i]); } } while(0);
}

static inline void vapi_type_ip_route_ntoh(vapi_type_ip_route *msg)
{
  msg->table_id = be32toh(msg->table_id);
  msg->stats_index = be32toh(msg->stats_index);
  do { unsigned i; for (i = 0; i < msg->n_paths; ++i) { vapi_type_fib_path_ntoh(&msg->paths[i]); } } while(0);
}
#endif

#ifndef defined_vapi_type_ip_route_v2
#define defined_vapi_type_ip_route_v2
typedef struct __attribute__((__packed__)) {
  u32 table_id;
  u32 stats_index;
  vapi_type_prefix prefix;
  u8 n_paths;
  u8 src;
  vapi_type_fib_path paths[0];
} vapi_type_ip_route_v2;

static inline void vapi_type_ip_route_v2_hton(vapi_type_ip_route_v2 *msg)
{
  msg->table_id = htobe32(msg->table_id);
  msg->stats_index = htobe32(msg->stats_index);
  do { unsigned i; for (i = 0; i < msg->n_paths; ++i) { vapi_type_fib_path_hton(&msg->paths[i]); } } while(0);
}

static inline void vapi_type_ip_route_v2_ntoh(vapi_type_ip_route_v2 *msg)
{
  msg->table_id = be32toh(msg->table_id);
  msg->stats_index = be32toh(msg->stats_index);
  do { unsigned i; for (i = 0; i < msg->n_paths; ++i) { vapi_type_fib_path_ntoh(&msg->paths[i]); } } while(0);
}
#endif

#ifndef defined_vapi_type_ip_mroute
#define defined_vapi_type_ip_mroute
typedef struct __attribute__((__packed__)) {
  u32 table_id;
  vapi_enum_mfib_entry_flags entry_flags;
  u32 rpf_id;
  vapi_type_mprefix prefix;
  u8 n_paths;
  vapi_type_mfib_path paths[0];
} vapi_type_ip_mroute;

static inline void vapi_type_ip_mroute_hton(vapi_type_ip_mroute *msg)
{
  msg->table_id = htobe32(msg->table_id);
  msg->entry_flags = (vapi_enum_mfib_entry_flags)htobe32(msg->entry_flags);
  msg->rpf_id = htobe32(msg->rpf_id);
  vapi_type_mprefix_hton(&msg->prefix);
  do { unsigned i; for (i = 0; i < msg->n_paths; ++i) { vapi_type_mfib_path_hton(&msg->paths[i]); } } while(0);
}

static inline void vapi_type_ip_mroute_ntoh(vapi_type_ip_mroute *msg)
{
  msg->table_id = be32toh(msg->table_id);
  msg->entry_flags = (vapi_enum_mfib_entry_flags)be32toh(msg->entry_flags);
  msg->rpf_id = be32toh(msg->rpf_id);
  vapi_type_mprefix_ntoh(&msg->prefix);
  do { unsigned i; for (i = 0; i < msg->n_paths; ++i) { vapi_type_mfib_path_ntoh(&msg->paths[i]); } } while(0);
}
#endif

#ifndef defined_vapi_type_interface_index
#define defined_vapi_type_interface_index
typedef u32 vapi_type_interface_index;

#endif

#ifndef defined_vapi_type_punt_redirect
#define defined_vapi_type_punt_redirect
typedef struct __attribute__((__packed__)) {
  vapi_type_interface_index rx_sw_if_index;
  vapi_type_interface_index tx_sw_if_index;
  vapi_type_address nh;
} vapi_type_punt_redirect;

static inline void vapi_type_punt_redirect_hton(vapi_type_punt_redirect *msg)
{
  msg->rx_sw_if_index = htobe32(msg->rx_sw_if_index);
  msg->tx_sw_if_index = htobe32(msg->tx_sw_if_index);
}

static inline void vapi_type_punt_redirect_ntoh(vapi_type_punt_redirect *msg)
{
  msg->rx_sw_if_index = be32toh(msg->rx_sw_if_index);
  msg->tx_sw_if_index = be32toh(msg->tx_sw_if_index);
}
#endif

#ifndef defined_vapi_type_punt_redirect_v2
#define defined_vapi_type_punt_redirect_v2
typedef struct __attribute__((__packed__)) {
  vapi_type_interface_index rx_sw_if_index;
  vapi_enum_address_family af;
  u32 n_paths;
  vapi_type_fib_path paths[0];
} vapi_type_punt_redirect_v2;

static inline void vapi_type_punt_redirect_v2_hton(vapi_type_punt_redirect_v2 *msg)
{
  msg->rx_sw_if_index = htobe32(msg->rx_sw_if_index);
  msg->n_paths = htobe32(msg->n_paths);
  do { unsigned i; for (i = 0; i < be32toh(msg->n_paths); ++i) { vapi_type_fib_path_hton(&msg->paths[i]); } } while(0);
}

static inline void vapi_type_punt_redirect_v2_ntoh(vapi_type_punt_redirect_v2 *msg)
{
  msg->rx_sw_if_index = be32toh(msg->rx_sw_if_index);
  msg->n_paths = be32toh(msg->n_paths);
  do { unsigned i; for (i = 0; i < msg->n_paths; ++i) { vapi_type_fib_path_ntoh(&msg->paths[i]); } } while(0);
}
#endif

#ifndef defined_vapi_type_ip_path_mtu
#define defined_vapi_type_ip_path_mtu
typedef struct __attribute__((__packed__)) {
  u32 client_index;
  u32 context;
  u32 table_id;
  vapi_type_address nh;
  u16 path_mtu;
} vapi_type_ip_path_mtu;

static inline void vapi_type_ip_path_mtu_hton(vapi_type_ip_path_mtu *msg)
{
  msg->client_index = htobe32(msg->client_index);
  msg->context = htobe32(msg->context);
  msg->table_id = htobe32(msg->table_id);
  msg->path_mtu = htobe16(msg->path_mtu);
}

static inline void vapi_type_ip_path_mtu_ntoh(vapi_type_ip_path_mtu *msg)
{
  msg->client_index = be32toh(msg->client_index);
  msg->context = be32toh(msg->context);
  msg->table_id = be32toh(msg->table_id);
  msg->path_mtu = be16toh(msg->path_mtu);
}
#endif

#ifndef defined_vapi_type_mac_address
#define defined_vapi_type_mac_address
typedef u8 vapi_type_mac_address[6];

#endif

#ifndef defined_vapi_type_address_with_prefix
#define defined_vapi_type_address_with_prefix
typedef vapi_type_prefix vapi_type_address_with_prefix;

#endif

#ifndef defined_vapi_type_ip4_address_with_prefix
#define defined_vapi_type_ip4_address_with_prefix
typedef vapi_type_ip4_prefix vapi_type_ip4_address_with_prefix;

#endif

#ifndef defined_vapi_type_ip6_address_with_prefix
#define defined_vapi_type_ip6_address_with_prefix
typedef vapi_type_ip6_prefix vapi_type_ip6_address_with_prefix;

#endif

#ifndef defined_vapi_msg_ip_table_add_del_reply
#define defined_vapi_msg_ip_table_add_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ip_table_add_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_table_add_del_reply payload;
} vapi_msg_ip_table_add_del_reply;

static inline void vapi_msg_ip_table_add_del_reply_payload_hton(vapi_payload_ip_table_add_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ip_table_add_del_reply_payload_ntoh(vapi_payload_ip_table_add_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ip_table_add_del_reply_hton(vapi_msg_ip_table_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_table_add_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_table_add_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_table_add_del_reply_ntoh(vapi_msg_ip_table_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_table_add_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_table_add_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_table_add_del_reply_msg_size(vapi_msg_ip_table_add_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_table_add_del_reply_msg_size(vapi_msg_ip_table_add_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_table_add_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_table_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_table_add_del_reply));
      return -1;
    }
  if (vapi_calc_ip_table_add_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_table_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_table_add_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_table_add_del_reply()
{
  static const char name[] = "ip_table_add_del_reply";
  static const char name_with_crc[] = "ip_table_add_del_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ip_table_add_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_table_add_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_table_add_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_table_add_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_ip_table_add_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_table_add_del_reply = vapi_register_msg(&__vapi_metadata_ip_table_add_del_reply);
  VAPI_DBG("Assigned msg id %d to ip_table_add_del_reply", vapi_msg_id_ip_table_add_del_reply);
}

static inline void vapi_set_vapi_msg_ip_table_add_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_table_add_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_table_add_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_table_add_del
#define defined_vapi_msg_ip_table_add_del
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_type_ip_table table; 
} vapi_payload_ip_table_add_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip_table_add_del payload;
} vapi_msg_ip_table_add_del;

static inline void vapi_msg_ip_table_add_del_payload_hton(vapi_payload_ip_table_add_del *payload)
{
  vapi_type_ip_table_hton(&payload->table);
}

static inline void vapi_msg_ip_table_add_del_payload_ntoh(vapi_payload_ip_table_add_del *payload)
{
  vapi_type_ip_table_ntoh(&payload->table);
}

static inline void vapi_msg_ip_table_add_del_hton(vapi_msg_ip_table_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_table_add_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip_table_add_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_table_add_del_ntoh(vapi_msg_ip_table_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_table_add_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip_table_add_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_table_add_del_msg_size(vapi_msg_ip_table_add_del *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_table_add_del_msg_size(vapi_msg_ip_table_add_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_table_add_del) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_table_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_table_add_del));
      return -1;
    }
  if (vapi_calc_ip_table_add_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_table_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_table_add_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_table_add_del* vapi_alloc_ip_table_add_del(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_table_add_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_table_add_del);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_table_add_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_table_add_del);

  return msg;
}

static inline vapi_error_e vapi_ip_table_add_del(struct vapi_ctx_s *ctx,
  vapi_msg_ip_table_add_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_table_add_del_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ip_table_add_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_table_add_del_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ip_table_add_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_table_add_del()
{
  static const char name[] = "ip_table_add_del";
  static const char name_with_crc[] = "ip_table_add_del_0ffdaec0";
  static vapi_message_desc_t __vapi_metadata_ip_table_add_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip_table_add_del, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_table_add_del_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_table_add_del_hton,
    (generic_swap_fn_t)vapi_msg_ip_table_add_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_table_add_del = vapi_register_msg(&__vapi_metadata_ip_table_add_del);
  VAPI_DBG("Assigned msg id %d to ip_table_add_del", vapi_msg_id_ip_table_add_del);
}
#endif

#ifndef defined_vapi_msg_ip_table_add_del_v2_reply
#define defined_vapi_msg_ip_table_add_del_v2_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ip_table_add_del_v2_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_table_add_del_v2_reply payload;
} vapi_msg_ip_table_add_del_v2_reply;

static inline void vapi_msg_ip_table_add_del_v2_reply_payload_hton(vapi_payload_ip_table_add_del_v2_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ip_table_add_del_v2_reply_payload_ntoh(vapi_payload_ip_table_add_del_v2_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ip_table_add_del_v2_reply_hton(vapi_msg_ip_table_add_del_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_table_add_del_v2_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_table_add_del_v2_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_table_add_del_v2_reply_ntoh(vapi_msg_ip_table_add_del_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_table_add_del_v2_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_table_add_del_v2_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_table_add_del_v2_reply_msg_size(vapi_msg_ip_table_add_del_v2_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_table_add_del_v2_reply_msg_size(vapi_msg_ip_table_add_del_v2_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_table_add_del_v2_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_table_add_del_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_table_add_del_v2_reply));
      return -1;
    }
  if (vapi_calc_ip_table_add_del_v2_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_table_add_del_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_table_add_del_v2_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_table_add_del_v2_reply()
{
  static const char name[] = "ip_table_add_del_v2_reply";
  static const char name_with_crc[] = "ip_table_add_del_v2_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ip_table_add_del_v2_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_table_add_del_v2_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_table_add_del_v2_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_table_add_del_v2_reply_hton,
    (generic_swap_fn_t)vapi_msg_ip_table_add_del_v2_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_table_add_del_v2_reply = vapi_register_msg(&__vapi_metadata_ip_table_add_del_v2_reply);
  VAPI_DBG("Assigned msg id %d to ip_table_add_del_v2_reply", vapi_msg_id_ip_table_add_del_v2_reply);
}

static inline void vapi_set_vapi_msg_ip_table_add_del_v2_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_table_add_del_v2_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_table_add_del_v2_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_table_add_del_v2
#define defined_vapi_msg_ip_table_add_del_v2
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip_table table;
  bool create_mfib;
  bool is_add; 
} vapi_payload_ip_table_add_del_v2;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip_table_add_del_v2 payload;
} vapi_msg_ip_table_add_del_v2;

static inline void vapi_msg_ip_table_add_del_v2_payload_hton(vapi_payload_ip_table_add_del_v2 *payload)
{
  vapi_type_ip_table_hton(&payload->table);
}

static inline void vapi_msg_ip_table_add_del_v2_payload_ntoh(vapi_payload_ip_table_add_del_v2 *payload)
{
  vapi_type_ip_table_ntoh(&payload->table);
}

static inline void vapi_msg_ip_table_add_del_v2_hton(vapi_msg_ip_table_add_del_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_table_add_del_v2'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip_table_add_del_v2_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_table_add_del_v2_ntoh(vapi_msg_ip_table_add_del_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_table_add_del_v2'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip_table_add_del_v2_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_table_add_del_v2_msg_size(vapi_msg_ip_table_add_del_v2 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_table_add_del_v2_msg_size(vapi_msg_ip_table_add_del_v2 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_table_add_del_v2) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_table_add_del_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_table_add_del_v2));
      return -1;
    }
  if (vapi_calc_ip_table_add_del_v2_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_table_add_del_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_table_add_del_v2_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_table_add_del_v2* vapi_alloc_ip_table_add_del_v2(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_table_add_del_v2 *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_table_add_del_v2);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_table_add_del_v2*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_table_add_del_v2);

  return msg;
}

static inline vapi_error_e vapi_ip_table_add_del_v2(struct vapi_ctx_s *ctx,
  vapi_msg_ip_table_add_del_v2 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_table_add_del_v2_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ip_table_add_del_v2_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_table_add_del_v2_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ip_table_add_del_v2_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_table_add_del_v2()
{
  static const char name[] = "ip_table_add_del_v2";
  static const char name_with_crc[] = "ip_table_add_del_v2_14e5081f";
  static vapi_message_desc_t __vapi_metadata_ip_table_add_del_v2 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip_table_add_del_v2, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_table_add_del_v2_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_table_add_del_v2_hton,
    (generic_swap_fn_t)vapi_msg_ip_table_add_del_v2_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_table_add_del_v2 = vapi_register_msg(&__vapi_metadata_ip_table_add_del_v2);
  VAPI_DBG("Assigned msg id %d to ip_table_add_del_v2", vapi_msg_id_ip_table_add_del_v2);
}
#endif

#ifndef defined_vapi_msg_ip_table_allocate_reply
#define defined_vapi_msg_ip_table_allocate_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vapi_type_ip_table table; 
} vapi_payload_ip_table_allocate_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_table_allocate_reply payload;
} vapi_msg_ip_table_allocate_reply;

static inline void vapi_msg_ip_table_allocate_reply_payload_hton(vapi_payload_ip_table_allocate_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  vapi_type_ip_table_hton(&payload->table);
}

static inline void vapi_msg_ip_table_allocate_reply_payload_ntoh(vapi_payload_ip_table_allocate_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  vapi_type_ip_table_ntoh(&payload->table);
}

static inline void vapi_msg_ip_table_allocate_reply_hton(vapi_msg_ip_table_allocate_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_table_allocate_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_table_allocate_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_table_allocate_reply_ntoh(vapi_msg_ip_table_allocate_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_table_allocate_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_table_allocate_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_table_allocate_reply_msg_size(vapi_msg_ip_table_allocate_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_table_allocate_reply_msg_size(vapi_msg_ip_table_allocate_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_table_allocate_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_table_allocate_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_table_allocate_reply));
      return -1;
    }
  if (vapi_calc_ip_table_allocate_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_table_allocate_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_table_allocate_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_table_allocate_reply()
{
  static const char name[] = "ip_table_allocate_reply";
  static const char name_with_crc[] = "ip_table_allocate_reply_1728303a";
  static vapi_message_desc_t __vapi_metadata_ip_table_allocate_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_table_allocate_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_table_allocate_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_table_allocate_reply_hton,
    (generic_swap_fn_t)vapi_msg_ip_table_allocate_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_table_allocate_reply = vapi_register_msg(&__vapi_metadata_ip_table_allocate_reply);
  VAPI_DBG("Assigned msg id %d to ip_table_allocate_reply", vapi_msg_id_ip_table_allocate_reply);
}

static inline void vapi_set_vapi_msg_ip_table_allocate_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_table_allocate_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_table_allocate_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_table_allocate
#define defined_vapi_msg_ip_table_allocate
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip_table table; 
} vapi_payload_ip_table_allocate;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip_table_allocate payload;
} vapi_msg_ip_table_allocate;

static inline void vapi_msg_ip_table_allocate_payload_hton(vapi_payload_ip_table_allocate *payload)
{
  vapi_type_ip_table_hton(&payload->table);
}

static inline void vapi_msg_ip_table_allocate_payload_ntoh(vapi_payload_ip_table_allocate *payload)
{
  vapi_type_ip_table_ntoh(&payload->table);
}

static inline void vapi_msg_ip_table_allocate_hton(vapi_msg_ip_table_allocate *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_table_allocate'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip_table_allocate_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_table_allocate_ntoh(vapi_msg_ip_table_allocate *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_table_allocate'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip_table_allocate_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_table_allocate_msg_size(vapi_msg_ip_table_allocate *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_table_allocate_msg_size(vapi_msg_ip_table_allocate *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_table_allocate) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_table_allocate' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_table_allocate));
      return -1;
    }
  if (vapi_calc_ip_table_allocate_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_table_allocate' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_table_allocate_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_table_allocate* vapi_alloc_ip_table_allocate(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_table_allocate *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_table_allocate);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_table_allocate*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_table_allocate);

  return msg;
}

static inline vapi_error_e vapi_ip_table_allocate(struct vapi_ctx_s *ctx,
  vapi_msg_ip_table_allocate *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_table_allocate_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ip_table_allocate_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_table_allocate_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ip_table_allocate_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_table_allocate()
{
  static const char name[] = "ip_table_allocate";
  static const char name_with_crc[] = "ip_table_allocate_b9d2e09e";
  static vapi_message_desc_t __vapi_metadata_ip_table_allocate = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip_table_allocate, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_table_allocate_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_table_allocate_hton,
    (generic_swap_fn_t)vapi_msg_ip_table_allocate_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_table_allocate = vapi_register_msg(&__vapi_metadata_ip_table_allocate);
  VAPI_DBG("Assigned msg id %d to ip_table_allocate", vapi_msg_id_ip_table_allocate);
}
#endif

#ifndef defined_vapi_msg_ip_table_details
#define defined_vapi_msg_ip_table_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip_table table; 
} vapi_payload_ip_table_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_table_details payload;
} vapi_msg_ip_table_details;

static inline void vapi_msg_ip_table_details_payload_hton(vapi_payload_ip_table_details *payload)
{
  vapi_type_ip_table_hton(&payload->table);
}

static inline void vapi_msg_ip_table_details_payload_ntoh(vapi_payload_ip_table_details *payload)
{
  vapi_type_ip_table_ntoh(&payload->table);
}

static inline void vapi_msg_ip_table_details_hton(vapi_msg_ip_table_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_table_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_table_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_table_details_ntoh(vapi_msg_ip_table_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_table_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_table_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_table_details_msg_size(vapi_msg_ip_table_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_table_details_msg_size(vapi_msg_ip_table_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_table_details) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_table_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_table_details));
      return -1;
    }
  if (vapi_calc_ip_table_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_table_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_table_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_table_details()
{
  static const char name[] = "ip_table_details";
  static const char name_with_crc[] = "ip_table_details_c79fca0f";
  static vapi_message_desc_t __vapi_metadata_ip_table_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_table_details, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_table_details_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_table_details_hton,
    (generic_swap_fn_t)vapi_msg_ip_table_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_table_details = vapi_register_msg(&__vapi_metadata_ip_table_details);
  VAPI_DBG("Assigned msg id %d to ip_table_details", vapi_msg_id_ip_table_details);
}

static inline void vapi_set_vapi_msg_ip_table_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_table_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_table_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_table_dump
#define defined_vapi_msg_ip_table_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_ip_table_dump;

static inline void vapi_msg_ip_table_dump_hton(vapi_msg_ip_table_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_table_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_ip_table_dump_ntoh(vapi_msg_ip_table_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_table_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_ip_table_dump_msg_size(vapi_msg_ip_table_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_table_dump_msg_size(vapi_msg_ip_table_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_table_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_table_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_table_dump));
      return -1;
    }
  if (vapi_calc_ip_table_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_table_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_table_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_table_dump* vapi_alloc_ip_table_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_table_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_table_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_table_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_table_dump);

  return msg;
}

static inline vapi_error_e vapi_ip_table_dump(struct vapi_ctx_s *ctx,
  vapi_msg_ip_table_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_table_details *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ip_table_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_table_details, VAPI_REQUEST_DUMP, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ip_table_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_table_dump()
{
  static const char name[] = "ip_table_dump";
  static const char name_with_crc[] = "ip_table_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_ip_table_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_ip_table_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_table_dump_hton,
    (generic_swap_fn_t)vapi_msg_ip_table_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_table_dump = vapi_register_msg(&__vapi_metadata_ip_table_dump);
  VAPI_DBG("Assigned msg id %d to ip_table_dump", vapi_msg_id_ip_table_dump);
}
#endif

#ifndef defined_vapi_msg_ip_table_replace_begin_reply
#define defined_vapi_msg_ip_table_replace_begin_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ip_table_replace_begin_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_table_replace_begin_reply payload;
} vapi_msg_ip_table_replace_begin_reply;

static inline void vapi_msg_ip_table_replace_begin_reply_payload_hton(vapi_payload_ip_table_replace_begin_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ip_table_replace_begin_reply_payload_ntoh(vapi_payload_ip_table_replace_begin_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ip_table_replace_begin_reply_hton(vapi_msg_ip_table_replace_begin_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_table_replace_begin_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_table_replace_begin_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_table_replace_begin_reply_ntoh(vapi_msg_ip_table_replace_begin_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_table_replace_begin_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_table_replace_begin_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_table_replace_begin_reply_msg_size(vapi_msg_ip_table_replace_begin_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_table_replace_begin_reply_msg_size(vapi_msg_ip_table_replace_begin_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_table_replace_begin_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_table_replace_begin_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_table_replace_begin_reply));
      return -1;
    }
  if (vapi_calc_ip_table_replace_begin_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_table_replace_begin_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_table_replace_begin_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_table_replace_begin_reply()
{
  static const char name[] = "ip_table_replace_begin_reply";
  static const char name_with_crc[] = "ip_table_replace_begin_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ip_table_replace_begin_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_table_replace_begin_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_table_replace_begin_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_table_replace_begin_reply_hton,
    (generic_swap_fn_t)vapi_msg_ip_table_replace_begin_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_table_replace_begin_reply = vapi_register_msg(&__vapi_metadata_ip_table_replace_begin_reply);
  VAPI_DBG("Assigned msg id %d to ip_table_replace_begin_reply", vapi_msg_id_ip_table_replace_begin_reply);
}

static inline void vapi_set_vapi_msg_ip_table_replace_begin_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_table_replace_begin_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_table_replace_begin_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_table_replace_begin
#define defined_vapi_msg_ip_table_replace_begin
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip_table table; 
} vapi_payload_ip_table_replace_begin;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip_table_replace_begin payload;
} vapi_msg_ip_table_replace_begin;

static inline void vapi_msg_ip_table_replace_begin_payload_hton(vapi_payload_ip_table_replace_begin *payload)
{
  vapi_type_ip_table_hton(&payload->table);
}

static inline void vapi_msg_ip_table_replace_begin_payload_ntoh(vapi_payload_ip_table_replace_begin *payload)
{
  vapi_type_ip_table_ntoh(&payload->table);
}

static inline void vapi_msg_ip_table_replace_begin_hton(vapi_msg_ip_table_replace_begin *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_table_replace_begin'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip_table_replace_begin_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_table_replace_begin_ntoh(vapi_msg_ip_table_replace_begin *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_table_replace_begin'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip_table_replace_begin_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_table_replace_begin_msg_size(vapi_msg_ip_table_replace_begin *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_table_replace_begin_msg_size(vapi_msg_ip_table_replace_begin *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_table_replace_begin) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_table_replace_begin' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_table_replace_begin));
      return -1;
    }
  if (vapi_calc_ip_table_replace_begin_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_table_replace_begin' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_table_replace_begin_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_table_replace_begin* vapi_alloc_ip_table_replace_begin(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_table_replace_begin *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_table_replace_begin);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_table_replace_begin*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_table_replace_begin);

  return msg;
}

static inline vapi_error_e vapi_ip_table_replace_begin(struct vapi_ctx_s *ctx,
  vapi_msg_ip_table_replace_begin *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_table_replace_begin_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ip_table_replace_begin_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_table_replace_begin_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ip_table_replace_begin_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_table_replace_begin()
{
  static const char name[] = "ip_table_replace_begin";
  static const char name_with_crc[] = "ip_table_replace_begin_b9d2e09e";
  static vapi_message_desc_t __vapi_metadata_ip_table_replace_begin = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip_table_replace_begin, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_table_replace_begin_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_table_replace_begin_hton,
    (generic_swap_fn_t)vapi_msg_ip_table_replace_begin_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_table_replace_begin = vapi_register_msg(&__vapi_metadata_ip_table_replace_begin);
  VAPI_DBG("Assigned msg id %d to ip_table_replace_begin", vapi_msg_id_ip_table_replace_begin);
}
#endif

#ifndef defined_vapi_msg_ip_table_replace_end_reply
#define defined_vapi_msg_ip_table_replace_end_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ip_table_replace_end_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_table_replace_end_reply payload;
} vapi_msg_ip_table_replace_end_reply;

static inline void vapi_msg_ip_table_replace_end_reply_payload_hton(vapi_payload_ip_table_replace_end_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ip_table_replace_end_reply_payload_ntoh(vapi_payload_ip_table_replace_end_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ip_table_replace_end_reply_hton(vapi_msg_ip_table_replace_end_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_table_replace_end_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_table_replace_end_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_table_replace_end_reply_ntoh(vapi_msg_ip_table_replace_end_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_table_replace_end_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_table_replace_end_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_table_replace_end_reply_msg_size(vapi_msg_ip_table_replace_end_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_table_replace_end_reply_msg_size(vapi_msg_ip_table_replace_end_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_table_replace_end_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_table_replace_end_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_table_replace_end_reply));
      return -1;
    }
  if (vapi_calc_ip_table_replace_end_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_table_replace_end_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_table_replace_end_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_table_replace_end_reply()
{
  static const char name[] = "ip_table_replace_end_reply";
  static const char name_with_crc[] = "ip_table_replace_end_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ip_table_replace_end_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_table_replace_end_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_table_replace_end_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_table_replace_end_reply_hton,
    (generic_swap_fn_t)vapi_msg_ip_table_replace_end_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_table_replace_end_reply = vapi_register_msg(&__vapi_metadata_ip_table_replace_end_reply);
  VAPI_DBG("Assigned msg id %d to ip_table_replace_end_reply", vapi_msg_id_ip_table_replace_end_reply);
}

static inline void vapi_set_vapi_msg_ip_table_replace_end_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_table_replace_end_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_table_replace_end_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_table_replace_end
#define defined_vapi_msg_ip_table_replace_end
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip_table table; 
} vapi_payload_ip_table_replace_end;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip_table_replace_end payload;
} vapi_msg_ip_table_replace_end;

static inline void vapi_msg_ip_table_replace_end_payload_hton(vapi_payload_ip_table_replace_end *payload)
{
  vapi_type_ip_table_hton(&payload->table);
}

static inline void vapi_msg_ip_table_replace_end_payload_ntoh(vapi_payload_ip_table_replace_end *payload)
{
  vapi_type_ip_table_ntoh(&payload->table);
}

static inline void vapi_msg_ip_table_replace_end_hton(vapi_msg_ip_table_replace_end *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_table_replace_end'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip_table_replace_end_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_table_replace_end_ntoh(vapi_msg_ip_table_replace_end *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_table_replace_end'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip_table_replace_end_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_table_replace_end_msg_size(vapi_msg_ip_table_replace_end *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_table_replace_end_msg_size(vapi_msg_ip_table_replace_end *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_table_replace_end) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_table_replace_end' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_table_replace_end));
      return -1;
    }
  if (vapi_calc_ip_table_replace_end_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_table_replace_end' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_table_replace_end_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_table_replace_end* vapi_alloc_ip_table_replace_end(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_table_replace_end *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_table_replace_end);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_table_replace_end*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_table_replace_end);

  return msg;
}

static inline vapi_error_e vapi_ip_table_replace_end(struct vapi_ctx_s *ctx,
  vapi_msg_ip_table_replace_end *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_table_replace_end_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ip_table_replace_end_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_table_replace_end_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ip_table_replace_end_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_table_replace_end()
{
  static const char name[] = "ip_table_replace_end";
  static const char name_with_crc[] = "ip_table_replace_end_b9d2e09e";
  static vapi_message_desc_t __vapi_metadata_ip_table_replace_end = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip_table_replace_end, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_table_replace_end_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_table_replace_end_hton,
    (generic_swap_fn_t)vapi_msg_ip_table_replace_end_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_table_replace_end = vapi_register_msg(&__vapi_metadata_ip_table_replace_end);
  VAPI_DBG("Assigned msg id %d to ip_table_replace_end", vapi_msg_id_ip_table_replace_end);
}
#endif

#ifndef defined_vapi_msg_ip_table_flush_reply
#define defined_vapi_msg_ip_table_flush_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ip_table_flush_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_table_flush_reply payload;
} vapi_msg_ip_table_flush_reply;

static inline void vapi_msg_ip_table_flush_reply_payload_hton(vapi_payload_ip_table_flush_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ip_table_flush_reply_payload_ntoh(vapi_payload_ip_table_flush_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ip_table_flush_reply_hton(vapi_msg_ip_table_flush_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_table_flush_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_table_flush_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_table_flush_reply_ntoh(vapi_msg_ip_table_flush_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_table_flush_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_table_flush_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_table_flush_reply_msg_size(vapi_msg_ip_table_flush_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_table_flush_reply_msg_size(vapi_msg_ip_table_flush_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_table_flush_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_table_flush_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_table_flush_reply));
      return -1;
    }
  if (vapi_calc_ip_table_flush_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_table_flush_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_table_flush_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_table_flush_reply()
{
  static const char name[] = "ip_table_flush_reply";
  static const char name_with_crc[] = "ip_table_flush_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ip_table_flush_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_table_flush_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_table_flush_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_table_flush_reply_hton,
    (generic_swap_fn_t)vapi_msg_ip_table_flush_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_table_flush_reply = vapi_register_msg(&__vapi_metadata_ip_table_flush_reply);
  VAPI_DBG("Assigned msg id %d to ip_table_flush_reply", vapi_msg_id_ip_table_flush_reply);
}

static inline void vapi_set_vapi_msg_ip_table_flush_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_table_flush_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_table_flush_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_table_flush
#define defined_vapi_msg_ip_table_flush
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip_table table; 
} vapi_payload_ip_table_flush;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip_table_flush payload;
} vapi_msg_ip_table_flush;

static inline void vapi_msg_ip_table_flush_payload_hton(vapi_payload_ip_table_flush *payload)
{
  vapi_type_ip_table_hton(&payload->table);
}

static inline void vapi_msg_ip_table_flush_payload_ntoh(vapi_payload_ip_table_flush *payload)
{
  vapi_type_ip_table_ntoh(&payload->table);
}

static inline void vapi_msg_ip_table_flush_hton(vapi_msg_ip_table_flush *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_table_flush'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip_table_flush_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_table_flush_ntoh(vapi_msg_ip_table_flush *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_table_flush'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip_table_flush_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_table_flush_msg_size(vapi_msg_ip_table_flush *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_table_flush_msg_size(vapi_msg_ip_table_flush *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_table_flush) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_table_flush' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_table_flush));
      return -1;
    }
  if (vapi_calc_ip_table_flush_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_table_flush' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_table_flush_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_table_flush* vapi_alloc_ip_table_flush(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_table_flush *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_table_flush);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_table_flush*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_table_flush);

  return msg;
}

static inline vapi_error_e vapi_ip_table_flush(struct vapi_ctx_s *ctx,
  vapi_msg_ip_table_flush *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_table_flush_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ip_table_flush_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_table_flush_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ip_table_flush_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_table_flush()
{
  static const char name[] = "ip_table_flush";
  static const char name_with_crc[] = "ip_table_flush_b9d2e09e";
  static vapi_message_desc_t __vapi_metadata_ip_table_flush = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip_table_flush, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_table_flush_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_table_flush_hton,
    (generic_swap_fn_t)vapi_msg_ip_table_flush_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_table_flush = vapi_register_msg(&__vapi_metadata_ip_table_flush);
  VAPI_DBG("Assigned msg id %d to ip_table_flush", vapi_msg_id_ip_table_flush);
}
#endif

#ifndef defined_vapi_msg_ip_route_add_del_reply
#define defined_vapi_msg_ip_route_add_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 stats_index; 
} vapi_payload_ip_route_add_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_route_add_del_reply payload;
} vapi_msg_ip_route_add_del_reply;

static inline void vapi_msg_ip_route_add_del_reply_payload_hton(vapi_payload_ip_route_add_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->stats_index = htobe32(payload->stats_index);
}

static inline void vapi_msg_ip_route_add_del_reply_payload_ntoh(vapi_payload_ip_route_add_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->stats_index = be32toh(payload->stats_index);
}

static inline void vapi_msg_ip_route_add_del_reply_hton(vapi_msg_ip_route_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_route_add_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_route_add_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_route_add_del_reply_ntoh(vapi_msg_ip_route_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_route_add_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_route_add_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_route_add_del_reply_msg_size(vapi_msg_ip_route_add_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_route_add_del_reply_msg_size(vapi_msg_ip_route_add_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_route_add_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_route_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_route_add_del_reply));
      return -1;
    }
  if (vapi_calc_ip_route_add_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_route_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_route_add_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_route_add_del_reply()
{
  static const char name[] = "ip_route_add_del_reply";
  static const char name_with_crc[] = "ip_route_add_del_reply_1992deab";
  static vapi_message_desc_t __vapi_metadata_ip_route_add_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_route_add_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_route_add_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_route_add_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_ip_route_add_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_route_add_del_reply = vapi_register_msg(&__vapi_metadata_ip_route_add_del_reply);
  VAPI_DBG("Assigned msg id %d to ip_route_add_del_reply", vapi_msg_id_ip_route_add_del_reply);
}

static inline void vapi_set_vapi_msg_ip_route_add_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_route_add_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_route_add_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_route_add_del
#define defined_vapi_msg_ip_route_add_del
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  bool is_multipath;
  vapi_type_ip_route route; 
} vapi_payload_ip_route_add_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip_route_add_del payload;
} vapi_msg_ip_route_add_del;

static inline void vapi_msg_ip_route_add_del_payload_hton(vapi_payload_ip_route_add_del *payload)
{
  vapi_type_ip_route_hton(&payload->route);
}

static inline void vapi_msg_ip_route_add_del_payload_ntoh(vapi_payload_ip_route_add_del *payload)
{
  vapi_type_ip_route_ntoh(&payload->route);
}

static inline void vapi_msg_ip_route_add_del_hton(vapi_msg_ip_route_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_route_add_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip_route_add_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_route_add_del_ntoh(vapi_msg_ip_route_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_route_add_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip_route_add_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_route_add_del_msg_size(vapi_msg_ip_route_add_del *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.route.paths[0]) * msg->payload.route.n_paths;
}

static inline int vapi_verify_ip_route_add_del_msg_size(vapi_msg_ip_route_add_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_route_add_del) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_route_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_route_add_del));
      return -1;
    }
  if (vapi_calc_ip_route_add_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_route_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_route_add_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_route_add_del* vapi_alloc_ip_route_add_del(struct vapi_ctx_s *ctx, size_t route_paths_array_size)
{
  vapi_msg_ip_route_add_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_route_add_del) + sizeof(msg->payload.route.paths[0]) * route_paths_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_route_add_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_route_add_del);
  msg->payload.route.n_paths = route_paths_array_size;

  return msg;
}

static inline vapi_error_e vapi_ip_route_add_del(struct vapi_ctx_s *ctx,
  vapi_msg_ip_route_add_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_route_add_del_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ip_route_add_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_route_add_del_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ip_route_add_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_route_add_del()
{
  static const char name[] = "ip_route_add_del";
  static const char name_with_crc[] = "ip_route_add_del_b8ecfe0d";
  static vapi_message_desc_t __vapi_metadata_ip_route_add_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip_route_add_del, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_route_add_del_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_route_add_del_hton,
    (generic_swap_fn_t)vapi_msg_ip_route_add_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_route_add_del = vapi_register_msg(&__vapi_metadata_ip_route_add_del);
  VAPI_DBG("Assigned msg id %d to ip_route_add_del", vapi_msg_id_ip_route_add_del);
}
#endif

#ifndef defined_vapi_msg_ip_route_add_del_v2_reply
#define defined_vapi_msg_ip_route_add_del_v2_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 stats_index; 
} vapi_payload_ip_route_add_del_v2_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_route_add_del_v2_reply payload;
} vapi_msg_ip_route_add_del_v2_reply;

static inline void vapi_msg_ip_route_add_del_v2_reply_payload_hton(vapi_payload_ip_route_add_del_v2_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->stats_index = htobe32(payload->stats_index);
}

static inline void vapi_msg_ip_route_add_del_v2_reply_payload_ntoh(vapi_payload_ip_route_add_del_v2_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->stats_index = be32toh(payload->stats_index);
}

static inline void vapi_msg_ip_route_add_del_v2_reply_hton(vapi_msg_ip_route_add_del_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_route_add_del_v2_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_route_add_del_v2_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_route_add_del_v2_reply_ntoh(vapi_msg_ip_route_add_del_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_route_add_del_v2_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_route_add_del_v2_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_route_add_del_v2_reply_msg_size(vapi_msg_ip_route_add_del_v2_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_route_add_del_v2_reply_msg_size(vapi_msg_ip_route_add_del_v2_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_route_add_del_v2_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_route_add_del_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_route_add_del_v2_reply));
      return -1;
    }
  if (vapi_calc_ip_route_add_del_v2_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_route_add_del_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_route_add_del_v2_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_route_add_del_v2_reply()
{
  static const char name[] = "ip_route_add_del_v2_reply";
  static const char name_with_crc[] = "ip_route_add_del_v2_reply_1992deab";
  static vapi_message_desc_t __vapi_metadata_ip_route_add_del_v2_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_route_add_del_v2_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_route_add_del_v2_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_route_add_del_v2_reply_hton,
    (generic_swap_fn_t)vapi_msg_ip_route_add_del_v2_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_route_add_del_v2_reply = vapi_register_msg(&__vapi_metadata_ip_route_add_del_v2_reply);
  VAPI_DBG("Assigned msg id %d to ip_route_add_del_v2_reply", vapi_msg_id_ip_route_add_del_v2_reply);
}

static inline void vapi_set_vapi_msg_ip_route_add_del_v2_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_route_add_del_v2_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_route_add_del_v2_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_route_add_del_v2
#define defined_vapi_msg_ip_route_add_del_v2
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  bool is_multipath;
  vapi_type_ip_route_v2 route; 
} vapi_payload_ip_route_add_del_v2;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip_route_add_del_v2 payload;
} vapi_msg_ip_route_add_del_v2;

static inline void vapi_msg_ip_route_add_del_v2_payload_hton(vapi_payload_ip_route_add_del_v2 *payload)
{
  vapi_type_ip_route_v2_hton(&payload->route);
}

static inline void vapi_msg_ip_route_add_del_v2_payload_ntoh(vapi_payload_ip_route_add_del_v2 *payload)
{
  vapi_type_ip_route_v2_ntoh(&payload->route);
}

static inline void vapi_msg_ip_route_add_del_v2_hton(vapi_msg_ip_route_add_del_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_route_add_del_v2'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip_route_add_del_v2_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_route_add_del_v2_ntoh(vapi_msg_ip_route_add_del_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_route_add_del_v2'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip_route_add_del_v2_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_route_add_del_v2_msg_size(vapi_msg_ip_route_add_del_v2 *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.route.paths[0]) * msg->payload.route.n_paths;
}

static inline int vapi_verify_ip_route_add_del_v2_msg_size(vapi_msg_ip_route_add_del_v2 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_route_add_del_v2) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_route_add_del_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_route_add_del_v2));
      return -1;
    }
  if (vapi_calc_ip_route_add_del_v2_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_route_add_del_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_route_add_del_v2_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_route_add_del_v2* vapi_alloc_ip_route_add_del_v2(struct vapi_ctx_s *ctx, size_t route_paths_array_size)
{
  vapi_msg_ip_route_add_del_v2 *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_route_add_del_v2) + sizeof(msg->payload.route.paths[0]) * route_paths_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_route_add_del_v2*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_route_add_del_v2);
  msg->payload.route.n_paths = route_paths_array_size;

  return msg;
}

static inline vapi_error_e vapi_ip_route_add_del_v2(struct vapi_ctx_s *ctx,
  vapi_msg_ip_route_add_del_v2 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_route_add_del_v2_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ip_route_add_del_v2_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_route_add_del_v2_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ip_route_add_del_v2_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_route_add_del_v2()
{
  static const char name[] = "ip_route_add_del_v2";
  static const char name_with_crc[] = "ip_route_add_del_v2_521ef330";
  static vapi_message_desc_t __vapi_metadata_ip_route_add_del_v2 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip_route_add_del_v2, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_route_add_del_v2_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_route_add_del_v2_hton,
    (generic_swap_fn_t)vapi_msg_ip_route_add_del_v2_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_route_add_del_v2 = vapi_register_msg(&__vapi_metadata_ip_route_add_del_v2);
  VAPI_DBG("Assigned msg id %d to ip_route_add_del_v2", vapi_msg_id_ip_route_add_del_v2);
}
#endif

#ifndef defined_vapi_msg_ip_route_details
#define defined_vapi_msg_ip_route_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip_route route; 
} vapi_payload_ip_route_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_route_details payload;
} vapi_msg_ip_route_details;

static inline void vapi_msg_ip_route_details_payload_hton(vapi_payload_ip_route_details *payload)
{
  vapi_type_ip_route_hton(&payload->route);
}

static inline void vapi_msg_ip_route_details_payload_ntoh(vapi_payload_ip_route_details *payload)
{
  vapi_type_ip_route_ntoh(&payload->route);
}

static inline void vapi_msg_ip_route_details_hton(vapi_msg_ip_route_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_route_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_route_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_route_details_ntoh(vapi_msg_ip_route_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_route_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_route_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_route_details_msg_size(vapi_msg_ip_route_details *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.route.paths[0]) * msg->payload.route.n_paths;
}

static inline int vapi_verify_ip_route_details_msg_size(vapi_msg_ip_route_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_route_details) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_route_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_route_details));
      return -1;
    }
  if (vapi_calc_ip_route_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_route_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_route_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_route_details()
{
  static const char name[] = "ip_route_details";
  static const char name_with_crc[] = "ip_route_details_bda8f315";
  static vapi_message_desc_t __vapi_metadata_ip_route_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_route_details, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_route_details_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_route_details_hton,
    (generic_swap_fn_t)vapi_msg_ip_route_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_route_details = vapi_register_msg(&__vapi_metadata_ip_route_details);
  VAPI_DBG("Assigned msg id %d to ip_route_details", vapi_msg_id_ip_route_details);
}

static inline void vapi_set_vapi_msg_ip_route_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_route_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_route_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_route_dump
#define defined_vapi_msg_ip_route_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip_table table; 
} vapi_payload_ip_route_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip_route_dump payload;
} vapi_msg_ip_route_dump;

static inline void vapi_msg_ip_route_dump_payload_hton(vapi_payload_ip_route_dump *payload)
{
  vapi_type_ip_table_hton(&payload->table);
}

static inline void vapi_msg_ip_route_dump_payload_ntoh(vapi_payload_ip_route_dump *payload)
{
  vapi_type_ip_table_ntoh(&payload->table);
}

static inline void vapi_msg_ip_route_dump_hton(vapi_msg_ip_route_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_route_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip_route_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_route_dump_ntoh(vapi_msg_ip_route_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_route_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip_route_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_route_dump_msg_size(vapi_msg_ip_route_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_route_dump_msg_size(vapi_msg_ip_route_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_route_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_route_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_route_dump));
      return -1;
    }
  if (vapi_calc_ip_route_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_route_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_route_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_route_dump* vapi_alloc_ip_route_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_route_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_route_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_route_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_route_dump);

  return msg;
}

static inline vapi_error_e vapi_ip_route_dump(struct vapi_ctx_s *ctx,
  vapi_msg_ip_route_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_route_details *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ip_route_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_route_details, VAPI_REQUEST_DUMP, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ip_route_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_route_dump()
{
  static const char name[] = "ip_route_dump";
  static const char name_with_crc[] = "ip_route_dump_b9d2e09e";
  static vapi_message_desc_t __vapi_metadata_ip_route_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip_route_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_route_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_route_dump_hton,
    (generic_swap_fn_t)vapi_msg_ip_route_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_route_dump = vapi_register_msg(&__vapi_metadata_ip_route_dump);
  VAPI_DBG("Assigned msg id %d to ip_route_dump", vapi_msg_id_ip_route_dump);
}
#endif

#ifndef defined_vapi_msg_ip_route_v2_details
#define defined_vapi_msg_ip_route_v2_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip_route_v2 route; 
} vapi_payload_ip_route_v2_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_route_v2_details payload;
} vapi_msg_ip_route_v2_details;

static inline void vapi_msg_ip_route_v2_details_payload_hton(vapi_payload_ip_route_v2_details *payload)
{
  vapi_type_ip_route_v2_hton(&payload->route);
}

static inline void vapi_msg_ip_route_v2_details_payload_ntoh(vapi_payload_ip_route_v2_details *payload)
{
  vapi_type_ip_route_v2_ntoh(&payload->route);
}

static inline void vapi_msg_ip_route_v2_details_hton(vapi_msg_ip_route_v2_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_route_v2_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_route_v2_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_route_v2_details_ntoh(vapi_msg_ip_route_v2_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_route_v2_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_route_v2_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_route_v2_details_msg_size(vapi_msg_ip_route_v2_details *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.route.paths[0]) * msg->payload.route.n_paths;
}

static inline int vapi_verify_ip_route_v2_details_msg_size(vapi_msg_ip_route_v2_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_route_v2_details) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_route_v2_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_route_v2_details));
      return -1;
    }
  if (vapi_calc_ip_route_v2_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_route_v2_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_route_v2_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_route_v2_details()
{
  static const char name[] = "ip_route_v2_details";
  static const char name_with_crc[] = "ip_route_v2_details_b09aa6c0";
  static vapi_message_desc_t __vapi_metadata_ip_route_v2_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_route_v2_details, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_route_v2_details_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_route_v2_details_hton,
    (generic_swap_fn_t)vapi_msg_ip_route_v2_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_route_v2_details = vapi_register_msg(&__vapi_metadata_ip_route_v2_details);
  VAPI_DBG("Assigned msg id %d to ip_route_v2_details", vapi_msg_id_ip_route_v2_details);
}

static inline void vapi_set_vapi_msg_ip_route_v2_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_route_v2_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_route_v2_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_route_v2_dump
#define defined_vapi_msg_ip_route_v2_dump
typedef struct __attribute__ ((__packed__)) {
  u8 src;
  vapi_type_ip_table table; 
} vapi_payload_ip_route_v2_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip_route_v2_dump payload;
} vapi_msg_ip_route_v2_dump;

static inline void vapi_msg_ip_route_v2_dump_payload_hton(vapi_payload_ip_route_v2_dump *payload)
{
  vapi_type_ip_table_hton(&payload->table);
}

static inline void vapi_msg_ip_route_v2_dump_payload_ntoh(vapi_payload_ip_route_v2_dump *payload)
{
  vapi_type_ip_table_ntoh(&payload->table);
}

static inline void vapi_msg_ip_route_v2_dump_hton(vapi_msg_ip_route_v2_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_route_v2_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip_route_v2_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_route_v2_dump_ntoh(vapi_msg_ip_route_v2_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_route_v2_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip_route_v2_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_route_v2_dump_msg_size(vapi_msg_ip_route_v2_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_route_v2_dump_msg_size(vapi_msg_ip_route_v2_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_route_v2_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_route_v2_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_route_v2_dump));
      return -1;
    }
  if (vapi_calc_ip_route_v2_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_route_v2_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_route_v2_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_route_v2_dump* vapi_alloc_ip_route_v2_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_route_v2_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_route_v2_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_route_v2_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_route_v2_dump);

  return msg;
}

static inline vapi_error_e vapi_ip_route_v2_dump(struct vapi_ctx_s *ctx,
  vapi_msg_ip_route_v2_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_route_v2_details *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ip_route_v2_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_route_v2_details, VAPI_REQUEST_DUMP, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ip_route_v2_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_route_v2_dump()
{
  static const char name[] = "ip_route_v2_dump";
  static const char name_with_crc[] = "ip_route_v2_dump_d16f72e6";
  static vapi_message_desc_t __vapi_metadata_ip_route_v2_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip_route_v2_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_route_v2_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_route_v2_dump_hton,
    (generic_swap_fn_t)vapi_msg_ip_route_v2_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_route_v2_dump = vapi_register_msg(&__vapi_metadata_ip_route_v2_dump);
  VAPI_DBG("Assigned msg id %d to ip_route_v2_dump", vapi_msg_id_ip_route_v2_dump);
}
#endif

#ifndef defined_vapi_msg_ip_route_lookup_reply
#define defined_vapi_msg_ip_route_lookup_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vapi_type_ip_route route; 
} vapi_payload_ip_route_lookup_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_route_lookup_reply payload;
} vapi_msg_ip_route_lookup_reply;

static inline void vapi_msg_ip_route_lookup_reply_payload_hton(vapi_payload_ip_route_lookup_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  vapi_type_ip_route_hton(&payload->route);
}

static inline void vapi_msg_ip_route_lookup_reply_payload_ntoh(vapi_payload_ip_route_lookup_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  vapi_type_ip_route_ntoh(&payload->route);
}

static inline void vapi_msg_ip_route_lookup_reply_hton(vapi_msg_ip_route_lookup_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_route_lookup_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_route_lookup_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_route_lookup_reply_ntoh(vapi_msg_ip_route_lookup_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_route_lookup_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_route_lookup_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_route_lookup_reply_msg_size(vapi_msg_ip_route_lookup_reply *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.route.paths[0]) * msg->payload.route.n_paths;
}

static inline int vapi_verify_ip_route_lookup_reply_msg_size(vapi_msg_ip_route_lookup_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_route_lookup_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_route_lookup_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_route_lookup_reply));
      return -1;
    }
  if (vapi_calc_ip_route_lookup_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_route_lookup_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_route_lookup_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_route_lookup_reply()
{
  static const char name[] = "ip_route_lookup_reply";
  static const char name_with_crc[] = "ip_route_lookup_reply_5d8febcb";
  static vapi_message_desc_t __vapi_metadata_ip_route_lookup_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_route_lookup_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_route_lookup_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_route_lookup_reply_hton,
    (generic_swap_fn_t)vapi_msg_ip_route_lookup_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_route_lookup_reply = vapi_register_msg(&__vapi_metadata_ip_route_lookup_reply);
  VAPI_DBG("Assigned msg id %d to ip_route_lookup_reply", vapi_msg_id_ip_route_lookup_reply);
}

static inline void vapi_set_vapi_msg_ip_route_lookup_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_route_lookup_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_route_lookup_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_route_lookup
#define defined_vapi_msg_ip_route_lookup
typedef struct __attribute__ ((__packed__)) {
  u32 table_id;
  u8 exact;
  vapi_type_prefix prefix; 
} vapi_payload_ip_route_lookup;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip_route_lookup payload;
} vapi_msg_ip_route_lookup;

static inline void vapi_msg_ip_route_lookup_payload_hton(vapi_payload_ip_route_lookup *payload)
{
  payload->table_id = htobe32(payload->table_id);
}

static inline void vapi_msg_ip_route_lookup_payload_ntoh(vapi_payload_ip_route_lookup *payload)
{
  payload->table_id = be32toh(payload->table_id);
}

static inline void vapi_msg_ip_route_lookup_hton(vapi_msg_ip_route_lookup *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_route_lookup'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip_route_lookup_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_route_lookup_ntoh(vapi_msg_ip_route_lookup *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_route_lookup'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip_route_lookup_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_route_lookup_msg_size(vapi_msg_ip_route_lookup *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_route_lookup_msg_size(vapi_msg_ip_route_lookup *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_route_lookup) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_route_lookup' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_route_lookup));
      return -1;
    }
  if (vapi_calc_ip_route_lookup_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_route_lookup' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_route_lookup_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_route_lookup* vapi_alloc_ip_route_lookup(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_route_lookup *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_route_lookup);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_route_lookup*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_route_lookup);

  return msg;
}

static inline vapi_error_e vapi_ip_route_lookup(struct vapi_ctx_s *ctx,
  vapi_msg_ip_route_lookup *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_route_lookup_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ip_route_lookup_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_route_lookup_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ip_route_lookup_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_route_lookup()
{
  static const char name[] = "ip_route_lookup";
  static const char name_with_crc[] = "ip_route_lookup_710d6471";
  static vapi_message_desc_t __vapi_metadata_ip_route_lookup = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip_route_lookup, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_route_lookup_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_route_lookup_hton,
    (generic_swap_fn_t)vapi_msg_ip_route_lookup_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_route_lookup = vapi_register_msg(&__vapi_metadata_ip_route_lookup);
  VAPI_DBG("Assigned msg id %d to ip_route_lookup", vapi_msg_id_ip_route_lookup);
}
#endif

#ifndef defined_vapi_msg_ip_route_lookup_v2_reply
#define defined_vapi_msg_ip_route_lookup_v2_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vapi_type_ip_route_v2 route; 
} vapi_payload_ip_route_lookup_v2_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_route_lookup_v2_reply payload;
} vapi_msg_ip_route_lookup_v2_reply;

static inline void vapi_msg_ip_route_lookup_v2_reply_payload_hton(vapi_payload_ip_route_lookup_v2_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  vapi_type_ip_route_v2_hton(&payload->route);
}

static inline void vapi_msg_ip_route_lookup_v2_reply_payload_ntoh(vapi_payload_ip_route_lookup_v2_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  vapi_type_ip_route_v2_ntoh(&payload->route);
}

static inline void vapi_msg_ip_route_lookup_v2_reply_hton(vapi_msg_ip_route_lookup_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_route_lookup_v2_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_route_lookup_v2_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_route_lookup_v2_reply_ntoh(vapi_msg_ip_route_lookup_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_route_lookup_v2_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_route_lookup_v2_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_route_lookup_v2_reply_msg_size(vapi_msg_ip_route_lookup_v2_reply *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.route.paths[0]) * msg->payload.route.n_paths;
}

static inline int vapi_verify_ip_route_lookup_v2_reply_msg_size(vapi_msg_ip_route_lookup_v2_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_route_lookup_v2_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_route_lookup_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_route_lookup_v2_reply));
      return -1;
    }
  if (vapi_calc_ip_route_lookup_v2_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_route_lookup_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_route_lookup_v2_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_route_lookup_v2_reply()
{
  static const char name[] = "ip_route_lookup_v2_reply";
  static const char name_with_crc[] = "ip_route_lookup_v2_reply_84cc9e03";
  static vapi_message_desc_t __vapi_metadata_ip_route_lookup_v2_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_route_lookup_v2_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_route_lookup_v2_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_route_lookup_v2_reply_hton,
    (generic_swap_fn_t)vapi_msg_ip_route_lookup_v2_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_route_lookup_v2_reply = vapi_register_msg(&__vapi_metadata_ip_route_lookup_v2_reply);
  VAPI_DBG("Assigned msg id %d to ip_route_lookup_v2_reply", vapi_msg_id_ip_route_lookup_v2_reply);
}

static inline void vapi_set_vapi_msg_ip_route_lookup_v2_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_route_lookup_v2_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_route_lookup_v2_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_route_lookup_v2
#define defined_vapi_msg_ip_route_lookup_v2
typedef struct __attribute__ ((__packed__)) {
  u32 table_id;
  u8 exact;
  vapi_type_prefix prefix; 
} vapi_payload_ip_route_lookup_v2;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip_route_lookup_v2 payload;
} vapi_msg_ip_route_lookup_v2;

static inline void vapi_msg_ip_route_lookup_v2_payload_hton(vapi_payload_ip_route_lookup_v2 *payload)
{
  payload->table_id = htobe32(payload->table_id);
}

static inline void vapi_msg_ip_route_lookup_v2_payload_ntoh(vapi_payload_ip_route_lookup_v2 *payload)
{
  payload->table_id = be32toh(payload->table_id);
}

static inline void vapi_msg_ip_route_lookup_v2_hton(vapi_msg_ip_route_lookup_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_route_lookup_v2'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip_route_lookup_v2_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_route_lookup_v2_ntoh(vapi_msg_ip_route_lookup_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_route_lookup_v2'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip_route_lookup_v2_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_route_lookup_v2_msg_size(vapi_msg_ip_route_lookup_v2 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_route_lookup_v2_msg_size(vapi_msg_ip_route_lookup_v2 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_route_lookup_v2) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_route_lookup_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_route_lookup_v2));
      return -1;
    }
  if (vapi_calc_ip_route_lookup_v2_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_route_lookup_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_route_lookup_v2_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_route_lookup_v2* vapi_alloc_ip_route_lookup_v2(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_route_lookup_v2 *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_route_lookup_v2);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_route_lookup_v2*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_route_lookup_v2);

  return msg;
}

static inline vapi_error_e vapi_ip_route_lookup_v2(struct vapi_ctx_s *ctx,
  vapi_msg_ip_route_lookup_v2 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_route_lookup_v2_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ip_route_lookup_v2_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_route_lookup_v2_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ip_route_lookup_v2_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_route_lookup_v2()
{
  static const char name[] = "ip_route_lookup_v2";
  static const char name_with_crc[] = "ip_route_lookup_v2_710d6471";
  static vapi_message_desc_t __vapi_metadata_ip_route_lookup_v2 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip_route_lookup_v2, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_route_lookup_v2_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_route_lookup_v2_hton,
    (generic_swap_fn_t)vapi_msg_ip_route_lookup_v2_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_route_lookup_v2 = vapi_register_msg(&__vapi_metadata_ip_route_lookup_v2);
  VAPI_DBG("Assigned msg id %d to ip_route_lookup_v2", vapi_msg_id_ip_route_lookup_v2);
}
#endif

#ifndef defined_vapi_msg_set_ip_flow_hash_reply
#define defined_vapi_msg_set_ip_flow_hash_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_set_ip_flow_hash_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_set_ip_flow_hash_reply payload;
} vapi_msg_set_ip_flow_hash_reply;

static inline void vapi_msg_set_ip_flow_hash_reply_payload_hton(vapi_payload_set_ip_flow_hash_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_set_ip_flow_hash_reply_payload_ntoh(vapi_payload_set_ip_flow_hash_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_set_ip_flow_hash_reply_hton(vapi_msg_set_ip_flow_hash_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_set_ip_flow_hash_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_set_ip_flow_hash_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_set_ip_flow_hash_reply_ntoh(vapi_msg_set_ip_flow_hash_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_set_ip_flow_hash_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_set_ip_flow_hash_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_set_ip_flow_hash_reply_msg_size(vapi_msg_set_ip_flow_hash_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_set_ip_flow_hash_reply_msg_size(vapi_msg_set_ip_flow_hash_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_set_ip_flow_hash_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'set_ip_flow_hash_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_set_ip_flow_hash_reply));
      return -1;
    }
  if (vapi_calc_set_ip_flow_hash_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'set_ip_flow_hash_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_set_ip_flow_hash_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_set_ip_flow_hash_reply()
{
  static const char name[] = "set_ip_flow_hash_reply";
  static const char name_with_crc[] = "set_ip_flow_hash_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_set_ip_flow_hash_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_set_ip_flow_hash_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_set_ip_flow_hash_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_set_ip_flow_hash_reply_hton,
    (generic_swap_fn_t)vapi_msg_set_ip_flow_hash_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_set_ip_flow_hash_reply = vapi_register_msg(&__vapi_metadata_set_ip_flow_hash_reply);
  VAPI_DBG("Assigned msg id %d to set_ip_flow_hash_reply", vapi_msg_id_set_ip_flow_hash_reply);
}

static inline void vapi_set_vapi_msg_set_ip_flow_hash_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_set_ip_flow_hash_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_set_ip_flow_hash_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_set_ip_flow_hash
#define defined_vapi_msg_set_ip_flow_hash
typedef struct __attribute__ ((__packed__)) {
  u32 vrf_id;
  bool is_ipv6;
  bool src;
  bool dst;
  bool sport;
  bool dport;
  bool proto;
  bool reverse;
  bool symmetric; 
} vapi_payload_set_ip_flow_hash;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_set_ip_flow_hash payload;
} vapi_msg_set_ip_flow_hash;

static inline void vapi_msg_set_ip_flow_hash_payload_hton(vapi_payload_set_ip_flow_hash *payload)
{
  payload->vrf_id = htobe32(payload->vrf_id);
}

static inline void vapi_msg_set_ip_flow_hash_payload_ntoh(vapi_payload_set_ip_flow_hash *payload)
{
  payload->vrf_id = be32toh(payload->vrf_id);
}

static inline void vapi_msg_set_ip_flow_hash_hton(vapi_msg_set_ip_flow_hash *msg)
{
  VAPI_DBG("Swapping `vapi_msg_set_ip_flow_hash'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_set_ip_flow_hash_payload_hton(&msg->payload);
}

static inline void vapi_msg_set_ip_flow_hash_ntoh(vapi_msg_set_ip_flow_hash *msg)
{
  VAPI_DBG("Swapping `vapi_msg_set_ip_flow_hash'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_set_ip_flow_hash_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_set_ip_flow_hash_msg_size(vapi_msg_set_ip_flow_hash *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_set_ip_flow_hash_msg_size(vapi_msg_set_ip_flow_hash *msg, uword buf_size)
{
  if (sizeof(vapi_msg_set_ip_flow_hash) > buf_size)
    {
      VAPI_ERR("Truncated 'set_ip_flow_hash' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_set_ip_flow_hash));
      return -1;
    }
  if (vapi_calc_set_ip_flow_hash_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'set_ip_flow_hash' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_set_ip_flow_hash_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_set_ip_flow_hash* vapi_alloc_set_ip_flow_hash(struct vapi_ctx_s *ctx)
{
  vapi_msg_set_ip_flow_hash *msg = NULL;
  const size_t size = sizeof(vapi_msg_set_ip_flow_hash);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_set_ip_flow_hash*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_set_ip_flow_hash);

  return msg;
}

static inline vapi_error_e vapi_set_ip_flow_hash(struct vapi_ctx_s *ctx,
  vapi_msg_set_ip_flow_hash *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_set_ip_flow_hash_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_set_ip_flow_hash_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_set_ip_flow_hash_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_set_ip_flow_hash_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_set_ip_flow_hash()
{
  static const char name[] = "set_ip_flow_hash";
  static const char name_with_crc[] = "set_ip_flow_hash_084ee09e";
  static vapi_message_desc_t __vapi_metadata_set_ip_flow_hash = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_set_ip_flow_hash, payload),
    (verify_msg_size_fn_t)vapi_verify_set_ip_flow_hash_msg_size,
    (generic_swap_fn_t)vapi_msg_set_ip_flow_hash_hton,
    (generic_swap_fn_t)vapi_msg_set_ip_flow_hash_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_set_ip_flow_hash = vapi_register_msg(&__vapi_metadata_set_ip_flow_hash);
  VAPI_DBG("Assigned msg id %d to set_ip_flow_hash", vapi_msg_id_set_ip_flow_hash);
}
#endif

#ifndef defined_vapi_msg_set_ip_flow_hash_v2_reply
#define defined_vapi_msg_set_ip_flow_hash_v2_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_set_ip_flow_hash_v2_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_set_ip_flow_hash_v2_reply payload;
} vapi_msg_set_ip_flow_hash_v2_reply;

static inline void vapi_msg_set_ip_flow_hash_v2_reply_payload_hton(vapi_payload_set_ip_flow_hash_v2_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_set_ip_flow_hash_v2_reply_payload_ntoh(vapi_payload_set_ip_flow_hash_v2_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_set_ip_flow_hash_v2_reply_hton(vapi_msg_set_ip_flow_hash_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_set_ip_flow_hash_v2_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_set_ip_flow_hash_v2_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_set_ip_flow_hash_v2_reply_ntoh(vapi_msg_set_ip_flow_hash_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_set_ip_flow_hash_v2_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_set_ip_flow_hash_v2_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_set_ip_flow_hash_v2_reply_msg_size(vapi_msg_set_ip_flow_hash_v2_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_set_ip_flow_hash_v2_reply_msg_size(vapi_msg_set_ip_flow_hash_v2_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_set_ip_flow_hash_v2_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'set_ip_flow_hash_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_set_ip_flow_hash_v2_reply));
      return -1;
    }
  if (vapi_calc_set_ip_flow_hash_v2_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'set_ip_flow_hash_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_set_ip_flow_hash_v2_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_set_ip_flow_hash_v2_reply()
{
  static const char name[] = "set_ip_flow_hash_v2_reply";
  static const char name_with_crc[] = "set_ip_flow_hash_v2_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_set_ip_flow_hash_v2_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_set_ip_flow_hash_v2_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_set_ip_flow_hash_v2_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_set_ip_flow_hash_v2_reply_hton,
    (generic_swap_fn_t)vapi_msg_set_ip_flow_hash_v2_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_set_ip_flow_hash_v2_reply = vapi_register_msg(&__vapi_metadata_set_ip_flow_hash_v2_reply);
  VAPI_DBG("Assigned msg id %d to set_ip_flow_hash_v2_reply", vapi_msg_id_set_ip_flow_hash_v2_reply);
}

static inline void vapi_set_vapi_msg_set_ip_flow_hash_v2_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_set_ip_flow_hash_v2_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_set_ip_flow_hash_v2_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_set_ip_flow_hash_v2
#define defined_vapi_msg_set_ip_flow_hash_v2
typedef struct __attribute__ ((__packed__)) {
  u32 table_id;
  vapi_enum_address_family af;
  vapi_enum_ip_flow_hash_config flow_hash_config; 
} vapi_payload_set_ip_flow_hash_v2;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_set_ip_flow_hash_v2 payload;
} vapi_msg_set_ip_flow_hash_v2;

static inline void vapi_msg_set_ip_flow_hash_v2_payload_hton(vapi_payload_set_ip_flow_hash_v2 *payload)
{
  payload->table_id = htobe32(payload->table_id);
  payload->flow_hash_config = (vapi_enum_ip_flow_hash_config)htobe32(payload->flow_hash_config);
}

static inline void vapi_msg_set_ip_flow_hash_v2_payload_ntoh(vapi_payload_set_ip_flow_hash_v2 *payload)
{
  payload->table_id = be32toh(payload->table_id);
  payload->flow_hash_config = (vapi_enum_ip_flow_hash_config)be32toh(payload->flow_hash_config);
}

static inline void vapi_msg_set_ip_flow_hash_v2_hton(vapi_msg_set_ip_flow_hash_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_set_ip_flow_hash_v2'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_set_ip_flow_hash_v2_payload_hton(&msg->payload);
}

static inline void vapi_msg_set_ip_flow_hash_v2_ntoh(vapi_msg_set_ip_flow_hash_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_set_ip_flow_hash_v2'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_set_ip_flow_hash_v2_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_set_ip_flow_hash_v2_msg_size(vapi_msg_set_ip_flow_hash_v2 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_set_ip_flow_hash_v2_msg_size(vapi_msg_set_ip_flow_hash_v2 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_set_ip_flow_hash_v2) > buf_size)
    {
      VAPI_ERR("Truncated 'set_ip_flow_hash_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_set_ip_flow_hash_v2));
      return -1;
    }
  if (vapi_calc_set_ip_flow_hash_v2_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'set_ip_flow_hash_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_set_ip_flow_hash_v2_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_set_ip_flow_hash_v2* vapi_alloc_set_ip_flow_hash_v2(struct vapi_ctx_s *ctx)
{
  vapi_msg_set_ip_flow_hash_v2 *msg = NULL;
  const size_t size = sizeof(vapi_msg_set_ip_flow_hash_v2);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_set_ip_flow_hash_v2*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_set_ip_flow_hash_v2);

  return msg;
}

static inline vapi_error_e vapi_set_ip_flow_hash_v2(struct vapi_ctx_s *ctx,
  vapi_msg_set_ip_flow_hash_v2 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_set_ip_flow_hash_v2_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_set_ip_flow_hash_v2_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_set_ip_flow_hash_v2_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_set_ip_flow_hash_v2_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_set_ip_flow_hash_v2()
{
  static const char name[] = "set_ip_flow_hash_v2";
  static const char name_with_crc[] = "set_ip_flow_hash_v2_6d132100";
  static vapi_message_desc_t __vapi_metadata_set_ip_flow_hash_v2 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_set_ip_flow_hash_v2, payload),
    (verify_msg_size_fn_t)vapi_verify_set_ip_flow_hash_v2_msg_size,
    (generic_swap_fn_t)vapi_msg_set_ip_flow_hash_v2_hton,
    (generic_swap_fn_t)vapi_msg_set_ip_flow_hash_v2_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_set_ip_flow_hash_v2 = vapi_register_msg(&__vapi_metadata_set_ip_flow_hash_v2);
  VAPI_DBG("Assigned msg id %d to set_ip_flow_hash_v2", vapi_msg_id_set_ip_flow_hash_v2);
}
#endif

#ifndef defined_vapi_msg_set_ip_flow_hash_v3_reply
#define defined_vapi_msg_set_ip_flow_hash_v3_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_set_ip_flow_hash_v3_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_set_ip_flow_hash_v3_reply payload;
} vapi_msg_set_ip_flow_hash_v3_reply;

static inline void vapi_msg_set_ip_flow_hash_v3_reply_payload_hton(vapi_payload_set_ip_flow_hash_v3_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_set_ip_flow_hash_v3_reply_payload_ntoh(vapi_payload_set_ip_flow_hash_v3_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_set_ip_flow_hash_v3_reply_hton(vapi_msg_set_ip_flow_hash_v3_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_set_ip_flow_hash_v3_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_set_ip_flow_hash_v3_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_set_ip_flow_hash_v3_reply_ntoh(vapi_msg_set_ip_flow_hash_v3_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_set_ip_flow_hash_v3_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_set_ip_flow_hash_v3_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_set_ip_flow_hash_v3_reply_msg_size(vapi_msg_set_ip_flow_hash_v3_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_set_ip_flow_hash_v3_reply_msg_size(vapi_msg_set_ip_flow_hash_v3_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_set_ip_flow_hash_v3_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'set_ip_flow_hash_v3_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_set_ip_flow_hash_v3_reply));
      return -1;
    }
  if (vapi_calc_set_ip_flow_hash_v3_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'set_ip_flow_hash_v3_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_set_ip_flow_hash_v3_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_set_ip_flow_hash_v3_reply()
{
  static const char name[] = "set_ip_flow_hash_v3_reply";
  static const char name_with_crc[] = "set_ip_flow_hash_v3_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_set_ip_flow_hash_v3_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_set_ip_flow_hash_v3_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_set_ip_flow_hash_v3_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_set_ip_flow_hash_v3_reply_hton,
    (generic_swap_fn_t)vapi_msg_set_ip_flow_hash_v3_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_set_ip_flow_hash_v3_reply = vapi_register_msg(&__vapi_metadata_set_ip_flow_hash_v3_reply);
  VAPI_DBG("Assigned msg id %d to set_ip_flow_hash_v3_reply", vapi_msg_id_set_ip_flow_hash_v3_reply);
}

static inline void vapi_set_vapi_msg_set_ip_flow_hash_v3_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_set_ip_flow_hash_v3_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_set_ip_flow_hash_v3_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_set_ip_flow_hash_v3
#define defined_vapi_msg_set_ip_flow_hash_v3
typedef struct __attribute__ ((__packed__)) {
  u32 table_id;
  vapi_enum_address_family af;
  vapi_enum_ip_flow_hash_config_v2 flow_hash_config; 
} vapi_payload_set_ip_flow_hash_v3;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_set_ip_flow_hash_v3 payload;
} vapi_msg_set_ip_flow_hash_v3;

static inline void vapi_msg_set_ip_flow_hash_v3_payload_hton(vapi_payload_set_ip_flow_hash_v3 *payload)
{
  payload->table_id = htobe32(payload->table_id);
  payload->flow_hash_config = (vapi_enum_ip_flow_hash_config_v2)htobe32(payload->flow_hash_config);
}

static inline void vapi_msg_set_ip_flow_hash_v3_payload_ntoh(vapi_payload_set_ip_flow_hash_v3 *payload)
{
  payload->table_id = be32toh(payload->table_id);
  payload->flow_hash_config = (vapi_enum_ip_flow_hash_config_v2)be32toh(payload->flow_hash_config);
}

static inline void vapi_msg_set_ip_flow_hash_v3_hton(vapi_msg_set_ip_flow_hash_v3 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_set_ip_flow_hash_v3'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_set_ip_flow_hash_v3_payload_hton(&msg->payload);
}

static inline void vapi_msg_set_ip_flow_hash_v3_ntoh(vapi_msg_set_ip_flow_hash_v3 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_set_ip_flow_hash_v3'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_set_ip_flow_hash_v3_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_set_ip_flow_hash_v3_msg_size(vapi_msg_set_ip_flow_hash_v3 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_set_ip_flow_hash_v3_msg_size(vapi_msg_set_ip_flow_hash_v3 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_set_ip_flow_hash_v3) > buf_size)
    {
      VAPI_ERR("Truncated 'set_ip_flow_hash_v3' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_set_ip_flow_hash_v3));
      return -1;
    }
  if (vapi_calc_set_ip_flow_hash_v3_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'set_ip_flow_hash_v3' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_set_ip_flow_hash_v3_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_set_ip_flow_hash_v3* vapi_alloc_set_ip_flow_hash_v3(struct vapi_ctx_s *ctx)
{
  vapi_msg_set_ip_flow_hash_v3 *msg = NULL;
  const size_t size = sizeof(vapi_msg_set_ip_flow_hash_v3);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_set_ip_flow_hash_v3*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_set_ip_flow_hash_v3);

  return msg;
}

static inline vapi_error_e vapi_set_ip_flow_hash_v3(struct vapi_ctx_s *ctx,
  vapi_msg_set_ip_flow_hash_v3 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_set_ip_flow_hash_v3_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_set_ip_flow_hash_v3_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_set_ip_flow_hash_v3_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_set_ip_flow_hash_v3_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_set_ip_flow_hash_v3()
{
  static const char name[] = "set_ip_flow_hash_v3";
  static const char name_with_crc[] = "set_ip_flow_hash_v3_b7876e07";
  static vapi_message_desc_t __vapi_metadata_set_ip_flow_hash_v3 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_set_ip_flow_hash_v3, payload),
    (verify_msg_size_fn_t)vapi_verify_set_ip_flow_hash_v3_msg_size,
    (generic_swap_fn_t)vapi_msg_set_ip_flow_hash_v3_hton,
    (generic_swap_fn_t)vapi_msg_set_ip_flow_hash_v3_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_set_ip_flow_hash_v3 = vapi_register_msg(&__vapi_metadata_set_ip_flow_hash_v3);
  VAPI_DBG("Assigned msg id %d to set_ip_flow_hash_v3", vapi_msg_id_set_ip_flow_hash_v3);
}
#endif

#ifndef defined_vapi_msg_set_ip_flow_hash_router_id_reply
#define defined_vapi_msg_set_ip_flow_hash_router_id_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_set_ip_flow_hash_router_id_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_set_ip_flow_hash_router_id_reply payload;
} vapi_msg_set_ip_flow_hash_router_id_reply;

static inline void vapi_msg_set_ip_flow_hash_router_id_reply_payload_hton(vapi_payload_set_ip_flow_hash_router_id_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_set_ip_flow_hash_router_id_reply_payload_ntoh(vapi_payload_set_ip_flow_hash_router_id_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_set_ip_flow_hash_router_id_reply_hton(vapi_msg_set_ip_flow_hash_router_id_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_set_ip_flow_hash_router_id_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_set_ip_flow_hash_router_id_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_set_ip_flow_hash_router_id_reply_ntoh(vapi_msg_set_ip_flow_hash_router_id_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_set_ip_flow_hash_router_id_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_set_ip_flow_hash_router_id_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_set_ip_flow_hash_router_id_reply_msg_size(vapi_msg_set_ip_flow_hash_router_id_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_set_ip_flow_hash_router_id_reply_msg_size(vapi_msg_set_ip_flow_hash_router_id_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_set_ip_flow_hash_router_id_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'set_ip_flow_hash_router_id_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_set_ip_flow_hash_router_id_reply));
      return -1;
    }
  if (vapi_calc_set_ip_flow_hash_router_id_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'set_ip_flow_hash_router_id_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_set_ip_flow_hash_router_id_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_set_ip_flow_hash_router_id_reply()
{
  static const char name[] = "set_ip_flow_hash_router_id_reply";
  static const char name_with_crc[] = "set_ip_flow_hash_router_id_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_set_ip_flow_hash_router_id_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_set_ip_flow_hash_router_id_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_set_ip_flow_hash_router_id_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_set_ip_flow_hash_router_id_reply_hton,
    (generic_swap_fn_t)vapi_msg_set_ip_flow_hash_router_id_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_set_ip_flow_hash_router_id_reply = vapi_register_msg(&__vapi_metadata_set_ip_flow_hash_router_id_reply);
  VAPI_DBG("Assigned msg id %d to set_ip_flow_hash_router_id_reply", vapi_msg_id_set_ip_flow_hash_router_id_reply);
}

static inline void vapi_set_vapi_msg_set_ip_flow_hash_router_id_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_set_ip_flow_hash_router_id_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_set_ip_flow_hash_router_id_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_set_ip_flow_hash_router_id
#define defined_vapi_msg_set_ip_flow_hash_router_id
typedef struct __attribute__ ((__packed__)) {
  u32 router_id; 
} vapi_payload_set_ip_flow_hash_router_id;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_set_ip_flow_hash_router_id payload;
} vapi_msg_set_ip_flow_hash_router_id;

static inline void vapi_msg_set_ip_flow_hash_router_id_payload_hton(vapi_payload_set_ip_flow_hash_router_id *payload)
{
  payload->router_id = htobe32(payload->router_id);
}

static inline void vapi_msg_set_ip_flow_hash_router_id_payload_ntoh(vapi_payload_set_ip_flow_hash_router_id *payload)
{
  payload->router_id = be32toh(payload->router_id);
}

static inline void vapi_msg_set_ip_flow_hash_router_id_hton(vapi_msg_set_ip_flow_hash_router_id *msg)
{
  VAPI_DBG("Swapping `vapi_msg_set_ip_flow_hash_router_id'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_set_ip_flow_hash_router_id_payload_hton(&msg->payload);
}

static inline void vapi_msg_set_ip_flow_hash_router_id_ntoh(vapi_msg_set_ip_flow_hash_router_id *msg)
{
  VAPI_DBG("Swapping `vapi_msg_set_ip_flow_hash_router_id'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_set_ip_flow_hash_router_id_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_set_ip_flow_hash_router_id_msg_size(vapi_msg_set_ip_flow_hash_router_id *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_set_ip_flow_hash_router_id_msg_size(vapi_msg_set_ip_flow_hash_router_id *msg, uword buf_size)
{
  if (sizeof(vapi_msg_set_ip_flow_hash_router_id) > buf_size)
    {
      VAPI_ERR("Truncated 'set_ip_flow_hash_router_id' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_set_ip_flow_hash_router_id));
      return -1;
    }
  if (vapi_calc_set_ip_flow_hash_router_id_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'set_ip_flow_hash_router_id' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_set_ip_flow_hash_router_id_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_set_ip_flow_hash_router_id* vapi_alloc_set_ip_flow_hash_router_id(struct vapi_ctx_s *ctx)
{
  vapi_msg_set_ip_flow_hash_router_id *msg = NULL;
  const size_t size = sizeof(vapi_msg_set_ip_flow_hash_router_id);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_set_ip_flow_hash_router_id*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_set_ip_flow_hash_router_id);

  return msg;
}

static inline vapi_error_e vapi_set_ip_flow_hash_router_id(struct vapi_ctx_s *ctx,
  vapi_msg_set_ip_flow_hash_router_id *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_set_ip_flow_hash_router_id_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_set_ip_flow_hash_router_id_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_set_ip_flow_hash_router_id_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_set_ip_flow_hash_router_id_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_set_ip_flow_hash_router_id()
{
  static const char name[] = "set_ip_flow_hash_router_id";
  static const char name_with_crc[] = "set_ip_flow_hash_router_id_03e4f48e";
  static vapi_message_desc_t __vapi_metadata_set_ip_flow_hash_router_id = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_set_ip_flow_hash_router_id, payload),
    (verify_msg_size_fn_t)vapi_verify_set_ip_flow_hash_router_id_msg_size,
    (generic_swap_fn_t)vapi_msg_set_ip_flow_hash_router_id_hton,
    (generic_swap_fn_t)vapi_msg_set_ip_flow_hash_router_id_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_set_ip_flow_hash_router_id = vapi_register_msg(&__vapi_metadata_set_ip_flow_hash_router_id);
  VAPI_DBG("Assigned msg id %d to set_ip_flow_hash_router_id", vapi_msg_id_set_ip_flow_hash_router_id);
}
#endif

#ifndef defined_vapi_msg_sw_interface_ip6_enable_disable_reply
#define defined_vapi_msg_sw_interface_ip6_enable_disable_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_sw_interface_ip6_enable_disable_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_sw_interface_ip6_enable_disable_reply payload;
} vapi_msg_sw_interface_ip6_enable_disable_reply;

static inline void vapi_msg_sw_interface_ip6_enable_disable_reply_payload_hton(vapi_payload_sw_interface_ip6_enable_disable_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_sw_interface_ip6_enable_disable_reply_payload_ntoh(vapi_payload_sw_interface_ip6_enable_disable_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_sw_interface_ip6_enable_disable_reply_hton(vapi_msg_sw_interface_ip6_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_ip6_enable_disable_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_sw_interface_ip6_enable_disable_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_sw_interface_ip6_enable_disable_reply_ntoh(vapi_msg_sw_interface_ip6_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_ip6_enable_disable_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_sw_interface_ip6_enable_disable_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sw_interface_ip6_enable_disable_reply_msg_size(vapi_msg_sw_interface_ip6_enable_disable_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sw_interface_ip6_enable_disable_reply_msg_size(vapi_msg_sw_interface_ip6_enable_disable_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sw_interface_ip6_enable_disable_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_ip6_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sw_interface_ip6_enable_disable_reply));
      return -1;
    }
  if (vapi_calc_sw_interface_ip6_enable_disable_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_ip6_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sw_interface_ip6_enable_disable_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_sw_interface_ip6_enable_disable_reply()
{
  static const char name[] = "sw_interface_ip6_enable_disable_reply";
  static const char name_with_crc[] = "sw_interface_ip6_enable_disable_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_sw_interface_ip6_enable_disable_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_sw_interface_ip6_enable_disable_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_sw_interface_ip6_enable_disable_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_sw_interface_ip6_enable_disable_reply_hton,
    (generic_swap_fn_t)vapi_msg_sw_interface_ip6_enable_disable_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sw_interface_ip6_enable_disable_reply = vapi_register_msg(&__vapi_metadata_sw_interface_ip6_enable_disable_reply);
  VAPI_DBG("Assigned msg id %d to sw_interface_ip6_enable_disable_reply", vapi_msg_id_sw_interface_ip6_enable_disable_reply);
}

static inline void vapi_set_vapi_msg_sw_interface_ip6_enable_disable_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_sw_interface_ip6_enable_disable_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_sw_interface_ip6_enable_disable_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_sw_interface_ip6_enable_disable
#define defined_vapi_msg_sw_interface_ip6_enable_disable
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  bool enable; 
} vapi_payload_sw_interface_ip6_enable_disable;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_sw_interface_ip6_enable_disable payload;
} vapi_msg_sw_interface_ip6_enable_disable;

static inline void vapi_msg_sw_interface_ip6_enable_disable_payload_hton(vapi_payload_sw_interface_ip6_enable_disable *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_sw_interface_ip6_enable_disable_payload_ntoh(vapi_payload_sw_interface_ip6_enable_disable *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_sw_interface_ip6_enable_disable_hton(vapi_msg_sw_interface_ip6_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_ip6_enable_disable'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_sw_interface_ip6_enable_disable_payload_hton(&msg->payload);
}

static inline void vapi_msg_sw_interface_ip6_enable_disable_ntoh(vapi_msg_sw_interface_ip6_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_ip6_enable_disable'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_sw_interface_ip6_enable_disable_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sw_interface_ip6_enable_disable_msg_size(vapi_msg_sw_interface_ip6_enable_disable *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sw_interface_ip6_enable_disable_msg_size(vapi_msg_sw_interface_ip6_enable_disable *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sw_interface_ip6_enable_disable) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_ip6_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sw_interface_ip6_enable_disable));
      return -1;
    }
  if (vapi_calc_sw_interface_ip6_enable_disable_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_ip6_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sw_interface_ip6_enable_disable_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_sw_interface_ip6_enable_disable* vapi_alloc_sw_interface_ip6_enable_disable(struct vapi_ctx_s *ctx)
{
  vapi_msg_sw_interface_ip6_enable_disable *msg = NULL;
  const size_t size = sizeof(vapi_msg_sw_interface_ip6_enable_disable);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_sw_interface_ip6_enable_disable*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_sw_interface_ip6_enable_disable);

  return msg;
}

static inline vapi_error_e vapi_sw_interface_ip6_enable_disable(struct vapi_ctx_s *ctx,
  vapi_msg_sw_interface_ip6_enable_disable *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_sw_interface_ip6_enable_disable_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_sw_interface_ip6_enable_disable_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_sw_interface_ip6_enable_disable_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_sw_interface_ip6_enable_disable_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_sw_interface_ip6_enable_disable()
{
  static const char name[] = "sw_interface_ip6_enable_disable";
  static const char name_with_crc[] = "sw_interface_ip6_enable_disable_ae6cfcfb";
  static vapi_message_desc_t __vapi_metadata_sw_interface_ip6_enable_disable = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_sw_interface_ip6_enable_disable, payload),
    (verify_msg_size_fn_t)vapi_verify_sw_interface_ip6_enable_disable_msg_size,
    (generic_swap_fn_t)vapi_msg_sw_interface_ip6_enable_disable_hton,
    (generic_swap_fn_t)vapi_msg_sw_interface_ip6_enable_disable_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sw_interface_ip6_enable_disable = vapi_register_msg(&__vapi_metadata_sw_interface_ip6_enable_disable);
  VAPI_DBG("Assigned msg id %d to sw_interface_ip6_enable_disable", vapi_msg_id_sw_interface_ip6_enable_disable);
}
#endif

#ifndef defined_vapi_msg_sw_interface_ip4_enable_disable_reply
#define defined_vapi_msg_sw_interface_ip4_enable_disable_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_sw_interface_ip4_enable_disable_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_sw_interface_ip4_enable_disable_reply payload;
} vapi_msg_sw_interface_ip4_enable_disable_reply;

static inline void vapi_msg_sw_interface_ip4_enable_disable_reply_payload_hton(vapi_payload_sw_interface_ip4_enable_disable_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_sw_interface_ip4_enable_disable_reply_payload_ntoh(vapi_payload_sw_interface_ip4_enable_disable_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_sw_interface_ip4_enable_disable_reply_hton(vapi_msg_sw_interface_ip4_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_ip4_enable_disable_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_sw_interface_ip4_enable_disable_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_sw_interface_ip4_enable_disable_reply_ntoh(vapi_msg_sw_interface_ip4_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_ip4_enable_disable_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_sw_interface_ip4_enable_disable_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sw_interface_ip4_enable_disable_reply_msg_size(vapi_msg_sw_interface_ip4_enable_disable_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sw_interface_ip4_enable_disable_reply_msg_size(vapi_msg_sw_interface_ip4_enable_disable_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sw_interface_ip4_enable_disable_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_ip4_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sw_interface_ip4_enable_disable_reply));
      return -1;
    }
  if (vapi_calc_sw_interface_ip4_enable_disable_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_ip4_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sw_interface_ip4_enable_disable_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_sw_interface_ip4_enable_disable_reply()
{
  static const char name[] = "sw_interface_ip4_enable_disable_reply";
  static const char name_with_crc[] = "sw_interface_ip4_enable_disable_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_sw_interface_ip4_enable_disable_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_sw_interface_ip4_enable_disable_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_sw_interface_ip4_enable_disable_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_sw_interface_ip4_enable_disable_reply_hton,
    (generic_swap_fn_t)vapi_msg_sw_interface_ip4_enable_disable_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sw_interface_ip4_enable_disable_reply = vapi_register_msg(&__vapi_metadata_sw_interface_ip4_enable_disable_reply);
  VAPI_DBG("Assigned msg id %d to sw_interface_ip4_enable_disable_reply", vapi_msg_id_sw_interface_ip4_enable_disable_reply);
}

static inline void vapi_set_vapi_msg_sw_interface_ip4_enable_disable_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_sw_interface_ip4_enable_disable_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_sw_interface_ip4_enable_disable_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_sw_interface_ip4_enable_disable
#define defined_vapi_msg_sw_interface_ip4_enable_disable
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  bool enable; 
} vapi_payload_sw_interface_ip4_enable_disable;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_sw_interface_ip4_enable_disable payload;
} vapi_msg_sw_interface_ip4_enable_disable;

static inline void vapi_msg_sw_interface_ip4_enable_disable_payload_hton(vapi_payload_sw_interface_ip4_enable_disable *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_sw_interface_ip4_enable_disable_payload_ntoh(vapi_payload_sw_interface_ip4_enable_disable *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_sw_interface_ip4_enable_disable_hton(vapi_msg_sw_interface_ip4_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_ip4_enable_disable'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_sw_interface_ip4_enable_disable_payload_hton(&msg->payload);
}

static inline void vapi_msg_sw_interface_ip4_enable_disable_ntoh(vapi_msg_sw_interface_ip4_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_ip4_enable_disable'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_sw_interface_ip4_enable_disable_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sw_interface_ip4_enable_disable_msg_size(vapi_msg_sw_interface_ip4_enable_disable *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sw_interface_ip4_enable_disable_msg_size(vapi_msg_sw_interface_ip4_enable_disable *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sw_interface_ip4_enable_disable) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_ip4_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sw_interface_ip4_enable_disable));
      return -1;
    }
  if (vapi_calc_sw_interface_ip4_enable_disable_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_ip4_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sw_interface_ip4_enable_disable_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_sw_interface_ip4_enable_disable* vapi_alloc_sw_interface_ip4_enable_disable(struct vapi_ctx_s *ctx)
{
  vapi_msg_sw_interface_ip4_enable_disable *msg = NULL;
  const size_t size = sizeof(vapi_msg_sw_interface_ip4_enable_disable);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_sw_interface_ip4_enable_disable*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_sw_interface_ip4_enable_disable);

  return msg;
}

static inline vapi_error_e vapi_sw_interface_ip4_enable_disable(struct vapi_ctx_s *ctx,
  vapi_msg_sw_interface_ip4_enable_disable *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_sw_interface_ip4_enable_disable_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_sw_interface_ip4_enable_disable_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_sw_interface_ip4_enable_disable_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_sw_interface_ip4_enable_disable_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_sw_interface_ip4_enable_disable()
{
  static const char name[] = "sw_interface_ip4_enable_disable";
  static const char name_with_crc[] = "sw_interface_ip4_enable_disable_ae6cfcfb";
  static vapi_message_desc_t __vapi_metadata_sw_interface_ip4_enable_disable = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_sw_interface_ip4_enable_disable, payload),
    (verify_msg_size_fn_t)vapi_verify_sw_interface_ip4_enable_disable_msg_size,
    (generic_swap_fn_t)vapi_msg_sw_interface_ip4_enable_disable_hton,
    (generic_swap_fn_t)vapi_msg_sw_interface_ip4_enable_disable_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sw_interface_ip4_enable_disable = vapi_register_msg(&__vapi_metadata_sw_interface_ip4_enable_disable);
  VAPI_DBG("Assigned msg id %d to sw_interface_ip4_enable_disable", vapi_msg_id_sw_interface_ip4_enable_disable);
}
#endif

#ifndef defined_vapi_msg_ip_mtable_details
#define defined_vapi_msg_ip_mtable_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip_table table; 
} vapi_payload_ip_mtable_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip_mtable_details payload;
} vapi_msg_ip_mtable_details;

static inline void vapi_msg_ip_mtable_details_payload_hton(vapi_payload_ip_mtable_details *payload)
{
  vapi_type_ip_table_hton(&payload->table);
}

static inline void vapi_msg_ip_mtable_details_payload_ntoh(vapi_payload_ip_mtable_details *payload)
{
  vapi_type_ip_table_ntoh(&payload->table);
}

static inline void vapi_msg_ip_mtable_details_hton(vapi_msg_ip_mtable_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_mtable_details'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip_mtable_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_mtable_details_ntoh(vapi_msg_ip_mtable_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_mtable_details'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip_mtable_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_mtable_details_msg_size(vapi_msg_ip_mtable_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_mtable_details_msg_size(vapi_msg_ip_mtable_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_mtable_details) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_mtable_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_mtable_details));
      return -1;
    }
  if (vapi_calc_ip_mtable_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_mtable_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_mtable_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_mtable_details()
{
  static const char name[] = "ip_mtable_details";
  static const char name_with_crc[] = "ip_mtable_details_b9d2e09e";
  static vapi_message_desc_t __vapi_metadata_ip_mtable_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip_mtable_details, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_mtable_details_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_mtable_details_hton,
    (generic_swap_fn_t)vapi_msg_ip_mtable_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_mtable_details = vapi_register_msg(&__vapi_metadata_ip_mtable_details);
  VAPI_DBG("Assigned msg id %d to ip_mtable_details", vapi_msg_id_ip_mtable_details);
}

static inline void vapi_set_vapi_msg_ip_mtable_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_mtable_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_mtable_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_mtable_dump
#define defined_vapi_msg_ip_mtable_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_ip_mtable_dump;

static inline void vapi_msg_ip_mtable_dump_hton(vapi_msg_ip_mtable_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_mtable_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_ip_mtable_dump_ntoh(vapi_msg_ip_mtable_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_mtable_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_ip_mtable_dump_msg_size(vapi_msg_ip_mtable_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_mtable_dump_msg_size(vapi_msg_ip_mtable_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_mtable_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_mtable_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_mtable_dump));
      return -1;
    }
  if (vapi_calc_ip_mtable_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_mtable_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_mtable_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_mtable_dump* vapi_alloc_ip_mtable_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_mtable_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_mtable_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_mtable_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_mtable_dump);

  return msg;
}

static inline vapi_error_e vapi_ip_mtable_dump(struct vapi_ctx_s *ctx,
  vapi_msg_ip_mtable_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_mtable_details *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ip_mtable_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_mtable_details, VAPI_REQUEST_DUMP, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ip_mtable_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_mtable_dump()
{
  static const char name[] = "ip_mtable_dump";
  static const char name_with_crc[] = "ip_mtable_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_ip_mtable_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_ip_mtable_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_mtable_dump_hton,
    (generic_swap_fn_t)vapi_msg_ip_mtable_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_mtable_dump = vapi_register_msg(&__vapi_metadata_ip_mtable_dump);
  VAPI_DBG("Assigned msg id %d to ip_mtable_dump", vapi_msg_id_ip_mtable_dump);
}
#endif

#ifndef defined_vapi_msg_ip_mroute_add_del_reply
#define defined_vapi_msg_ip_mroute_add_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 stats_index; 
} vapi_payload_ip_mroute_add_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_mroute_add_del_reply payload;
} vapi_msg_ip_mroute_add_del_reply;

static inline void vapi_msg_ip_mroute_add_del_reply_payload_hton(vapi_payload_ip_mroute_add_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->stats_index = htobe32(payload->stats_index);
}

static inline void vapi_msg_ip_mroute_add_del_reply_payload_ntoh(vapi_payload_ip_mroute_add_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->stats_index = be32toh(payload->stats_index);
}

static inline void vapi_msg_ip_mroute_add_del_reply_hton(vapi_msg_ip_mroute_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_mroute_add_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_mroute_add_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_mroute_add_del_reply_ntoh(vapi_msg_ip_mroute_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_mroute_add_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_mroute_add_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_mroute_add_del_reply_msg_size(vapi_msg_ip_mroute_add_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_mroute_add_del_reply_msg_size(vapi_msg_ip_mroute_add_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_mroute_add_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_mroute_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_mroute_add_del_reply));
      return -1;
    }
  if (vapi_calc_ip_mroute_add_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_mroute_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_mroute_add_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_mroute_add_del_reply()
{
  static const char name[] = "ip_mroute_add_del_reply";
  static const char name_with_crc[] = "ip_mroute_add_del_reply_1992deab";
  static vapi_message_desc_t __vapi_metadata_ip_mroute_add_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_mroute_add_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_mroute_add_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_mroute_add_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_ip_mroute_add_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_mroute_add_del_reply = vapi_register_msg(&__vapi_metadata_ip_mroute_add_del_reply);
  VAPI_DBG("Assigned msg id %d to ip_mroute_add_del_reply", vapi_msg_id_ip_mroute_add_del_reply);
}

static inline void vapi_set_vapi_msg_ip_mroute_add_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_mroute_add_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_mroute_add_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_mroute_add_del
#define defined_vapi_msg_ip_mroute_add_del
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  bool is_multipath;
  vapi_type_ip_mroute route; 
} vapi_payload_ip_mroute_add_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip_mroute_add_del payload;
} vapi_msg_ip_mroute_add_del;

static inline void vapi_msg_ip_mroute_add_del_payload_hton(vapi_payload_ip_mroute_add_del *payload)
{
  vapi_type_ip_mroute_hton(&payload->route);
}

static inline void vapi_msg_ip_mroute_add_del_payload_ntoh(vapi_payload_ip_mroute_add_del *payload)
{
  vapi_type_ip_mroute_ntoh(&payload->route);
}

static inline void vapi_msg_ip_mroute_add_del_hton(vapi_msg_ip_mroute_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_mroute_add_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip_mroute_add_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_mroute_add_del_ntoh(vapi_msg_ip_mroute_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_mroute_add_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip_mroute_add_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_mroute_add_del_msg_size(vapi_msg_ip_mroute_add_del *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.route.paths[0]) * msg->payload.route.n_paths;
}

static inline int vapi_verify_ip_mroute_add_del_msg_size(vapi_msg_ip_mroute_add_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_mroute_add_del) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_mroute_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_mroute_add_del));
      return -1;
    }
  if (vapi_calc_ip_mroute_add_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_mroute_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_mroute_add_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_mroute_add_del* vapi_alloc_ip_mroute_add_del(struct vapi_ctx_s *ctx, size_t route_paths_array_size)
{
  vapi_msg_ip_mroute_add_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_mroute_add_del) + sizeof(msg->payload.route.paths[0]) * route_paths_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_mroute_add_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_mroute_add_del);
  msg->payload.route.n_paths = route_paths_array_size;

  return msg;
}

static inline vapi_error_e vapi_ip_mroute_add_del(struct vapi_ctx_s *ctx,
  vapi_msg_ip_mroute_add_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_mroute_add_del_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ip_mroute_add_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_mroute_add_del_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ip_mroute_add_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_mroute_add_del()
{
  static const char name[] = "ip_mroute_add_del";
  static const char name_with_crc[] = "ip_mroute_add_del_0dd7e790";
  static vapi_message_desc_t __vapi_metadata_ip_mroute_add_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip_mroute_add_del, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_mroute_add_del_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_mroute_add_del_hton,
    (generic_swap_fn_t)vapi_msg_ip_mroute_add_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_mroute_add_del = vapi_register_msg(&__vapi_metadata_ip_mroute_add_del);
  VAPI_DBG("Assigned msg id %d to ip_mroute_add_del", vapi_msg_id_ip_mroute_add_del);
}
#endif

#ifndef defined_vapi_msg_ip_mroute_details
#define defined_vapi_msg_ip_mroute_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip_mroute route; 
} vapi_payload_ip_mroute_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_mroute_details payload;
} vapi_msg_ip_mroute_details;

static inline void vapi_msg_ip_mroute_details_payload_hton(vapi_payload_ip_mroute_details *payload)
{
  vapi_type_ip_mroute_hton(&payload->route);
}

static inline void vapi_msg_ip_mroute_details_payload_ntoh(vapi_payload_ip_mroute_details *payload)
{
  vapi_type_ip_mroute_ntoh(&payload->route);
}

static inline void vapi_msg_ip_mroute_details_hton(vapi_msg_ip_mroute_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_mroute_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_mroute_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_mroute_details_ntoh(vapi_msg_ip_mroute_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_mroute_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_mroute_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_mroute_details_msg_size(vapi_msg_ip_mroute_details *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.route.paths[0]) * msg->payload.route.n_paths;
}

static inline int vapi_verify_ip_mroute_details_msg_size(vapi_msg_ip_mroute_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_mroute_details) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_mroute_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_mroute_details));
      return -1;
    }
  if (vapi_calc_ip_mroute_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_mroute_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_mroute_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_mroute_details()
{
  static const char name[] = "ip_mroute_details";
  static const char name_with_crc[] = "ip_mroute_details_c5cb23fc";
  static vapi_message_desc_t __vapi_metadata_ip_mroute_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_mroute_details, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_mroute_details_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_mroute_details_hton,
    (generic_swap_fn_t)vapi_msg_ip_mroute_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_mroute_details = vapi_register_msg(&__vapi_metadata_ip_mroute_details);
  VAPI_DBG("Assigned msg id %d to ip_mroute_details", vapi_msg_id_ip_mroute_details);
}

static inline void vapi_set_vapi_msg_ip_mroute_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_mroute_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_mroute_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_mroute_dump
#define defined_vapi_msg_ip_mroute_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip_table table; 
} vapi_payload_ip_mroute_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip_mroute_dump payload;
} vapi_msg_ip_mroute_dump;

static inline void vapi_msg_ip_mroute_dump_payload_hton(vapi_payload_ip_mroute_dump *payload)
{
  vapi_type_ip_table_hton(&payload->table);
}

static inline void vapi_msg_ip_mroute_dump_payload_ntoh(vapi_payload_ip_mroute_dump *payload)
{
  vapi_type_ip_table_ntoh(&payload->table);
}

static inline void vapi_msg_ip_mroute_dump_hton(vapi_msg_ip_mroute_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_mroute_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip_mroute_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_mroute_dump_ntoh(vapi_msg_ip_mroute_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_mroute_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip_mroute_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_mroute_dump_msg_size(vapi_msg_ip_mroute_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_mroute_dump_msg_size(vapi_msg_ip_mroute_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_mroute_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_mroute_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_mroute_dump));
      return -1;
    }
  if (vapi_calc_ip_mroute_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_mroute_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_mroute_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_mroute_dump* vapi_alloc_ip_mroute_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_mroute_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_mroute_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_mroute_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_mroute_dump);

  return msg;
}

static inline vapi_error_e vapi_ip_mroute_dump(struct vapi_ctx_s *ctx,
  vapi_msg_ip_mroute_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_mroute_details *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ip_mroute_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_mroute_details, VAPI_REQUEST_DUMP, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ip_mroute_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_mroute_dump()
{
  static const char name[] = "ip_mroute_dump";
  static const char name_with_crc[] = "ip_mroute_dump_b9d2e09e";
  static vapi_message_desc_t __vapi_metadata_ip_mroute_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip_mroute_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_mroute_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_mroute_dump_hton,
    (generic_swap_fn_t)vapi_msg_ip_mroute_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_mroute_dump = vapi_register_msg(&__vapi_metadata_ip_mroute_dump);
  VAPI_DBG("Assigned msg id %d to ip_mroute_dump", vapi_msg_id_ip_mroute_dump);
}
#endif

#ifndef defined_vapi_msg_ip_address_details
#define defined_vapi_msg_ip_address_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  vapi_type_address_with_prefix prefix; 
} vapi_payload_ip_address_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_address_details payload;
} vapi_msg_ip_address_details;

static inline void vapi_msg_ip_address_details_payload_hton(vapi_payload_ip_address_details *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_ip_address_details_payload_ntoh(vapi_payload_ip_address_details *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_ip_address_details_hton(vapi_msg_ip_address_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_address_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_address_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_address_details_ntoh(vapi_msg_ip_address_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_address_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_address_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_address_details_msg_size(vapi_msg_ip_address_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_address_details_msg_size(vapi_msg_ip_address_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_address_details) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_address_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_address_details));
      return -1;
    }
  if (vapi_calc_ip_address_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_address_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_address_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_address_details()
{
  static const char name[] = "ip_address_details";
  static const char name_with_crc[] = "ip_address_details_ee29b797";
  static vapi_message_desc_t __vapi_metadata_ip_address_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_address_details, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_address_details_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_address_details_hton,
    (generic_swap_fn_t)vapi_msg_ip_address_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_address_details = vapi_register_msg(&__vapi_metadata_ip_address_details);
  VAPI_DBG("Assigned msg id %d to ip_address_details", vapi_msg_id_ip_address_details);
}

static inline void vapi_set_vapi_msg_ip_address_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_address_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_address_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_address_dump
#define defined_vapi_msg_ip_address_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  bool is_ipv6; 
} vapi_payload_ip_address_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip_address_dump payload;
} vapi_msg_ip_address_dump;

static inline void vapi_msg_ip_address_dump_payload_hton(vapi_payload_ip_address_dump *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_ip_address_dump_payload_ntoh(vapi_payload_ip_address_dump *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_ip_address_dump_hton(vapi_msg_ip_address_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_address_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip_address_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_address_dump_ntoh(vapi_msg_ip_address_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_address_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip_address_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_address_dump_msg_size(vapi_msg_ip_address_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_address_dump_msg_size(vapi_msg_ip_address_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_address_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_address_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_address_dump));
      return -1;
    }
  if (vapi_calc_ip_address_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_address_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_address_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_address_dump* vapi_alloc_ip_address_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_address_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_address_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_address_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_address_dump);

  return msg;
}

static inline vapi_error_e vapi_ip_address_dump(struct vapi_ctx_s *ctx,
  vapi_msg_ip_address_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_address_details *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ip_address_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_address_details, VAPI_REQUEST_DUMP, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ip_address_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_address_dump()
{
  static const char name[] = "ip_address_dump";
  static const char name_with_crc[] = "ip_address_dump_2d033de4";
  static vapi_message_desc_t __vapi_metadata_ip_address_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip_address_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_address_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_address_dump_hton,
    (generic_swap_fn_t)vapi_msg_ip_address_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_address_dump = vapi_register_msg(&__vapi_metadata_ip_address_dump);
  VAPI_DBG("Assigned msg id %d to ip_address_dump", vapi_msg_id_ip_address_dump);
}
#endif

#ifndef defined_vapi_msg_ip_unnumbered_details
#define defined_vapi_msg_ip_unnumbered_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  vapi_type_interface_index ip_sw_if_index; 
} vapi_payload_ip_unnumbered_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_unnumbered_details payload;
} vapi_msg_ip_unnumbered_details;

static inline void vapi_msg_ip_unnumbered_details_payload_hton(vapi_payload_ip_unnumbered_details *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->ip_sw_if_index = htobe32(payload->ip_sw_if_index);
}

static inline void vapi_msg_ip_unnumbered_details_payload_ntoh(vapi_payload_ip_unnumbered_details *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->ip_sw_if_index = be32toh(payload->ip_sw_if_index);
}

static inline void vapi_msg_ip_unnumbered_details_hton(vapi_msg_ip_unnumbered_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_unnumbered_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_unnumbered_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_unnumbered_details_ntoh(vapi_msg_ip_unnumbered_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_unnumbered_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_unnumbered_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_unnumbered_details_msg_size(vapi_msg_ip_unnumbered_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_unnumbered_details_msg_size(vapi_msg_ip_unnumbered_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_unnumbered_details) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_unnumbered_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_unnumbered_details));
      return -1;
    }
  if (vapi_calc_ip_unnumbered_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_unnumbered_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_unnumbered_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_unnumbered_details()
{
  static const char name[] = "ip_unnumbered_details";
  static const char name_with_crc[] = "ip_unnumbered_details_cc59bd42";
  static vapi_message_desc_t __vapi_metadata_ip_unnumbered_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_unnumbered_details, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_unnumbered_details_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_unnumbered_details_hton,
    (generic_swap_fn_t)vapi_msg_ip_unnumbered_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_unnumbered_details = vapi_register_msg(&__vapi_metadata_ip_unnumbered_details);
  VAPI_DBG("Assigned msg id %d to ip_unnumbered_details", vapi_msg_id_ip_unnumbered_details);
}

static inline void vapi_set_vapi_msg_ip_unnumbered_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_unnumbered_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_unnumbered_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_unnumbered_dump
#define defined_vapi_msg_ip_unnumbered_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index; 
} vapi_payload_ip_unnumbered_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip_unnumbered_dump payload;
} vapi_msg_ip_unnumbered_dump;

static inline void vapi_msg_ip_unnumbered_dump_payload_hton(vapi_payload_ip_unnumbered_dump *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_ip_unnumbered_dump_payload_ntoh(vapi_payload_ip_unnumbered_dump *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_ip_unnumbered_dump_hton(vapi_msg_ip_unnumbered_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_unnumbered_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip_unnumbered_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_unnumbered_dump_ntoh(vapi_msg_ip_unnumbered_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_unnumbered_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip_unnumbered_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_unnumbered_dump_msg_size(vapi_msg_ip_unnumbered_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_unnumbered_dump_msg_size(vapi_msg_ip_unnumbered_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_unnumbered_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_unnumbered_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_unnumbered_dump));
      return -1;
    }
  if (vapi_calc_ip_unnumbered_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_unnumbered_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_unnumbered_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_unnumbered_dump* vapi_alloc_ip_unnumbered_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_unnumbered_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_unnumbered_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_unnumbered_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_unnumbered_dump);

  return msg;
}

static inline vapi_error_e vapi_ip_unnumbered_dump(struct vapi_ctx_s *ctx,
  vapi_msg_ip_unnumbered_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_unnumbered_details *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ip_unnumbered_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_unnumbered_details, VAPI_REQUEST_DUMP, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ip_unnumbered_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_unnumbered_dump()
{
  static const char name[] = "ip_unnumbered_dump";
  static const char name_with_crc[] = "ip_unnumbered_dump_f9e6675e";
  static vapi_message_desc_t __vapi_metadata_ip_unnumbered_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip_unnumbered_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_unnumbered_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_unnumbered_dump_hton,
    (generic_swap_fn_t)vapi_msg_ip_unnumbered_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_unnumbered_dump = vapi_register_msg(&__vapi_metadata_ip_unnumbered_dump);
  VAPI_DBG("Assigned msg id %d to ip_unnumbered_dump", vapi_msg_id_ip_unnumbered_dump);
}
#endif

#ifndef defined_vapi_msg_ip_details
#define defined_vapi_msg_ip_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  bool is_ipv6; 
} vapi_payload_ip_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_details payload;
} vapi_msg_ip_details;

static inline void vapi_msg_ip_details_payload_hton(vapi_payload_ip_details *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_ip_details_payload_ntoh(vapi_payload_ip_details *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_ip_details_hton(vapi_msg_ip_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_details_ntoh(vapi_msg_ip_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_details_msg_size(vapi_msg_ip_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_details_msg_size(vapi_msg_ip_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_details) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_details));
      return -1;
    }
  if (vapi_calc_ip_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_details()
{
  static const char name[] = "ip_details";
  static const char name_with_crc[] = "ip_details_eb152d07";
  static vapi_message_desc_t __vapi_metadata_ip_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_details, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_details_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_details_hton,
    (generic_swap_fn_t)vapi_msg_ip_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_details = vapi_register_msg(&__vapi_metadata_ip_details);
  VAPI_DBG("Assigned msg id %d to ip_details", vapi_msg_id_ip_details);
}

static inline void vapi_set_vapi_msg_ip_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_dump
#define defined_vapi_msg_ip_dump
typedef struct __attribute__ ((__packed__)) {
  bool is_ipv6; 
} vapi_payload_ip_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip_dump payload;
} vapi_msg_ip_dump;

static inline void vapi_msg_ip_dump_payload_hton(vapi_payload_ip_dump *payload)
{

}

static inline void vapi_msg_ip_dump_payload_ntoh(vapi_payload_ip_dump *payload)
{

}

static inline void vapi_msg_ip_dump_hton(vapi_msg_ip_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_dump_ntoh(vapi_msg_ip_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_dump_msg_size(vapi_msg_ip_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_dump_msg_size(vapi_msg_ip_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_dump));
      return -1;
    }
  if (vapi_calc_ip_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_dump* vapi_alloc_ip_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_dump);

  return msg;
}

static inline vapi_error_e vapi_ip_dump(struct vapi_ctx_s *ctx,
  vapi_msg_ip_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_details *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ip_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_details, VAPI_REQUEST_DUMP, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ip_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_dump()
{
  static const char name[] = "ip_dump";
  static const char name_with_crc[] = "ip_dump_98d231ca";
  static vapi_message_desc_t __vapi_metadata_ip_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_dump_hton,
    (generic_swap_fn_t)vapi_msg_ip_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_dump = vapi_register_msg(&__vapi_metadata_ip_dump);
  VAPI_DBG("Assigned msg id %d to ip_dump", vapi_msg_id_ip_dump);
}
#endif

#ifndef defined_vapi_msg_mfib_signal_details
#define defined_vapi_msg_mfib_signal_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  u32 table_id;
  vapi_type_mprefix prefix;
  u16 ip_packet_len;
  u8 ip_packet_data[256]; 
} vapi_payload_mfib_signal_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_mfib_signal_details payload;
} vapi_msg_mfib_signal_details;

static inline void vapi_msg_mfib_signal_details_payload_hton(vapi_payload_mfib_signal_details *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->table_id = htobe32(payload->table_id);
  vapi_type_mprefix_hton(&payload->prefix);
  payload->ip_packet_len = htobe16(payload->ip_packet_len);
}

static inline void vapi_msg_mfib_signal_details_payload_ntoh(vapi_payload_mfib_signal_details *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->table_id = be32toh(payload->table_id);
  vapi_type_mprefix_ntoh(&payload->prefix);
  payload->ip_packet_len = be16toh(payload->ip_packet_len);
}

static inline void vapi_msg_mfib_signal_details_hton(vapi_msg_mfib_signal_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_mfib_signal_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_mfib_signal_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_mfib_signal_details_ntoh(vapi_msg_mfib_signal_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_mfib_signal_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_mfib_signal_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_mfib_signal_details_msg_size(vapi_msg_mfib_signal_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_mfib_signal_details_msg_size(vapi_msg_mfib_signal_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_mfib_signal_details) > buf_size)
    {
      VAPI_ERR("Truncated 'mfib_signal_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_mfib_signal_details));
      return -1;
    }
  if (vapi_calc_mfib_signal_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'mfib_signal_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_mfib_signal_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_mfib_signal_details()
{
  static const char name[] = "mfib_signal_details";
  static const char name_with_crc[] = "mfib_signal_details_6f4a4cfb";
  static vapi_message_desc_t __vapi_metadata_mfib_signal_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_mfib_signal_details, payload),
    (verify_msg_size_fn_t)vapi_verify_mfib_signal_details_msg_size,
    (generic_swap_fn_t)vapi_msg_mfib_signal_details_hton,
    (generic_swap_fn_t)vapi_msg_mfib_signal_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_mfib_signal_details = vapi_register_msg(&__vapi_metadata_mfib_signal_details);
  VAPI_DBG("Assigned msg id %d to mfib_signal_details", vapi_msg_id_mfib_signal_details);
}

static inline void vapi_set_vapi_msg_mfib_signal_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_mfib_signal_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_mfib_signal_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_mfib_signal_dump
#define defined_vapi_msg_mfib_signal_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_mfib_signal_dump;

static inline void vapi_msg_mfib_signal_dump_hton(vapi_msg_mfib_signal_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_mfib_signal_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_mfib_signal_dump_ntoh(vapi_msg_mfib_signal_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_mfib_signal_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_mfib_signal_dump_msg_size(vapi_msg_mfib_signal_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_mfib_signal_dump_msg_size(vapi_msg_mfib_signal_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_mfib_signal_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'mfib_signal_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_mfib_signal_dump));
      return -1;
    }
  if (vapi_calc_mfib_signal_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'mfib_signal_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_mfib_signal_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_mfib_signal_dump* vapi_alloc_mfib_signal_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_mfib_signal_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_mfib_signal_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_mfib_signal_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_mfib_signal_dump);

  return msg;
}

static inline vapi_error_e vapi_mfib_signal_dump(struct vapi_ctx_s *ctx,
  vapi_msg_mfib_signal_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_mfib_signal_details *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_mfib_signal_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_mfib_signal_details, VAPI_REQUEST_DUMP, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_mfib_signal_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_mfib_signal_dump()
{
  static const char name[] = "mfib_signal_dump";
  static const char name_with_crc[] = "mfib_signal_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_mfib_signal_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_mfib_signal_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_mfib_signal_dump_hton,
    (generic_swap_fn_t)vapi_msg_mfib_signal_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_mfib_signal_dump = vapi_register_msg(&__vapi_metadata_mfib_signal_dump);
  VAPI_DBG("Assigned msg id %d to mfib_signal_dump", vapi_msg_id_mfib_signal_dump);
}
#endif

#ifndef defined_vapi_msg_ip_punt_police_reply
#define defined_vapi_msg_ip_punt_police_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ip_punt_police_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_punt_police_reply payload;
} vapi_msg_ip_punt_police_reply;

static inline void vapi_msg_ip_punt_police_reply_payload_hton(vapi_payload_ip_punt_police_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ip_punt_police_reply_payload_ntoh(vapi_payload_ip_punt_police_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ip_punt_police_reply_hton(vapi_msg_ip_punt_police_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_punt_police_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_punt_police_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_punt_police_reply_ntoh(vapi_msg_ip_punt_police_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_punt_police_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_punt_police_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_punt_police_reply_msg_size(vapi_msg_ip_punt_police_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_punt_police_reply_msg_size(vapi_msg_ip_punt_police_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_punt_police_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_punt_police_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_punt_police_reply));
      return -1;
    }
  if (vapi_calc_ip_punt_police_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_punt_police_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_punt_police_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_punt_police_reply()
{
  static const char name[] = "ip_punt_police_reply";
  static const char name_with_crc[] = "ip_punt_police_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ip_punt_police_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_punt_police_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_punt_police_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_punt_police_reply_hton,
    (generic_swap_fn_t)vapi_msg_ip_punt_police_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_punt_police_reply = vapi_register_msg(&__vapi_metadata_ip_punt_police_reply);
  VAPI_DBG("Assigned msg id %d to ip_punt_police_reply", vapi_msg_id_ip_punt_police_reply);
}

static inline void vapi_set_vapi_msg_ip_punt_police_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_punt_police_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_punt_police_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_punt_police
#define defined_vapi_msg_ip_punt_police
typedef struct __attribute__ ((__packed__)) {
  u32 policer_index;
  bool is_add;
  bool is_ip6; 
} vapi_payload_ip_punt_police;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip_punt_police payload;
} vapi_msg_ip_punt_police;

static inline void vapi_msg_ip_punt_police_payload_hton(vapi_payload_ip_punt_police *payload)
{
  payload->policer_index = htobe32(payload->policer_index);
}

static inline void vapi_msg_ip_punt_police_payload_ntoh(vapi_payload_ip_punt_police *payload)
{
  payload->policer_index = be32toh(payload->policer_index);
}

static inline void vapi_msg_ip_punt_police_hton(vapi_msg_ip_punt_police *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_punt_police'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip_punt_police_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_punt_police_ntoh(vapi_msg_ip_punt_police *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_punt_police'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip_punt_police_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_punt_police_msg_size(vapi_msg_ip_punt_police *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_punt_police_msg_size(vapi_msg_ip_punt_police *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_punt_police) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_punt_police' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_punt_police));
      return -1;
    }
  if (vapi_calc_ip_punt_police_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_punt_police' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_punt_police_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_punt_police* vapi_alloc_ip_punt_police(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_punt_police *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_punt_police);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_punt_police*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_punt_police);

  return msg;
}

static inline vapi_error_e vapi_ip_punt_police(struct vapi_ctx_s *ctx,
  vapi_msg_ip_punt_police *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_punt_police_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ip_punt_police_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_punt_police_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ip_punt_police_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_punt_police()
{
  static const char name[] = "ip_punt_police";
  static const char name_with_crc[] = "ip_punt_police_db867cea";
  static vapi_message_desc_t __vapi_metadata_ip_punt_police = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip_punt_police, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_punt_police_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_punt_police_hton,
    (generic_swap_fn_t)vapi_msg_ip_punt_police_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_punt_police = vapi_register_msg(&__vapi_metadata_ip_punt_police);
  VAPI_DBG("Assigned msg id %d to ip_punt_police", vapi_msg_id_ip_punt_police);
}
#endif

#ifndef defined_vapi_msg_ip_punt_redirect_reply
#define defined_vapi_msg_ip_punt_redirect_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ip_punt_redirect_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_punt_redirect_reply payload;
} vapi_msg_ip_punt_redirect_reply;

static inline void vapi_msg_ip_punt_redirect_reply_payload_hton(vapi_payload_ip_punt_redirect_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ip_punt_redirect_reply_payload_ntoh(vapi_payload_ip_punt_redirect_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ip_punt_redirect_reply_hton(vapi_msg_ip_punt_redirect_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_punt_redirect_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_punt_redirect_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_punt_redirect_reply_ntoh(vapi_msg_ip_punt_redirect_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_punt_redirect_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_punt_redirect_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_punt_redirect_reply_msg_size(vapi_msg_ip_punt_redirect_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_punt_redirect_reply_msg_size(vapi_msg_ip_punt_redirect_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_punt_redirect_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_punt_redirect_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_punt_redirect_reply));
      return -1;
    }
  if (vapi_calc_ip_punt_redirect_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_punt_redirect_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_punt_redirect_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_punt_redirect_reply()
{
  static const char name[] = "ip_punt_redirect_reply";
  static const char name_with_crc[] = "ip_punt_redirect_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ip_punt_redirect_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_punt_redirect_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_punt_redirect_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_punt_redirect_reply_hton,
    (generic_swap_fn_t)vapi_msg_ip_punt_redirect_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_punt_redirect_reply = vapi_register_msg(&__vapi_metadata_ip_punt_redirect_reply);
  VAPI_DBG("Assigned msg id %d to ip_punt_redirect_reply", vapi_msg_id_ip_punt_redirect_reply);
}

static inline void vapi_set_vapi_msg_ip_punt_redirect_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_punt_redirect_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_punt_redirect_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_punt_redirect
#define defined_vapi_msg_ip_punt_redirect
typedef struct __attribute__ ((__packed__)) {
  vapi_type_punt_redirect punt;
  bool is_add; 
} vapi_payload_ip_punt_redirect;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip_punt_redirect payload;
} vapi_msg_ip_punt_redirect;

static inline void vapi_msg_ip_punt_redirect_payload_hton(vapi_payload_ip_punt_redirect *payload)
{
  vapi_type_punt_redirect_hton(&payload->punt);
}

static inline void vapi_msg_ip_punt_redirect_payload_ntoh(vapi_payload_ip_punt_redirect *payload)
{
  vapi_type_punt_redirect_ntoh(&payload->punt);
}

static inline void vapi_msg_ip_punt_redirect_hton(vapi_msg_ip_punt_redirect *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_punt_redirect'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip_punt_redirect_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_punt_redirect_ntoh(vapi_msg_ip_punt_redirect *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_punt_redirect'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip_punt_redirect_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_punt_redirect_msg_size(vapi_msg_ip_punt_redirect *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_punt_redirect_msg_size(vapi_msg_ip_punt_redirect *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_punt_redirect) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_punt_redirect' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_punt_redirect));
      return -1;
    }
  if (vapi_calc_ip_punt_redirect_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_punt_redirect' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_punt_redirect_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_punt_redirect* vapi_alloc_ip_punt_redirect(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_punt_redirect *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_punt_redirect);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_punt_redirect*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_punt_redirect);

  return msg;
}

static inline vapi_error_e vapi_ip_punt_redirect(struct vapi_ctx_s *ctx,
  vapi_msg_ip_punt_redirect *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_punt_redirect_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ip_punt_redirect_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_punt_redirect_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ip_punt_redirect_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_punt_redirect()
{
  static const char name[] = "ip_punt_redirect";
  static const char name_with_crc[] = "ip_punt_redirect_6580f635";
  static vapi_message_desc_t __vapi_metadata_ip_punt_redirect = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip_punt_redirect, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_punt_redirect_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_punt_redirect_hton,
    (generic_swap_fn_t)vapi_msg_ip_punt_redirect_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_punt_redirect = vapi_register_msg(&__vapi_metadata_ip_punt_redirect);
  VAPI_DBG("Assigned msg id %d to ip_punt_redirect", vapi_msg_id_ip_punt_redirect);
}
#endif

#ifndef defined_vapi_msg_ip_punt_redirect_details
#define defined_vapi_msg_ip_punt_redirect_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_punt_redirect punt; 
} vapi_payload_ip_punt_redirect_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_punt_redirect_details payload;
} vapi_msg_ip_punt_redirect_details;

static inline void vapi_msg_ip_punt_redirect_details_payload_hton(vapi_payload_ip_punt_redirect_details *payload)
{
  vapi_type_punt_redirect_hton(&payload->punt);
}

static inline void vapi_msg_ip_punt_redirect_details_payload_ntoh(vapi_payload_ip_punt_redirect_details *payload)
{
  vapi_type_punt_redirect_ntoh(&payload->punt);
}

static inline void vapi_msg_ip_punt_redirect_details_hton(vapi_msg_ip_punt_redirect_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_punt_redirect_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_punt_redirect_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_punt_redirect_details_ntoh(vapi_msg_ip_punt_redirect_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_punt_redirect_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_punt_redirect_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_punt_redirect_details_msg_size(vapi_msg_ip_punt_redirect_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_punt_redirect_details_msg_size(vapi_msg_ip_punt_redirect_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_punt_redirect_details) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_punt_redirect_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_punt_redirect_details));
      return -1;
    }
  if (vapi_calc_ip_punt_redirect_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_punt_redirect_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_punt_redirect_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_punt_redirect_details()
{
  static const char name[] = "ip_punt_redirect_details";
  static const char name_with_crc[] = "ip_punt_redirect_details_2cef63e7";
  static vapi_message_desc_t __vapi_metadata_ip_punt_redirect_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_punt_redirect_details, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_punt_redirect_details_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_punt_redirect_details_hton,
    (generic_swap_fn_t)vapi_msg_ip_punt_redirect_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_punt_redirect_details = vapi_register_msg(&__vapi_metadata_ip_punt_redirect_details);
  VAPI_DBG("Assigned msg id %d to ip_punt_redirect_details", vapi_msg_id_ip_punt_redirect_details);
}

static inline void vapi_set_vapi_msg_ip_punt_redirect_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_punt_redirect_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_punt_redirect_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_punt_redirect_dump
#define defined_vapi_msg_ip_punt_redirect_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  bool is_ipv6; 
} vapi_payload_ip_punt_redirect_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip_punt_redirect_dump payload;
} vapi_msg_ip_punt_redirect_dump;

static inline void vapi_msg_ip_punt_redirect_dump_payload_hton(vapi_payload_ip_punt_redirect_dump *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_ip_punt_redirect_dump_payload_ntoh(vapi_payload_ip_punt_redirect_dump *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_ip_punt_redirect_dump_hton(vapi_msg_ip_punt_redirect_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_punt_redirect_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip_punt_redirect_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_punt_redirect_dump_ntoh(vapi_msg_ip_punt_redirect_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_punt_redirect_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip_punt_redirect_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_punt_redirect_dump_msg_size(vapi_msg_ip_punt_redirect_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_punt_redirect_dump_msg_size(vapi_msg_ip_punt_redirect_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_punt_redirect_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_punt_redirect_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_punt_redirect_dump));
      return -1;
    }
  if (vapi_calc_ip_punt_redirect_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_punt_redirect_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_punt_redirect_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_punt_redirect_dump* vapi_alloc_ip_punt_redirect_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_punt_redirect_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_punt_redirect_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_punt_redirect_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_punt_redirect_dump);

  return msg;
}

static inline vapi_error_e vapi_ip_punt_redirect_dump(struct vapi_ctx_s *ctx,
  vapi_msg_ip_punt_redirect_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_punt_redirect_details *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ip_punt_redirect_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_punt_redirect_details, VAPI_REQUEST_DUMP, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ip_punt_redirect_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_punt_redirect_dump()
{
  static const char name[] = "ip_punt_redirect_dump";
  static const char name_with_crc[] = "ip_punt_redirect_dump_2d033de4";
  static vapi_message_desc_t __vapi_metadata_ip_punt_redirect_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip_punt_redirect_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_punt_redirect_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_punt_redirect_dump_hton,
    (generic_swap_fn_t)vapi_msg_ip_punt_redirect_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_punt_redirect_dump = vapi_register_msg(&__vapi_metadata_ip_punt_redirect_dump);
  VAPI_DBG("Assigned msg id %d to ip_punt_redirect_dump", vapi_msg_id_ip_punt_redirect_dump);
}
#endif

#ifndef defined_vapi_msg_add_del_ip_punt_redirect_v2_reply
#define defined_vapi_msg_add_del_ip_punt_redirect_v2_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_add_del_ip_punt_redirect_v2_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_add_del_ip_punt_redirect_v2_reply payload;
} vapi_msg_add_del_ip_punt_redirect_v2_reply;

static inline void vapi_msg_add_del_ip_punt_redirect_v2_reply_payload_hton(vapi_payload_add_del_ip_punt_redirect_v2_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_add_del_ip_punt_redirect_v2_reply_payload_ntoh(vapi_payload_add_del_ip_punt_redirect_v2_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_add_del_ip_punt_redirect_v2_reply_hton(vapi_msg_add_del_ip_punt_redirect_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_add_del_ip_punt_redirect_v2_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_add_del_ip_punt_redirect_v2_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_add_del_ip_punt_redirect_v2_reply_ntoh(vapi_msg_add_del_ip_punt_redirect_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_add_del_ip_punt_redirect_v2_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_add_del_ip_punt_redirect_v2_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_add_del_ip_punt_redirect_v2_reply_msg_size(vapi_msg_add_del_ip_punt_redirect_v2_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_add_del_ip_punt_redirect_v2_reply_msg_size(vapi_msg_add_del_ip_punt_redirect_v2_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_add_del_ip_punt_redirect_v2_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'add_del_ip_punt_redirect_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_add_del_ip_punt_redirect_v2_reply));
      return -1;
    }
  if (vapi_calc_add_del_ip_punt_redirect_v2_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'add_del_ip_punt_redirect_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_add_del_ip_punt_redirect_v2_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_add_del_ip_punt_redirect_v2_reply()
{
  static const char name[] = "add_del_ip_punt_redirect_v2_reply";
  static const char name_with_crc[] = "add_del_ip_punt_redirect_v2_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_add_del_ip_punt_redirect_v2_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_add_del_ip_punt_redirect_v2_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_add_del_ip_punt_redirect_v2_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_add_del_ip_punt_redirect_v2_reply_hton,
    (generic_swap_fn_t)vapi_msg_add_del_ip_punt_redirect_v2_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_add_del_ip_punt_redirect_v2_reply = vapi_register_msg(&__vapi_metadata_add_del_ip_punt_redirect_v2_reply);
  VAPI_DBG("Assigned msg id %d to add_del_ip_punt_redirect_v2_reply", vapi_msg_id_add_del_ip_punt_redirect_v2_reply);
}

static inline void vapi_set_vapi_msg_add_del_ip_punt_redirect_v2_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_add_del_ip_punt_redirect_v2_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_add_del_ip_punt_redirect_v2_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_add_del_ip_punt_redirect_v2
#define defined_vapi_msg_add_del_ip_punt_redirect_v2
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_type_punt_redirect_v2 punt; 
} vapi_payload_add_del_ip_punt_redirect_v2;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_add_del_ip_punt_redirect_v2 payload;
} vapi_msg_add_del_ip_punt_redirect_v2;

static inline void vapi_msg_add_del_ip_punt_redirect_v2_payload_hton(vapi_payload_add_del_ip_punt_redirect_v2 *payload)
{
  vapi_type_punt_redirect_v2_hton(&payload->punt);
}

static inline void vapi_msg_add_del_ip_punt_redirect_v2_payload_ntoh(vapi_payload_add_del_ip_punt_redirect_v2 *payload)
{
  vapi_type_punt_redirect_v2_ntoh(&payload->punt);
}

static inline void vapi_msg_add_del_ip_punt_redirect_v2_hton(vapi_msg_add_del_ip_punt_redirect_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_add_del_ip_punt_redirect_v2'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_add_del_ip_punt_redirect_v2_payload_hton(&msg->payload);
}

static inline void vapi_msg_add_del_ip_punt_redirect_v2_ntoh(vapi_msg_add_del_ip_punt_redirect_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_add_del_ip_punt_redirect_v2'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_add_del_ip_punt_redirect_v2_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_add_del_ip_punt_redirect_v2_msg_size(vapi_msg_add_del_ip_punt_redirect_v2 *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.punt.paths[0]) * msg->payload.punt.n_paths;
}

static inline int vapi_verify_add_del_ip_punt_redirect_v2_msg_size(vapi_msg_add_del_ip_punt_redirect_v2 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_add_del_ip_punt_redirect_v2) > buf_size)
    {
      VAPI_ERR("Truncated 'add_del_ip_punt_redirect_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_add_del_ip_punt_redirect_v2));
      return -1;
    }
  if (vapi_calc_add_del_ip_punt_redirect_v2_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'add_del_ip_punt_redirect_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_add_del_ip_punt_redirect_v2_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_add_del_ip_punt_redirect_v2* vapi_alloc_add_del_ip_punt_redirect_v2(struct vapi_ctx_s *ctx, size_t punt_paths_array_size)
{
  vapi_msg_add_del_ip_punt_redirect_v2 *msg = NULL;
  const size_t size = sizeof(vapi_msg_add_del_ip_punt_redirect_v2) + sizeof(msg->payload.punt.paths[0]) * punt_paths_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_add_del_ip_punt_redirect_v2*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_add_del_ip_punt_redirect_v2);
  msg->payload.punt.n_paths = punt_paths_array_size;

  return msg;
}

static inline vapi_error_e vapi_add_del_ip_punt_redirect_v2(struct vapi_ctx_s *ctx,
  vapi_msg_add_del_ip_punt_redirect_v2 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_add_del_ip_punt_redirect_v2_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_add_del_ip_punt_redirect_v2_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_add_del_ip_punt_redirect_v2_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_add_del_ip_punt_redirect_v2_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_add_del_ip_punt_redirect_v2()
{
  static const char name[] = "add_del_ip_punt_redirect_v2";
  static const char name_with_crc[] = "add_del_ip_punt_redirect_v2_9e804227";
  static vapi_message_desc_t __vapi_metadata_add_del_ip_punt_redirect_v2 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_add_del_ip_punt_redirect_v2, payload),
    (verify_msg_size_fn_t)vapi_verify_add_del_ip_punt_redirect_v2_msg_size,
    (generic_swap_fn_t)vapi_msg_add_del_ip_punt_redirect_v2_hton,
    (generic_swap_fn_t)vapi_msg_add_del_ip_punt_redirect_v2_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_add_del_ip_punt_redirect_v2 = vapi_register_msg(&__vapi_metadata_add_del_ip_punt_redirect_v2);
  VAPI_DBG("Assigned msg id %d to add_del_ip_punt_redirect_v2", vapi_msg_id_add_del_ip_punt_redirect_v2);
}
#endif

#ifndef defined_vapi_msg_ip_punt_redirect_v2_details
#define defined_vapi_msg_ip_punt_redirect_v2_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_punt_redirect_v2 punt; 
} vapi_payload_ip_punt_redirect_v2_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_punt_redirect_v2_details payload;
} vapi_msg_ip_punt_redirect_v2_details;

static inline void vapi_msg_ip_punt_redirect_v2_details_payload_hton(vapi_payload_ip_punt_redirect_v2_details *payload)
{
  vapi_type_punt_redirect_v2_hton(&payload->punt);
}

static inline void vapi_msg_ip_punt_redirect_v2_details_payload_ntoh(vapi_payload_ip_punt_redirect_v2_details *payload)
{
  vapi_type_punt_redirect_v2_ntoh(&payload->punt);
}

static inline void vapi_msg_ip_punt_redirect_v2_details_hton(vapi_msg_ip_punt_redirect_v2_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_punt_redirect_v2_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_punt_redirect_v2_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_punt_redirect_v2_details_ntoh(vapi_msg_ip_punt_redirect_v2_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_punt_redirect_v2_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_punt_redirect_v2_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_punt_redirect_v2_details_msg_size(vapi_msg_ip_punt_redirect_v2_details *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.punt.paths[0]) * msg->payload.punt.n_paths;
}

static inline int vapi_verify_ip_punt_redirect_v2_details_msg_size(vapi_msg_ip_punt_redirect_v2_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_punt_redirect_v2_details) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_punt_redirect_v2_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_punt_redirect_v2_details));
      return -1;
    }
  if (vapi_calc_ip_punt_redirect_v2_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_punt_redirect_v2_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_punt_redirect_v2_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_punt_redirect_v2_details()
{
  static const char name[] = "ip_punt_redirect_v2_details";
  static const char name_with_crc[] = "ip_punt_redirect_v2_details_7ba42e1d";
  static vapi_message_desc_t __vapi_metadata_ip_punt_redirect_v2_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_punt_redirect_v2_details, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_punt_redirect_v2_details_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_punt_redirect_v2_details_hton,
    (generic_swap_fn_t)vapi_msg_ip_punt_redirect_v2_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_punt_redirect_v2_details = vapi_register_msg(&__vapi_metadata_ip_punt_redirect_v2_details);
  VAPI_DBG("Assigned msg id %d to ip_punt_redirect_v2_details", vapi_msg_id_ip_punt_redirect_v2_details);
}

static inline void vapi_set_vapi_msg_ip_punt_redirect_v2_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_punt_redirect_v2_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_punt_redirect_v2_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_punt_redirect_v2_dump
#define defined_vapi_msg_ip_punt_redirect_v2_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  vapi_enum_address_family af; 
} vapi_payload_ip_punt_redirect_v2_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip_punt_redirect_v2_dump payload;
} vapi_msg_ip_punt_redirect_v2_dump;

static inline void vapi_msg_ip_punt_redirect_v2_dump_payload_hton(vapi_payload_ip_punt_redirect_v2_dump *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_ip_punt_redirect_v2_dump_payload_ntoh(vapi_payload_ip_punt_redirect_v2_dump *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_ip_punt_redirect_v2_dump_hton(vapi_msg_ip_punt_redirect_v2_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_punt_redirect_v2_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip_punt_redirect_v2_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_punt_redirect_v2_dump_ntoh(vapi_msg_ip_punt_redirect_v2_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_punt_redirect_v2_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip_punt_redirect_v2_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_punt_redirect_v2_dump_msg_size(vapi_msg_ip_punt_redirect_v2_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_punt_redirect_v2_dump_msg_size(vapi_msg_ip_punt_redirect_v2_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_punt_redirect_v2_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_punt_redirect_v2_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_punt_redirect_v2_dump));
      return -1;
    }
  if (vapi_calc_ip_punt_redirect_v2_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_punt_redirect_v2_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_punt_redirect_v2_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_punt_redirect_v2_dump* vapi_alloc_ip_punt_redirect_v2_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_punt_redirect_v2_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_punt_redirect_v2_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_punt_redirect_v2_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_punt_redirect_v2_dump);

  return msg;
}

static inline vapi_error_e vapi_ip_punt_redirect_v2_dump(struct vapi_ctx_s *ctx,
  vapi_msg_ip_punt_redirect_v2_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_punt_redirect_v2_details *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ip_punt_redirect_v2_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_punt_redirect_v2_details, VAPI_REQUEST_DUMP, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ip_punt_redirect_v2_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_punt_redirect_v2_dump()
{
  static const char name[] = "ip_punt_redirect_v2_dump";
  static const char name_with_crc[] = "ip_punt_redirect_v2_dump_d817a484";
  static vapi_message_desc_t __vapi_metadata_ip_punt_redirect_v2_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip_punt_redirect_v2_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_punt_redirect_v2_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_punt_redirect_v2_dump_hton,
    (generic_swap_fn_t)vapi_msg_ip_punt_redirect_v2_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_punt_redirect_v2_dump = vapi_register_msg(&__vapi_metadata_ip_punt_redirect_v2_dump);
  VAPI_DBG("Assigned msg id %d to ip_punt_redirect_v2_dump", vapi_msg_id_ip_punt_redirect_v2_dump);
}
#endif

#ifndef defined_vapi_msg_ip_container_proxy_add_del_reply
#define defined_vapi_msg_ip_container_proxy_add_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ip_container_proxy_add_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_container_proxy_add_del_reply payload;
} vapi_msg_ip_container_proxy_add_del_reply;

static inline void vapi_msg_ip_container_proxy_add_del_reply_payload_hton(vapi_payload_ip_container_proxy_add_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ip_container_proxy_add_del_reply_payload_ntoh(vapi_payload_ip_container_proxy_add_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ip_container_proxy_add_del_reply_hton(vapi_msg_ip_container_proxy_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_container_proxy_add_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_container_proxy_add_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_container_proxy_add_del_reply_ntoh(vapi_msg_ip_container_proxy_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_container_proxy_add_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_container_proxy_add_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_container_proxy_add_del_reply_msg_size(vapi_msg_ip_container_proxy_add_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_container_proxy_add_del_reply_msg_size(vapi_msg_ip_container_proxy_add_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_container_proxy_add_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_container_proxy_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_container_proxy_add_del_reply));
      return -1;
    }
  if (vapi_calc_ip_container_proxy_add_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_container_proxy_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_container_proxy_add_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_container_proxy_add_del_reply()
{
  static const char name[] = "ip_container_proxy_add_del_reply";
  static const char name_with_crc[] = "ip_container_proxy_add_del_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ip_container_proxy_add_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_container_proxy_add_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_container_proxy_add_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_container_proxy_add_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_ip_container_proxy_add_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_container_proxy_add_del_reply = vapi_register_msg(&__vapi_metadata_ip_container_proxy_add_del_reply);
  VAPI_DBG("Assigned msg id %d to ip_container_proxy_add_del_reply", vapi_msg_id_ip_container_proxy_add_del_reply);
}

static inline void vapi_set_vapi_msg_ip_container_proxy_add_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_container_proxy_add_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_container_proxy_add_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_container_proxy_add_del
#define defined_vapi_msg_ip_container_proxy_add_del
typedef struct __attribute__ ((__packed__)) {
  vapi_type_prefix pfx;
  vapi_type_interface_index sw_if_index;
  bool is_add; 
} vapi_payload_ip_container_proxy_add_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip_container_proxy_add_del payload;
} vapi_msg_ip_container_proxy_add_del;

static inline void vapi_msg_ip_container_proxy_add_del_payload_hton(vapi_payload_ip_container_proxy_add_del *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_ip_container_proxy_add_del_payload_ntoh(vapi_payload_ip_container_proxy_add_del *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_ip_container_proxy_add_del_hton(vapi_msg_ip_container_proxy_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_container_proxy_add_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip_container_proxy_add_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_container_proxy_add_del_ntoh(vapi_msg_ip_container_proxy_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_container_proxy_add_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip_container_proxy_add_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_container_proxy_add_del_msg_size(vapi_msg_ip_container_proxy_add_del *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_container_proxy_add_del_msg_size(vapi_msg_ip_container_proxy_add_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_container_proxy_add_del) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_container_proxy_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_container_proxy_add_del));
      return -1;
    }
  if (vapi_calc_ip_container_proxy_add_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_container_proxy_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_container_proxy_add_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_container_proxy_add_del* vapi_alloc_ip_container_proxy_add_del(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_container_proxy_add_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_container_proxy_add_del);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_container_proxy_add_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_container_proxy_add_del);

  return msg;
}

static inline vapi_error_e vapi_ip_container_proxy_add_del(struct vapi_ctx_s *ctx,
  vapi_msg_ip_container_proxy_add_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_container_proxy_add_del_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ip_container_proxy_add_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_container_proxy_add_del_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ip_container_proxy_add_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_container_proxy_add_del()
{
  static const char name[] = "ip_container_proxy_add_del";
  static const char name_with_crc[] = "ip_container_proxy_add_del_7df1dff1";
  static vapi_message_desc_t __vapi_metadata_ip_container_proxy_add_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip_container_proxy_add_del, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_container_proxy_add_del_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_container_proxy_add_del_hton,
    (generic_swap_fn_t)vapi_msg_ip_container_proxy_add_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_container_proxy_add_del = vapi_register_msg(&__vapi_metadata_ip_container_proxy_add_del);
  VAPI_DBG("Assigned msg id %d to ip_container_proxy_add_del", vapi_msg_id_ip_container_proxy_add_del);
}
#endif

#ifndef defined_vapi_msg_ip_container_proxy_details
#define defined_vapi_msg_ip_container_proxy_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  vapi_type_prefix prefix; 
} vapi_payload_ip_container_proxy_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_container_proxy_details payload;
} vapi_msg_ip_container_proxy_details;

static inline void vapi_msg_ip_container_proxy_details_payload_hton(vapi_payload_ip_container_proxy_details *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_ip_container_proxy_details_payload_ntoh(vapi_payload_ip_container_proxy_details *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_ip_container_proxy_details_hton(vapi_msg_ip_container_proxy_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_container_proxy_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_container_proxy_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_container_proxy_details_ntoh(vapi_msg_ip_container_proxy_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_container_proxy_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_container_proxy_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_container_proxy_details_msg_size(vapi_msg_ip_container_proxy_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_container_proxy_details_msg_size(vapi_msg_ip_container_proxy_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_container_proxy_details) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_container_proxy_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_container_proxy_details));
      return -1;
    }
  if (vapi_calc_ip_container_proxy_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_container_proxy_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_container_proxy_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_container_proxy_details()
{
  static const char name[] = "ip_container_proxy_details";
  static const char name_with_crc[] = "ip_container_proxy_details_a8085523";
  static vapi_message_desc_t __vapi_metadata_ip_container_proxy_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_container_proxy_details, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_container_proxy_details_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_container_proxy_details_hton,
    (generic_swap_fn_t)vapi_msg_ip_container_proxy_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_container_proxy_details = vapi_register_msg(&__vapi_metadata_ip_container_proxy_details);
  VAPI_DBG("Assigned msg id %d to ip_container_proxy_details", vapi_msg_id_ip_container_proxy_details);
}

static inline void vapi_set_vapi_msg_ip_container_proxy_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_container_proxy_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_container_proxy_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_container_proxy_dump
#define defined_vapi_msg_ip_container_proxy_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_ip_container_proxy_dump;

static inline void vapi_msg_ip_container_proxy_dump_hton(vapi_msg_ip_container_proxy_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_container_proxy_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_ip_container_proxy_dump_ntoh(vapi_msg_ip_container_proxy_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_container_proxy_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_ip_container_proxy_dump_msg_size(vapi_msg_ip_container_proxy_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_container_proxy_dump_msg_size(vapi_msg_ip_container_proxy_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_container_proxy_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_container_proxy_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_container_proxy_dump));
      return -1;
    }
  if (vapi_calc_ip_container_proxy_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_container_proxy_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_container_proxy_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_container_proxy_dump* vapi_alloc_ip_container_proxy_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_container_proxy_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_container_proxy_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_container_proxy_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_container_proxy_dump);

  return msg;
}

static inline vapi_error_e vapi_ip_container_proxy_dump(struct vapi_ctx_s *ctx,
  vapi_msg_ip_container_proxy_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_container_proxy_details *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ip_container_proxy_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_container_proxy_details, VAPI_REQUEST_DUMP, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ip_container_proxy_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_container_proxy_dump()
{
  static const char name[] = "ip_container_proxy_dump";
  static const char name_with_crc[] = "ip_container_proxy_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_ip_container_proxy_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_ip_container_proxy_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_container_proxy_dump_hton,
    (generic_swap_fn_t)vapi_msg_ip_container_proxy_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_container_proxy_dump = vapi_register_msg(&__vapi_metadata_ip_container_proxy_dump);
  VAPI_DBG("Assigned msg id %d to ip_container_proxy_dump", vapi_msg_id_ip_container_proxy_dump);
}
#endif

#ifndef defined_vapi_msg_ip_source_and_port_range_check_add_del_reply
#define defined_vapi_msg_ip_source_and_port_range_check_add_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ip_source_and_port_range_check_add_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_source_and_port_range_check_add_del_reply payload;
} vapi_msg_ip_source_and_port_range_check_add_del_reply;

static inline void vapi_msg_ip_source_and_port_range_check_add_del_reply_payload_hton(vapi_payload_ip_source_and_port_range_check_add_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ip_source_and_port_range_check_add_del_reply_payload_ntoh(vapi_payload_ip_source_and_port_range_check_add_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ip_source_and_port_range_check_add_del_reply_hton(vapi_msg_ip_source_and_port_range_check_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_source_and_port_range_check_add_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_source_and_port_range_check_add_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_source_and_port_range_check_add_del_reply_ntoh(vapi_msg_ip_source_and_port_range_check_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_source_and_port_range_check_add_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_source_and_port_range_check_add_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_source_and_port_range_check_add_del_reply_msg_size(vapi_msg_ip_source_and_port_range_check_add_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_source_and_port_range_check_add_del_reply_msg_size(vapi_msg_ip_source_and_port_range_check_add_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_source_and_port_range_check_add_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_source_and_port_range_check_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_source_and_port_range_check_add_del_reply));
      return -1;
    }
  if (vapi_calc_ip_source_and_port_range_check_add_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_source_and_port_range_check_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_source_and_port_range_check_add_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_source_and_port_range_check_add_del_reply()
{
  static const char name[] = "ip_source_and_port_range_check_add_del_reply";
  static const char name_with_crc[] = "ip_source_and_port_range_check_add_del_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ip_source_and_port_range_check_add_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_source_and_port_range_check_add_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_source_and_port_range_check_add_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_source_and_port_range_check_add_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_ip_source_and_port_range_check_add_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_source_and_port_range_check_add_del_reply = vapi_register_msg(&__vapi_metadata_ip_source_and_port_range_check_add_del_reply);
  VAPI_DBG("Assigned msg id %d to ip_source_and_port_range_check_add_del_reply", vapi_msg_id_ip_source_and_port_range_check_add_del_reply);
}

static inline void vapi_set_vapi_msg_ip_source_and_port_range_check_add_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_source_and_port_range_check_add_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_source_and_port_range_check_add_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_source_and_port_range_check_add_del
#define defined_vapi_msg_ip_source_and_port_range_check_add_del
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_type_prefix prefix;
  u8 number_of_ranges;
  u16 low_ports[32];
  u16 high_ports[32];
  u32 vrf_id; 
} vapi_payload_ip_source_and_port_range_check_add_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip_source_and_port_range_check_add_del payload;
} vapi_msg_ip_source_and_port_range_check_add_del;

static inline void vapi_msg_ip_source_and_port_range_check_add_del_payload_hton(vapi_payload_ip_source_and_port_range_check_add_del *payload)
{
  do { unsigned i; for (i = 0; i < 32; ++i) { payload->low_ports[i] = htobe16(payload->low_ports[i]); } } while(0);
  do { unsigned i; for (i = 0; i < 32; ++i) { payload->high_ports[i] = htobe16(payload->high_ports[i]); } } while(0);
  payload->vrf_id = htobe32(payload->vrf_id);
}

static inline void vapi_msg_ip_source_and_port_range_check_add_del_payload_ntoh(vapi_payload_ip_source_and_port_range_check_add_del *payload)
{
  do { unsigned i; for (i = 0; i < 32; ++i) { payload->low_ports[i] = be16toh(payload->low_ports[i]); } } while(0);
  do { unsigned i; for (i = 0; i < 32; ++i) { payload->high_ports[i] = be16toh(payload->high_ports[i]); } } while(0);
  payload->vrf_id = be32toh(payload->vrf_id);
}

static inline void vapi_msg_ip_source_and_port_range_check_add_del_hton(vapi_msg_ip_source_and_port_range_check_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_source_and_port_range_check_add_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip_source_and_port_range_check_add_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_source_and_port_range_check_add_del_ntoh(vapi_msg_ip_source_and_port_range_check_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_source_and_port_range_check_add_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip_source_and_port_range_check_add_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_source_and_port_range_check_add_del_msg_size(vapi_msg_ip_source_and_port_range_check_add_del *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_source_and_port_range_check_add_del_msg_size(vapi_msg_ip_source_and_port_range_check_add_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_source_and_port_range_check_add_del) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_source_and_port_range_check_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_source_and_port_range_check_add_del));
      return -1;
    }
  if (vapi_calc_ip_source_and_port_range_check_add_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_source_and_port_range_check_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_source_and_port_range_check_add_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_source_and_port_range_check_add_del* vapi_alloc_ip_source_and_port_range_check_add_del(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_source_and_port_range_check_add_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_source_and_port_range_check_add_del);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_source_and_port_range_check_add_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_source_and_port_range_check_add_del);

  return msg;
}

static inline vapi_error_e vapi_ip_source_and_port_range_check_add_del(struct vapi_ctx_s *ctx,
  vapi_msg_ip_source_and_port_range_check_add_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_source_and_port_range_check_add_del_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ip_source_and_port_range_check_add_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_source_and_port_range_check_add_del_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ip_source_and_port_range_check_add_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_source_and_port_range_check_add_del()
{
  static const char name[] = "ip_source_and_port_range_check_add_del";
  static const char name_with_crc[] = "ip_source_and_port_range_check_add_del_92a067e3";
  static vapi_message_desc_t __vapi_metadata_ip_source_and_port_range_check_add_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip_source_and_port_range_check_add_del, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_source_and_port_range_check_add_del_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_source_and_port_range_check_add_del_hton,
    (generic_swap_fn_t)vapi_msg_ip_source_and_port_range_check_add_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_source_and_port_range_check_add_del = vapi_register_msg(&__vapi_metadata_ip_source_and_port_range_check_add_del);
  VAPI_DBG("Assigned msg id %d to ip_source_and_port_range_check_add_del", vapi_msg_id_ip_source_and_port_range_check_add_del);
}
#endif

#ifndef defined_vapi_msg_ip_source_and_port_range_check_interface_add_del_reply
#define defined_vapi_msg_ip_source_and_port_range_check_interface_add_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ip_source_and_port_range_check_interface_add_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_source_and_port_range_check_interface_add_del_reply payload;
} vapi_msg_ip_source_and_port_range_check_interface_add_del_reply;

static inline void vapi_msg_ip_source_and_port_range_check_interface_add_del_reply_payload_hton(vapi_payload_ip_source_and_port_range_check_interface_add_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ip_source_and_port_range_check_interface_add_del_reply_payload_ntoh(vapi_payload_ip_source_and_port_range_check_interface_add_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ip_source_and_port_range_check_interface_add_del_reply_hton(vapi_msg_ip_source_and_port_range_check_interface_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_source_and_port_range_check_interface_add_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_source_and_port_range_check_interface_add_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_source_and_port_range_check_interface_add_del_reply_ntoh(vapi_msg_ip_source_and_port_range_check_interface_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_source_and_port_range_check_interface_add_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_source_and_port_range_check_interface_add_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_source_and_port_range_check_interface_add_del_reply_msg_size(vapi_msg_ip_source_and_port_range_check_interface_add_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_source_and_port_range_check_interface_add_del_reply_msg_size(vapi_msg_ip_source_and_port_range_check_interface_add_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_source_and_port_range_check_interface_add_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_source_and_port_range_check_interface_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_source_and_port_range_check_interface_add_del_reply));
      return -1;
    }
  if (vapi_calc_ip_source_and_port_range_check_interface_add_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_source_and_port_range_check_interface_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_source_and_port_range_check_interface_add_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_source_and_port_range_check_interface_add_del_reply()
{
  static const char name[] = "ip_source_and_port_range_check_interface_add_del_reply";
  static const char name_with_crc[] = "ip_source_and_port_range_check_interface_add_del_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ip_source_and_port_range_check_interface_add_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_source_and_port_range_check_interface_add_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_source_and_port_range_check_interface_add_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_source_and_port_range_check_interface_add_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_ip_source_and_port_range_check_interface_add_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_source_and_port_range_check_interface_add_del_reply = vapi_register_msg(&__vapi_metadata_ip_source_and_port_range_check_interface_add_del_reply);
  VAPI_DBG("Assigned msg id %d to ip_source_and_port_range_check_interface_add_del_reply", vapi_msg_id_ip_source_and_port_range_check_interface_add_del_reply);
}

static inline void vapi_set_vapi_msg_ip_source_and_port_range_check_interface_add_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_source_and_port_range_check_interface_add_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_source_and_port_range_check_interface_add_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_source_and_port_range_check_interface_add_del
#define defined_vapi_msg_ip_source_and_port_range_check_interface_add_del
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_type_interface_index sw_if_index;
  u32 tcp_in_vrf_id;
  u32 tcp_out_vrf_id;
  u32 udp_in_vrf_id;
  u32 udp_out_vrf_id; 
} vapi_payload_ip_source_and_port_range_check_interface_add_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip_source_and_port_range_check_interface_add_del payload;
} vapi_msg_ip_source_and_port_range_check_interface_add_del;

static inline void vapi_msg_ip_source_and_port_range_check_interface_add_del_payload_hton(vapi_payload_ip_source_and_port_range_check_interface_add_del *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->tcp_in_vrf_id = htobe32(payload->tcp_in_vrf_id);
  payload->tcp_out_vrf_id = htobe32(payload->tcp_out_vrf_id);
  payload->udp_in_vrf_id = htobe32(payload->udp_in_vrf_id);
  payload->udp_out_vrf_id = htobe32(payload->udp_out_vrf_id);
}

static inline void vapi_msg_ip_source_and_port_range_check_interface_add_del_payload_ntoh(vapi_payload_ip_source_and_port_range_check_interface_add_del *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->tcp_in_vrf_id = be32toh(payload->tcp_in_vrf_id);
  payload->tcp_out_vrf_id = be32toh(payload->tcp_out_vrf_id);
  payload->udp_in_vrf_id = be32toh(payload->udp_in_vrf_id);
  payload->udp_out_vrf_id = be32toh(payload->udp_out_vrf_id);
}

static inline void vapi_msg_ip_source_and_port_range_check_interface_add_del_hton(vapi_msg_ip_source_and_port_range_check_interface_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_source_and_port_range_check_interface_add_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip_source_and_port_range_check_interface_add_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_source_and_port_range_check_interface_add_del_ntoh(vapi_msg_ip_source_and_port_range_check_interface_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_source_and_port_range_check_interface_add_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip_source_and_port_range_check_interface_add_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_source_and_port_range_check_interface_add_del_msg_size(vapi_msg_ip_source_and_port_range_check_interface_add_del *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_source_and_port_range_check_interface_add_del_msg_size(vapi_msg_ip_source_and_port_range_check_interface_add_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_source_and_port_range_check_interface_add_del) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_source_and_port_range_check_interface_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_source_and_port_range_check_interface_add_del));
      return -1;
    }
  if (vapi_calc_ip_source_and_port_range_check_interface_add_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_source_and_port_range_check_interface_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_source_and_port_range_check_interface_add_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_source_and_port_range_check_interface_add_del* vapi_alloc_ip_source_and_port_range_check_interface_add_del(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_source_and_port_range_check_interface_add_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_source_and_port_range_check_interface_add_del);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_source_and_port_range_check_interface_add_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_source_and_port_range_check_interface_add_del);

  return msg;
}

static inline vapi_error_e vapi_ip_source_and_port_range_check_interface_add_del(struct vapi_ctx_s *ctx,
  vapi_msg_ip_source_and_port_range_check_interface_add_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_source_and_port_range_check_interface_add_del_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ip_source_and_port_range_check_interface_add_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_source_and_port_range_check_interface_add_del_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ip_source_and_port_range_check_interface_add_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_source_and_port_range_check_interface_add_del()
{
  static const char name[] = "ip_source_and_port_range_check_interface_add_del";
  static const char name_with_crc[] = "ip_source_and_port_range_check_interface_add_del_e1ba8987";
  static vapi_message_desc_t __vapi_metadata_ip_source_and_port_range_check_interface_add_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip_source_and_port_range_check_interface_add_del, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_source_and_port_range_check_interface_add_del_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_source_and_port_range_check_interface_add_del_hton,
    (generic_swap_fn_t)vapi_msg_ip_source_and_port_range_check_interface_add_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_source_and_port_range_check_interface_add_del = vapi_register_msg(&__vapi_metadata_ip_source_and_port_range_check_interface_add_del);
  VAPI_DBG("Assigned msg id %d to ip_source_and_port_range_check_interface_add_del", vapi_msg_id_ip_source_and_port_range_check_interface_add_del);
}
#endif

#ifndef defined_vapi_msg_sw_interface_ip6_set_link_local_address_reply
#define defined_vapi_msg_sw_interface_ip6_set_link_local_address_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_sw_interface_ip6_set_link_local_address_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_sw_interface_ip6_set_link_local_address_reply payload;
} vapi_msg_sw_interface_ip6_set_link_local_address_reply;

static inline void vapi_msg_sw_interface_ip6_set_link_local_address_reply_payload_hton(vapi_payload_sw_interface_ip6_set_link_local_address_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_sw_interface_ip6_set_link_local_address_reply_payload_ntoh(vapi_payload_sw_interface_ip6_set_link_local_address_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_sw_interface_ip6_set_link_local_address_reply_hton(vapi_msg_sw_interface_ip6_set_link_local_address_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_ip6_set_link_local_address_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_sw_interface_ip6_set_link_local_address_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_sw_interface_ip6_set_link_local_address_reply_ntoh(vapi_msg_sw_interface_ip6_set_link_local_address_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_ip6_set_link_local_address_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_sw_interface_ip6_set_link_local_address_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sw_interface_ip6_set_link_local_address_reply_msg_size(vapi_msg_sw_interface_ip6_set_link_local_address_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sw_interface_ip6_set_link_local_address_reply_msg_size(vapi_msg_sw_interface_ip6_set_link_local_address_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sw_interface_ip6_set_link_local_address_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_ip6_set_link_local_address_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sw_interface_ip6_set_link_local_address_reply));
      return -1;
    }
  if (vapi_calc_sw_interface_ip6_set_link_local_address_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_ip6_set_link_local_address_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sw_interface_ip6_set_link_local_address_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_sw_interface_ip6_set_link_local_address_reply()
{
  static const char name[] = "sw_interface_ip6_set_link_local_address_reply";
  static const char name_with_crc[] = "sw_interface_ip6_set_link_local_address_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_sw_interface_ip6_set_link_local_address_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_sw_interface_ip6_set_link_local_address_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_sw_interface_ip6_set_link_local_address_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_sw_interface_ip6_set_link_local_address_reply_hton,
    (generic_swap_fn_t)vapi_msg_sw_interface_ip6_set_link_local_address_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sw_interface_ip6_set_link_local_address_reply = vapi_register_msg(&__vapi_metadata_sw_interface_ip6_set_link_local_address_reply);
  VAPI_DBG("Assigned msg id %d to sw_interface_ip6_set_link_local_address_reply", vapi_msg_id_sw_interface_ip6_set_link_local_address_reply);
}

static inline void vapi_set_vapi_msg_sw_interface_ip6_set_link_local_address_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_sw_interface_ip6_set_link_local_address_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_sw_interface_ip6_set_link_local_address_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_sw_interface_ip6_set_link_local_address
#define defined_vapi_msg_sw_interface_ip6_set_link_local_address
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  vapi_type_ip6_address ip; 
} vapi_payload_sw_interface_ip6_set_link_local_address;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_sw_interface_ip6_set_link_local_address payload;
} vapi_msg_sw_interface_ip6_set_link_local_address;

static inline void vapi_msg_sw_interface_ip6_set_link_local_address_payload_hton(vapi_payload_sw_interface_ip6_set_link_local_address *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_sw_interface_ip6_set_link_local_address_payload_ntoh(vapi_payload_sw_interface_ip6_set_link_local_address *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_sw_interface_ip6_set_link_local_address_hton(vapi_msg_sw_interface_ip6_set_link_local_address *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_ip6_set_link_local_address'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_sw_interface_ip6_set_link_local_address_payload_hton(&msg->payload);
}

static inline void vapi_msg_sw_interface_ip6_set_link_local_address_ntoh(vapi_msg_sw_interface_ip6_set_link_local_address *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_ip6_set_link_local_address'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_sw_interface_ip6_set_link_local_address_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sw_interface_ip6_set_link_local_address_msg_size(vapi_msg_sw_interface_ip6_set_link_local_address *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sw_interface_ip6_set_link_local_address_msg_size(vapi_msg_sw_interface_ip6_set_link_local_address *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sw_interface_ip6_set_link_local_address) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_ip6_set_link_local_address' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sw_interface_ip6_set_link_local_address));
      return -1;
    }
  if (vapi_calc_sw_interface_ip6_set_link_local_address_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_ip6_set_link_local_address' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sw_interface_ip6_set_link_local_address_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_sw_interface_ip6_set_link_local_address* vapi_alloc_sw_interface_ip6_set_link_local_address(struct vapi_ctx_s *ctx)
{
  vapi_msg_sw_interface_ip6_set_link_local_address *msg = NULL;
  const size_t size = sizeof(vapi_msg_sw_interface_ip6_set_link_local_address);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_sw_interface_ip6_set_link_local_address*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_sw_interface_ip6_set_link_local_address);

  return msg;
}

static inline vapi_error_e vapi_sw_interface_ip6_set_link_local_address(struct vapi_ctx_s *ctx,
  vapi_msg_sw_interface_ip6_set_link_local_address *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_sw_interface_ip6_set_link_local_address_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_sw_interface_ip6_set_link_local_address_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_sw_interface_ip6_set_link_local_address_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_sw_interface_ip6_set_link_local_address_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_sw_interface_ip6_set_link_local_address()
{
  static const char name[] = "sw_interface_ip6_set_link_local_address";
  static const char name_with_crc[] = "sw_interface_ip6_set_link_local_address_1c10f15f";
  static vapi_message_desc_t __vapi_metadata_sw_interface_ip6_set_link_local_address = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_sw_interface_ip6_set_link_local_address, payload),
    (verify_msg_size_fn_t)vapi_verify_sw_interface_ip6_set_link_local_address_msg_size,
    (generic_swap_fn_t)vapi_msg_sw_interface_ip6_set_link_local_address_hton,
    (generic_swap_fn_t)vapi_msg_sw_interface_ip6_set_link_local_address_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sw_interface_ip6_set_link_local_address = vapi_register_msg(&__vapi_metadata_sw_interface_ip6_set_link_local_address);
  VAPI_DBG("Assigned msg id %d to sw_interface_ip6_set_link_local_address", vapi_msg_id_sw_interface_ip6_set_link_local_address);
}
#endif

#ifndef defined_vapi_msg_sw_interface_ip6_get_link_local_address_reply
#define defined_vapi_msg_sw_interface_ip6_get_link_local_address_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vapi_type_ip6_address ip; 
} vapi_payload_sw_interface_ip6_get_link_local_address_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_sw_interface_ip6_get_link_local_address_reply payload;
} vapi_msg_sw_interface_ip6_get_link_local_address_reply;

static inline void vapi_msg_sw_interface_ip6_get_link_local_address_reply_payload_hton(vapi_payload_sw_interface_ip6_get_link_local_address_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_sw_interface_ip6_get_link_local_address_reply_payload_ntoh(vapi_payload_sw_interface_ip6_get_link_local_address_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_sw_interface_ip6_get_link_local_address_reply_hton(vapi_msg_sw_interface_ip6_get_link_local_address_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_ip6_get_link_local_address_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_sw_interface_ip6_get_link_local_address_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_sw_interface_ip6_get_link_local_address_reply_ntoh(vapi_msg_sw_interface_ip6_get_link_local_address_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_ip6_get_link_local_address_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_sw_interface_ip6_get_link_local_address_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sw_interface_ip6_get_link_local_address_reply_msg_size(vapi_msg_sw_interface_ip6_get_link_local_address_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sw_interface_ip6_get_link_local_address_reply_msg_size(vapi_msg_sw_interface_ip6_get_link_local_address_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sw_interface_ip6_get_link_local_address_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_ip6_get_link_local_address_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sw_interface_ip6_get_link_local_address_reply));
      return -1;
    }
  if (vapi_calc_sw_interface_ip6_get_link_local_address_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_ip6_get_link_local_address_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sw_interface_ip6_get_link_local_address_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_sw_interface_ip6_get_link_local_address_reply()
{
  static const char name[] = "sw_interface_ip6_get_link_local_address_reply";
  static const char name_with_crc[] = "sw_interface_ip6_get_link_local_address_reply_d16b7130";
  static vapi_message_desc_t __vapi_metadata_sw_interface_ip6_get_link_local_address_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_sw_interface_ip6_get_link_local_address_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_sw_interface_ip6_get_link_local_address_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_sw_interface_ip6_get_link_local_address_reply_hton,
    (generic_swap_fn_t)vapi_msg_sw_interface_ip6_get_link_local_address_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sw_interface_ip6_get_link_local_address_reply = vapi_register_msg(&__vapi_metadata_sw_interface_ip6_get_link_local_address_reply);
  VAPI_DBG("Assigned msg id %d to sw_interface_ip6_get_link_local_address_reply", vapi_msg_id_sw_interface_ip6_get_link_local_address_reply);
}

static inline void vapi_set_vapi_msg_sw_interface_ip6_get_link_local_address_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_sw_interface_ip6_get_link_local_address_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_sw_interface_ip6_get_link_local_address_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_sw_interface_ip6_get_link_local_address
#define defined_vapi_msg_sw_interface_ip6_get_link_local_address
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index; 
} vapi_payload_sw_interface_ip6_get_link_local_address;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_sw_interface_ip6_get_link_local_address payload;
} vapi_msg_sw_interface_ip6_get_link_local_address;

static inline void vapi_msg_sw_interface_ip6_get_link_local_address_payload_hton(vapi_payload_sw_interface_ip6_get_link_local_address *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_sw_interface_ip6_get_link_local_address_payload_ntoh(vapi_payload_sw_interface_ip6_get_link_local_address *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_sw_interface_ip6_get_link_local_address_hton(vapi_msg_sw_interface_ip6_get_link_local_address *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_ip6_get_link_local_address'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_sw_interface_ip6_get_link_local_address_payload_hton(&msg->payload);
}

static inline void vapi_msg_sw_interface_ip6_get_link_local_address_ntoh(vapi_msg_sw_interface_ip6_get_link_local_address *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_ip6_get_link_local_address'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_sw_interface_ip6_get_link_local_address_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sw_interface_ip6_get_link_local_address_msg_size(vapi_msg_sw_interface_ip6_get_link_local_address *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sw_interface_ip6_get_link_local_address_msg_size(vapi_msg_sw_interface_ip6_get_link_local_address *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sw_interface_ip6_get_link_local_address) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_ip6_get_link_local_address' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sw_interface_ip6_get_link_local_address));
      return -1;
    }
  if (vapi_calc_sw_interface_ip6_get_link_local_address_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_ip6_get_link_local_address' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sw_interface_ip6_get_link_local_address_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_sw_interface_ip6_get_link_local_address* vapi_alloc_sw_interface_ip6_get_link_local_address(struct vapi_ctx_s *ctx)
{
  vapi_msg_sw_interface_ip6_get_link_local_address *msg = NULL;
  const size_t size = sizeof(vapi_msg_sw_interface_ip6_get_link_local_address);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_sw_interface_ip6_get_link_local_address*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_sw_interface_ip6_get_link_local_address);

  return msg;
}

static inline vapi_error_e vapi_sw_interface_ip6_get_link_local_address(struct vapi_ctx_s *ctx,
  vapi_msg_sw_interface_ip6_get_link_local_address *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_sw_interface_ip6_get_link_local_address_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_sw_interface_ip6_get_link_local_address_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_sw_interface_ip6_get_link_local_address_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_sw_interface_ip6_get_link_local_address_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_sw_interface_ip6_get_link_local_address()
{
  static const char name[] = "sw_interface_ip6_get_link_local_address";
  static const char name_with_crc[] = "sw_interface_ip6_get_link_local_address_f9e6675e";
  static vapi_message_desc_t __vapi_metadata_sw_interface_ip6_get_link_local_address = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_sw_interface_ip6_get_link_local_address, payload),
    (verify_msg_size_fn_t)vapi_verify_sw_interface_ip6_get_link_local_address_msg_size,
    (generic_swap_fn_t)vapi_msg_sw_interface_ip6_get_link_local_address_hton,
    (generic_swap_fn_t)vapi_msg_sw_interface_ip6_get_link_local_address_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sw_interface_ip6_get_link_local_address = vapi_register_msg(&__vapi_metadata_sw_interface_ip6_get_link_local_address);
  VAPI_DBG("Assigned msg id %d to sw_interface_ip6_get_link_local_address", vapi_msg_id_sw_interface_ip6_get_link_local_address);
}
#endif

#ifndef defined_vapi_msg_ioam_enable_reply
#define defined_vapi_msg_ioam_enable_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ioam_enable_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ioam_enable_reply payload;
} vapi_msg_ioam_enable_reply;

static inline void vapi_msg_ioam_enable_reply_payload_hton(vapi_payload_ioam_enable_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ioam_enable_reply_payload_ntoh(vapi_payload_ioam_enable_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ioam_enable_reply_hton(vapi_msg_ioam_enable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ioam_enable_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ioam_enable_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ioam_enable_reply_ntoh(vapi_msg_ioam_enable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ioam_enable_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ioam_enable_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ioam_enable_reply_msg_size(vapi_msg_ioam_enable_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ioam_enable_reply_msg_size(vapi_msg_ioam_enable_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ioam_enable_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ioam_enable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ioam_enable_reply));
      return -1;
    }
  if (vapi_calc_ioam_enable_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ioam_enable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ioam_enable_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ioam_enable_reply()
{
  static const char name[] = "ioam_enable_reply";
  static const char name_with_crc[] = "ioam_enable_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ioam_enable_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ioam_enable_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ioam_enable_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ioam_enable_reply_hton,
    (generic_swap_fn_t)vapi_msg_ioam_enable_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ioam_enable_reply = vapi_register_msg(&__vapi_metadata_ioam_enable_reply);
  VAPI_DBG("Assigned msg id %d to ioam_enable_reply", vapi_msg_id_ioam_enable_reply);
}

static inline void vapi_set_vapi_msg_ioam_enable_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ioam_enable_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ioam_enable_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ioam_enable
#define defined_vapi_msg_ioam_enable
typedef struct __attribute__ ((__packed__)) {
  u16 id;
  bool seqno;
  bool analyse;
  bool pot_enable;
  bool trace_enable;
  u32 node_id; 
} vapi_payload_ioam_enable;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ioam_enable payload;
} vapi_msg_ioam_enable;

static inline void vapi_msg_ioam_enable_payload_hton(vapi_payload_ioam_enable *payload)
{
  payload->id = htobe16(payload->id);
  payload->node_id = htobe32(payload->node_id);
}

static inline void vapi_msg_ioam_enable_payload_ntoh(vapi_payload_ioam_enable *payload)
{
  payload->id = be16toh(payload->id);
  payload->node_id = be32toh(payload->node_id);
}

static inline void vapi_msg_ioam_enable_hton(vapi_msg_ioam_enable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ioam_enable'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ioam_enable_payload_hton(&msg->payload);
}

static inline void vapi_msg_ioam_enable_ntoh(vapi_msg_ioam_enable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ioam_enable'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ioam_enable_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ioam_enable_msg_size(vapi_msg_ioam_enable *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ioam_enable_msg_size(vapi_msg_ioam_enable *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ioam_enable) > buf_size)
    {
      VAPI_ERR("Truncated 'ioam_enable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ioam_enable));
      return -1;
    }
  if (vapi_calc_ioam_enable_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ioam_enable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ioam_enable_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ioam_enable* vapi_alloc_ioam_enable(struct vapi_ctx_s *ctx)
{
  vapi_msg_ioam_enable *msg = NULL;
  const size_t size = sizeof(vapi_msg_ioam_enable);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ioam_enable*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ioam_enable);

  return msg;
}

static inline vapi_error_e vapi_ioam_enable(struct vapi_ctx_s *ctx,
  vapi_msg_ioam_enable *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ioam_enable_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ioam_enable_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ioam_enable_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ioam_enable_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ioam_enable()
{
  static const char name[] = "ioam_enable";
  static const char name_with_crc[] = "ioam_enable_51ccd868";
  static vapi_message_desc_t __vapi_metadata_ioam_enable = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ioam_enable, payload),
    (verify_msg_size_fn_t)vapi_verify_ioam_enable_msg_size,
    (generic_swap_fn_t)vapi_msg_ioam_enable_hton,
    (generic_swap_fn_t)vapi_msg_ioam_enable_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ioam_enable = vapi_register_msg(&__vapi_metadata_ioam_enable);
  VAPI_DBG("Assigned msg id %d to ioam_enable", vapi_msg_id_ioam_enable);
}
#endif

#ifndef defined_vapi_msg_ioam_disable_reply
#define defined_vapi_msg_ioam_disable_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ioam_disable_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ioam_disable_reply payload;
} vapi_msg_ioam_disable_reply;

static inline void vapi_msg_ioam_disable_reply_payload_hton(vapi_payload_ioam_disable_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ioam_disable_reply_payload_ntoh(vapi_payload_ioam_disable_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ioam_disable_reply_hton(vapi_msg_ioam_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ioam_disable_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ioam_disable_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ioam_disable_reply_ntoh(vapi_msg_ioam_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ioam_disable_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ioam_disable_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ioam_disable_reply_msg_size(vapi_msg_ioam_disable_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ioam_disable_reply_msg_size(vapi_msg_ioam_disable_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ioam_disable_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ioam_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ioam_disable_reply));
      return -1;
    }
  if (vapi_calc_ioam_disable_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ioam_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ioam_disable_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ioam_disable_reply()
{
  static const char name[] = "ioam_disable_reply";
  static const char name_with_crc[] = "ioam_disable_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ioam_disable_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ioam_disable_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ioam_disable_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ioam_disable_reply_hton,
    (generic_swap_fn_t)vapi_msg_ioam_disable_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ioam_disable_reply = vapi_register_msg(&__vapi_metadata_ioam_disable_reply);
  VAPI_DBG("Assigned msg id %d to ioam_disable_reply", vapi_msg_id_ioam_disable_reply);
}

static inline void vapi_set_vapi_msg_ioam_disable_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ioam_disable_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ioam_disable_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ioam_disable
#define defined_vapi_msg_ioam_disable
typedef struct __attribute__ ((__packed__)) {
  u16 id; 
} vapi_payload_ioam_disable;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ioam_disable payload;
} vapi_msg_ioam_disable;

static inline void vapi_msg_ioam_disable_payload_hton(vapi_payload_ioam_disable *payload)
{
  payload->id = htobe16(payload->id);
}

static inline void vapi_msg_ioam_disable_payload_ntoh(vapi_payload_ioam_disable *payload)
{
  payload->id = be16toh(payload->id);
}

static inline void vapi_msg_ioam_disable_hton(vapi_msg_ioam_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ioam_disable'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ioam_disable_payload_hton(&msg->payload);
}

static inline void vapi_msg_ioam_disable_ntoh(vapi_msg_ioam_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ioam_disable'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ioam_disable_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ioam_disable_msg_size(vapi_msg_ioam_disable *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ioam_disable_msg_size(vapi_msg_ioam_disable *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ioam_disable) > buf_size)
    {
      VAPI_ERR("Truncated 'ioam_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ioam_disable));
      return -1;
    }
  if (vapi_calc_ioam_disable_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ioam_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ioam_disable_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ioam_disable* vapi_alloc_ioam_disable(struct vapi_ctx_s *ctx)
{
  vapi_msg_ioam_disable *msg = NULL;
  const size_t size = sizeof(vapi_msg_ioam_disable);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ioam_disable*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ioam_disable);

  return msg;
}

static inline vapi_error_e vapi_ioam_disable(struct vapi_ctx_s *ctx,
  vapi_msg_ioam_disable *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ioam_disable_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ioam_disable_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ioam_disable_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ioam_disable_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ioam_disable()
{
  static const char name[] = "ioam_disable";
  static const char name_with_crc[] = "ioam_disable_6b16a45e";
  static vapi_message_desc_t __vapi_metadata_ioam_disable = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ioam_disable, payload),
    (verify_msg_size_fn_t)vapi_verify_ioam_disable_msg_size,
    (generic_swap_fn_t)vapi_msg_ioam_disable_hton,
    (generic_swap_fn_t)vapi_msg_ioam_disable_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ioam_disable = vapi_register_msg(&__vapi_metadata_ioam_disable);
  VAPI_DBG("Assigned msg id %d to ioam_disable", vapi_msg_id_ioam_disable);
}
#endif

#ifndef defined_vapi_msg_ip_reassembly_set_reply
#define defined_vapi_msg_ip_reassembly_set_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ip_reassembly_set_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_reassembly_set_reply payload;
} vapi_msg_ip_reassembly_set_reply;

static inline void vapi_msg_ip_reassembly_set_reply_payload_hton(vapi_payload_ip_reassembly_set_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ip_reassembly_set_reply_payload_ntoh(vapi_payload_ip_reassembly_set_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ip_reassembly_set_reply_hton(vapi_msg_ip_reassembly_set_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_reassembly_set_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_reassembly_set_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_reassembly_set_reply_ntoh(vapi_msg_ip_reassembly_set_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_reassembly_set_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_reassembly_set_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_reassembly_set_reply_msg_size(vapi_msg_ip_reassembly_set_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_reassembly_set_reply_msg_size(vapi_msg_ip_reassembly_set_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_reassembly_set_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_reassembly_set_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_reassembly_set_reply));
      return -1;
    }
  if (vapi_calc_ip_reassembly_set_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_reassembly_set_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_reassembly_set_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_reassembly_set_reply()
{
  static const char name[] = "ip_reassembly_set_reply";
  static const char name_with_crc[] = "ip_reassembly_set_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ip_reassembly_set_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_reassembly_set_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_reassembly_set_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_reassembly_set_reply_hton,
    (generic_swap_fn_t)vapi_msg_ip_reassembly_set_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_reassembly_set_reply = vapi_register_msg(&__vapi_metadata_ip_reassembly_set_reply);
  VAPI_DBG("Assigned msg id %d to ip_reassembly_set_reply", vapi_msg_id_ip_reassembly_set_reply);
}

static inline void vapi_set_vapi_msg_ip_reassembly_set_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_reassembly_set_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_reassembly_set_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_reassembly_set
#define defined_vapi_msg_ip_reassembly_set
typedef struct __attribute__ ((__packed__)) {
  u32 timeout_ms;
  u32 max_reassemblies;
  u32 max_reassembly_length;
  u32 expire_walk_interval_ms;
  bool is_ip6;
  vapi_enum_ip_reass_type type; 
} vapi_payload_ip_reassembly_set;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip_reassembly_set payload;
} vapi_msg_ip_reassembly_set;

static inline void vapi_msg_ip_reassembly_set_payload_hton(vapi_payload_ip_reassembly_set *payload)
{
  payload->timeout_ms = htobe32(payload->timeout_ms);
  payload->max_reassemblies = htobe32(payload->max_reassemblies);
  payload->max_reassembly_length = htobe32(payload->max_reassembly_length);
  payload->expire_walk_interval_ms = htobe32(payload->expire_walk_interval_ms);
  payload->type = (vapi_enum_ip_reass_type)htobe32(payload->type);
}

static inline void vapi_msg_ip_reassembly_set_payload_ntoh(vapi_payload_ip_reassembly_set *payload)
{
  payload->timeout_ms = be32toh(payload->timeout_ms);
  payload->max_reassemblies = be32toh(payload->max_reassemblies);
  payload->max_reassembly_length = be32toh(payload->max_reassembly_length);
  payload->expire_walk_interval_ms = be32toh(payload->expire_walk_interval_ms);
  payload->type = (vapi_enum_ip_reass_type)be32toh(payload->type);
}

static inline void vapi_msg_ip_reassembly_set_hton(vapi_msg_ip_reassembly_set *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_reassembly_set'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip_reassembly_set_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_reassembly_set_ntoh(vapi_msg_ip_reassembly_set *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_reassembly_set'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip_reassembly_set_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_reassembly_set_msg_size(vapi_msg_ip_reassembly_set *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_reassembly_set_msg_size(vapi_msg_ip_reassembly_set *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_reassembly_set) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_reassembly_set' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_reassembly_set));
      return -1;
    }
  if (vapi_calc_ip_reassembly_set_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_reassembly_set' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_reassembly_set_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_reassembly_set* vapi_alloc_ip_reassembly_set(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_reassembly_set *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_reassembly_set);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_reassembly_set*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_reassembly_set);

  return msg;
}

static inline vapi_error_e vapi_ip_reassembly_set(struct vapi_ctx_s *ctx,
  vapi_msg_ip_reassembly_set *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_reassembly_set_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ip_reassembly_set_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_reassembly_set_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ip_reassembly_set_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_reassembly_set()
{
  static const char name[] = "ip_reassembly_set";
  static const char name_with_crc[] = "ip_reassembly_set_16467d25";
  static vapi_message_desc_t __vapi_metadata_ip_reassembly_set = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip_reassembly_set, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_reassembly_set_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_reassembly_set_hton,
    (generic_swap_fn_t)vapi_msg_ip_reassembly_set_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_reassembly_set = vapi_register_msg(&__vapi_metadata_ip_reassembly_set);
  VAPI_DBG("Assigned msg id %d to ip_reassembly_set", vapi_msg_id_ip_reassembly_set);
}
#endif

#ifndef defined_vapi_msg_ip_reassembly_get_reply
#define defined_vapi_msg_ip_reassembly_get_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 timeout_ms;
  u32 max_reassemblies;
  u32 max_reassembly_length;
  u32 expire_walk_interval_ms;
  bool is_ip6; 
} vapi_payload_ip_reassembly_get_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_reassembly_get_reply payload;
} vapi_msg_ip_reassembly_get_reply;

static inline void vapi_msg_ip_reassembly_get_reply_payload_hton(vapi_payload_ip_reassembly_get_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->timeout_ms = htobe32(payload->timeout_ms);
  payload->max_reassemblies = htobe32(payload->max_reassemblies);
  payload->max_reassembly_length = htobe32(payload->max_reassembly_length);
  payload->expire_walk_interval_ms = htobe32(payload->expire_walk_interval_ms);
}

static inline void vapi_msg_ip_reassembly_get_reply_payload_ntoh(vapi_payload_ip_reassembly_get_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->timeout_ms = be32toh(payload->timeout_ms);
  payload->max_reassemblies = be32toh(payload->max_reassemblies);
  payload->max_reassembly_length = be32toh(payload->max_reassembly_length);
  payload->expire_walk_interval_ms = be32toh(payload->expire_walk_interval_ms);
}

static inline void vapi_msg_ip_reassembly_get_reply_hton(vapi_msg_ip_reassembly_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_reassembly_get_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_reassembly_get_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_reassembly_get_reply_ntoh(vapi_msg_ip_reassembly_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_reassembly_get_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_reassembly_get_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_reassembly_get_reply_msg_size(vapi_msg_ip_reassembly_get_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_reassembly_get_reply_msg_size(vapi_msg_ip_reassembly_get_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_reassembly_get_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_reassembly_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_reassembly_get_reply));
      return -1;
    }
  if (vapi_calc_ip_reassembly_get_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_reassembly_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_reassembly_get_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_reassembly_get_reply()
{
  static const char name[] = "ip_reassembly_get_reply";
  static const char name_with_crc[] = "ip_reassembly_get_reply_d5eb8d34";
  static vapi_message_desc_t __vapi_metadata_ip_reassembly_get_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_reassembly_get_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_reassembly_get_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_reassembly_get_reply_hton,
    (generic_swap_fn_t)vapi_msg_ip_reassembly_get_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_reassembly_get_reply = vapi_register_msg(&__vapi_metadata_ip_reassembly_get_reply);
  VAPI_DBG("Assigned msg id %d to ip_reassembly_get_reply", vapi_msg_id_ip_reassembly_get_reply);
}

static inline void vapi_set_vapi_msg_ip_reassembly_get_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_reassembly_get_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_reassembly_get_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_reassembly_get
#define defined_vapi_msg_ip_reassembly_get
typedef struct __attribute__ ((__packed__)) {
  bool is_ip6;
  vapi_enum_ip_reass_type type; 
} vapi_payload_ip_reassembly_get;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip_reassembly_get payload;
} vapi_msg_ip_reassembly_get;

static inline void vapi_msg_ip_reassembly_get_payload_hton(vapi_payload_ip_reassembly_get *payload)
{
  payload->type = (vapi_enum_ip_reass_type)htobe32(payload->type);
}

static inline void vapi_msg_ip_reassembly_get_payload_ntoh(vapi_payload_ip_reassembly_get *payload)
{
  payload->type = (vapi_enum_ip_reass_type)be32toh(payload->type);
}

static inline void vapi_msg_ip_reassembly_get_hton(vapi_msg_ip_reassembly_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_reassembly_get'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip_reassembly_get_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_reassembly_get_ntoh(vapi_msg_ip_reassembly_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_reassembly_get'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip_reassembly_get_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_reassembly_get_msg_size(vapi_msg_ip_reassembly_get *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_reassembly_get_msg_size(vapi_msg_ip_reassembly_get *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_reassembly_get) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_reassembly_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_reassembly_get));
      return -1;
    }
  if (vapi_calc_ip_reassembly_get_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_reassembly_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_reassembly_get_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_reassembly_get* vapi_alloc_ip_reassembly_get(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_reassembly_get *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_reassembly_get);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_reassembly_get*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_reassembly_get);

  return msg;
}

static inline vapi_error_e vapi_ip_reassembly_get(struct vapi_ctx_s *ctx,
  vapi_msg_ip_reassembly_get *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_reassembly_get_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ip_reassembly_get_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_reassembly_get_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ip_reassembly_get_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_reassembly_get()
{
  static const char name[] = "ip_reassembly_get";
  static const char name_with_crc[] = "ip_reassembly_get_ea13ff63";
  static vapi_message_desc_t __vapi_metadata_ip_reassembly_get = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip_reassembly_get, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_reassembly_get_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_reassembly_get_hton,
    (generic_swap_fn_t)vapi_msg_ip_reassembly_get_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_reassembly_get = vapi_register_msg(&__vapi_metadata_ip_reassembly_get);
  VAPI_DBG("Assigned msg id %d to ip_reassembly_get", vapi_msg_id_ip_reassembly_get);
}
#endif

#ifndef defined_vapi_msg_ip_reassembly_enable_disable_reply
#define defined_vapi_msg_ip_reassembly_enable_disable_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ip_reassembly_enable_disable_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_reassembly_enable_disable_reply payload;
} vapi_msg_ip_reassembly_enable_disable_reply;

static inline void vapi_msg_ip_reassembly_enable_disable_reply_payload_hton(vapi_payload_ip_reassembly_enable_disable_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ip_reassembly_enable_disable_reply_payload_ntoh(vapi_payload_ip_reassembly_enable_disable_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ip_reassembly_enable_disable_reply_hton(vapi_msg_ip_reassembly_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_reassembly_enable_disable_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_reassembly_enable_disable_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_reassembly_enable_disable_reply_ntoh(vapi_msg_ip_reassembly_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_reassembly_enable_disable_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_reassembly_enable_disable_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_reassembly_enable_disable_reply_msg_size(vapi_msg_ip_reassembly_enable_disable_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_reassembly_enable_disable_reply_msg_size(vapi_msg_ip_reassembly_enable_disable_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_reassembly_enable_disable_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_reassembly_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_reassembly_enable_disable_reply));
      return -1;
    }
  if (vapi_calc_ip_reassembly_enable_disable_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_reassembly_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_reassembly_enable_disable_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_reassembly_enable_disable_reply()
{
  static const char name[] = "ip_reassembly_enable_disable_reply";
  static const char name_with_crc[] = "ip_reassembly_enable_disable_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ip_reassembly_enable_disable_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_reassembly_enable_disable_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_reassembly_enable_disable_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_reassembly_enable_disable_reply_hton,
    (generic_swap_fn_t)vapi_msg_ip_reassembly_enable_disable_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_reassembly_enable_disable_reply = vapi_register_msg(&__vapi_metadata_ip_reassembly_enable_disable_reply);
  VAPI_DBG("Assigned msg id %d to ip_reassembly_enable_disable_reply", vapi_msg_id_ip_reassembly_enable_disable_reply);
}

static inline void vapi_set_vapi_msg_ip_reassembly_enable_disable_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_reassembly_enable_disable_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_reassembly_enable_disable_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_reassembly_enable_disable
#define defined_vapi_msg_ip_reassembly_enable_disable
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  bool enable_ip4;
  bool enable_ip6;
  vapi_enum_ip_reass_type type; 
} vapi_payload_ip_reassembly_enable_disable;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip_reassembly_enable_disable payload;
} vapi_msg_ip_reassembly_enable_disable;

static inline void vapi_msg_ip_reassembly_enable_disable_payload_hton(vapi_payload_ip_reassembly_enable_disable *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->type = (vapi_enum_ip_reass_type)htobe32(payload->type);
}

static inline void vapi_msg_ip_reassembly_enable_disable_payload_ntoh(vapi_payload_ip_reassembly_enable_disable *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->type = (vapi_enum_ip_reass_type)be32toh(payload->type);
}

static inline void vapi_msg_ip_reassembly_enable_disable_hton(vapi_msg_ip_reassembly_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_reassembly_enable_disable'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip_reassembly_enable_disable_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_reassembly_enable_disable_ntoh(vapi_msg_ip_reassembly_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_reassembly_enable_disable'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip_reassembly_enable_disable_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_reassembly_enable_disable_msg_size(vapi_msg_ip_reassembly_enable_disable *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_reassembly_enable_disable_msg_size(vapi_msg_ip_reassembly_enable_disable *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_reassembly_enable_disable) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_reassembly_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_reassembly_enable_disable));
      return -1;
    }
  if (vapi_calc_ip_reassembly_enable_disable_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_reassembly_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_reassembly_enable_disable_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_reassembly_enable_disable* vapi_alloc_ip_reassembly_enable_disable(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_reassembly_enable_disable *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_reassembly_enable_disable);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_reassembly_enable_disable*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_reassembly_enable_disable);

  return msg;
}

static inline vapi_error_e vapi_ip_reassembly_enable_disable(struct vapi_ctx_s *ctx,
  vapi_msg_ip_reassembly_enable_disable *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_reassembly_enable_disable_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ip_reassembly_enable_disable_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_reassembly_enable_disable_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ip_reassembly_enable_disable_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_reassembly_enable_disable()
{
  static const char name[] = "ip_reassembly_enable_disable";
  static const char name_with_crc[] = "ip_reassembly_enable_disable_eb77968d";
  static vapi_message_desc_t __vapi_metadata_ip_reassembly_enable_disable = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip_reassembly_enable_disable, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_reassembly_enable_disable_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_reassembly_enable_disable_hton,
    (generic_swap_fn_t)vapi_msg_ip_reassembly_enable_disable_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_reassembly_enable_disable = vapi_register_msg(&__vapi_metadata_ip_reassembly_enable_disable);
  VAPI_DBG("Assigned msg id %d to ip_reassembly_enable_disable", vapi_msg_id_ip_reassembly_enable_disable);
}
#endif

#ifndef defined_vapi_msg_ip_local_reass_enable_disable_reply
#define defined_vapi_msg_ip_local_reass_enable_disable_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ip_local_reass_enable_disable_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_local_reass_enable_disable_reply payload;
} vapi_msg_ip_local_reass_enable_disable_reply;

static inline void vapi_msg_ip_local_reass_enable_disable_reply_payload_hton(vapi_payload_ip_local_reass_enable_disable_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ip_local_reass_enable_disable_reply_payload_ntoh(vapi_payload_ip_local_reass_enable_disable_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ip_local_reass_enable_disable_reply_hton(vapi_msg_ip_local_reass_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_local_reass_enable_disable_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_local_reass_enable_disable_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_local_reass_enable_disable_reply_ntoh(vapi_msg_ip_local_reass_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_local_reass_enable_disable_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_local_reass_enable_disable_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_local_reass_enable_disable_reply_msg_size(vapi_msg_ip_local_reass_enable_disable_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_local_reass_enable_disable_reply_msg_size(vapi_msg_ip_local_reass_enable_disable_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_local_reass_enable_disable_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_local_reass_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_local_reass_enable_disable_reply));
      return -1;
    }
  if (vapi_calc_ip_local_reass_enable_disable_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_local_reass_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_local_reass_enable_disable_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_local_reass_enable_disable_reply()
{
  static const char name[] = "ip_local_reass_enable_disable_reply";
  static const char name_with_crc[] = "ip_local_reass_enable_disable_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ip_local_reass_enable_disable_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_local_reass_enable_disable_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_local_reass_enable_disable_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_local_reass_enable_disable_reply_hton,
    (generic_swap_fn_t)vapi_msg_ip_local_reass_enable_disable_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_local_reass_enable_disable_reply = vapi_register_msg(&__vapi_metadata_ip_local_reass_enable_disable_reply);
  VAPI_DBG("Assigned msg id %d to ip_local_reass_enable_disable_reply", vapi_msg_id_ip_local_reass_enable_disable_reply);
}

static inline void vapi_set_vapi_msg_ip_local_reass_enable_disable_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_local_reass_enable_disable_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_local_reass_enable_disable_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_local_reass_enable_disable
#define defined_vapi_msg_ip_local_reass_enable_disable
typedef struct __attribute__ ((__packed__)) {
  bool enable_ip4;
  bool enable_ip6; 
} vapi_payload_ip_local_reass_enable_disable;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip_local_reass_enable_disable payload;
} vapi_msg_ip_local_reass_enable_disable;

static inline void vapi_msg_ip_local_reass_enable_disable_payload_hton(vapi_payload_ip_local_reass_enable_disable *payload)
{

}

static inline void vapi_msg_ip_local_reass_enable_disable_payload_ntoh(vapi_payload_ip_local_reass_enable_disable *payload)
{

}

static inline void vapi_msg_ip_local_reass_enable_disable_hton(vapi_msg_ip_local_reass_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_local_reass_enable_disable'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip_local_reass_enable_disable_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_local_reass_enable_disable_ntoh(vapi_msg_ip_local_reass_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_local_reass_enable_disable'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip_local_reass_enable_disable_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_local_reass_enable_disable_msg_size(vapi_msg_ip_local_reass_enable_disable *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_local_reass_enable_disable_msg_size(vapi_msg_ip_local_reass_enable_disable *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_local_reass_enable_disable) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_local_reass_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_local_reass_enable_disable));
      return -1;
    }
  if (vapi_calc_ip_local_reass_enable_disable_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_local_reass_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_local_reass_enable_disable_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_local_reass_enable_disable* vapi_alloc_ip_local_reass_enable_disable(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_local_reass_enable_disable *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_local_reass_enable_disable);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_local_reass_enable_disable*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_local_reass_enable_disable);

  return msg;
}

static inline vapi_error_e vapi_ip_local_reass_enable_disable(struct vapi_ctx_s *ctx,
  vapi_msg_ip_local_reass_enable_disable *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_local_reass_enable_disable_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ip_local_reass_enable_disable_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_local_reass_enable_disable_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ip_local_reass_enable_disable_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_local_reass_enable_disable()
{
  static const char name[] = "ip_local_reass_enable_disable";
  static const char name_with_crc[] = "ip_local_reass_enable_disable_34e2ccc4";
  static vapi_message_desc_t __vapi_metadata_ip_local_reass_enable_disable = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip_local_reass_enable_disable, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_local_reass_enable_disable_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_local_reass_enable_disable_hton,
    (generic_swap_fn_t)vapi_msg_ip_local_reass_enable_disable_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_local_reass_enable_disable = vapi_register_msg(&__vapi_metadata_ip_local_reass_enable_disable);
  VAPI_DBG("Assigned msg id %d to ip_local_reass_enable_disable", vapi_msg_id_ip_local_reass_enable_disable);
}
#endif

#ifndef defined_vapi_msg_ip_local_reass_get_reply
#define defined_vapi_msg_ip_local_reass_get_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  bool ip4_is_enabled;
  bool ip6_is_enabled; 
} vapi_payload_ip_local_reass_get_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_local_reass_get_reply payload;
} vapi_msg_ip_local_reass_get_reply;

static inline void vapi_msg_ip_local_reass_get_reply_payload_hton(vapi_payload_ip_local_reass_get_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ip_local_reass_get_reply_payload_ntoh(vapi_payload_ip_local_reass_get_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ip_local_reass_get_reply_hton(vapi_msg_ip_local_reass_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_local_reass_get_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_local_reass_get_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_local_reass_get_reply_ntoh(vapi_msg_ip_local_reass_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_local_reass_get_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_local_reass_get_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_local_reass_get_reply_msg_size(vapi_msg_ip_local_reass_get_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_local_reass_get_reply_msg_size(vapi_msg_ip_local_reass_get_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_local_reass_get_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_local_reass_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_local_reass_get_reply));
      return -1;
    }
  if (vapi_calc_ip_local_reass_get_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_local_reass_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_local_reass_get_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_local_reass_get_reply()
{
  static const char name[] = "ip_local_reass_get_reply";
  static const char name_with_crc[] = "ip_local_reass_get_reply_3e93a702";
  static vapi_message_desc_t __vapi_metadata_ip_local_reass_get_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_local_reass_get_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_local_reass_get_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_local_reass_get_reply_hton,
    (generic_swap_fn_t)vapi_msg_ip_local_reass_get_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_local_reass_get_reply = vapi_register_msg(&__vapi_metadata_ip_local_reass_get_reply);
  VAPI_DBG("Assigned msg id %d to ip_local_reass_get_reply", vapi_msg_id_ip_local_reass_get_reply);
}

static inline void vapi_set_vapi_msg_ip_local_reass_get_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_local_reass_get_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_local_reass_get_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_local_reass_get
#define defined_vapi_msg_ip_local_reass_get
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_ip_local_reass_get;

static inline void vapi_msg_ip_local_reass_get_hton(vapi_msg_ip_local_reass_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_local_reass_get'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_ip_local_reass_get_ntoh(vapi_msg_ip_local_reass_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_local_reass_get'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_ip_local_reass_get_msg_size(vapi_msg_ip_local_reass_get *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_local_reass_get_msg_size(vapi_msg_ip_local_reass_get *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_local_reass_get) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_local_reass_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_local_reass_get));
      return -1;
    }
  if (vapi_calc_ip_local_reass_get_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_local_reass_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_local_reass_get_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_local_reass_get* vapi_alloc_ip_local_reass_get(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_local_reass_get *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_local_reass_get);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_local_reass_get*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_local_reass_get);

  return msg;
}

static inline vapi_error_e vapi_ip_local_reass_get(struct vapi_ctx_s *ctx,
  vapi_msg_ip_local_reass_get *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_local_reass_get_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ip_local_reass_get_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_local_reass_get_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ip_local_reass_get_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_local_reass_get()
{
  static const char name[] = "ip_local_reass_get";
  static const char name_with_crc[] = "ip_local_reass_get_51077d14";
  static vapi_message_desc_t __vapi_metadata_ip_local_reass_get = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_ip_local_reass_get_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_local_reass_get_hton,
    (generic_swap_fn_t)vapi_msg_ip_local_reass_get_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_local_reass_get = vapi_register_msg(&__vapi_metadata_ip_local_reass_get);
  VAPI_DBG("Assigned msg id %d to ip_local_reass_get", vapi_msg_id_ip_local_reass_get);
}
#endif

#ifndef defined_vapi_msg_ip_path_mtu_update_reply
#define defined_vapi_msg_ip_path_mtu_update_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ip_path_mtu_update_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_path_mtu_update_reply payload;
} vapi_msg_ip_path_mtu_update_reply;

static inline void vapi_msg_ip_path_mtu_update_reply_payload_hton(vapi_payload_ip_path_mtu_update_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ip_path_mtu_update_reply_payload_ntoh(vapi_payload_ip_path_mtu_update_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ip_path_mtu_update_reply_hton(vapi_msg_ip_path_mtu_update_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_path_mtu_update_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_path_mtu_update_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_path_mtu_update_reply_ntoh(vapi_msg_ip_path_mtu_update_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_path_mtu_update_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_path_mtu_update_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_path_mtu_update_reply_msg_size(vapi_msg_ip_path_mtu_update_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_path_mtu_update_reply_msg_size(vapi_msg_ip_path_mtu_update_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_path_mtu_update_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_path_mtu_update_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_path_mtu_update_reply));
      return -1;
    }
  if (vapi_calc_ip_path_mtu_update_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_path_mtu_update_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_path_mtu_update_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_path_mtu_update_reply()
{
  static const char name[] = "ip_path_mtu_update_reply";
  static const char name_with_crc[] = "ip_path_mtu_update_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ip_path_mtu_update_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_path_mtu_update_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_path_mtu_update_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_path_mtu_update_reply_hton,
    (generic_swap_fn_t)vapi_msg_ip_path_mtu_update_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_path_mtu_update_reply = vapi_register_msg(&__vapi_metadata_ip_path_mtu_update_reply);
  VAPI_DBG("Assigned msg id %d to ip_path_mtu_update_reply", vapi_msg_id_ip_path_mtu_update_reply);
}

static inline void vapi_set_vapi_msg_ip_path_mtu_update_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_path_mtu_update_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_path_mtu_update_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_path_mtu_update
#define defined_vapi_msg_ip_path_mtu_update
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip_path_mtu pmtu; 
} vapi_payload_ip_path_mtu_update;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip_path_mtu_update payload;
} vapi_msg_ip_path_mtu_update;

static inline void vapi_msg_ip_path_mtu_update_payload_hton(vapi_payload_ip_path_mtu_update *payload)
{
  vapi_type_ip_path_mtu_hton(&payload->pmtu);
}

static inline void vapi_msg_ip_path_mtu_update_payload_ntoh(vapi_payload_ip_path_mtu_update *payload)
{
  vapi_type_ip_path_mtu_ntoh(&payload->pmtu);
}

static inline void vapi_msg_ip_path_mtu_update_hton(vapi_msg_ip_path_mtu_update *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_path_mtu_update'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip_path_mtu_update_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_path_mtu_update_ntoh(vapi_msg_ip_path_mtu_update *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_path_mtu_update'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip_path_mtu_update_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_path_mtu_update_msg_size(vapi_msg_ip_path_mtu_update *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_path_mtu_update_msg_size(vapi_msg_ip_path_mtu_update *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_path_mtu_update) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_path_mtu_update' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_path_mtu_update));
      return -1;
    }
  if (vapi_calc_ip_path_mtu_update_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_path_mtu_update' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_path_mtu_update_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_path_mtu_update* vapi_alloc_ip_path_mtu_update(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_path_mtu_update *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_path_mtu_update);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_path_mtu_update*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_path_mtu_update);

  return msg;
}

static inline vapi_error_e vapi_ip_path_mtu_update(struct vapi_ctx_s *ctx,
  vapi_msg_ip_path_mtu_update *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_path_mtu_update_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ip_path_mtu_update_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_path_mtu_update_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ip_path_mtu_update_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_path_mtu_update()
{
  static const char name[] = "ip_path_mtu_update";
  static const char name_with_crc[] = "ip_path_mtu_update_10bbe5cb";
  static vapi_message_desc_t __vapi_metadata_ip_path_mtu_update = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip_path_mtu_update, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_path_mtu_update_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_path_mtu_update_hton,
    (generic_swap_fn_t)vapi_msg_ip_path_mtu_update_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_path_mtu_update = vapi_register_msg(&__vapi_metadata_ip_path_mtu_update);
  VAPI_DBG("Assigned msg id %d to ip_path_mtu_update", vapi_msg_id_ip_path_mtu_update);
}
#endif

#ifndef defined_vapi_msg_ip_path_mtu_get_reply
#define defined_vapi_msg_ip_path_mtu_get_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 cursor; 
} vapi_payload_ip_path_mtu_get_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_path_mtu_get_reply payload;
} vapi_msg_ip_path_mtu_get_reply;

static inline void vapi_msg_ip_path_mtu_get_reply_payload_hton(vapi_payload_ip_path_mtu_get_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->cursor = htobe32(payload->cursor);
}

static inline void vapi_msg_ip_path_mtu_get_reply_payload_ntoh(vapi_payload_ip_path_mtu_get_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->cursor = be32toh(payload->cursor);
}

static inline void vapi_msg_ip_path_mtu_get_reply_hton(vapi_msg_ip_path_mtu_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_path_mtu_get_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_path_mtu_get_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_path_mtu_get_reply_ntoh(vapi_msg_ip_path_mtu_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_path_mtu_get_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_path_mtu_get_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_path_mtu_get_reply_msg_size(vapi_msg_ip_path_mtu_get_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_path_mtu_get_reply_msg_size(vapi_msg_ip_path_mtu_get_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_path_mtu_get_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_path_mtu_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_path_mtu_get_reply));
      return -1;
    }
  if (vapi_calc_ip_path_mtu_get_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_path_mtu_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_path_mtu_get_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_path_mtu_get_reply()
{
  static const char name[] = "ip_path_mtu_get_reply";
  static const char name_with_crc[] = "ip_path_mtu_get_reply_53b48f5d";
  static vapi_message_desc_t __vapi_metadata_ip_path_mtu_get_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_path_mtu_get_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_path_mtu_get_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_path_mtu_get_reply_hton,
    (generic_swap_fn_t)vapi_msg_ip_path_mtu_get_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_path_mtu_get_reply = vapi_register_msg(&__vapi_metadata_ip_path_mtu_get_reply);
  VAPI_DBG("Assigned msg id %d to ip_path_mtu_get_reply", vapi_msg_id_ip_path_mtu_get_reply);
}

static inline void vapi_set_vapi_msg_ip_path_mtu_get_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_path_mtu_get_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_path_mtu_get_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_path_mtu_details
#define defined_vapi_msg_ip_path_mtu_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip_path_mtu pmtu; 
} vapi_payload_ip_path_mtu_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_path_mtu_details payload;
} vapi_msg_ip_path_mtu_details;

static inline void vapi_msg_ip_path_mtu_details_payload_hton(vapi_payload_ip_path_mtu_details *payload)
{
  vapi_type_ip_path_mtu_hton(&payload->pmtu);
}

static inline void vapi_msg_ip_path_mtu_details_payload_ntoh(vapi_payload_ip_path_mtu_details *payload)
{
  vapi_type_ip_path_mtu_ntoh(&payload->pmtu);
}

static inline void vapi_msg_ip_path_mtu_details_hton(vapi_msg_ip_path_mtu_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_path_mtu_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_path_mtu_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_path_mtu_details_ntoh(vapi_msg_ip_path_mtu_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_path_mtu_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_path_mtu_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_path_mtu_details_msg_size(vapi_msg_ip_path_mtu_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_path_mtu_details_msg_size(vapi_msg_ip_path_mtu_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_path_mtu_details) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_path_mtu_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_path_mtu_details));
      return -1;
    }
  if (vapi_calc_ip_path_mtu_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_path_mtu_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_path_mtu_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_path_mtu_details()
{
  static const char name[] = "ip_path_mtu_details";
  static const char name_with_crc[] = "ip_path_mtu_details_ac9539a7";
  static vapi_message_desc_t __vapi_metadata_ip_path_mtu_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_path_mtu_details, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_path_mtu_details_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_path_mtu_details_hton,
    (generic_swap_fn_t)vapi_msg_ip_path_mtu_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_path_mtu_details = vapi_register_msg(&__vapi_metadata_ip_path_mtu_details);
  VAPI_DBG("Assigned msg id %d to ip_path_mtu_details", vapi_msg_id_ip_path_mtu_details);
}
#endif

#ifndef defined_vapi_msg_ip_path_mtu_get
#define defined_vapi_msg_ip_path_mtu_get
typedef struct __attribute__ ((__packed__)) {
  u32 cursor; 
} vapi_payload_ip_path_mtu_get;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip_path_mtu_get payload;
} vapi_msg_ip_path_mtu_get;

static inline void vapi_msg_ip_path_mtu_get_payload_hton(vapi_payload_ip_path_mtu_get *payload)
{
  payload->cursor = htobe32(payload->cursor);
}

static inline void vapi_msg_ip_path_mtu_get_payload_ntoh(vapi_payload_ip_path_mtu_get *payload)
{
  payload->cursor = be32toh(payload->cursor);
}

static inline void vapi_msg_ip_path_mtu_get_hton(vapi_msg_ip_path_mtu_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_path_mtu_get'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip_path_mtu_get_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_path_mtu_get_ntoh(vapi_msg_ip_path_mtu_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_path_mtu_get'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip_path_mtu_get_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_path_mtu_get_msg_size(vapi_msg_ip_path_mtu_get *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_path_mtu_get_msg_size(vapi_msg_ip_path_mtu_get *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_path_mtu_get) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_path_mtu_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_path_mtu_get));
      return -1;
    }
  if (vapi_calc_ip_path_mtu_get_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_path_mtu_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_path_mtu_get_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_path_mtu_get* vapi_alloc_ip_path_mtu_get(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_path_mtu_get *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_path_mtu_get);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_path_mtu_get*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_path_mtu_get);

  return msg;
}

static inline vapi_error_e vapi_ip_path_mtu_get(struct vapi_ctx_s *ctx,
  vapi_msg_ip_path_mtu_get *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_path_mtu_get_reply *reply),
  void *reply_callback_ctx,
  vapi_error_e (*details_callback)(struct vapi_ctx_s *ctx,
                                   void *callback_ctx,
                                   vapi_error_e rv,
                                   bool is_last,
                                   vapi_payload_ip_path_mtu_details *details),
  void *details_callback_ctx)
{
  if (!msg || !reply_callback || !details_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ip_path_mtu_get_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_path_mtu_details, VAPI_REQUEST_STREAM, 
                       (vapi_cb_t)details_callback, details_callback_ctx);
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_path_mtu_get_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ip_path_mtu_get_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_path_mtu_get()
{
  static const char name[] = "ip_path_mtu_get";
  static const char name_with_crc[] = "ip_path_mtu_get_f75ba505";
  static vapi_message_desc_t __vapi_metadata_ip_path_mtu_get = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip_path_mtu_get, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_path_mtu_get_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_path_mtu_get_hton,
    (generic_swap_fn_t)vapi_msg_ip_path_mtu_get_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_path_mtu_get = vapi_register_msg(&__vapi_metadata_ip_path_mtu_get);
  VAPI_DBG("Assigned msg id %d to ip_path_mtu_get", vapi_msg_id_ip_path_mtu_get);
}
#endif

#ifndef defined_vapi_msg_ip_path_mtu_replace_begin_reply
#define defined_vapi_msg_ip_path_mtu_replace_begin_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ip_path_mtu_replace_begin_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_path_mtu_replace_begin_reply payload;
} vapi_msg_ip_path_mtu_replace_begin_reply;

static inline void vapi_msg_ip_path_mtu_replace_begin_reply_payload_hton(vapi_payload_ip_path_mtu_replace_begin_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ip_path_mtu_replace_begin_reply_payload_ntoh(vapi_payload_ip_path_mtu_replace_begin_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ip_path_mtu_replace_begin_reply_hton(vapi_msg_ip_path_mtu_replace_begin_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_path_mtu_replace_begin_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_path_mtu_replace_begin_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_path_mtu_replace_begin_reply_ntoh(vapi_msg_ip_path_mtu_replace_begin_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_path_mtu_replace_begin_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_path_mtu_replace_begin_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_path_mtu_replace_begin_reply_msg_size(vapi_msg_ip_path_mtu_replace_begin_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_path_mtu_replace_begin_reply_msg_size(vapi_msg_ip_path_mtu_replace_begin_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_path_mtu_replace_begin_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_path_mtu_replace_begin_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_path_mtu_replace_begin_reply));
      return -1;
    }
  if (vapi_calc_ip_path_mtu_replace_begin_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_path_mtu_replace_begin_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_path_mtu_replace_begin_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_path_mtu_replace_begin_reply()
{
  static const char name[] = "ip_path_mtu_replace_begin_reply";
  static const char name_with_crc[] = "ip_path_mtu_replace_begin_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ip_path_mtu_replace_begin_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_path_mtu_replace_begin_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_path_mtu_replace_begin_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_path_mtu_replace_begin_reply_hton,
    (generic_swap_fn_t)vapi_msg_ip_path_mtu_replace_begin_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_path_mtu_replace_begin_reply = vapi_register_msg(&__vapi_metadata_ip_path_mtu_replace_begin_reply);
  VAPI_DBG("Assigned msg id %d to ip_path_mtu_replace_begin_reply", vapi_msg_id_ip_path_mtu_replace_begin_reply);
}

static inline void vapi_set_vapi_msg_ip_path_mtu_replace_begin_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_path_mtu_replace_begin_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_path_mtu_replace_begin_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_path_mtu_replace_begin
#define defined_vapi_msg_ip_path_mtu_replace_begin
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_ip_path_mtu_replace_begin;

static inline void vapi_msg_ip_path_mtu_replace_begin_hton(vapi_msg_ip_path_mtu_replace_begin *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_path_mtu_replace_begin'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_ip_path_mtu_replace_begin_ntoh(vapi_msg_ip_path_mtu_replace_begin *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_path_mtu_replace_begin'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_ip_path_mtu_replace_begin_msg_size(vapi_msg_ip_path_mtu_replace_begin *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_path_mtu_replace_begin_msg_size(vapi_msg_ip_path_mtu_replace_begin *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_path_mtu_replace_begin) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_path_mtu_replace_begin' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_path_mtu_replace_begin));
      return -1;
    }
  if (vapi_calc_ip_path_mtu_replace_begin_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_path_mtu_replace_begin' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_path_mtu_replace_begin_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_path_mtu_replace_begin* vapi_alloc_ip_path_mtu_replace_begin(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_path_mtu_replace_begin *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_path_mtu_replace_begin);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_path_mtu_replace_begin*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_path_mtu_replace_begin);

  return msg;
}

static inline vapi_error_e vapi_ip_path_mtu_replace_begin(struct vapi_ctx_s *ctx,
  vapi_msg_ip_path_mtu_replace_begin *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_path_mtu_replace_begin_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ip_path_mtu_replace_begin_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_path_mtu_replace_begin_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ip_path_mtu_replace_begin_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_path_mtu_replace_begin()
{
  static const char name[] = "ip_path_mtu_replace_begin";
  static const char name_with_crc[] = "ip_path_mtu_replace_begin_51077d14";
  static vapi_message_desc_t __vapi_metadata_ip_path_mtu_replace_begin = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_ip_path_mtu_replace_begin_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_path_mtu_replace_begin_hton,
    (generic_swap_fn_t)vapi_msg_ip_path_mtu_replace_begin_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_path_mtu_replace_begin = vapi_register_msg(&__vapi_metadata_ip_path_mtu_replace_begin);
  VAPI_DBG("Assigned msg id %d to ip_path_mtu_replace_begin", vapi_msg_id_ip_path_mtu_replace_begin);
}
#endif

#ifndef defined_vapi_msg_ip_path_mtu_replace_end_reply
#define defined_vapi_msg_ip_path_mtu_replace_end_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ip_path_mtu_replace_end_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_path_mtu_replace_end_reply payload;
} vapi_msg_ip_path_mtu_replace_end_reply;

static inline void vapi_msg_ip_path_mtu_replace_end_reply_payload_hton(vapi_payload_ip_path_mtu_replace_end_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ip_path_mtu_replace_end_reply_payload_ntoh(vapi_payload_ip_path_mtu_replace_end_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ip_path_mtu_replace_end_reply_hton(vapi_msg_ip_path_mtu_replace_end_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_path_mtu_replace_end_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_path_mtu_replace_end_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_path_mtu_replace_end_reply_ntoh(vapi_msg_ip_path_mtu_replace_end_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_path_mtu_replace_end_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_path_mtu_replace_end_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_path_mtu_replace_end_reply_msg_size(vapi_msg_ip_path_mtu_replace_end_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_path_mtu_replace_end_reply_msg_size(vapi_msg_ip_path_mtu_replace_end_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_path_mtu_replace_end_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_path_mtu_replace_end_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_path_mtu_replace_end_reply));
      return -1;
    }
  if (vapi_calc_ip_path_mtu_replace_end_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_path_mtu_replace_end_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_path_mtu_replace_end_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_path_mtu_replace_end_reply()
{
  static const char name[] = "ip_path_mtu_replace_end_reply";
  static const char name_with_crc[] = "ip_path_mtu_replace_end_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ip_path_mtu_replace_end_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_path_mtu_replace_end_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_path_mtu_replace_end_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_path_mtu_replace_end_reply_hton,
    (generic_swap_fn_t)vapi_msg_ip_path_mtu_replace_end_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_path_mtu_replace_end_reply = vapi_register_msg(&__vapi_metadata_ip_path_mtu_replace_end_reply);
  VAPI_DBG("Assigned msg id %d to ip_path_mtu_replace_end_reply", vapi_msg_id_ip_path_mtu_replace_end_reply);
}

static inline void vapi_set_vapi_msg_ip_path_mtu_replace_end_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_path_mtu_replace_end_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_path_mtu_replace_end_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_path_mtu_replace_end
#define defined_vapi_msg_ip_path_mtu_replace_end
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_ip_path_mtu_replace_end;

static inline void vapi_msg_ip_path_mtu_replace_end_hton(vapi_msg_ip_path_mtu_replace_end *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_path_mtu_replace_end'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_ip_path_mtu_replace_end_ntoh(vapi_msg_ip_path_mtu_replace_end *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_path_mtu_replace_end'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_ip_path_mtu_replace_end_msg_size(vapi_msg_ip_path_mtu_replace_end *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_path_mtu_replace_end_msg_size(vapi_msg_ip_path_mtu_replace_end *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_path_mtu_replace_end) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_path_mtu_replace_end' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_path_mtu_replace_end));
      return -1;
    }
  if (vapi_calc_ip_path_mtu_replace_end_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_path_mtu_replace_end' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_path_mtu_replace_end_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_path_mtu_replace_end* vapi_alloc_ip_path_mtu_replace_end(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_path_mtu_replace_end *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_path_mtu_replace_end);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_path_mtu_replace_end*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_path_mtu_replace_end);

  return msg;
}

static inline vapi_error_e vapi_ip_path_mtu_replace_end(struct vapi_ctx_s *ctx,
  vapi_msg_ip_path_mtu_replace_end *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_path_mtu_replace_end_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ip_path_mtu_replace_end_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_path_mtu_replace_end_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ip_path_mtu_replace_end_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_path_mtu_replace_end()
{
  static const char name[] = "ip_path_mtu_replace_end";
  static const char name_with_crc[] = "ip_path_mtu_replace_end_51077d14";
  static vapi_message_desc_t __vapi_metadata_ip_path_mtu_replace_end = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_ip_path_mtu_replace_end_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_path_mtu_replace_end_hton,
    (generic_swap_fn_t)vapi_msg_ip_path_mtu_replace_end_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_path_mtu_replace_end = vapi_register_msg(&__vapi_metadata_ip_path_mtu_replace_end);
  VAPI_DBG("Assigned msg id %d to ip_path_mtu_replace_end", vapi_msg_id_ip_path_mtu_replace_end);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
