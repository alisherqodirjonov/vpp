#ifndef __included_dhcp_api_json
#define __included_dhcp_api_json

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

extern vapi_msg_id_t vapi_msg_id_dhcp_plugin_get_version;
extern vapi_msg_id_t vapi_msg_id_dhcp_plugin_get_version_reply;
extern vapi_msg_id_t vapi_msg_id_dhcp_plugin_control_ping;
extern vapi_msg_id_t vapi_msg_id_dhcp_plugin_control_ping_reply;
extern vapi_msg_id_t vapi_msg_id_dhcp_proxy_config;
extern vapi_msg_id_t vapi_msg_id_dhcp_proxy_config_reply;
extern vapi_msg_id_t vapi_msg_id_dhcp_proxy_set_vss;
extern vapi_msg_id_t vapi_msg_id_dhcp_proxy_set_vss_reply;
extern vapi_msg_id_t vapi_msg_id_dhcp_client_config;
extern vapi_msg_id_t vapi_msg_id_dhcp_client_config_reply;
extern vapi_msg_id_t vapi_msg_id_dhcp_compl_event;
extern vapi_msg_id_t vapi_msg_id_dhcp_client_dump;
extern vapi_msg_id_t vapi_msg_id_dhcp_client_details;
extern vapi_msg_id_t vapi_msg_id_dhcp_proxy_dump;
extern vapi_msg_id_t vapi_msg_id_dhcp_proxy_details;
extern vapi_msg_id_t vapi_msg_id_dhcp_client_detect_enable_disable;
extern vapi_msg_id_t vapi_msg_id_dhcp_client_detect_enable_disable_reply;
extern vapi_msg_id_t vapi_msg_id_dhcp6_duid_ll_set;
extern vapi_msg_id_t vapi_msg_id_dhcp6_duid_ll_set_reply;
extern vapi_msg_id_t vapi_msg_id_dhcp6_clients_enable_disable;
extern vapi_msg_id_t vapi_msg_id_dhcp6_clients_enable_disable_reply;
extern vapi_msg_id_t vapi_msg_id_dhcp6_send_client_message;
extern vapi_msg_id_t vapi_msg_id_dhcp6_send_client_message_reply;
extern vapi_msg_id_t vapi_msg_id_dhcp6_pd_send_client_message;
extern vapi_msg_id_t vapi_msg_id_dhcp6_pd_send_client_message_reply;
extern vapi_msg_id_t vapi_msg_id_want_dhcp6_reply_events;
extern vapi_msg_id_t vapi_msg_id_want_dhcp6_reply_events_reply;
extern vapi_msg_id_t vapi_msg_id_want_dhcp6_pd_reply_events;
extern vapi_msg_id_t vapi_msg_id_want_dhcp6_pd_reply_events_reply;
extern vapi_msg_id_t vapi_msg_id_dhcp6_reply_event;
extern vapi_msg_id_t vapi_msg_id_dhcp6_pd_reply_event;

#define DEFINE_VAPI_MSG_IDS_DHCP_API_JSON\
  vapi_msg_id_t vapi_msg_id_dhcp_plugin_get_version;\
  vapi_msg_id_t vapi_msg_id_dhcp_plugin_get_version_reply;\
  vapi_msg_id_t vapi_msg_id_dhcp_plugin_control_ping;\
  vapi_msg_id_t vapi_msg_id_dhcp_plugin_control_ping_reply;\
  vapi_msg_id_t vapi_msg_id_dhcp_proxy_config;\
  vapi_msg_id_t vapi_msg_id_dhcp_proxy_config_reply;\
  vapi_msg_id_t vapi_msg_id_dhcp_proxy_set_vss;\
  vapi_msg_id_t vapi_msg_id_dhcp_proxy_set_vss_reply;\
  vapi_msg_id_t vapi_msg_id_dhcp_client_config;\
  vapi_msg_id_t vapi_msg_id_dhcp_client_config_reply;\
  vapi_msg_id_t vapi_msg_id_dhcp_compl_event;\
  vapi_msg_id_t vapi_msg_id_dhcp_client_dump;\
  vapi_msg_id_t vapi_msg_id_dhcp_client_details;\
  vapi_msg_id_t vapi_msg_id_dhcp_proxy_dump;\
  vapi_msg_id_t vapi_msg_id_dhcp_proxy_details;\
  vapi_msg_id_t vapi_msg_id_dhcp_client_detect_enable_disable;\
  vapi_msg_id_t vapi_msg_id_dhcp_client_detect_enable_disable_reply;\
  vapi_msg_id_t vapi_msg_id_dhcp6_duid_ll_set;\
  vapi_msg_id_t vapi_msg_id_dhcp6_duid_ll_set_reply;\
  vapi_msg_id_t vapi_msg_id_dhcp6_clients_enable_disable;\
  vapi_msg_id_t vapi_msg_id_dhcp6_clients_enable_disable_reply;\
  vapi_msg_id_t vapi_msg_id_dhcp6_send_client_message;\
  vapi_msg_id_t vapi_msg_id_dhcp6_send_client_message_reply;\
  vapi_msg_id_t vapi_msg_id_dhcp6_pd_send_client_message;\
  vapi_msg_id_t vapi_msg_id_dhcp6_pd_send_client_message_reply;\
  vapi_msg_id_t vapi_msg_id_want_dhcp6_reply_events;\
  vapi_msg_id_t vapi_msg_id_want_dhcp6_reply_events_reply;\
  vapi_msg_id_t vapi_msg_id_want_dhcp6_pd_reply_events;\
  vapi_msg_id_t vapi_msg_id_want_dhcp6_pd_reply_events_reply;\
  vapi_msg_id_t vapi_msg_id_dhcp6_reply_event;\
  vapi_msg_id_t vapi_msg_id_dhcp6_pd_reply_event;


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

#ifndef defined_vapi_enum_vss_type
#define defined_vapi_enum_vss_type
typedef enum {
  VSS_TYPE_API_ASCII = 0,
  VSS_TYPE_API_VPN_ID = 1,
  VSS_TYPE_API_INVALID = 123,
  VSS_TYPE_API_DEFAULT = 255,
}  vapi_enum_vss_type;

#endif

#ifndef defined_vapi_enum_dhcp_client_state
#define defined_vapi_enum_dhcp_client_state
typedef enum {
  DHCP_CLIENT_STATE_API_DISCOVER = 0,
  DHCP_CLIENT_STATE_API_REQUEST = 1,
  DHCP_CLIENT_STATE_API_BOUND = 2,
}  vapi_enum_dhcp_client_state;

#endif

#ifndef defined_vapi_enum_dhcpv6_msg_type
#define defined_vapi_enum_dhcpv6_msg_type
typedef enum {
  DHCPV6_MSG_API_SOLICIT = 1,
  DHCPV6_MSG_API_ADVERTISE = 2,
  DHCPV6_MSG_API_REQUEST = 3,
  DHCPV6_MSG_API_CONFIRM = 4,
  DHCPV6_MSG_API_RENEW = 5,
  DHCPV6_MSG_API_REBIND = 6,
  DHCPV6_MSG_API_REPLY = 7,
  DHCPV6_MSG_API_RELEASE = 8,
  DHCPV6_MSG_API_DECLINE = 9,
  DHCPV6_MSG_API_RECONFIGURE = 10,
  DHCPV6_MSG_API_INFORMATION_REQUEST = 11,
  DHCPV6_MSG_API_RELAY_FORW = 12,
  DHCPV6_MSG_API_RELAY_REPL = 13,
}  vapi_enum_dhcpv6_msg_type;

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

#ifndef defined_vapi_type_interface_index
#define defined_vapi_type_interface_index
typedef u32 vapi_type_interface_index;

#endif

#ifndef defined_vapi_type_dhcp_client
#define defined_vapi_type_dhcp_client
typedef struct __attribute__((__packed__)) {
  vapi_type_interface_index sw_if_index;
  u8 hostname[64];
  u8 id[64];
  bool want_dhcp_event;
  bool set_broadcast_flag;
  vapi_enum_ip_dscp dscp;
  u32 pid;
} vapi_type_dhcp_client;

static inline void vapi_type_dhcp_client_hton(vapi_type_dhcp_client *msg)
{
  msg->sw_if_index = htobe32(msg->sw_if_index);
  msg->pid = htobe32(msg->pid);
}

static inline void vapi_type_dhcp_client_ntoh(vapi_type_dhcp_client *msg)
{
  msg->sw_if_index = be32toh(msg->sw_if_index);
  msg->pid = be32toh(msg->pid);
}
#endif

#ifndef defined_vapi_type_domain_server
#define defined_vapi_type_domain_server
typedef struct __attribute__((__packed__)) {
  vapi_type_address address;
} vapi_type_domain_server;

static inline void vapi_type_domain_server_hton(vapi_type_domain_server *msg)
{

}

static inline void vapi_type_domain_server_ntoh(vapi_type_domain_server *msg)
{

}
#endif

#ifndef defined_vapi_type_mac_address
#define defined_vapi_type_mac_address
typedef u8 vapi_type_mac_address[6];

#endif

#ifndef defined_vapi_type_dhcp_lease
#define defined_vapi_type_dhcp_lease
typedef struct __attribute__((__packed__)) {
  vapi_type_interface_index sw_if_index;
  vapi_enum_dhcp_client_state state;
  bool is_ipv6;
  u8 hostname[64];
  u8 mask_width;
  vapi_type_address host_address;
  vapi_type_address router_address;
  vapi_type_mac_address host_mac;
  u8 count;
  vapi_type_domain_server domain_server[0];
} vapi_type_dhcp_lease;

static inline void vapi_type_dhcp_lease_hton(vapi_type_dhcp_lease *msg)
{
  msg->sw_if_index = htobe32(msg->sw_if_index);
  msg->state = (vapi_enum_dhcp_client_state)htobe32(msg->state);
}

static inline void vapi_type_dhcp_lease_ntoh(vapi_type_dhcp_lease *msg)
{
  msg->sw_if_index = be32toh(msg->sw_if_index);
  msg->state = (vapi_enum_dhcp_client_state)be32toh(msg->state);
}
#endif

#ifndef defined_vapi_type_dhcp_server
#define defined_vapi_type_dhcp_server
typedef struct __attribute__((__packed__)) {
  u32 server_vrf_id;
  vapi_type_address dhcp_server;
} vapi_type_dhcp_server;

static inline void vapi_type_dhcp_server_hton(vapi_type_dhcp_server *msg)
{
  msg->server_vrf_id = htobe32(msg->server_vrf_id);
}

static inline void vapi_type_dhcp_server_ntoh(vapi_type_dhcp_server *msg)
{
  msg->server_vrf_id = be32toh(msg->server_vrf_id);
}
#endif

#ifndef defined_vapi_type_dhcp6_address_info
#define defined_vapi_type_dhcp6_address_info
typedef struct __attribute__((__packed__)) {
  vapi_type_ip6_address address;
  u32 valid_time;
  u32 preferred_time;
} vapi_type_dhcp6_address_info;

static inline void vapi_type_dhcp6_address_info_hton(vapi_type_dhcp6_address_info *msg)
{
  msg->valid_time = htobe32(msg->valid_time);
  msg->preferred_time = htobe32(msg->preferred_time);
}

static inline void vapi_type_dhcp6_address_info_ntoh(vapi_type_dhcp6_address_info *msg)
{
  msg->valid_time = be32toh(msg->valid_time);
  msg->preferred_time = be32toh(msg->preferred_time);
}
#endif

#ifndef defined_vapi_type_dhcp6_pd_prefix_info
#define defined_vapi_type_dhcp6_pd_prefix_info
typedef struct __attribute__((__packed__)) {
  vapi_type_ip6_prefix prefix;
  u32 valid_time;
  u32 preferred_time;
} vapi_type_dhcp6_pd_prefix_info;

static inline void vapi_type_dhcp6_pd_prefix_info_hton(vapi_type_dhcp6_pd_prefix_info *msg)
{
  msg->valid_time = htobe32(msg->valid_time);
  msg->preferred_time = htobe32(msg->preferred_time);
}

static inline void vapi_type_dhcp6_pd_prefix_info_ntoh(vapi_type_dhcp6_pd_prefix_info *msg)
{
  msg->valid_time = be32toh(msg->valid_time);
  msg->preferred_time = be32toh(msg->preferred_time);
}
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

#ifndef defined_vapi_msg_dhcp_plugin_get_version_reply
#define defined_vapi_msg_dhcp_plugin_get_version_reply
typedef struct __attribute__ ((__packed__)) {
  u32 major;
  u32 minor; 
} vapi_payload_dhcp_plugin_get_version_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_dhcp_plugin_get_version_reply payload;
} vapi_msg_dhcp_plugin_get_version_reply;

static inline void vapi_msg_dhcp_plugin_get_version_reply_payload_hton(vapi_payload_dhcp_plugin_get_version_reply *payload)
{
  payload->major = htobe32(payload->major);
  payload->minor = htobe32(payload->minor);
}

static inline void vapi_msg_dhcp_plugin_get_version_reply_payload_ntoh(vapi_payload_dhcp_plugin_get_version_reply *payload)
{
  payload->major = be32toh(payload->major);
  payload->minor = be32toh(payload->minor);
}

static inline void vapi_msg_dhcp_plugin_get_version_reply_hton(vapi_msg_dhcp_plugin_get_version_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp_plugin_get_version_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_dhcp_plugin_get_version_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_dhcp_plugin_get_version_reply_ntoh(vapi_msg_dhcp_plugin_get_version_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp_plugin_get_version_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_dhcp_plugin_get_version_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dhcp_plugin_get_version_reply_msg_size(vapi_msg_dhcp_plugin_get_version_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_dhcp_plugin_get_version_reply_msg_size(vapi_msg_dhcp_plugin_get_version_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dhcp_plugin_get_version_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp_plugin_get_version_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dhcp_plugin_get_version_reply));
      return -1;
    }
  if (vapi_calc_dhcp_plugin_get_version_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp_plugin_get_version_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dhcp_plugin_get_version_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_dhcp_plugin_get_version_reply()
{
  static const char name[] = "dhcp_plugin_get_version_reply";
  static const char name_with_crc[] = "dhcp_plugin_get_version_reply_9b32cf86";
  static vapi_message_desc_t __vapi_metadata_dhcp_plugin_get_version_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_dhcp_plugin_get_version_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_dhcp_plugin_get_version_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_dhcp_plugin_get_version_reply_hton,
    (generic_swap_fn_t)vapi_msg_dhcp_plugin_get_version_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dhcp_plugin_get_version_reply = vapi_register_msg(&__vapi_metadata_dhcp_plugin_get_version_reply);
  VAPI_DBG("Assigned msg id %d to dhcp_plugin_get_version_reply", vapi_msg_id_dhcp_plugin_get_version_reply);
}

static inline void vapi_set_vapi_msg_dhcp_plugin_get_version_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_dhcp_plugin_get_version_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_dhcp_plugin_get_version_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_dhcp_plugin_get_version
#define defined_vapi_msg_dhcp_plugin_get_version
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_dhcp_plugin_get_version;

static inline void vapi_msg_dhcp_plugin_get_version_hton(vapi_msg_dhcp_plugin_get_version *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp_plugin_get_version'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_dhcp_plugin_get_version_ntoh(vapi_msg_dhcp_plugin_get_version *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp_plugin_get_version'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_dhcp_plugin_get_version_msg_size(vapi_msg_dhcp_plugin_get_version *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_dhcp_plugin_get_version_msg_size(vapi_msg_dhcp_plugin_get_version *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dhcp_plugin_get_version) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp_plugin_get_version' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dhcp_plugin_get_version));
      return -1;
    }
  if (vapi_calc_dhcp_plugin_get_version_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp_plugin_get_version' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dhcp_plugin_get_version_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_dhcp_plugin_get_version* vapi_alloc_dhcp_plugin_get_version(struct vapi_ctx_s *ctx)
{
  vapi_msg_dhcp_plugin_get_version *msg = NULL;
  const size_t size = sizeof(vapi_msg_dhcp_plugin_get_version);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_dhcp_plugin_get_version*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_dhcp_plugin_get_version);

  return msg;
}

static inline vapi_error_e vapi_dhcp_plugin_get_version(struct vapi_ctx_s *ctx,
  vapi_msg_dhcp_plugin_get_version *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_dhcp_plugin_get_version_reply *reply),
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
  vapi_msg_dhcp_plugin_get_version_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_dhcp_plugin_get_version_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_dhcp_plugin_get_version_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_dhcp_plugin_get_version()
{
  static const char name[] = "dhcp_plugin_get_version";
  static const char name_with_crc[] = "dhcp_plugin_get_version_51077d14";
  static vapi_message_desc_t __vapi_metadata_dhcp_plugin_get_version = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_dhcp_plugin_get_version_msg_size,
    (generic_swap_fn_t)vapi_msg_dhcp_plugin_get_version_hton,
    (generic_swap_fn_t)vapi_msg_dhcp_plugin_get_version_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dhcp_plugin_get_version = vapi_register_msg(&__vapi_metadata_dhcp_plugin_get_version);
  VAPI_DBG("Assigned msg id %d to dhcp_plugin_get_version", vapi_msg_id_dhcp_plugin_get_version);
}
#endif

#ifndef defined_vapi_msg_dhcp_plugin_control_ping_reply
#define defined_vapi_msg_dhcp_plugin_control_ping_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 client_index;
  u32 vpe_pid; 
} vapi_payload_dhcp_plugin_control_ping_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_dhcp_plugin_control_ping_reply payload;
} vapi_msg_dhcp_plugin_control_ping_reply;

static inline void vapi_msg_dhcp_plugin_control_ping_reply_payload_hton(vapi_payload_dhcp_plugin_control_ping_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->client_index = htobe32(payload->client_index);
  payload->vpe_pid = htobe32(payload->vpe_pid);
}

static inline void vapi_msg_dhcp_plugin_control_ping_reply_payload_ntoh(vapi_payload_dhcp_plugin_control_ping_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->client_index = be32toh(payload->client_index);
  payload->vpe_pid = be32toh(payload->vpe_pid);
}

static inline void vapi_msg_dhcp_plugin_control_ping_reply_hton(vapi_msg_dhcp_plugin_control_ping_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp_plugin_control_ping_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_dhcp_plugin_control_ping_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_dhcp_plugin_control_ping_reply_ntoh(vapi_msg_dhcp_plugin_control_ping_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp_plugin_control_ping_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_dhcp_plugin_control_ping_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dhcp_plugin_control_ping_reply_msg_size(vapi_msg_dhcp_plugin_control_ping_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_dhcp_plugin_control_ping_reply_msg_size(vapi_msg_dhcp_plugin_control_ping_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dhcp_plugin_control_ping_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp_plugin_control_ping_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dhcp_plugin_control_ping_reply));
      return -1;
    }
  if (vapi_calc_dhcp_plugin_control_ping_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp_plugin_control_ping_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dhcp_plugin_control_ping_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_dhcp_plugin_control_ping_reply()
{
  static const char name[] = "dhcp_plugin_control_ping_reply";
  static const char name_with_crc[] = "dhcp_plugin_control_ping_reply_f6b0b8ca";
  static vapi_message_desc_t __vapi_metadata_dhcp_plugin_control_ping_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_dhcp_plugin_control_ping_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_dhcp_plugin_control_ping_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_dhcp_plugin_control_ping_reply_hton,
    (generic_swap_fn_t)vapi_msg_dhcp_plugin_control_ping_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dhcp_plugin_control_ping_reply = vapi_register_msg(&__vapi_metadata_dhcp_plugin_control_ping_reply);
  VAPI_DBG("Assigned msg id %d to dhcp_plugin_control_ping_reply", vapi_msg_id_dhcp_plugin_control_ping_reply);
}

static inline void vapi_set_vapi_msg_dhcp_plugin_control_ping_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_dhcp_plugin_control_ping_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_dhcp_plugin_control_ping_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_dhcp_plugin_control_ping
#define defined_vapi_msg_dhcp_plugin_control_ping
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_dhcp_plugin_control_ping;

static inline void vapi_msg_dhcp_plugin_control_ping_hton(vapi_msg_dhcp_plugin_control_ping *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp_plugin_control_ping'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_dhcp_plugin_control_ping_ntoh(vapi_msg_dhcp_plugin_control_ping *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp_plugin_control_ping'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_dhcp_plugin_control_ping_msg_size(vapi_msg_dhcp_plugin_control_ping *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_dhcp_plugin_control_ping_msg_size(vapi_msg_dhcp_plugin_control_ping *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dhcp_plugin_control_ping) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp_plugin_control_ping' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dhcp_plugin_control_ping));
      return -1;
    }
  if (vapi_calc_dhcp_plugin_control_ping_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp_plugin_control_ping' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dhcp_plugin_control_ping_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_dhcp_plugin_control_ping* vapi_alloc_dhcp_plugin_control_ping(struct vapi_ctx_s *ctx)
{
  vapi_msg_dhcp_plugin_control_ping *msg = NULL;
  const size_t size = sizeof(vapi_msg_dhcp_plugin_control_ping);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_dhcp_plugin_control_ping*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_dhcp_plugin_control_ping);

  return msg;
}

static inline vapi_error_e vapi_dhcp_plugin_control_ping(struct vapi_ctx_s *ctx,
  vapi_msg_dhcp_plugin_control_ping *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_dhcp_plugin_control_ping_reply *reply),
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
  vapi_msg_dhcp_plugin_control_ping_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_dhcp_plugin_control_ping_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_dhcp_plugin_control_ping_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_dhcp_plugin_control_ping()
{
  static const char name[] = "dhcp_plugin_control_ping";
  static const char name_with_crc[] = "dhcp_plugin_control_ping_51077d14";
  static vapi_message_desc_t __vapi_metadata_dhcp_plugin_control_ping = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_dhcp_plugin_control_ping_msg_size,
    (generic_swap_fn_t)vapi_msg_dhcp_plugin_control_ping_hton,
    (generic_swap_fn_t)vapi_msg_dhcp_plugin_control_ping_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dhcp_plugin_control_ping = vapi_register_msg(&__vapi_metadata_dhcp_plugin_control_ping);
  VAPI_DBG("Assigned msg id %d to dhcp_plugin_control_ping", vapi_msg_id_dhcp_plugin_control_ping);
}
#endif

#ifndef defined_vapi_msg_dhcp_proxy_config_reply
#define defined_vapi_msg_dhcp_proxy_config_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_dhcp_proxy_config_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_dhcp_proxy_config_reply payload;
} vapi_msg_dhcp_proxy_config_reply;

static inline void vapi_msg_dhcp_proxy_config_reply_payload_hton(vapi_payload_dhcp_proxy_config_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_dhcp_proxy_config_reply_payload_ntoh(vapi_payload_dhcp_proxy_config_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_dhcp_proxy_config_reply_hton(vapi_msg_dhcp_proxy_config_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp_proxy_config_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_dhcp_proxy_config_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_dhcp_proxy_config_reply_ntoh(vapi_msg_dhcp_proxy_config_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp_proxy_config_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_dhcp_proxy_config_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dhcp_proxy_config_reply_msg_size(vapi_msg_dhcp_proxy_config_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_dhcp_proxy_config_reply_msg_size(vapi_msg_dhcp_proxy_config_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dhcp_proxy_config_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp_proxy_config_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dhcp_proxy_config_reply));
      return -1;
    }
  if (vapi_calc_dhcp_proxy_config_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp_proxy_config_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dhcp_proxy_config_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_dhcp_proxy_config_reply()
{
  static const char name[] = "dhcp_proxy_config_reply";
  static const char name_with_crc[] = "dhcp_proxy_config_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_dhcp_proxy_config_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_dhcp_proxy_config_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_dhcp_proxy_config_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_dhcp_proxy_config_reply_hton,
    (generic_swap_fn_t)vapi_msg_dhcp_proxy_config_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dhcp_proxy_config_reply = vapi_register_msg(&__vapi_metadata_dhcp_proxy_config_reply);
  VAPI_DBG("Assigned msg id %d to dhcp_proxy_config_reply", vapi_msg_id_dhcp_proxy_config_reply);
}

static inline void vapi_set_vapi_msg_dhcp_proxy_config_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_dhcp_proxy_config_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_dhcp_proxy_config_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_dhcp_proxy_config
#define defined_vapi_msg_dhcp_proxy_config
typedef struct __attribute__ ((__packed__)) {
  u32 rx_vrf_id;
  u32 server_vrf_id;
  bool is_add;
  vapi_type_address dhcp_server;
  vapi_type_address dhcp_src_address; 
} vapi_payload_dhcp_proxy_config;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_dhcp_proxy_config payload;
} vapi_msg_dhcp_proxy_config;

static inline void vapi_msg_dhcp_proxy_config_payload_hton(vapi_payload_dhcp_proxy_config *payload)
{
  payload->rx_vrf_id = htobe32(payload->rx_vrf_id);
  payload->server_vrf_id = htobe32(payload->server_vrf_id);
}

static inline void vapi_msg_dhcp_proxy_config_payload_ntoh(vapi_payload_dhcp_proxy_config *payload)
{
  payload->rx_vrf_id = be32toh(payload->rx_vrf_id);
  payload->server_vrf_id = be32toh(payload->server_vrf_id);
}

static inline void vapi_msg_dhcp_proxy_config_hton(vapi_msg_dhcp_proxy_config *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp_proxy_config'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_dhcp_proxy_config_payload_hton(&msg->payload);
}

static inline void vapi_msg_dhcp_proxy_config_ntoh(vapi_msg_dhcp_proxy_config *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp_proxy_config'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_dhcp_proxy_config_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dhcp_proxy_config_msg_size(vapi_msg_dhcp_proxy_config *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_dhcp_proxy_config_msg_size(vapi_msg_dhcp_proxy_config *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dhcp_proxy_config) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp_proxy_config' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dhcp_proxy_config));
      return -1;
    }
  if (vapi_calc_dhcp_proxy_config_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp_proxy_config' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dhcp_proxy_config_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_dhcp_proxy_config* vapi_alloc_dhcp_proxy_config(struct vapi_ctx_s *ctx)
{
  vapi_msg_dhcp_proxy_config *msg = NULL;
  const size_t size = sizeof(vapi_msg_dhcp_proxy_config);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_dhcp_proxy_config*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_dhcp_proxy_config);

  return msg;
}

static inline vapi_error_e vapi_dhcp_proxy_config(struct vapi_ctx_s *ctx,
  vapi_msg_dhcp_proxy_config *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_dhcp_proxy_config_reply *reply),
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
  vapi_msg_dhcp_proxy_config_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_dhcp_proxy_config_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_dhcp_proxy_config_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_dhcp_proxy_config()
{
  static const char name[] = "dhcp_proxy_config";
  static const char name_with_crc[] = "dhcp_proxy_config_4058a689";
  static vapi_message_desc_t __vapi_metadata_dhcp_proxy_config = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_dhcp_proxy_config, payload),
    (verify_msg_size_fn_t)vapi_verify_dhcp_proxy_config_msg_size,
    (generic_swap_fn_t)vapi_msg_dhcp_proxy_config_hton,
    (generic_swap_fn_t)vapi_msg_dhcp_proxy_config_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dhcp_proxy_config = vapi_register_msg(&__vapi_metadata_dhcp_proxy_config);
  VAPI_DBG("Assigned msg id %d to dhcp_proxy_config", vapi_msg_id_dhcp_proxy_config);
}
#endif

#ifndef defined_vapi_msg_dhcp_proxy_set_vss_reply
#define defined_vapi_msg_dhcp_proxy_set_vss_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_dhcp_proxy_set_vss_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_dhcp_proxy_set_vss_reply payload;
} vapi_msg_dhcp_proxy_set_vss_reply;

static inline void vapi_msg_dhcp_proxy_set_vss_reply_payload_hton(vapi_payload_dhcp_proxy_set_vss_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_dhcp_proxy_set_vss_reply_payload_ntoh(vapi_payload_dhcp_proxy_set_vss_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_dhcp_proxy_set_vss_reply_hton(vapi_msg_dhcp_proxy_set_vss_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp_proxy_set_vss_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_dhcp_proxy_set_vss_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_dhcp_proxy_set_vss_reply_ntoh(vapi_msg_dhcp_proxy_set_vss_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp_proxy_set_vss_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_dhcp_proxy_set_vss_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dhcp_proxy_set_vss_reply_msg_size(vapi_msg_dhcp_proxy_set_vss_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_dhcp_proxy_set_vss_reply_msg_size(vapi_msg_dhcp_proxy_set_vss_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dhcp_proxy_set_vss_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp_proxy_set_vss_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dhcp_proxy_set_vss_reply));
      return -1;
    }
  if (vapi_calc_dhcp_proxy_set_vss_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp_proxy_set_vss_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dhcp_proxy_set_vss_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_dhcp_proxy_set_vss_reply()
{
  static const char name[] = "dhcp_proxy_set_vss_reply";
  static const char name_with_crc[] = "dhcp_proxy_set_vss_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_dhcp_proxy_set_vss_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_dhcp_proxy_set_vss_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_dhcp_proxy_set_vss_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_dhcp_proxy_set_vss_reply_hton,
    (generic_swap_fn_t)vapi_msg_dhcp_proxy_set_vss_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dhcp_proxy_set_vss_reply = vapi_register_msg(&__vapi_metadata_dhcp_proxy_set_vss_reply);
  VAPI_DBG("Assigned msg id %d to dhcp_proxy_set_vss_reply", vapi_msg_id_dhcp_proxy_set_vss_reply);
}

static inline void vapi_set_vapi_msg_dhcp_proxy_set_vss_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_dhcp_proxy_set_vss_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_dhcp_proxy_set_vss_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_dhcp_proxy_set_vss
#define defined_vapi_msg_dhcp_proxy_set_vss
typedef struct __attribute__ ((__packed__)) {
  u32 tbl_id;
  vapi_enum_vss_type vss_type;
  u8 vpn_ascii_id[129];
  u32 oui;
  u32 vpn_index;
  bool is_ipv6;
  bool is_add; 
} vapi_payload_dhcp_proxy_set_vss;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_dhcp_proxy_set_vss payload;
} vapi_msg_dhcp_proxy_set_vss;

static inline void vapi_msg_dhcp_proxy_set_vss_payload_hton(vapi_payload_dhcp_proxy_set_vss *payload)
{
  payload->tbl_id = htobe32(payload->tbl_id);
  payload->vss_type = (vapi_enum_vss_type)htobe32(payload->vss_type);
  payload->oui = htobe32(payload->oui);
  payload->vpn_index = htobe32(payload->vpn_index);
}

static inline void vapi_msg_dhcp_proxy_set_vss_payload_ntoh(vapi_payload_dhcp_proxy_set_vss *payload)
{
  payload->tbl_id = be32toh(payload->tbl_id);
  payload->vss_type = (vapi_enum_vss_type)be32toh(payload->vss_type);
  payload->oui = be32toh(payload->oui);
  payload->vpn_index = be32toh(payload->vpn_index);
}

static inline void vapi_msg_dhcp_proxy_set_vss_hton(vapi_msg_dhcp_proxy_set_vss *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp_proxy_set_vss'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_dhcp_proxy_set_vss_payload_hton(&msg->payload);
}

static inline void vapi_msg_dhcp_proxy_set_vss_ntoh(vapi_msg_dhcp_proxy_set_vss *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp_proxy_set_vss'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_dhcp_proxy_set_vss_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dhcp_proxy_set_vss_msg_size(vapi_msg_dhcp_proxy_set_vss *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_dhcp_proxy_set_vss_msg_size(vapi_msg_dhcp_proxy_set_vss *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dhcp_proxy_set_vss) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp_proxy_set_vss' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dhcp_proxy_set_vss));
      return -1;
    }
  if (vapi_calc_dhcp_proxy_set_vss_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp_proxy_set_vss' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dhcp_proxy_set_vss_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_dhcp_proxy_set_vss* vapi_alloc_dhcp_proxy_set_vss(struct vapi_ctx_s *ctx)
{
  vapi_msg_dhcp_proxy_set_vss *msg = NULL;
  const size_t size = sizeof(vapi_msg_dhcp_proxy_set_vss);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_dhcp_proxy_set_vss*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_dhcp_proxy_set_vss);

  return msg;
}

static inline vapi_error_e vapi_dhcp_proxy_set_vss(struct vapi_ctx_s *ctx,
  vapi_msg_dhcp_proxy_set_vss *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_dhcp_proxy_set_vss_reply *reply),
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
  vapi_msg_dhcp_proxy_set_vss_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_dhcp_proxy_set_vss_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_dhcp_proxy_set_vss_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_dhcp_proxy_set_vss()
{
  static const char name[] = "dhcp_proxy_set_vss";
  static const char name_with_crc[] = "dhcp_proxy_set_vss_50537301";
  static vapi_message_desc_t __vapi_metadata_dhcp_proxy_set_vss = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_dhcp_proxy_set_vss, payload),
    (verify_msg_size_fn_t)vapi_verify_dhcp_proxy_set_vss_msg_size,
    (generic_swap_fn_t)vapi_msg_dhcp_proxy_set_vss_hton,
    (generic_swap_fn_t)vapi_msg_dhcp_proxy_set_vss_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dhcp_proxy_set_vss = vapi_register_msg(&__vapi_metadata_dhcp_proxy_set_vss);
  VAPI_DBG("Assigned msg id %d to dhcp_proxy_set_vss", vapi_msg_id_dhcp_proxy_set_vss);
}
#endif

#ifndef defined_vapi_msg_dhcp_client_config_reply
#define defined_vapi_msg_dhcp_client_config_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_dhcp_client_config_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_dhcp_client_config_reply payload;
} vapi_msg_dhcp_client_config_reply;

static inline void vapi_msg_dhcp_client_config_reply_payload_hton(vapi_payload_dhcp_client_config_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_dhcp_client_config_reply_payload_ntoh(vapi_payload_dhcp_client_config_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_dhcp_client_config_reply_hton(vapi_msg_dhcp_client_config_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp_client_config_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_dhcp_client_config_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_dhcp_client_config_reply_ntoh(vapi_msg_dhcp_client_config_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp_client_config_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_dhcp_client_config_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dhcp_client_config_reply_msg_size(vapi_msg_dhcp_client_config_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_dhcp_client_config_reply_msg_size(vapi_msg_dhcp_client_config_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dhcp_client_config_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp_client_config_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dhcp_client_config_reply));
      return -1;
    }
  if (vapi_calc_dhcp_client_config_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp_client_config_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dhcp_client_config_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_dhcp_client_config_reply()
{
  static const char name[] = "dhcp_client_config_reply";
  static const char name_with_crc[] = "dhcp_client_config_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_dhcp_client_config_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_dhcp_client_config_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_dhcp_client_config_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_dhcp_client_config_reply_hton,
    (generic_swap_fn_t)vapi_msg_dhcp_client_config_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dhcp_client_config_reply = vapi_register_msg(&__vapi_metadata_dhcp_client_config_reply);
  VAPI_DBG("Assigned msg id %d to dhcp_client_config_reply", vapi_msg_id_dhcp_client_config_reply);
}

static inline void vapi_set_vapi_msg_dhcp_client_config_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_dhcp_client_config_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_dhcp_client_config_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_dhcp_client_config
#define defined_vapi_msg_dhcp_client_config
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_type_dhcp_client client; 
} vapi_payload_dhcp_client_config;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_dhcp_client_config payload;
} vapi_msg_dhcp_client_config;

static inline void vapi_msg_dhcp_client_config_payload_hton(vapi_payload_dhcp_client_config *payload)
{
  vapi_type_dhcp_client_hton(&payload->client);
}

static inline void vapi_msg_dhcp_client_config_payload_ntoh(vapi_payload_dhcp_client_config *payload)
{
  vapi_type_dhcp_client_ntoh(&payload->client);
}

static inline void vapi_msg_dhcp_client_config_hton(vapi_msg_dhcp_client_config *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp_client_config'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_dhcp_client_config_payload_hton(&msg->payload);
}

static inline void vapi_msg_dhcp_client_config_ntoh(vapi_msg_dhcp_client_config *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp_client_config'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_dhcp_client_config_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dhcp_client_config_msg_size(vapi_msg_dhcp_client_config *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_dhcp_client_config_msg_size(vapi_msg_dhcp_client_config *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dhcp_client_config) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp_client_config' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dhcp_client_config));
      return -1;
    }
  if (vapi_calc_dhcp_client_config_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp_client_config' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dhcp_client_config_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_dhcp_client_config* vapi_alloc_dhcp_client_config(struct vapi_ctx_s *ctx)
{
  vapi_msg_dhcp_client_config *msg = NULL;
  const size_t size = sizeof(vapi_msg_dhcp_client_config);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_dhcp_client_config*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_dhcp_client_config);

  return msg;
}

static inline vapi_error_e vapi_dhcp_client_config(struct vapi_ctx_s *ctx,
  vapi_msg_dhcp_client_config *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_dhcp_client_config_reply *reply),
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
  vapi_msg_dhcp_client_config_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_dhcp_client_config_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_dhcp_client_config_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_dhcp_client_config()
{
  static const char name[] = "dhcp_client_config";
  static const char name_with_crc[] = "dhcp_client_config_1af013ea";
  static vapi_message_desc_t __vapi_metadata_dhcp_client_config = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_dhcp_client_config, payload),
    (verify_msg_size_fn_t)vapi_verify_dhcp_client_config_msg_size,
    (generic_swap_fn_t)vapi_msg_dhcp_client_config_hton,
    (generic_swap_fn_t)vapi_msg_dhcp_client_config_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dhcp_client_config = vapi_register_msg(&__vapi_metadata_dhcp_client_config);
  VAPI_DBG("Assigned msg id %d to dhcp_client_config", vapi_msg_id_dhcp_client_config);
}
#endif

#ifndef defined_vapi_msg_dhcp_compl_event
#define defined_vapi_msg_dhcp_compl_event
typedef struct __attribute__ ((__packed__)) {
  u16 _vl_msg_id;
  u32 client_index;
  u32 pid;
  vapi_type_dhcp_lease lease; 
} vapi_payload_dhcp_compl_event;

typedef struct __attribute__ ((__packed__)) {

  vapi_payload_dhcp_compl_event payload;
} vapi_msg_dhcp_compl_event;

static inline void vapi_msg_dhcp_compl_event_payload_hton(vapi_payload_dhcp_compl_event *payload)
{
  payload->_vl_msg_id = htobe16(payload->_vl_msg_id);
  payload->client_index = htobe32(payload->client_index);
  payload->pid = htobe32(payload->pid);
  vapi_type_dhcp_lease_hton(&payload->lease);
}

static inline void vapi_msg_dhcp_compl_event_payload_ntoh(vapi_payload_dhcp_compl_event *payload)
{
  payload->_vl_msg_id = be16toh(payload->_vl_msg_id);
  payload->client_index = be32toh(payload->client_index);
  payload->pid = be32toh(payload->pid);
  vapi_type_dhcp_lease_ntoh(&payload->lease);
}

static inline void vapi_msg_dhcp_compl_event_hton(vapi_msg_dhcp_compl_event *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp_compl_event'@%p to big endian", msg);

  vapi_msg_dhcp_compl_event_payload_hton(&msg->payload);
}

static inline void vapi_msg_dhcp_compl_event_ntoh(vapi_msg_dhcp_compl_event *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp_compl_event'@%p to host byte order", msg);

  vapi_msg_dhcp_compl_event_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dhcp_compl_event_msg_size(vapi_msg_dhcp_compl_event *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.lease.domain_server[0]) * msg->payload.lease.count;
}

static inline int vapi_verify_dhcp_compl_event_msg_size(vapi_msg_dhcp_compl_event *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dhcp_compl_event) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp_compl_event' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dhcp_compl_event));
      return -1;
    }
  if (vapi_calc_dhcp_compl_event_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp_compl_event' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dhcp_compl_event_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_dhcp_compl_event()
{
  static const char name[] = "dhcp_compl_event";
  static const char name_with_crc[] = "dhcp_compl_event_e18124b7";
  static vapi_message_desc_t __vapi_metadata_dhcp_compl_event = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    false,
    0,
    offsetof(vapi_msg_dhcp_compl_event, payload),
    (verify_msg_size_fn_t)vapi_verify_dhcp_compl_event_msg_size,
    (generic_swap_fn_t)vapi_msg_dhcp_compl_event_hton,
    (generic_swap_fn_t)vapi_msg_dhcp_compl_event_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dhcp_compl_event = vapi_register_msg(&__vapi_metadata_dhcp_compl_event);
  VAPI_DBG("Assigned msg id %d to dhcp_compl_event", vapi_msg_id_dhcp_compl_event);
}

static inline void vapi_set_vapi_msg_dhcp_compl_event_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_dhcp_compl_event *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_dhcp_compl_event, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_dhcp_client_details
#define defined_vapi_msg_dhcp_client_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_dhcp_client client;
  vapi_type_dhcp_lease lease; 
} vapi_payload_dhcp_client_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_dhcp_client_details payload;
} vapi_msg_dhcp_client_details;

static inline void vapi_msg_dhcp_client_details_payload_hton(vapi_payload_dhcp_client_details *payload)
{
  vapi_type_dhcp_client_hton(&payload->client);
  vapi_type_dhcp_lease_hton(&payload->lease);
}

static inline void vapi_msg_dhcp_client_details_payload_ntoh(vapi_payload_dhcp_client_details *payload)
{
  vapi_type_dhcp_client_ntoh(&payload->client);
  vapi_type_dhcp_lease_ntoh(&payload->lease);
}

static inline void vapi_msg_dhcp_client_details_hton(vapi_msg_dhcp_client_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp_client_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_dhcp_client_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_dhcp_client_details_ntoh(vapi_msg_dhcp_client_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp_client_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_dhcp_client_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dhcp_client_details_msg_size(vapi_msg_dhcp_client_details *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.lease.domain_server[0]) * msg->payload.lease.count;
}

static inline int vapi_verify_dhcp_client_details_msg_size(vapi_msg_dhcp_client_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dhcp_client_details) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp_client_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dhcp_client_details));
      return -1;
    }
  if (vapi_calc_dhcp_client_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp_client_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dhcp_client_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_dhcp_client_details()
{
  static const char name[] = "dhcp_client_details";
  static const char name_with_crc[] = "dhcp_client_details_8897b2d8";
  static vapi_message_desc_t __vapi_metadata_dhcp_client_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_dhcp_client_details, payload),
    (verify_msg_size_fn_t)vapi_verify_dhcp_client_details_msg_size,
    (generic_swap_fn_t)vapi_msg_dhcp_client_details_hton,
    (generic_swap_fn_t)vapi_msg_dhcp_client_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dhcp_client_details = vapi_register_msg(&__vapi_metadata_dhcp_client_details);
  VAPI_DBG("Assigned msg id %d to dhcp_client_details", vapi_msg_id_dhcp_client_details);
}

static inline void vapi_set_vapi_msg_dhcp_client_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_dhcp_client_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_dhcp_client_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_dhcp_client_dump
#define defined_vapi_msg_dhcp_client_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_dhcp_client_dump;

static inline void vapi_msg_dhcp_client_dump_hton(vapi_msg_dhcp_client_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp_client_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_dhcp_client_dump_ntoh(vapi_msg_dhcp_client_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp_client_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_dhcp_client_dump_msg_size(vapi_msg_dhcp_client_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_dhcp_client_dump_msg_size(vapi_msg_dhcp_client_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dhcp_client_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp_client_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dhcp_client_dump));
      return -1;
    }
  if (vapi_calc_dhcp_client_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp_client_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dhcp_client_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_dhcp_client_dump* vapi_alloc_dhcp_client_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_dhcp_client_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_dhcp_client_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_dhcp_client_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_dhcp_client_dump);

  return msg;
}

static inline vapi_error_e vapi_dhcp_client_dump(struct vapi_ctx_s *ctx,
  vapi_msg_dhcp_client_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_dhcp_client_details *reply),
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
  vapi_msg_dhcp_client_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_dhcp_client_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_dhcp_client_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_dhcp_client_dump()
{
  static const char name[] = "dhcp_client_dump";
  static const char name_with_crc[] = "dhcp_client_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_dhcp_client_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_dhcp_client_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_dhcp_client_dump_hton,
    (generic_swap_fn_t)vapi_msg_dhcp_client_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dhcp_client_dump = vapi_register_msg(&__vapi_metadata_dhcp_client_dump);
  VAPI_DBG("Assigned msg id %d to dhcp_client_dump", vapi_msg_id_dhcp_client_dump);
}
#endif

#ifndef defined_vapi_msg_dhcp_proxy_details
#define defined_vapi_msg_dhcp_proxy_details
typedef struct __attribute__ ((__packed__)) {
  u32 rx_vrf_id;
  u32 vss_oui;
  u32 vss_fib_id;
  vapi_enum_vss_type vss_type;
  bool is_ipv6;
  u8 vss_vpn_ascii_id[129];
  vapi_type_address dhcp_src_address;
  u8 count;
  vapi_type_dhcp_server servers[0]; 
} vapi_payload_dhcp_proxy_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_dhcp_proxy_details payload;
} vapi_msg_dhcp_proxy_details;

static inline void vapi_msg_dhcp_proxy_details_payload_hton(vapi_payload_dhcp_proxy_details *payload)
{
  payload->rx_vrf_id = htobe32(payload->rx_vrf_id);
  payload->vss_oui = htobe32(payload->vss_oui);
  payload->vss_fib_id = htobe32(payload->vss_fib_id);
  payload->vss_type = (vapi_enum_vss_type)htobe32(payload->vss_type);
  do { unsigned i; for (i = 0; i < payload->count; ++i) { vapi_type_dhcp_server_hton(&payload->servers[i]); } } while(0);
}

static inline void vapi_msg_dhcp_proxy_details_payload_ntoh(vapi_payload_dhcp_proxy_details *payload)
{
  payload->rx_vrf_id = be32toh(payload->rx_vrf_id);
  payload->vss_oui = be32toh(payload->vss_oui);
  payload->vss_fib_id = be32toh(payload->vss_fib_id);
  payload->vss_type = (vapi_enum_vss_type)be32toh(payload->vss_type);
  do { unsigned i; for (i = 0; i < payload->count; ++i) { vapi_type_dhcp_server_ntoh(&payload->servers[i]); } } while(0);
}

static inline void vapi_msg_dhcp_proxy_details_hton(vapi_msg_dhcp_proxy_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp_proxy_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_dhcp_proxy_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_dhcp_proxy_details_ntoh(vapi_msg_dhcp_proxy_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp_proxy_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_dhcp_proxy_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dhcp_proxy_details_msg_size(vapi_msg_dhcp_proxy_details *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.servers[0]) * msg->payload.count;
}

static inline int vapi_verify_dhcp_proxy_details_msg_size(vapi_msg_dhcp_proxy_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dhcp_proxy_details) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp_proxy_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dhcp_proxy_details));
      return -1;
    }
  if (vapi_calc_dhcp_proxy_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp_proxy_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dhcp_proxy_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_dhcp_proxy_details()
{
  static const char name[] = "dhcp_proxy_details";
  static const char name_with_crc[] = "dhcp_proxy_details_dcbaf540";
  static vapi_message_desc_t __vapi_metadata_dhcp_proxy_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_dhcp_proxy_details, payload),
    (verify_msg_size_fn_t)vapi_verify_dhcp_proxy_details_msg_size,
    (generic_swap_fn_t)vapi_msg_dhcp_proxy_details_hton,
    (generic_swap_fn_t)vapi_msg_dhcp_proxy_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dhcp_proxy_details = vapi_register_msg(&__vapi_metadata_dhcp_proxy_details);
  VAPI_DBG("Assigned msg id %d to dhcp_proxy_details", vapi_msg_id_dhcp_proxy_details);
}

static inline void vapi_set_vapi_msg_dhcp_proxy_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_dhcp_proxy_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_dhcp_proxy_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_dhcp_proxy_dump
#define defined_vapi_msg_dhcp_proxy_dump
typedef struct __attribute__ ((__packed__)) {
  bool is_ip6; 
} vapi_payload_dhcp_proxy_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_dhcp_proxy_dump payload;
} vapi_msg_dhcp_proxy_dump;

static inline void vapi_msg_dhcp_proxy_dump_payload_hton(vapi_payload_dhcp_proxy_dump *payload)
{

}

static inline void vapi_msg_dhcp_proxy_dump_payload_ntoh(vapi_payload_dhcp_proxy_dump *payload)
{

}

static inline void vapi_msg_dhcp_proxy_dump_hton(vapi_msg_dhcp_proxy_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp_proxy_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_dhcp_proxy_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_dhcp_proxy_dump_ntoh(vapi_msg_dhcp_proxy_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp_proxy_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_dhcp_proxy_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dhcp_proxy_dump_msg_size(vapi_msg_dhcp_proxy_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_dhcp_proxy_dump_msg_size(vapi_msg_dhcp_proxy_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dhcp_proxy_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp_proxy_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dhcp_proxy_dump));
      return -1;
    }
  if (vapi_calc_dhcp_proxy_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp_proxy_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dhcp_proxy_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_dhcp_proxy_dump* vapi_alloc_dhcp_proxy_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_dhcp_proxy_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_dhcp_proxy_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_dhcp_proxy_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_dhcp_proxy_dump);

  return msg;
}

static inline vapi_error_e vapi_dhcp_proxy_dump(struct vapi_ctx_s *ctx,
  vapi_msg_dhcp_proxy_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_dhcp_proxy_details *reply),
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
  vapi_msg_dhcp_proxy_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_dhcp_proxy_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_dhcp_proxy_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_dhcp_proxy_dump()
{
  static const char name[] = "dhcp_proxy_dump";
  static const char name_with_crc[] = "dhcp_proxy_dump_5c5b063f";
  static vapi_message_desc_t __vapi_metadata_dhcp_proxy_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_dhcp_proxy_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_dhcp_proxy_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_dhcp_proxy_dump_hton,
    (generic_swap_fn_t)vapi_msg_dhcp_proxy_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dhcp_proxy_dump = vapi_register_msg(&__vapi_metadata_dhcp_proxy_dump);
  VAPI_DBG("Assigned msg id %d to dhcp_proxy_dump", vapi_msg_id_dhcp_proxy_dump);
}
#endif

#ifndef defined_vapi_msg_dhcp_client_detect_enable_disable_reply
#define defined_vapi_msg_dhcp_client_detect_enable_disable_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_dhcp_client_detect_enable_disable_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_dhcp_client_detect_enable_disable_reply payload;
} vapi_msg_dhcp_client_detect_enable_disable_reply;

static inline void vapi_msg_dhcp_client_detect_enable_disable_reply_payload_hton(vapi_payload_dhcp_client_detect_enable_disable_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_dhcp_client_detect_enable_disable_reply_payload_ntoh(vapi_payload_dhcp_client_detect_enable_disable_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_dhcp_client_detect_enable_disable_reply_hton(vapi_msg_dhcp_client_detect_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp_client_detect_enable_disable_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_dhcp_client_detect_enable_disable_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_dhcp_client_detect_enable_disable_reply_ntoh(vapi_msg_dhcp_client_detect_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp_client_detect_enable_disable_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_dhcp_client_detect_enable_disable_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dhcp_client_detect_enable_disable_reply_msg_size(vapi_msg_dhcp_client_detect_enable_disable_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_dhcp_client_detect_enable_disable_reply_msg_size(vapi_msg_dhcp_client_detect_enable_disable_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dhcp_client_detect_enable_disable_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp_client_detect_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dhcp_client_detect_enable_disable_reply));
      return -1;
    }
  if (vapi_calc_dhcp_client_detect_enable_disable_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp_client_detect_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dhcp_client_detect_enable_disable_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_dhcp_client_detect_enable_disable_reply()
{
  static const char name[] = "dhcp_client_detect_enable_disable_reply";
  static const char name_with_crc[] = "dhcp_client_detect_enable_disable_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_dhcp_client_detect_enable_disable_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_dhcp_client_detect_enable_disable_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_dhcp_client_detect_enable_disable_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_dhcp_client_detect_enable_disable_reply_hton,
    (generic_swap_fn_t)vapi_msg_dhcp_client_detect_enable_disable_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dhcp_client_detect_enable_disable_reply = vapi_register_msg(&__vapi_metadata_dhcp_client_detect_enable_disable_reply);
  VAPI_DBG("Assigned msg id %d to dhcp_client_detect_enable_disable_reply", vapi_msg_id_dhcp_client_detect_enable_disable_reply);
}

static inline void vapi_set_vapi_msg_dhcp_client_detect_enable_disable_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_dhcp_client_detect_enable_disable_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_dhcp_client_detect_enable_disable_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_dhcp_client_detect_enable_disable
#define defined_vapi_msg_dhcp_client_detect_enable_disable
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  bool enable; 
} vapi_payload_dhcp_client_detect_enable_disable;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_dhcp_client_detect_enable_disable payload;
} vapi_msg_dhcp_client_detect_enable_disable;

static inline void vapi_msg_dhcp_client_detect_enable_disable_payload_hton(vapi_payload_dhcp_client_detect_enable_disable *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_dhcp_client_detect_enable_disable_payload_ntoh(vapi_payload_dhcp_client_detect_enable_disable *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_dhcp_client_detect_enable_disable_hton(vapi_msg_dhcp_client_detect_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp_client_detect_enable_disable'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_dhcp_client_detect_enable_disable_payload_hton(&msg->payload);
}

static inline void vapi_msg_dhcp_client_detect_enable_disable_ntoh(vapi_msg_dhcp_client_detect_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp_client_detect_enable_disable'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_dhcp_client_detect_enable_disable_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dhcp_client_detect_enable_disable_msg_size(vapi_msg_dhcp_client_detect_enable_disable *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_dhcp_client_detect_enable_disable_msg_size(vapi_msg_dhcp_client_detect_enable_disable *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dhcp_client_detect_enable_disable) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp_client_detect_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dhcp_client_detect_enable_disable));
      return -1;
    }
  if (vapi_calc_dhcp_client_detect_enable_disable_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp_client_detect_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dhcp_client_detect_enable_disable_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_dhcp_client_detect_enable_disable* vapi_alloc_dhcp_client_detect_enable_disable(struct vapi_ctx_s *ctx)
{
  vapi_msg_dhcp_client_detect_enable_disable *msg = NULL;
  const size_t size = sizeof(vapi_msg_dhcp_client_detect_enable_disable);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_dhcp_client_detect_enable_disable*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_dhcp_client_detect_enable_disable);

  return msg;
}

static inline vapi_error_e vapi_dhcp_client_detect_enable_disable(struct vapi_ctx_s *ctx,
  vapi_msg_dhcp_client_detect_enable_disable *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_dhcp_client_detect_enable_disable_reply *reply),
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
  vapi_msg_dhcp_client_detect_enable_disable_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_dhcp_client_detect_enable_disable_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_dhcp_client_detect_enable_disable_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_dhcp_client_detect_enable_disable()
{
  static const char name[] = "dhcp_client_detect_enable_disable";
  static const char name_with_crc[] = "dhcp_client_detect_enable_disable_ae6cfcfb";
  static vapi_message_desc_t __vapi_metadata_dhcp_client_detect_enable_disable = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_dhcp_client_detect_enable_disable, payload),
    (verify_msg_size_fn_t)vapi_verify_dhcp_client_detect_enable_disable_msg_size,
    (generic_swap_fn_t)vapi_msg_dhcp_client_detect_enable_disable_hton,
    (generic_swap_fn_t)vapi_msg_dhcp_client_detect_enable_disable_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dhcp_client_detect_enable_disable = vapi_register_msg(&__vapi_metadata_dhcp_client_detect_enable_disable);
  VAPI_DBG("Assigned msg id %d to dhcp_client_detect_enable_disable", vapi_msg_id_dhcp_client_detect_enable_disable);
}
#endif

#ifndef defined_vapi_msg_dhcp6_duid_ll_set_reply
#define defined_vapi_msg_dhcp6_duid_ll_set_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_dhcp6_duid_ll_set_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_dhcp6_duid_ll_set_reply payload;
} vapi_msg_dhcp6_duid_ll_set_reply;

static inline void vapi_msg_dhcp6_duid_ll_set_reply_payload_hton(vapi_payload_dhcp6_duid_ll_set_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_dhcp6_duid_ll_set_reply_payload_ntoh(vapi_payload_dhcp6_duid_ll_set_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_dhcp6_duid_ll_set_reply_hton(vapi_msg_dhcp6_duid_ll_set_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp6_duid_ll_set_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_dhcp6_duid_ll_set_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_dhcp6_duid_ll_set_reply_ntoh(vapi_msg_dhcp6_duid_ll_set_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp6_duid_ll_set_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_dhcp6_duid_ll_set_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dhcp6_duid_ll_set_reply_msg_size(vapi_msg_dhcp6_duid_ll_set_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_dhcp6_duid_ll_set_reply_msg_size(vapi_msg_dhcp6_duid_ll_set_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dhcp6_duid_ll_set_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp6_duid_ll_set_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dhcp6_duid_ll_set_reply));
      return -1;
    }
  if (vapi_calc_dhcp6_duid_ll_set_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp6_duid_ll_set_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dhcp6_duid_ll_set_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_dhcp6_duid_ll_set_reply()
{
  static const char name[] = "dhcp6_duid_ll_set_reply";
  static const char name_with_crc[] = "dhcp6_duid_ll_set_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_dhcp6_duid_ll_set_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_dhcp6_duid_ll_set_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_dhcp6_duid_ll_set_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_dhcp6_duid_ll_set_reply_hton,
    (generic_swap_fn_t)vapi_msg_dhcp6_duid_ll_set_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dhcp6_duid_ll_set_reply = vapi_register_msg(&__vapi_metadata_dhcp6_duid_ll_set_reply);
  VAPI_DBG("Assigned msg id %d to dhcp6_duid_ll_set_reply", vapi_msg_id_dhcp6_duid_ll_set_reply);
}

static inline void vapi_set_vapi_msg_dhcp6_duid_ll_set_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_dhcp6_duid_ll_set_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_dhcp6_duid_ll_set_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_dhcp6_duid_ll_set
#define defined_vapi_msg_dhcp6_duid_ll_set
typedef struct __attribute__ ((__packed__)) {
  u8 duid_ll[10]; 
} vapi_payload_dhcp6_duid_ll_set;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_dhcp6_duid_ll_set payload;
} vapi_msg_dhcp6_duid_ll_set;

static inline void vapi_msg_dhcp6_duid_ll_set_payload_hton(vapi_payload_dhcp6_duid_ll_set *payload)
{

}

static inline void vapi_msg_dhcp6_duid_ll_set_payload_ntoh(vapi_payload_dhcp6_duid_ll_set *payload)
{

}

static inline void vapi_msg_dhcp6_duid_ll_set_hton(vapi_msg_dhcp6_duid_ll_set *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp6_duid_ll_set'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_dhcp6_duid_ll_set_payload_hton(&msg->payload);
}

static inline void vapi_msg_dhcp6_duid_ll_set_ntoh(vapi_msg_dhcp6_duid_ll_set *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp6_duid_ll_set'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_dhcp6_duid_ll_set_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dhcp6_duid_ll_set_msg_size(vapi_msg_dhcp6_duid_ll_set *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_dhcp6_duid_ll_set_msg_size(vapi_msg_dhcp6_duid_ll_set *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dhcp6_duid_ll_set) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp6_duid_ll_set' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dhcp6_duid_ll_set));
      return -1;
    }
  if (vapi_calc_dhcp6_duid_ll_set_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp6_duid_ll_set' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dhcp6_duid_ll_set_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_dhcp6_duid_ll_set* vapi_alloc_dhcp6_duid_ll_set(struct vapi_ctx_s *ctx)
{
  vapi_msg_dhcp6_duid_ll_set *msg = NULL;
  const size_t size = sizeof(vapi_msg_dhcp6_duid_ll_set);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_dhcp6_duid_ll_set*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_dhcp6_duid_ll_set);

  return msg;
}

static inline vapi_error_e vapi_dhcp6_duid_ll_set(struct vapi_ctx_s *ctx,
  vapi_msg_dhcp6_duid_ll_set *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_dhcp6_duid_ll_set_reply *reply),
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
  vapi_msg_dhcp6_duid_ll_set_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_dhcp6_duid_ll_set_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_dhcp6_duid_ll_set_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_dhcp6_duid_ll_set()
{
  static const char name[] = "dhcp6_duid_ll_set";
  static const char name_with_crc[] = "dhcp6_duid_ll_set_0f6ca323";
  static vapi_message_desc_t __vapi_metadata_dhcp6_duid_ll_set = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_dhcp6_duid_ll_set, payload),
    (verify_msg_size_fn_t)vapi_verify_dhcp6_duid_ll_set_msg_size,
    (generic_swap_fn_t)vapi_msg_dhcp6_duid_ll_set_hton,
    (generic_swap_fn_t)vapi_msg_dhcp6_duid_ll_set_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dhcp6_duid_ll_set = vapi_register_msg(&__vapi_metadata_dhcp6_duid_ll_set);
  VAPI_DBG("Assigned msg id %d to dhcp6_duid_ll_set", vapi_msg_id_dhcp6_duid_ll_set);
}
#endif

#ifndef defined_vapi_msg_dhcp6_clients_enable_disable_reply
#define defined_vapi_msg_dhcp6_clients_enable_disable_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_dhcp6_clients_enable_disable_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_dhcp6_clients_enable_disable_reply payload;
} vapi_msg_dhcp6_clients_enable_disable_reply;

static inline void vapi_msg_dhcp6_clients_enable_disable_reply_payload_hton(vapi_payload_dhcp6_clients_enable_disable_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_dhcp6_clients_enable_disable_reply_payload_ntoh(vapi_payload_dhcp6_clients_enable_disable_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_dhcp6_clients_enable_disable_reply_hton(vapi_msg_dhcp6_clients_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp6_clients_enable_disable_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_dhcp6_clients_enable_disable_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_dhcp6_clients_enable_disable_reply_ntoh(vapi_msg_dhcp6_clients_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp6_clients_enable_disable_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_dhcp6_clients_enable_disable_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dhcp6_clients_enable_disable_reply_msg_size(vapi_msg_dhcp6_clients_enable_disable_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_dhcp6_clients_enable_disable_reply_msg_size(vapi_msg_dhcp6_clients_enable_disable_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dhcp6_clients_enable_disable_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp6_clients_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dhcp6_clients_enable_disable_reply));
      return -1;
    }
  if (vapi_calc_dhcp6_clients_enable_disable_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp6_clients_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dhcp6_clients_enable_disable_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_dhcp6_clients_enable_disable_reply()
{
  static const char name[] = "dhcp6_clients_enable_disable_reply";
  static const char name_with_crc[] = "dhcp6_clients_enable_disable_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_dhcp6_clients_enable_disable_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_dhcp6_clients_enable_disable_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_dhcp6_clients_enable_disable_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_dhcp6_clients_enable_disable_reply_hton,
    (generic_swap_fn_t)vapi_msg_dhcp6_clients_enable_disable_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dhcp6_clients_enable_disable_reply = vapi_register_msg(&__vapi_metadata_dhcp6_clients_enable_disable_reply);
  VAPI_DBG("Assigned msg id %d to dhcp6_clients_enable_disable_reply", vapi_msg_id_dhcp6_clients_enable_disable_reply);
}

static inline void vapi_set_vapi_msg_dhcp6_clients_enable_disable_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_dhcp6_clients_enable_disable_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_dhcp6_clients_enable_disable_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_dhcp6_clients_enable_disable
#define defined_vapi_msg_dhcp6_clients_enable_disable
typedef struct __attribute__ ((__packed__)) {
  bool enable; 
} vapi_payload_dhcp6_clients_enable_disable;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_dhcp6_clients_enable_disable payload;
} vapi_msg_dhcp6_clients_enable_disable;

static inline void vapi_msg_dhcp6_clients_enable_disable_payload_hton(vapi_payload_dhcp6_clients_enable_disable *payload)
{

}

static inline void vapi_msg_dhcp6_clients_enable_disable_payload_ntoh(vapi_payload_dhcp6_clients_enable_disable *payload)
{

}

static inline void vapi_msg_dhcp6_clients_enable_disable_hton(vapi_msg_dhcp6_clients_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp6_clients_enable_disable'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_dhcp6_clients_enable_disable_payload_hton(&msg->payload);
}

static inline void vapi_msg_dhcp6_clients_enable_disable_ntoh(vapi_msg_dhcp6_clients_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp6_clients_enable_disable'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_dhcp6_clients_enable_disable_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dhcp6_clients_enable_disable_msg_size(vapi_msg_dhcp6_clients_enable_disable *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_dhcp6_clients_enable_disable_msg_size(vapi_msg_dhcp6_clients_enable_disable *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dhcp6_clients_enable_disable) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp6_clients_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dhcp6_clients_enable_disable));
      return -1;
    }
  if (vapi_calc_dhcp6_clients_enable_disable_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp6_clients_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dhcp6_clients_enable_disable_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_dhcp6_clients_enable_disable* vapi_alloc_dhcp6_clients_enable_disable(struct vapi_ctx_s *ctx)
{
  vapi_msg_dhcp6_clients_enable_disable *msg = NULL;
  const size_t size = sizeof(vapi_msg_dhcp6_clients_enable_disable);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_dhcp6_clients_enable_disable*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_dhcp6_clients_enable_disable);

  return msg;
}

static inline vapi_error_e vapi_dhcp6_clients_enable_disable(struct vapi_ctx_s *ctx,
  vapi_msg_dhcp6_clients_enable_disable *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_dhcp6_clients_enable_disable_reply *reply),
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
  vapi_msg_dhcp6_clients_enable_disable_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_dhcp6_clients_enable_disable_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_dhcp6_clients_enable_disable_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_dhcp6_clients_enable_disable()
{
  static const char name[] = "dhcp6_clients_enable_disable";
  static const char name_with_crc[] = "dhcp6_clients_enable_disable_b3e225d2";
  static vapi_message_desc_t __vapi_metadata_dhcp6_clients_enable_disable = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_dhcp6_clients_enable_disable, payload),
    (verify_msg_size_fn_t)vapi_verify_dhcp6_clients_enable_disable_msg_size,
    (generic_swap_fn_t)vapi_msg_dhcp6_clients_enable_disable_hton,
    (generic_swap_fn_t)vapi_msg_dhcp6_clients_enable_disable_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dhcp6_clients_enable_disable = vapi_register_msg(&__vapi_metadata_dhcp6_clients_enable_disable);
  VAPI_DBG("Assigned msg id %d to dhcp6_clients_enable_disable", vapi_msg_id_dhcp6_clients_enable_disable);
}
#endif

#ifndef defined_vapi_msg_dhcp6_send_client_message_reply
#define defined_vapi_msg_dhcp6_send_client_message_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_dhcp6_send_client_message_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_dhcp6_send_client_message_reply payload;
} vapi_msg_dhcp6_send_client_message_reply;

static inline void vapi_msg_dhcp6_send_client_message_reply_payload_hton(vapi_payload_dhcp6_send_client_message_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_dhcp6_send_client_message_reply_payload_ntoh(vapi_payload_dhcp6_send_client_message_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_dhcp6_send_client_message_reply_hton(vapi_msg_dhcp6_send_client_message_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp6_send_client_message_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_dhcp6_send_client_message_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_dhcp6_send_client_message_reply_ntoh(vapi_msg_dhcp6_send_client_message_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp6_send_client_message_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_dhcp6_send_client_message_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dhcp6_send_client_message_reply_msg_size(vapi_msg_dhcp6_send_client_message_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_dhcp6_send_client_message_reply_msg_size(vapi_msg_dhcp6_send_client_message_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dhcp6_send_client_message_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp6_send_client_message_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dhcp6_send_client_message_reply));
      return -1;
    }
  if (vapi_calc_dhcp6_send_client_message_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp6_send_client_message_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dhcp6_send_client_message_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_dhcp6_send_client_message_reply()
{
  static const char name[] = "dhcp6_send_client_message_reply";
  static const char name_with_crc[] = "dhcp6_send_client_message_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_dhcp6_send_client_message_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_dhcp6_send_client_message_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_dhcp6_send_client_message_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_dhcp6_send_client_message_reply_hton,
    (generic_swap_fn_t)vapi_msg_dhcp6_send_client_message_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dhcp6_send_client_message_reply = vapi_register_msg(&__vapi_metadata_dhcp6_send_client_message_reply);
  VAPI_DBG("Assigned msg id %d to dhcp6_send_client_message_reply", vapi_msg_id_dhcp6_send_client_message_reply);
}

static inline void vapi_set_vapi_msg_dhcp6_send_client_message_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_dhcp6_send_client_message_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_dhcp6_send_client_message_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_dhcp6_send_client_message
#define defined_vapi_msg_dhcp6_send_client_message
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  u32 server_index;
  u32 irt;
  u32 mrt;
  u32 mrc;
  u32 mrd;
  bool stop;
  vapi_enum_dhcpv6_msg_type msg_type;
  u32 T1;
  u32 T2;
  u32 n_addresses;
  vapi_type_dhcp6_address_info addresses[0]; 
} vapi_payload_dhcp6_send_client_message;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_dhcp6_send_client_message payload;
} vapi_msg_dhcp6_send_client_message;

static inline void vapi_msg_dhcp6_send_client_message_payload_hton(vapi_payload_dhcp6_send_client_message *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->server_index = htobe32(payload->server_index);
  payload->irt = htobe32(payload->irt);
  payload->mrt = htobe32(payload->mrt);
  payload->mrc = htobe32(payload->mrc);
  payload->mrd = htobe32(payload->mrd);
  payload->msg_type = (vapi_enum_dhcpv6_msg_type)htobe32(payload->msg_type);
  payload->T1 = htobe32(payload->T1);
  payload->T2 = htobe32(payload->T2);
  payload->n_addresses = htobe32(payload->n_addresses);
  do { unsigned i; for (i = 0; i < be32toh(payload->n_addresses); ++i) { vapi_type_dhcp6_address_info_hton(&payload->addresses[i]); } } while(0);
}

static inline void vapi_msg_dhcp6_send_client_message_payload_ntoh(vapi_payload_dhcp6_send_client_message *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->server_index = be32toh(payload->server_index);
  payload->irt = be32toh(payload->irt);
  payload->mrt = be32toh(payload->mrt);
  payload->mrc = be32toh(payload->mrc);
  payload->mrd = be32toh(payload->mrd);
  payload->msg_type = (vapi_enum_dhcpv6_msg_type)be32toh(payload->msg_type);
  payload->T1 = be32toh(payload->T1);
  payload->T2 = be32toh(payload->T2);
  payload->n_addresses = be32toh(payload->n_addresses);
  do { unsigned i; for (i = 0; i < payload->n_addresses; ++i) { vapi_type_dhcp6_address_info_ntoh(&payload->addresses[i]); } } while(0);
}

static inline void vapi_msg_dhcp6_send_client_message_hton(vapi_msg_dhcp6_send_client_message *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp6_send_client_message'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_dhcp6_send_client_message_payload_hton(&msg->payload);
}

static inline void vapi_msg_dhcp6_send_client_message_ntoh(vapi_msg_dhcp6_send_client_message *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp6_send_client_message'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_dhcp6_send_client_message_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dhcp6_send_client_message_msg_size(vapi_msg_dhcp6_send_client_message *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.addresses[0]) * msg->payload.n_addresses;
}

static inline int vapi_verify_dhcp6_send_client_message_msg_size(vapi_msg_dhcp6_send_client_message *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dhcp6_send_client_message) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp6_send_client_message' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dhcp6_send_client_message));
      return -1;
    }
  if (vapi_calc_dhcp6_send_client_message_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp6_send_client_message' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dhcp6_send_client_message_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_dhcp6_send_client_message* vapi_alloc_dhcp6_send_client_message(struct vapi_ctx_s *ctx, size_t _addresses_array_size)
{
  vapi_msg_dhcp6_send_client_message *msg = NULL;
  const size_t size = sizeof(vapi_msg_dhcp6_send_client_message) + sizeof(msg->payload.addresses[0]) * _addresses_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_dhcp6_send_client_message*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_dhcp6_send_client_message);
  msg->payload.n_addresses = _addresses_array_size;

  return msg;
}

static inline vapi_error_e vapi_dhcp6_send_client_message(struct vapi_ctx_s *ctx,
  vapi_msg_dhcp6_send_client_message *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_dhcp6_send_client_message_reply *reply),
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
  vapi_msg_dhcp6_send_client_message_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_dhcp6_send_client_message_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_dhcp6_send_client_message_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_dhcp6_send_client_message()
{
  static const char name[] = "dhcp6_send_client_message";
  static const char name_with_crc[] = "dhcp6_send_client_message_f8222476";
  static vapi_message_desc_t __vapi_metadata_dhcp6_send_client_message = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_dhcp6_send_client_message, payload),
    (verify_msg_size_fn_t)vapi_verify_dhcp6_send_client_message_msg_size,
    (generic_swap_fn_t)vapi_msg_dhcp6_send_client_message_hton,
    (generic_swap_fn_t)vapi_msg_dhcp6_send_client_message_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dhcp6_send_client_message = vapi_register_msg(&__vapi_metadata_dhcp6_send_client_message);
  VAPI_DBG("Assigned msg id %d to dhcp6_send_client_message", vapi_msg_id_dhcp6_send_client_message);
}
#endif

#ifndef defined_vapi_msg_dhcp6_pd_send_client_message_reply
#define defined_vapi_msg_dhcp6_pd_send_client_message_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_dhcp6_pd_send_client_message_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_dhcp6_pd_send_client_message_reply payload;
} vapi_msg_dhcp6_pd_send_client_message_reply;

static inline void vapi_msg_dhcp6_pd_send_client_message_reply_payload_hton(vapi_payload_dhcp6_pd_send_client_message_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_dhcp6_pd_send_client_message_reply_payload_ntoh(vapi_payload_dhcp6_pd_send_client_message_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_dhcp6_pd_send_client_message_reply_hton(vapi_msg_dhcp6_pd_send_client_message_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp6_pd_send_client_message_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_dhcp6_pd_send_client_message_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_dhcp6_pd_send_client_message_reply_ntoh(vapi_msg_dhcp6_pd_send_client_message_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp6_pd_send_client_message_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_dhcp6_pd_send_client_message_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dhcp6_pd_send_client_message_reply_msg_size(vapi_msg_dhcp6_pd_send_client_message_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_dhcp6_pd_send_client_message_reply_msg_size(vapi_msg_dhcp6_pd_send_client_message_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dhcp6_pd_send_client_message_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp6_pd_send_client_message_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dhcp6_pd_send_client_message_reply));
      return -1;
    }
  if (vapi_calc_dhcp6_pd_send_client_message_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp6_pd_send_client_message_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dhcp6_pd_send_client_message_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_dhcp6_pd_send_client_message_reply()
{
  static const char name[] = "dhcp6_pd_send_client_message_reply";
  static const char name_with_crc[] = "dhcp6_pd_send_client_message_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_dhcp6_pd_send_client_message_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_dhcp6_pd_send_client_message_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_dhcp6_pd_send_client_message_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_dhcp6_pd_send_client_message_reply_hton,
    (generic_swap_fn_t)vapi_msg_dhcp6_pd_send_client_message_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dhcp6_pd_send_client_message_reply = vapi_register_msg(&__vapi_metadata_dhcp6_pd_send_client_message_reply);
  VAPI_DBG("Assigned msg id %d to dhcp6_pd_send_client_message_reply", vapi_msg_id_dhcp6_pd_send_client_message_reply);
}

static inline void vapi_set_vapi_msg_dhcp6_pd_send_client_message_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_dhcp6_pd_send_client_message_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_dhcp6_pd_send_client_message_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_dhcp6_pd_send_client_message
#define defined_vapi_msg_dhcp6_pd_send_client_message
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  u32 server_index;
  u32 irt;
  u32 mrt;
  u32 mrc;
  u32 mrd;
  bool stop;
  vapi_enum_dhcpv6_msg_type msg_type;
  u32 T1;
  u32 T2;
  u32 n_prefixes;
  vapi_type_dhcp6_pd_prefix_info prefixes[0]; 
} vapi_payload_dhcp6_pd_send_client_message;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_dhcp6_pd_send_client_message payload;
} vapi_msg_dhcp6_pd_send_client_message;

static inline void vapi_msg_dhcp6_pd_send_client_message_payload_hton(vapi_payload_dhcp6_pd_send_client_message *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->server_index = htobe32(payload->server_index);
  payload->irt = htobe32(payload->irt);
  payload->mrt = htobe32(payload->mrt);
  payload->mrc = htobe32(payload->mrc);
  payload->mrd = htobe32(payload->mrd);
  payload->msg_type = (vapi_enum_dhcpv6_msg_type)htobe32(payload->msg_type);
  payload->T1 = htobe32(payload->T1);
  payload->T2 = htobe32(payload->T2);
  payload->n_prefixes = htobe32(payload->n_prefixes);
  do { unsigned i; for (i = 0; i < be32toh(payload->n_prefixes); ++i) { vapi_type_dhcp6_pd_prefix_info_hton(&payload->prefixes[i]); } } while(0);
}

static inline void vapi_msg_dhcp6_pd_send_client_message_payload_ntoh(vapi_payload_dhcp6_pd_send_client_message *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->server_index = be32toh(payload->server_index);
  payload->irt = be32toh(payload->irt);
  payload->mrt = be32toh(payload->mrt);
  payload->mrc = be32toh(payload->mrc);
  payload->mrd = be32toh(payload->mrd);
  payload->msg_type = (vapi_enum_dhcpv6_msg_type)be32toh(payload->msg_type);
  payload->T1 = be32toh(payload->T1);
  payload->T2 = be32toh(payload->T2);
  payload->n_prefixes = be32toh(payload->n_prefixes);
  do { unsigned i; for (i = 0; i < payload->n_prefixes; ++i) { vapi_type_dhcp6_pd_prefix_info_ntoh(&payload->prefixes[i]); } } while(0);
}

static inline void vapi_msg_dhcp6_pd_send_client_message_hton(vapi_msg_dhcp6_pd_send_client_message *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp6_pd_send_client_message'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_dhcp6_pd_send_client_message_payload_hton(&msg->payload);
}

static inline void vapi_msg_dhcp6_pd_send_client_message_ntoh(vapi_msg_dhcp6_pd_send_client_message *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp6_pd_send_client_message'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_dhcp6_pd_send_client_message_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dhcp6_pd_send_client_message_msg_size(vapi_msg_dhcp6_pd_send_client_message *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.prefixes[0]) * msg->payload.n_prefixes;
}

static inline int vapi_verify_dhcp6_pd_send_client_message_msg_size(vapi_msg_dhcp6_pd_send_client_message *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dhcp6_pd_send_client_message) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp6_pd_send_client_message' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dhcp6_pd_send_client_message));
      return -1;
    }
  if (vapi_calc_dhcp6_pd_send_client_message_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp6_pd_send_client_message' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dhcp6_pd_send_client_message_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_dhcp6_pd_send_client_message* vapi_alloc_dhcp6_pd_send_client_message(struct vapi_ctx_s *ctx, size_t _prefixes_array_size)
{
  vapi_msg_dhcp6_pd_send_client_message *msg = NULL;
  const size_t size = sizeof(vapi_msg_dhcp6_pd_send_client_message) + sizeof(msg->payload.prefixes[0]) * _prefixes_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_dhcp6_pd_send_client_message*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_dhcp6_pd_send_client_message);
  msg->payload.n_prefixes = _prefixes_array_size;

  return msg;
}

static inline vapi_error_e vapi_dhcp6_pd_send_client_message(struct vapi_ctx_s *ctx,
  vapi_msg_dhcp6_pd_send_client_message *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_dhcp6_pd_send_client_message_reply *reply),
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
  vapi_msg_dhcp6_pd_send_client_message_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_dhcp6_pd_send_client_message_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_dhcp6_pd_send_client_message_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_dhcp6_pd_send_client_message()
{
  static const char name[] = "dhcp6_pd_send_client_message";
  static const char name_with_crc[] = "dhcp6_pd_send_client_message_3739fd8d";
  static vapi_message_desc_t __vapi_metadata_dhcp6_pd_send_client_message = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_dhcp6_pd_send_client_message, payload),
    (verify_msg_size_fn_t)vapi_verify_dhcp6_pd_send_client_message_msg_size,
    (generic_swap_fn_t)vapi_msg_dhcp6_pd_send_client_message_hton,
    (generic_swap_fn_t)vapi_msg_dhcp6_pd_send_client_message_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dhcp6_pd_send_client_message = vapi_register_msg(&__vapi_metadata_dhcp6_pd_send_client_message);
  VAPI_DBG("Assigned msg id %d to dhcp6_pd_send_client_message", vapi_msg_id_dhcp6_pd_send_client_message);
}
#endif

#ifndef defined_vapi_msg_want_dhcp6_reply_events_reply
#define defined_vapi_msg_want_dhcp6_reply_events_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_want_dhcp6_reply_events_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_want_dhcp6_reply_events_reply payload;
} vapi_msg_want_dhcp6_reply_events_reply;

static inline void vapi_msg_want_dhcp6_reply_events_reply_payload_hton(vapi_payload_want_dhcp6_reply_events_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_want_dhcp6_reply_events_reply_payload_ntoh(vapi_payload_want_dhcp6_reply_events_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_want_dhcp6_reply_events_reply_hton(vapi_msg_want_dhcp6_reply_events_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_dhcp6_reply_events_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_want_dhcp6_reply_events_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_want_dhcp6_reply_events_reply_ntoh(vapi_msg_want_dhcp6_reply_events_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_dhcp6_reply_events_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_want_dhcp6_reply_events_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_want_dhcp6_reply_events_reply_msg_size(vapi_msg_want_dhcp6_reply_events_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_want_dhcp6_reply_events_reply_msg_size(vapi_msg_want_dhcp6_reply_events_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_want_dhcp6_reply_events_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'want_dhcp6_reply_events_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_want_dhcp6_reply_events_reply));
      return -1;
    }
  if (vapi_calc_want_dhcp6_reply_events_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'want_dhcp6_reply_events_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_want_dhcp6_reply_events_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_want_dhcp6_reply_events_reply()
{
  static const char name[] = "want_dhcp6_reply_events_reply";
  static const char name_with_crc[] = "want_dhcp6_reply_events_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_want_dhcp6_reply_events_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_want_dhcp6_reply_events_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_want_dhcp6_reply_events_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_want_dhcp6_reply_events_reply_hton,
    (generic_swap_fn_t)vapi_msg_want_dhcp6_reply_events_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_want_dhcp6_reply_events_reply = vapi_register_msg(&__vapi_metadata_want_dhcp6_reply_events_reply);
  VAPI_DBG("Assigned msg id %d to want_dhcp6_reply_events_reply", vapi_msg_id_want_dhcp6_reply_events_reply);
}

static inline void vapi_set_vapi_msg_want_dhcp6_reply_events_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_want_dhcp6_reply_events_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_want_dhcp6_reply_events_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_want_dhcp6_reply_events
#define defined_vapi_msg_want_dhcp6_reply_events
typedef struct __attribute__ ((__packed__)) {
  u8 enable_disable;
  u32 pid; 
} vapi_payload_want_dhcp6_reply_events;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_want_dhcp6_reply_events payload;
} vapi_msg_want_dhcp6_reply_events;

static inline void vapi_msg_want_dhcp6_reply_events_payload_hton(vapi_payload_want_dhcp6_reply_events *payload)
{
  payload->pid = htobe32(payload->pid);
}

static inline void vapi_msg_want_dhcp6_reply_events_payload_ntoh(vapi_payload_want_dhcp6_reply_events *payload)
{
  payload->pid = be32toh(payload->pid);
}

static inline void vapi_msg_want_dhcp6_reply_events_hton(vapi_msg_want_dhcp6_reply_events *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_dhcp6_reply_events'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_want_dhcp6_reply_events_payload_hton(&msg->payload);
}

static inline void vapi_msg_want_dhcp6_reply_events_ntoh(vapi_msg_want_dhcp6_reply_events *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_dhcp6_reply_events'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_want_dhcp6_reply_events_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_want_dhcp6_reply_events_msg_size(vapi_msg_want_dhcp6_reply_events *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_want_dhcp6_reply_events_msg_size(vapi_msg_want_dhcp6_reply_events *msg, uword buf_size)
{
  if (sizeof(vapi_msg_want_dhcp6_reply_events) > buf_size)
    {
      VAPI_ERR("Truncated 'want_dhcp6_reply_events' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_want_dhcp6_reply_events));
      return -1;
    }
  if (vapi_calc_want_dhcp6_reply_events_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'want_dhcp6_reply_events' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_want_dhcp6_reply_events_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_want_dhcp6_reply_events* vapi_alloc_want_dhcp6_reply_events(struct vapi_ctx_s *ctx)
{
  vapi_msg_want_dhcp6_reply_events *msg = NULL;
  const size_t size = sizeof(vapi_msg_want_dhcp6_reply_events);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_want_dhcp6_reply_events*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_want_dhcp6_reply_events);

  return msg;
}

static inline vapi_error_e vapi_want_dhcp6_reply_events(struct vapi_ctx_s *ctx,
  vapi_msg_want_dhcp6_reply_events *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_want_dhcp6_reply_events_reply *reply),
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
  vapi_msg_want_dhcp6_reply_events_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_want_dhcp6_reply_events_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_want_dhcp6_reply_events_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_want_dhcp6_reply_events()
{
  static const char name[] = "want_dhcp6_reply_events";
  static const char name_with_crc[] = "want_dhcp6_reply_events_05b454b5";
  static vapi_message_desc_t __vapi_metadata_want_dhcp6_reply_events = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_want_dhcp6_reply_events, payload),
    (verify_msg_size_fn_t)vapi_verify_want_dhcp6_reply_events_msg_size,
    (generic_swap_fn_t)vapi_msg_want_dhcp6_reply_events_hton,
    (generic_swap_fn_t)vapi_msg_want_dhcp6_reply_events_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_want_dhcp6_reply_events = vapi_register_msg(&__vapi_metadata_want_dhcp6_reply_events);
  VAPI_DBG("Assigned msg id %d to want_dhcp6_reply_events", vapi_msg_id_want_dhcp6_reply_events);
}
#endif

#ifndef defined_vapi_msg_want_dhcp6_pd_reply_events_reply
#define defined_vapi_msg_want_dhcp6_pd_reply_events_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_want_dhcp6_pd_reply_events_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_want_dhcp6_pd_reply_events_reply payload;
} vapi_msg_want_dhcp6_pd_reply_events_reply;

static inline void vapi_msg_want_dhcp6_pd_reply_events_reply_payload_hton(vapi_payload_want_dhcp6_pd_reply_events_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_want_dhcp6_pd_reply_events_reply_payload_ntoh(vapi_payload_want_dhcp6_pd_reply_events_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_want_dhcp6_pd_reply_events_reply_hton(vapi_msg_want_dhcp6_pd_reply_events_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_dhcp6_pd_reply_events_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_want_dhcp6_pd_reply_events_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_want_dhcp6_pd_reply_events_reply_ntoh(vapi_msg_want_dhcp6_pd_reply_events_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_dhcp6_pd_reply_events_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_want_dhcp6_pd_reply_events_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_want_dhcp6_pd_reply_events_reply_msg_size(vapi_msg_want_dhcp6_pd_reply_events_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_want_dhcp6_pd_reply_events_reply_msg_size(vapi_msg_want_dhcp6_pd_reply_events_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_want_dhcp6_pd_reply_events_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'want_dhcp6_pd_reply_events_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_want_dhcp6_pd_reply_events_reply));
      return -1;
    }
  if (vapi_calc_want_dhcp6_pd_reply_events_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'want_dhcp6_pd_reply_events_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_want_dhcp6_pd_reply_events_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_want_dhcp6_pd_reply_events_reply()
{
  static const char name[] = "want_dhcp6_pd_reply_events_reply";
  static const char name_with_crc[] = "want_dhcp6_pd_reply_events_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_want_dhcp6_pd_reply_events_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_want_dhcp6_pd_reply_events_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_want_dhcp6_pd_reply_events_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_want_dhcp6_pd_reply_events_reply_hton,
    (generic_swap_fn_t)vapi_msg_want_dhcp6_pd_reply_events_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_want_dhcp6_pd_reply_events_reply = vapi_register_msg(&__vapi_metadata_want_dhcp6_pd_reply_events_reply);
  VAPI_DBG("Assigned msg id %d to want_dhcp6_pd_reply_events_reply", vapi_msg_id_want_dhcp6_pd_reply_events_reply);
}

static inline void vapi_set_vapi_msg_want_dhcp6_pd_reply_events_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_want_dhcp6_pd_reply_events_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_want_dhcp6_pd_reply_events_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_want_dhcp6_pd_reply_events
#define defined_vapi_msg_want_dhcp6_pd_reply_events
typedef struct __attribute__ ((__packed__)) {
  bool enable_disable;
  u32 pid; 
} vapi_payload_want_dhcp6_pd_reply_events;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_want_dhcp6_pd_reply_events payload;
} vapi_msg_want_dhcp6_pd_reply_events;

static inline void vapi_msg_want_dhcp6_pd_reply_events_payload_hton(vapi_payload_want_dhcp6_pd_reply_events *payload)
{
  payload->pid = htobe32(payload->pid);
}

static inline void vapi_msg_want_dhcp6_pd_reply_events_payload_ntoh(vapi_payload_want_dhcp6_pd_reply_events *payload)
{
  payload->pid = be32toh(payload->pid);
}

static inline void vapi_msg_want_dhcp6_pd_reply_events_hton(vapi_msg_want_dhcp6_pd_reply_events *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_dhcp6_pd_reply_events'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_want_dhcp6_pd_reply_events_payload_hton(&msg->payload);
}

static inline void vapi_msg_want_dhcp6_pd_reply_events_ntoh(vapi_msg_want_dhcp6_pd_reply_events *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_dhcp6_pd_reply_events'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_want_dhcp6_pd_reply_events_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_want_dhcp6_pd_reply_events_msg_size(vapi_msg_want_dhcp6_pd_reply_events *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_want_dhcp6_pd_reply_events_msg_size(vapi_msg_want_dhcp6_pd_reply_events *msg, uword buf_size)
{
  if (sizeof(vapi_msg_want_dhcp6_pd_reply_events) > buf_size)
    {
      VAPI_ERR("Truncated 'want_dhcp6_pd_reply_events' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_want_dhcp6_pd_reply_events));
      return -1;
    }
  if (vapi_calc_want_dhcp6_pd_reply_events_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'want_dhcp6_pd_reply_events' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_want_dhcp6_pd_reply_events_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_want_dhcp6_pd_reply_events* vapi_alloc_want_dhcp6_pd_reply_events(struct vapi_ctx_s *ctx)
{
  vapi_msg_want_dhcp6_pd_reply_events *msg = NULL;
  const size_t size = sizeof(vapi_msg_want_dhcp6_pd_reply_events);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_want_dhcp6_pd_reply_events*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_want_dhcp6_pd_reply_events);

  return msg;
}

static inline vapi_error_e vapi_want_dhcp6_pd_reply_events(struct vapi_ctx_s *ctx,
  vapi_msg_want_dhcp6_pd_reply_events *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_want_dhcp6_pd_reply_events_reply *reply),
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
  vapi_msg_want_dhcp6_pd_reply_events_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_want_dhcp6_pd_reply_events_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_want_dhcp6_pd_reply_events_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_want_dhcp6_pd_reply_events()
{
  static const char name[] = "want_dhcp6_pd_reply_events";
  static const char name_with_crc[] = "want_dhcp6_pd_reply_events_c5e2af94";
  static vapi_message_desc_t __vapi_metadata_want_dhcp6_pd_reply_events = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_want_dhcp6_pd_reply_events, payload),
    (verify_msg_size_fn_t)vapi_verify_want_dhcp6_pd_reply_events_msg_size,
    (generic_swap_fn_t)vapi_msg_want_dhcp6_pd_reply_events_hton,
    (generic_swap_fn_t)vapi_msg_want_dhcp6_pd_reply_events_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_want_dhcp6_pd_reply_events = vapi_register_msg(&__vapi_metadata_want_dhcp6_pd_reply_events);
  VAPI_DBG("Assigned msg id %d to want_dhcp6_pd_reply_events", vapi_msg_id_want_dhcp6_pd_reply_events);
}
#endif

#ifndef defined_vapi_msg_dhcp6_reply_event
#define defined_vapi_msg_dhcp6_reply_event
typedef struct __attribute__ ((__packed__)) {
  u16 _vl_msg_id;
  u32 client_index;
  u32 pid;
  vapi_type_interface_index sw_if_index;
  u32 server_index;
  vapi_enum_dhcpv6_msg_type msg_type;
  u32 T1;
  u32 T2;
  u16 inner_status_code;
  u16 status_code;
  u8 preference;
  u32 n_addresses;
  vapi_type_dhcp6_address_info addresses[0]; 
} vapi_payload_dhcp6_reply_event;

typedef struct __attribute__ ((__packed__)) {

  vapi_payload_dhcp6_reply_event payload;
} vapi_msg_dhcp6_reply_event;

static inline void vapi_msg_dhcp6_reply_event_payload_hton(vapi_payload_dhcp6_reply_event *payload)
{
  payload->_vl_msg_id = htobe16(payload->_vl_msg_id);
  payload->client_index = htobe32(payload->client_index);
  payload->pid = htobe32(payload->pid);
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->server_index = htobe32(payload->server_index);
  payload->msg_type = (vapi_enum_dhcpv6_msg_type)htobe32(payload->msg_type);
  payload->T1 = htobe32(payload->T1);
  payload->T2 = htobe32(payload->T2);
  payload->inner_status_code = htobe16(payload->inner_status_code);
  payload->status_code = htobe16(payload->status_code);
  payload->n_addresses = htobe32(payload->n_addresses);
  do { unsigned i; for (i = 0; i < be32toh(payload->n_addresses); ++i) { vapi_type_dhcp6_address_info_hton(&payload->addresses[i]); } } while(0);
}

static inline void vapi_msg_dhcp6_reply_event_payload_ntoh(vapi_payload_dhcp6_reply_event *payload)
{
  payload->_vl_msg_id = be16toh(payload->_vl_msg_id);
  payload->client_index = be32toh(payload->client_index);
  payload->pid = be32toh(payload->pid);
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->server_index = be32toh(payload->server_index);
  payload->msg_type = (vapi_enum_dhcpv6_msg_type)be32toh(payload->msg_type);
  payload->T1 = be32toh(payload->T1);
  payload->T2 = be32toh(payload->T2);
  payload->inner_status_code = be16toh(payload->inner_status_code);
  payload->status_code = be16toh(payload->status_code);
  payload->n_addresses = be32toh(payload->n_addresses);
  do { unsigned i; for (i = 0; i < payload->n_addresses; ++i) { vapi_type_dhcp6_address_info_ntoh(&payload->addresses[i]); } } while(0);
}

static inline void vapi_msg_dhcp6_reply_event_hton(vapi_msg_dhcp6_reply_event *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp6_reply_event'@%p to big endian", msg);

  vapi_msg_dhcp6_reply_event_payload_hton(&msg->payload);
}

static inline void vapi_msg_dhcp6_reply_event_ntoh(vapi_msg_dhcp6_reply_event *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp6_reply_event'@%p to host byte order", msg);

  vapi_msg_dhcp6_reply_event_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dhcp6_reply_event_msg_size(vapi_msg_dhcp6_reply_event *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.addresses[0]) * msg->payload.n_addresses;
}

static inline int vapi_verify_dhcp6_reply_event_msg_size(vapi_msg_dhcp6_reply_event *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dhcp6_reply_event) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp6_reply_event' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dhcp6_reply_event));
      return -1;
    }
  if (vapi_calc_dhcp6_reply_event_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp6_reply_event' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dhcp6_reply_event_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_dhcp6_reply_event()
{
  static const char name[] = "dhcp6_reply_event";
  static const char name_with_crc[] = "dhcp6_reply_event_85b7b17e";
  static vapi_message_desc_t __vapi_metadata_dhcp6_reply_event = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    false,
    0,
    offsetof(vapi_msg_dhcp6_reply_event, payload),
    (verify_msg_size_fn_t)vapi_verify_dhcp6_reply_event_msg_size,
    (generic_swap_fn_t)vapi_msg_dhcp6_reply_event_hton,
    (generic_swap_fn_t)vapi_msg_dhcp6_reply_event_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dhcp6_reply_event = vapi_register_msg(&__vapi_metadata_dhcp6_reply_event);
  VAPI_DBG("Assigned msg id %d to dhcp6_reply_event", vapi_msg_id_dhcp6_reply_event);
}

static inline void vapi_set_vapi_msg_dhcp6_reply_event_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_dhcp6_reply_event *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_dhcp6_reply_event, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_dhcp6_pd_reply_event
#define defined_vapi_msg_dhcp6_pd_reply_event
typedef struct __attribute__ ((__packed__)) {
  u16 _vl_msg_id;
  u32 client_index;
  u32 pid;
  vapi_type_interface_index sw_if_index;
  u32 server_index;
  vapi_enum_dhcpv6_msg_type msg_type;
  u32 T1;
  u32 T2;
  u16 inner_status_code;
  u16 status_code;
  u8 preference;
  u32 n_prefixes;
  vapi_type_dhcp6_pd_prefix_info prefixes[0]; 
} vapi_payload_dhcp6_pd_reply_event;

typedef struct __attribute__ ((__packed__)) {

  vapi_payload_dhcp6_pd_reply_event payload;
} vapi_msg_dhcp6_pd_reply_event;

static inline void vapi_msg_dhcp6_pd_reply_event_payload_hton(vapi_payload_dhcp6_pd_reply_event *payload)
{
  payload->_vl_msg_id = htobe16(payload->_vl_msg_id);
  payload->client_index = htobe32(payload->client_index);
  payload->pid = htobe32(payload->pid);
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->server_index = htobe32(payload->server_index);
  payload->msg_type = (vapi_enum_dhcpv6_msg_type)htobe32(payload->msg_type);
  payload->T1 = htobe32(payload->T1);
  payload->T2 = htobe32(payload->T2);
  payload->inner_status_code = htobe16(payload->inner_status_code);
  payload->status_code = htobe16(payload->status_code);
  payload->n_prefixes = htobe32(payload->n_prefixes);
  do { unsigned i; for (i = 0; i < be32toh(payload->n_prefixes); ++i) { vapi_type_dhcp6_pd_prefix_info_hton(&payload->prefixes[i]); } } while(0);
}

static inline void vapi_msg_dhcp6_pd_reply_event_payload_ntoh(vapi_payload_dhcp6_pd_reply_event *payload)
{
  payload->_vl_msg_id = be16toh(payload->_vl_msg_id);
  payload->client_index = be32toh(payload->client_index);
  payload->pid = be32toh(payload->pid);
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->server_index = be32toh(payload->server_index);
  payload->msg_type = (vapi_enum_dhcpv6_msg_type)be32toh(payload->msg_type);
  payload->T1 = be32toh(payload->T1);
  payload->T2 = be32toh(payload->T2);
  payload->inner_status_code = be16toh(payload->inner_status_code);
  payload->status_code = be16toh(payload->status_code);
  payload->n_prefixes = be32toh(payload->n_prefixes);
  do { unsigned i; for (i = 0; i < payload->n_prefixes; ++i) { vapi_type_dhcp6_pd_prefix_info_ntoh(&payload->prefixes[i]); } } while(0);
}

static inline void vapi_msg_dhcp6_pd_reply_event_hton(vapi_msg_dhcp6_pd_reply_event *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp6_pd_reply_event'@%p to big endian", msg);

  vapi_msg_dhcp6_pd_reply_event_payload_hton(&msg->payload);
}

static inline void vapi_msg_dhcp6_pd_reply_event_ntoh(vapi_msg_dhcp6_pd_reply_event *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dhcp6_pd_reply_event'@%p to host byte order", msg);

  vapi_msg_dhcp6_pd_reply_event_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dhcp6_pd_reply_event_msg_size(vapi_msg_dhcp6_pd_reply_event *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.prefixes[0]) * msg->payload.n_prefixes;
}

static inline int vapi_verify_dhcp6_pd_reply_event_msg_size(vapi_msg_dhcp6_pd_reply_event *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dhcp6_pd_reply_event) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp6_pd_reply_event' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dhcp6_pd_reply_event));
      return -1;
    }
  if (vapi_calc_dhcp6_pd_reply_event_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dhcp6_pd_reply_event' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dhcp6_pd_reply_event_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_dhcp6_pd_reply_event()
{
  static const char name[] = "dhcp6_pd_reply_event";
  static const char name_with_crc[] = "dhcp6_pd_reply_event_5e878029";
  static vapi_message_desc_t __vapi_metadata_dhcp6_pd_reply_event = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    false,
    0,
    offsetof(vapi_msg_dhcp6_pd_reply_event, payload),
    (verify_msg_size_fn_t)vapi_verify_dhcp6_pd_reply_event_msg_size,
    (generic_swap_fn_t)vapi_msg_dhcp6_pd_reply_event_hton,
    (generic_swap_fn_t)vapi_msg_dhcp6_pd_reply_event_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dhcp6_pd_reply_event = vapi_register_msg(&__vapi_metadata_dhcp6_pd_reply_event);
  VAPI_DBG("Assigned msg id %d to dhcp6_pd_reply_event", vapi_msg_id_dhcp6_pd_reply_event);
}

static inline void vapi_set_vapi_msg_dhcp6_pd_reply_event_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_dhcp6_pd_reply_event *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_dhcp6_pd_reply_event, (vapi_event_cb)callback, callback_ctx);
};
#endif


#ifdef __cplusplus
}
#endif

#endif
