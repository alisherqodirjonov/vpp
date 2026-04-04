#ifndef included_dhcp_api_types_h
#define included_dhcp_api_types_h
#define VL_API_DHCP_API_VERSION_MAJOR 3
#define VL_API_DHCP_API_VERSION_MINOR 0
#define VL_API_DHCP_API_VERSION_PATCH 1
/* Imported API files */
#include <vnet/interface_types.api_types.h>
#include <vnet/ip/ip_types.api_types.h>
#include <vnet/ethernet/ethernet_types.api_types.h>
typedef enum {
    VSS_TYPE_API_ASCII = 0,
    VSS_TYPE_API_VPN_ID = 1,
    VSS_TYPE_API_INVALID = 123,
    VSS_TYPE_API_DEFAULT = 255,
} vl_api_vss_type_t;
typedef enum {
    DHCP_CLIENT_STATE_API_DISCOVER = 0,
    DHCP_CLIENT_STATE_API_REQUEST = 1,
    DHCP_CLIENT_STATE_API_BOUND = 2,
} vl_api_dhcp_client_state_t;
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
} vl_api_dhcpv6_msg_type_t;
typedef struct __attribute__ ((packed)) _vl_api_dhcp_client {
    vl_api_interface_index_t sw_if_index;
    u8 hostname[64];
    u8 id[64];
    bool want_dhcp_event;
    bool set_broadcast_flag;
    vl_api_ip_dscp_t dscp;
    u32 pid;
} vl_api_dhcp_client_t;
#define VL_API_DHCP_CLIENT_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_domain_server {
    vl_api_address_t address;
} vl_api_domain_server_t;
#define VL_API_DOMAIN_SERVER_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_dhcp_lease {
    vl_api_interface_index_t sw_if_index;
    vl_api_dhcp_client_state_t state;
    bool is_ipv6;
    u8 hostname[64];
    u8 mask_width;
    vl_api_address_t host_address;
    vl_api_address_t router_address;
    vl_api_mac_address_t host_mac;
    u8 count;
    vl_api_domain_server_t domain_server[0];
} vl_api_dhcp_lease_t;
#define VL_API_DHCP_LEASE_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_dhcp_server {
    u32 server_vrf_id;
    vl_api_address_t dhcp_server;
} vl_api_dhcp_server_t;
#define VL_API_DHCP_SERVER_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_dhcp6_address_info {
    vl_api_ip6_address_t address;
    u32 valid_time;
    u32 preferred_time;
} vl_api_dhcp6_address_info_t;
#define VL_API_DHCP6_ADDRESS_INFO_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_dhcp6_pd_prefix_info {
    vl_api_ip6_prefix_t prefix;
    u32 valid_time;
    u32 preferred_time;
} vl_api_dhcp6_pd_prefix_info_t;
#define VL_API_DHCP6_PD_PREFIX_INFO_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_dhcp_plugin_get_version {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_dhcp_plugin_get_version_t;
#define VL_API_DHCP_PLUGIN_GET_VERSION_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_dhcp_plugin_get_version_reply {
    u16 _vl_msg_id;
    u32 context;
    u32 major;
    u32 minor;
} vl_api_dhcp_plugin_get_version_reply_t;
#define VL_API_DHCP_PLUGIN_GET_VERSION_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_dhcp_plugin_control_ping {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_dhcp_plugin_control_ping_t;
#define VL_API_DHCP_PLUGIN_CONTROL_PING_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_dhcp_plugin_control_ping_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 client_index;
    u32 vpe_pid;
} vl_api_dhcp_plugin_control_ping_reply_t;
#define VL_API_DHCP_PLUGIN_CONTROL_PING_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_dhcp_proxy_config {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 rx_vrf_id;
    u32 server_vrf_id;
    bool is_add;
    vl_api_address_t dhcp_server;
    vl_api_address_t dhcp_src_address;
} vl_api_dhcp_proxy_config_t;
#define VL_API_DHCP_PROXY_CONFIG_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_dhcp_proxy_config_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_dhcp_proxy_config_reply_t;
#define VL_API_DHCP_PROXY_CONFIG_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_dhcp_proxy_set_vss {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 tbl_id;
    vl_api_vss_type_t vss_type;
    u8 vpn_ascii_id[129];
    u32 oui;
    u32 vpn_index;
    bool is_ipv6;
    bool is_add;
} vl_api_dhcp_proxy_set_vss_t;
#define VL_API_DHCP_PROXY_SET_VSS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_dhcp_proxy_set_vss_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_dhcp_proxy_set_vss_reply_t;
#define VL_API_DHCP_PROXY_SET_VSS_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_dhcp_client_config {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_dhcp_client_t client;
} vl_api_dhcp_client_config_t;
#define VL_API_DHCP_CLIENT_CONFIG_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_dhcp_client_config_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_dhcp_client_config_reply_t;
#define VL_API_DHCP_CLIENT_CONFIG_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_dhcp_compl_event {
    u16 _vl_msg_id;
    u32 client_index;
    u32 pid;
    vl_api_dhcp_lease_t lease;
} vl_api_dhcp_compl_event_t;
#define VL_API_DHCP_COMPL_EVENT_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_dhcp_client_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_dhcp_client_dump_t;
#define VL_API_DHCP_CLIENT_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_dhcp_client_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_dhcp_client_t client;
    vl_api_dhcp_lease_t lease;
} vl_api_dhcp_client_details_t;
#define VL_API_DHCP_CLIENT_DETAILS_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_dhcp_proxy_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_ip6;
} vl_api_dhcp_proxy_dump_t;
#define VL_API_DHCP_PROXY_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_dhcp_proxy_details {
    u16 _vl_msg_id;
    u32 context;
    u32 rx_vrf_id;
    u32 vss_oui;
    u32 vss_fib_id;
    vl_api_vss_type_t vss_type;
    bool is_ipv6;
    u8 vss_vpn_ascii_id[129];
    vl_api_address_t dhcp_src_address;
    u8 count;
    vl_api_dhcp_server_t servers[0];
} vl_api_dhcp_proxy_details_t;
#define VL_API_DHCP_PROXY_DETAILS_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_dhcp_client_detect_enable_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    bool enable;
} vl_api_dhcp_client_detect_enable_disable_t;
#define VL_API_DHCP_CLIENT_DETECT_ENABLE_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_dhcp_client_detect_enable_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_dhcp_client_detect_enable_disable_reply_t;
#define VL_API_DHCP_CLIENT_DETECT_ENABLE_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_dhcp6_duid_ll_set {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u8 duid_ll[10];
} vl_api_dhcp6_duid_ll_set_t;
#define VL_API_DHCP6_DUID_LL_SET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_dhcp6_duid_ll_set_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_dhcp6_duid_ll_set_reply_t;
#define VL_API_DHCP6_DUID_LL_SET_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_dhcp6_clients_enable_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool enable;
} vl_api_dhcp6_clients_enable_disable_t;
#define VL_API_DHCP6_CLIENTS_ENABLE_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_dhcp6_clients_enable_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_dhcp6_clients_enable_disable_reply_t;
#define VL_API_DHCP6_CLIENTS_ENABLE_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_dhcp6_send_client_message {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u32 server_index;
    u32 irt;
    u32 mrt;
    u32 mrc;
    u32 mrd;
    bool stop;
    vl_api_dhcpv6_msg_type_t msg_type;
    u32 T1;
    u32 T2;
    u32 n_addresses;
    vl_api_dhcp6_address_info_t addresses[0];
} vl_api_dhcp6_send_client_message_t;
#define VL_API_DHCP6_SEND_CLIENT_MESSAGE_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_dhcp6_send_client_message_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_dhcp6_send_client_message_reply_t;
#define VL_API_DHCP6_SEND_CLIENT_MESSAGE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_dhcp6_pd_send_client_message {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u32 server_index;
    u32 irt;
    u32 mrt;
    u32 mrc;
    u32 mrd;
    bool stop;
    vl_api_dhcpv6_msg_type_t msg_type;
    u32 T1;
    u32 T2;
    u32 n_prefixes;
    vl_api_dhcp6_pd_prefix_info_t prefixes[0];
} vl_api_dhcp6_pd_send_client_message_t;
#define VL_API_DHCP6_PD_SEND_CLIENT_MESSAGE_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_dhcp6_pd_send_client_message_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_dhcp6_pd_send_client_message_reply_t;
#define VL_API_DHCP6_PD_SEND_CLIENT_MESSAGE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_want_dhcp6_reply_events {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u8 enable_disable;
    u32 pid;
} vl_api_want_dhcp6_reply_events_t;
#define VL_API_WANT_DHCP6_REPLY_EVENTS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_want_dhcp6_reply_events_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_want_dhcp6_reply_events_reply_t;
#define VL_API_WANT_DHCP6_REPLY_EVENTS_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_want_dhcp6_pd_reply_events {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool enable_disable;
    u32 pid;
} vl_api_want_dhcp6_pd_reply_events_t;
#define VL_API_WANT_DHCP6_PD_REPLY_EVENTS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_want_dhcp6_pd_reply_events_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_want_dhcp6_pd_reply_events_reply_t;
#define VL_API_WANT_DHCP6_PD_REPLY_EVENTS_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_dhcp6_reply_event {
    u16 _vl_msg_id;
    u32 client_index;
    u32 pid;
    vl_api_interface_index_t sw_if_index;
    u32 server_index;
    vl_api_dhcpv6_msg_type_t msg_type;
    u32 T1;
    u32 T2;
    u16 inner_status_code;
    u16 status_code;
    u8 preference;
    u32 n_addresses;
    vl_api_dhcp6_address_info_t addresses[0];
} vl_api_dhcp6_reply_event_t;
#define VL_API_DHCP6_REPLY_EVENT_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_dhcp6_pd_reply_event {
    u16 _vl_msg_id;
    u32 client_index;
    u32 pid;
    vl_api_interface_index_t sw_if_index;
    u32 server_index;
    vl_api_dhcpv6_msg_type_t msg_type;
    u32 T1;
    u32 T2;
    u16 inner_status_code;
    u16 status_code;
    u8 preference;
    u32 n_prefixes;
    vl_api_dhcp6_pd_prefix_info_t prefixes[0];
} vl_api_dhcp6_pd_reply_event_t;
#define VL_API_DHCP6_PD_REPLY_EVENT_IS_CONSTANT_SIZE (0)

#define VL_API_DHCP_PLUGIN_GET_VERSION_CRC "dhcp_plugin_get_version_51077d14"
#define VL_API_DHCP_PLUGIN_GET_VERSION_REPLY_CRC "dhcp_plugin_get_version_reply_9b32cf86"
#define VL_API_DHCP_PLUGIN_CONTROL_PING_CRC "dhcp_plugin_control_ping_51077d14"
#define VL_API_DHCP_PLUGIN_CONTROL_PING_REPLY_CRC "dhcp_plugin_control_ping_reply_f6b0b8ca"
#define VL_API_DHCP_PROXY_CONFIG_CRC "dhcp_proxy_config_4058a689"
#define VL_API_DHCP_PROXY_CONFIG_REPLY_CRC "dhcp_proxy_config_reply_e8d4e804"
#define VL_API_DHCP_PROXY_SET_VSS_CRC "dhcp_proxy_set_vss_50537301"
#define VL_API_DHCP_PROXY_SET_VSS_REPLY_CRC "dhcp_proxy_set_vss_reply_e8d4e804"
#define VL_API_DHCP_CLIENT_CONFIG_CRC "dhcp_client_config_1af013ea"
#define VL_API_DHCP_CLIENT_CONFIG_REPLY_CRC "dhcp_client_config_reply_e8d4e804"
#define VL_API_DHCP_COMPL_EVENT_CRC "dhcp_compl_event_e18124b7"
#define VL_API_DHCP_CLIENT_DUMP_CRC "dhcp_client_dump_51077d14"
#define VL_API_DHCP_CLIENT_DETAILS_CRC "dhcp_client_details_8897b2d8"
#define VL_API_DHCP_PROXY_DUMP_CRC "dhcp_proxy_dump_5c5b063f"
#define VL_API_DHCP_PROXY_DETAILS_CRC "dhcp_proxy_details_dcbaf540"
#define VL_API_DHCP_CLIENT_DETECT_ENABLE_DISABLE_CRC "dhcp_client_detect_enable_disable_ae6cfcfb"
#define VL_API_DHCP_CLIENT_DETECT_ENABLE_DISABLE_REPLY_CRC "dhcp_client_detect_enable_disable_reply_e8d4e804"
#define VL_API_DHCP6_DUID_LL_SET_CRC "dhcp6_duid_ll_set_0f6ca323"
#define VL_API_DHCP6_DUID_LL_SET_REPLY_CRC "dhcp6_duid_ll_set_reply_e8d4e804"
#define VL_API_DHCP6_CLIENTS_ENABLE_DISABLE_CRC "dhcp6_clients_enable_disable_b3e225d2"
#define VL_API_DHCP6_CLIENTS_ENABLE_DISABLE_REPLY_CRC "dhcp6_clients_enable_disable_reply_e8d4e804"
#define VL_API_DHCP6_SEND_CLIENT_MESSAGE_CRC "dhcp6_send_client_message_f8222476"
#define VL_API_DHCP6_SEND_CLIENT_MESSAGE_REPLY_CRC "dhcp6_send_client_message_reply_e8d4e804"
#define VL_API_DHCP6_PD_SEND_CLIENT_MESSAGE_CRC "dhcp6_pd_send_client_message_3739fd8d"
#define VL_API_DHCP6_PD_SEND_CLIENT_MESSAGE_REPLY_CRC "dhcp6_pd_send_client_message_reply_e8d4e804"
#define VL_API_WANT_DHCP6_REPLY_EVENTS_CRC "want_dhcp6_reply_events_05b454b5"
#define VL_API_WANT_DHCP6_REPLY_EVENTS_REPLY_CRC "want_dhcp6_reply_events_reply_e8d4e804"
#define VL_API_WANT_DHCP6_PD_REPLY_EVENTS_CRC "want_dhcp6_pd_reply_events_c5e2af94"
#define VL_API_WANT_DHCP6_PD_REPLY_EVENTS_REPLY_CRC "want_dhcp6_pd_reply_events_reply_e8d4e804"
#define VL_API_DHCP6_REPLY_EVENT_CRC "dhcp6_reply_event_85b7b17e"
#define VL_API_DHCP6_PD_REPLY_EVENT_CRC "dhcp6_pd_reply_event_5e878029"

#endif
