#ifndef included_ip6_nd_api_types_h
#define included_ip6_nd_api_types_h
#define VL_API_IP6_ND_API_VERSION_MAJOR 1
#define VL_API_IP6_ND_API_VERSION_MINOR 1
#define VL_API_IP6_ND_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/ip/ip_types.api_types.h>
#include <vnet/interface_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_ip6nd_ra_prefix {
    vl_api_prefix_t prefix;
    bool onlink_flag;
    bool autonomous_flag;
    u32 val_lifetime;
    u32 pref_lifetime;
    f64 valid_lifetime_expires;
    f64 pref_lifetime_expires;
    bool decrement_lifetime_flag;
    bool no_advertise;
} vl_api_ip6nd_ra_prefix_t;
#define VL_API_IP6ND_RA_PREFIX_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ip6_ra_prefix_info {
    vl_api_prefix_t prefix;
    u8 flags;
    u32 valid_time;
    u32 preferred_time;
} vl_api_ip6_ra_prefix_info_t;
#define VL_API_IP6_RA_PREFIX_INFO_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sw_interface_ip6nd_ra_config {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u8 suppress;
    u8 managed;
    u8 other;
    u8 ll_option;
    u8 send_unicast;
    u8 cease;
    bool is_no;
    u8 default_router;
    u32 max_interval;
    u32 min_interval;
    u32 lifetime;
    u32 initial_count;
    u32 initial_interval;
} vl_api_sw_interface_ip6nd_ra_config_t;
#define VL_API_SW_INTERFACE_IP6ND_RA_CONFIG_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sw_interface_ip6nd_ra_config_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_sw_interface_ip6nd_ra_config_reply_t;
#define VL_API_SW_INTERFACE_IP6ND_RA_CONFIG_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sw_interface_ip6nd_ra_prefix {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    vl_api_prefix_t prefix;
    bool use_default;
    bool no_advertise;
    bool off_link;
    bool no_autoconfig;
    bool no_onlink;
    bool is_no;
    u32 val_lifetime;
    u32 pref_lifetime;
} vl_api_sw_interface_ip6nd_ra_prefix_t;
#define VL_API_SW_INTERFACE_IP6ND_RA_PREFIX_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sw_interface_ip6nd_ra_prefix_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_sw_interface_ip6nd_ra_prefix_reply_t;
#define VL_API_SW_INTERFACE_IP6ND_RA_PREFIX_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sw_interface_ip6nd_ra_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_sw_interface_ip6nd_ra_dump_t;
#define VL_API_SW_INTERFACE_IP6ND_RA_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sw_interface_ip6nd_ra_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u8 cur_hop_limit;
    bool adv_managed_flag;
    bool adv_other_flag;
    u16 adv_router_lifetime;
    u32 adv_neighbor_reachable_time;
    u32 adv_retransmit_interval;
    u32 adv_link_mtu;
    bool send_radv;
    bool cease_radv;
    bool send_unicast;
    bool adv_link_layer_address;
    f64 max_radv_interval;
    f64 min_radv_interval;
    f64 last_radv_time;
    f64 last_multicast_time;
    f64 next_multicast_time;
    u32 initial_adverts_count;
    f64 initial_adverts_interval;
    bool initial_adverts_sent;
    u32 n_advertisements_sent;
    u32 n_solicitations_rcvd;
    u32 n_solicitations_dropped;
    u32 n_prefixes;
    vl_api_ip6nd_ra_prefix_t prefixes[0];
} vl_api_sw_interface_ip6nd_ra_details_t;
#define VL_API_SW_INTERFACE_IP6ND_RA_DETAILS_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_ip6nd_proxy_enable_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    bool is_enable;
} vl_api_ip6nd_proxy_enable_disable_t;
#define VL_API_IP6ND_PROXY_ENABLE_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ip6nd_proxy_enable_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_ip6nd_proxy_enable_disable_reply_t;
#define VL_API_IP6ND_PROXY_ENABLE_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ip6nd_proxy_add_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    bool is_add;
    vl_api_ip6_address_t ip;
} vl_api_ip6nd_proxy_add_del_t;
#define VL_API_IP6ND_PROXY_ADD_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ip6nd_proxy_add_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_ip6nd_proxy_add_del_reply_t;
#define VL_API_IP6ND_PROXY_ADD_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ip6nd_proxy_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    vl_api_ip6_address_t ip;
} vl_api_ip6nd_proxy_details_t;
#define VL_API_IP6ND_PROXY_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ip6nd_proxy_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_ip6nd_proxy_dump_t;
#define VL_API_IP6ND_PROXY_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ip6nd_send_router_solicitation {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 irt;
    u32 mrt;
    u32 mrc;
    u32 mrd;
    vl_api_interface_index_t sw_if_index;
    bool stop;
} vl_api_ip6nd_send_router_solicitation_t;
#define VL_API_IP6ND_SEND_ROUTER_SOLICITATION_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ip6nd_send_router_solicitation_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_ip6nd_send_router_solicitation_reply_t;
#define VL_API_IP6ND_SEND_ROUTER_SOLICITATION_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_want_ip6_ra_events {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool enable;
    u32 pid;
} vl_api_want_ip6_ra_events_t;
#define VL_API_WANT_IP6_RA_EVENTS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_want_ip6_ra_events_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_want_ip6_ra_events_reply_t;
#define VL_API_WANT_IP6_RA_EVENTS_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ip6_ra_event {
    u16 _vl_msg_id;
    u32 client_index;
    u32 pid;
    vl_api_interface_index_t sw_if_index;
    vl_api_ip6_address_t router_addr;
    u8 current_hop_limit;
    u8 flags;
    u16 router_lifetime_in_sec;
    u32 neighbor_reachable_time_in_msec;
    u32 time_in_msec_between_retransmitted_neighbor_solicitations;
    u32 n_prefixes;
    vl_api_ip6_ra_prefix_info_t prefixes[0];
} vl_api_ip6_ra_event_t;
#define VL_API_IP6_RA_EVENT_IS_CONSTANT_SIZE (0)

#define VL_API_SW_INTERFACE_IP6ND_RA_CONFIG_CRC "sw_interface_ip6nd_ra_config_3eb00b1c"
#define VL_API_SW_INTERFACE_IP6ND_RA_CONFIG_REPLY_CRC "sw_interface_ip6nd_ra_config_reply_e8d4e804"
#define VL_API_SW_INTERFACE_IP6ND_RA_PREFIX_CRC "sw_interface_ip6nd_ra_prefix_82cc1b28"
#define VL_API_SW_INTERFACE_IP6ND_RA_PREFIX_REPLY_CRC "sw_interface_ip6nd_ra_prefix_reply_e8d4e804"
#define VL_API_SW_INTERFACE_IP6ND_RA_DUMP_CRC "sw_interface_ip6nd_ra_dump_f9e6675e"
#define VL_API_SW_INTERFACE_IP6ND_RA_DETAILS_CRC "sw_interface_ip6nd_ra_details_d3198de5"
#define VL_API_IP6ND_PROXY_ENABLE_DISABLE_CRC "ip6nd_proxy_enable_disable_7daa1e3a"
#define VL_API_IP6ND_PROXY_ENABLE_DISABLE_REPLY_CRC "ip6nd_proxy_enable_disable_reply_e8d4e804"
#define VL_API_IP6ND_PROXY_ADD_DEL_CRC "ip6nd_proxy_add_del_c2e4a686"
#define VL_API_IP6ND_PROXY_ADD_DEL_REPLY_CRC "ip6nd_proxy_add_del_reply_e8d4e804"
#define VL_API_IP6ND_PROXY_DETAILS_CRC "ip6nd_proxy_details_30b9ff4a"
#define VL_API_IP6ND_PROXY_DUMP_CRC "ip6nd_proxy_dump_51077d14"
#define VL_API_IP6ND_SEND_ROUTER_SOLICITATION_CRC "ip6nd_send_router_solicitation_e5de609c"
#define VL_API_IP6ND_SEND_ROUTER_SOLICITATION_REPLY_CRC "ip6nd_send_router_solicitation_reply_e8d4e804"
#define VL_API_WANT_IP6_RA_EVENTS_CRC "want_ip6_ra_events_3ec6d6c2"
#define VL_API_WANT_IP6_RA_EVENTS_REPLY_CRC "want_ip6_ra_events_reply_e8d4e804"
#define VL_API_IP6_RA_EVENT_CRC "ip6_ra_event_0364c1c5"

#endif
