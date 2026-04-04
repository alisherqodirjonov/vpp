#ifndef included_igmp_api_types_h
#define included_igmp_api_types_h
#define VL_API_IGMP_API_VERSION_MAJOR 1
#define VL_API_IGMP_API_VERSION_MINOR 0
#define VL_API_IGMP_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/ip/ip_types.api_types.h>
#include <vnet/interface_types.api_types.h>
typedef enum {
    EXCLUDE = 0,
    INCLUDE = 1,
} vl_api_filter_mode_t;
typedef struct __attribute__ ((packed)) _vl_api_igmp_group {
    vl_api_filter_mode_t filter;
    u8 n_srcs;
    vl_api_interface_index_t sw_if_index;
    vl_api_ip4_address_t gaddr;
    vl_api_ip4_address_t saddrs[0];
} vl_api_igmp_group_t;
#define VL_API_IGMP_GROUP_IS_CONSTANT_SIZE (0)

typedef enum {
    ASM = 0,
    SSM = 1,
} vl_api_group_prefix_type_t;
typedef struct __attribute__ ((packed)) _vl_api_group_prefix {
    vl_api_group_prefix_type_t type;
    vl_api_prefix_t prefix;
} vl_api_group_prefix_t;
#define VL_API_GROUP_PREFIX_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_igmp_listen {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_igmp_group_t group;
} vl_api_igmp_listen_t;
#define VL_API_IGMP_LISTEN_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_igmp_listen_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_igmp_listen_reply_t;
#define VL_API_IGMP_LISTEN_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_igmp_enable_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool enable;
    u8 mode;
    vl_api_interface_index_t sw_if_index;
} vl_api_igmp_enable_disable_t;
#define VL_API_IGMP_ENABLE_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_igmp_enable_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_igmp_enable_disable_reply_t;
#define VL_API_IGMP_ENABLE_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_igmp_proxy_device_add_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u8 add;
    u32 vrf_id;
    vl_api_interface_index_t sw_if_index;
} vl_api_igmp_proxy_device_add_del_t;
#define VL_API_IGMP_PROXY_DEVICE_ADD_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_igmp_proxy_device_add_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_igmp_proxy_device_add_del_reply_t;
#define VL_API_IGMP_PROXY_DEVICE_ADD_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_igmp_proxy_device_add_del_interface {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool add;
    u32 vrf_id;
    vl_api_interface_index_t sw_if_index;
} vl_api_igmp_proxy_device_add_del_interface_t;
#define VL_API_IGMP_PROXY_DEVICE_ADD_DEL_INTERFACE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_igmp_proxy_device_add_del_interface_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_igmp_proxy_device_add_del_interface_reply_t;
#define VL_API_IGMP_PROXY_DEVICE_ADD_DEL_INTERFACE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_igmp_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_igmp_dump_t;
#define VL_API_IGMP_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_igmp_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    vl_api_ip4_address_t saddr;
    vl_api_ip4_address_t gaddr;
} vl_api_igmp_details_t;
#define VL_API_IGMP_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_igmp_clear_interface {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_igmp_clear_interface_t;
#define VL_API_IGMP_CLEAR_INTERFACE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_igmp_clear_interface_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_igmp_clear_interface_reply_t;
#define VL_API_IGMP_CLEAR_INTERFACE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_want_igmp_events {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 enable;
    u32 pid;
} vl_api_want_igmp_events_t;
#define VL_API_WANT_IGMP_EVENTS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_want_igmp_events_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_want_igmp_events_reply_t;
#define VL_API_WANT_IGMP_EVENTS_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_igmp_event {
    u16 _vl_msg_id;
    vl_api_interface_index_t sw_if_index;
    vl_api_filter_mode_t filter;
    vl_api_ip4_address_t saddr;
    vl_api_ip4_address_t gaddr;
} vl_api_igmp_event_t;
#define VL_API_IGMP_EVENT_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_igmp_group_prefix_set {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_group_prefix_t gp;
} vl_api_igmp_group_prefix_set_t;
#define VL_API_IGMP_GROUP_PREFIX_SET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_igmp_group_prefix_set_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_igmp_group_prefix_set_reply_t;
#define VL_API_IGMP_GROUP_PREFIX_SET_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_igmp_group_prefix_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_igmp_group_prefix_dump_t;
#define VL_API_IGMP_GROUP_PREFIX_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_igmp_group_prefix_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_group_prefix_t gp;
} vl_api_igmp_group_prefix_details_t;
#define VL_API_IGMP_GROUP_PREFIX_DETAILS_IS_CONSTANT_SIZE (1)

#define VL_API_IGMP_LISTEN_CRC "igmp_listen_19a49f1e"
#define VL_API_IGMP_LISTEN_REPLY_CRC "igmp_listen_reply_e8d4e804"
#define VL_API_IGMP_ENABLE_DISABLE_CRC "igmp_enable_disable_b1edfb96"
#define VL_API_IGMP_ENABLE_DISABLE_REPLY_CRC "igmp_enable_disable_reply_e8d4e804"
#define VL_API_IGMP_PROXY_DEVICE_ADD_DEL_CRC "igmp_proxy_device_add_del_0b9be9ce"
#define VL_API_IGMP_PROXY_DEVICE_ADD_DEL_REPLY_CRC "igmp_proxy_device_add_del_reply_e8d4e804"
#define VL_API_IGMP_PROXY_DEVICE_ADD_DEL_INTERFACE_CRC "igmp_proxy_device_add_del_interface_1a9ec24a"
#define VL_API_IGMP_PROXY_DEVICE_ADD_DEL_INTERFACE_REPLY_CRC "igmp_proxy_device_add_del_interface_reply_e8d4e804"
#define VL_API_IGMP_DUMP_CRC "igmp_dump_f9e6675e"
#define VL_API_IGMP_DETAILS_CRC "igmp_details_38f09929"
#define VL_API_IGMP_CLEAR_INTERFACE_CRC "igmp_clear_interface_f9e6675e"
#define VL_API_IGMP_CLEAR_INTERFACE_REPLY_CRC "igmp_clear_interface_reply_e8d4e804"
#define VL_API_WANT_IGMP_EVENTS_CRC "want_igmp_events_cfaccc1f"
#define VL_API_WANT_IGMP_EVENTS_REPLY_CRC "want_igmp_events_reply_e8d4e804"
#define VL_API_IGMP_EVENT_CRC "igmp_event_85fe93ec"
#define VL_API_IGMP_GROUP_PREFIX_SET_CRC "igmp_group_prefix_set_5b14a5ce"
#define VL_API_IGMP_GROUP_PREFIX_SET_REPLY_CRC "igmp_group_prefix_set_reply_e8d4e804"
#define VL_API_IGMP_GROUP_PREFIX_DUMP_CRC "igmp_group_prefix_dump_51077d14"
#define VL_API_IGMP_GROUP_PREFIX_DETAILS_CRC "igmp_group_prefix_details_259ccd81"

#endif
