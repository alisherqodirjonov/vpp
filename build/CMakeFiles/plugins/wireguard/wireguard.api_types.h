#ifndef included_wireguard_api_types_h
#define included_wireguard_api_types_h
#define VL_API_WIREGUARD_API_VERSION_MAJOR 1
#define VL_API_WIREGUARD_API_VERSION_MINOR 3
#define VL_API_WIREGUARD_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/interface_types.api_types.h>
#include <vnet/ip/ip_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_wireguard_interface {
    u32 user_instance;
    vl_api_interface_index_t sw_if_index;
    u8 private_key[32];
    u8 public_key[32];
    u16 port;
    vl_api_address_t src_ip;
} vl_api_wireguard_interface_t;
#define VL_API_WIREGUARD_INTERFACE_IS_CONSTANT_SIZE (1)

typedef enum __attribute__((packed)) {
    WIREGUARD_PEER_STATUS_DEAD = 1,
    WIREGUARD_PEER_ESTABLISHED = 2,
} vl_api_wireguard_peer_flags_t;
STATIC_ASSERT(sizeof(vl_api_wireguard_peer_flags_t) == sizeof(u8), "size of API enum wireguard_peer_flags is wrong");
typedef struct __attribute__ ((packed)) _vl_api_wireguard_peer {
    u32 peer_index;
    u8 public_key[32];
    u16 port;
    u16 persistent_keepalive;
    u32 table_id;
    vl_api_address_t endpoint;
    vl_api_interface_index_t sw_if_index;
    vl_api_wireguard_peer_flags_t flags;
    u8 n_allowed_ips;
    vl_api_prefix_t allowed_ips[0];
} vl_api_wireguard_peer_t;
#define VL_API_WIREGUARD_PEER_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_wireguard_interface_create {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_wireguard_interface_t interface;
    bool generate_key;
} vl_api_wireguard_interface_create_t;
#define VL_API_WIREGUARD_INTERFACE_CREATE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_wireguard_interface_create_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_interface_index_t sw_if_index;
} vl_api_wireguard_interface_create_reply_t;
#define VL_API_WIREGUARD_INTERFACE_CREATE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_wireguard_interface_delete {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_wireguard_interface_delete_t;
#define VL_API_WIREGUARD_INTERFACE_DELETE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_wireguard_interface_delete_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_wireguard_interface_delete_reply_t;
#define VL_API_WIREGUARD_INTERFACE_DELETE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_wireguard_interface_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool show_private_key;
    vl_api_interface_index_t sw_if_index;
} vl_api_wireguard_interface_dump_t;
#define VL_API_WIREGUARD_INTERFACE_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_wireguard_interface_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_wireguard_interface_t interface;
} vl_api_wireguard_interface_details_t;
#define VL_API_WIREGUARD_INTERFACE_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_want_wireguard_peer_events {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u32 peer_index;
    u32 enable_disable;
    u32 pid;
} vl_api_want_wireguard_peer_events_t;
#define VL_API_WANT_WIREGUARD_PEER_EVENTS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_want_wireguard_peer_events_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_want_wireguard_peer_events_reply_t;
#define VL_API_WANT_WIREGUARD_PEER_EVENTS_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_wireguard_peer_event {
    u16 _vl_msg_id;
    u32 client_index;
    u32 pid;
    u32 peer_index;
    vl_api_wireguard_peer_flags_t flags;
} vl_api_wireguard_peer_event_t;
#define VL_API_WIREGUARD_PEER_EVENT_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_wireguard_peer_add {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_wireguard_peer_t peer;
} vl_api_wireguard_peer_add_t;
#define VL_API_WIREGUARD_PEER_ADD_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_wireguard_peer_add_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 peer_index;
} vl_api_wireguard_peer_add_reply_t;
#define VL_API_WIREGUARD_PEER_ADD_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_wireguard_peer_remove {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 peer_index;
} vl_api_wireguard_peer_remove_t;
#define VL_API_WIREGUARD_PEER_REMOVE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_wireguard_peer_remove_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_wireguard_peer_remove_reply_t;
#define VL_API_WIREGUARD_PEER_REMOVE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_wireguard_peers_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 peer_index;
} vl_api_wireguard_peers_dump_t;
#define VL_API_WIREGUARD_PEERS_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_wireguard_peers_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_wireguard_peer_t peer;
} vl_api_wireguard_peers_details_t;
#define VL_API_WIREGUARD_PEERS_DETAILS_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_wg_set_async_mode {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool async_enable;
} vl_api_wg_set_async_mode_t;
#define VL_API_WG_SET_ASYNC_MODE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_wg_set_async_mode_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_wg_set_async_mode_reply_t;
#define VL_API_WG_SET_ASYNC_MODE_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_WIREGUARD_INTERFACE_CREATE_CRC "wireguard_interface_create_a530137e"
#define VL_API_WIREGUARD_INTERFACE_CREATE_REPLY_CRC "wireguard_interface_create_reply_5383d31f"
#define VL_API_WIREGUARD_INTERFACE_DELETE_CRC "wireguard_interface_delete_f9e6675e"
#define VL_API_WIREGUARD_INTERFACE_DELETE_REPLY_CRC "wireguard_interface_delete_reply_e8d4e804"
#define VL_API_WIREGUARD_INTERFACE_DUMP_CRC "wireguard_interface_dump_2c954158"
#define VL_API_WIREGUARD_INTERFACE_DETAILS_CRC "wireguard_interface_details_0dd4865d"
#define VL_API_WANT_WIREGUARD_PEER_EVENTS_CRC "want_wireguard_peer_events_3bc666c8"
#define VL_API_WANT_WIREGUARD_PEER_EVENTS_REPLY_CRC "want_wireguard_peer_events_reply_e8d4e804"
#define VL_API_WIREGUARD_PEER_EVENT_CRC "wireguard_peer_event_4e1b5d67"
#define VL_API_WIREGUARD_PEER_ADD_CRC "wireguard_peer_add_9b8aad61"
#define VL_API_WIREGUARD_PEER_ADD_REPLY_CRC "wireguard_peer_add_reply_084a0cd3"
#define VL_API_WIREGUARD_PEER_REMOVE_CRC "wireguard_peer_remove_3b74607a"
#define VL_API_WIREGUARD_PEER_REMOVE_REPLY_CRC "wireguard_peer_remove_reply_e8d4e804"
#define VL_API_WIREGUARD_PEERS_DUMP_CRC "wireguard_peers_dump_3b74607a"
#define VL_API_WIREGUARD_PEERS_DETAILS_CRC "wireguard_peers_details_6a9f6bc3"
#define VL_API_WG_SET_ASYNC_MODE_CRC "wg_set_async_mode_a6465f7c"
#define VL_API_WG_SET_ASYNC_MODE_REPLY_CRC "wg_set_async_mode_reply_e8d4e804"

#endif
