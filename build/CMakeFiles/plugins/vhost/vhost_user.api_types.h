#ifndef included_vhost_user_api_types_h
#define included_vhost_user_api_types_h
#define VL_API_VHOST_USER_API_VERSION_MAJOR 4
#define VL_API_VHOST_USER_API_VERSION_MINOR 1
#define VL_API_VHOST_USER_API_VERSION_PATCH 1
/* Imported API files */
#include <vnet/interface_types.api_types.h>
#include <vnet/ethernet/ethernet_types.api_types.h>
#include <vnet/devices/virtio/virtio_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_create_vhost_user_if {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_server;
    u8 sock_filename[256];
    bool renumber;
    bool disable_mrg_rxbuf;
    bool disable_indirect_desc;
    bool enable_gso;
    bool enable_packed;
    u32 custom_dev_instance;
    bool use_custom_mac;
    vl_api_mac_address_t mac_address;
    u8 tag[64];
} vl_api_create_vhost_user_if_t;
#define VL_API_CREATE_VHOST_USER_IF_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_create_vhost_user_if_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_interface_index_t sw_if_index;
} vl_api_create_vhost_user_if_reply_t;
#define VL_API_CREATE_VHOST_USER_IF_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_modify_vhost_user_if {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    bool is_server;
    u8 sock_filename[256];
    bool renumber;
    bool enable_gso;
    bool enable_packed;
    u32 custom_dev_instance;
} vl_api_modify_vhost_user_if_t;
#define VL_API_MODIFY_VHOST_USER_IF_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_modify_vhost_user_if_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_modify_vhost_user_if_reply_t;
#define VL_API_MODIFY_VHOST_USER_IF_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_create_vhost_user_if_v2 {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_server;
    u8 sock_filename[256];
    bool renumber;
    bool disable_mrg_rxbuf;
    bool disable_indirect_desc;
    bool enable_gso;
    bool enable_packed;
    bool enable_event_idx;
    u32 custom_dev_instance;
    bool use_custom_mac;
    vl_api_mac_address_t mac_address;
    u8 tag[64];
} vl_api_create_vhost_user_if_v2_t;
#define VL_API_CREATE_VHOST_USER_IF_V2_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_create_vhost_user_if_v2_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_interface_index_t sw_if_index;
} vl_api_create_vhost_user_if_v2_reply_t;
#define VL_API_CREATE_VHOST_USER_IF_V2_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_modify_vhost_user_if_v2 {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    bool is_server;
    u8 sock_filename[256];
    bool renumber;
    bool enable_gso;
    bool enable_packed;
    bool enable_event_idx;
    u32 custom_dev_instance;
} vl_api_modify_vhost_user_if_v2_t;
#define VL_API_MODIFY_VHOST_USER_IF_V2_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_modify_vhost_user_if_v2_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_modify_vhost_user_if_v2_reply_t;
#define VL_API_MODIFY_VHOST_USER_IF_V2_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_delete_vhost_user_if {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_delete_vhost_user_if_t;
#define VL_API_DELETE_VHOST_USER_IF_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_delete_vhost_user_if_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_delete_vhost_user_if_reply_t;
#define VL_API_DELETE_VHOST_USER_IF_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sw_interface_vhost_user_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u8 interface_name[64];
    u32 virtio_net_hdr_sz;
    vl_api_virtio_net_features_first_32_t features_first_32;
    vl_api_virtio_net_features_last_32_t features_last_32;
    bool is_server;
    u8 sock_filename[256];
    u32 num_regions;
    i32 sock_errno;
} vl_api_sw_interface_vhost_user_details_t;
#define VL_API_SW_INTERFACE_VHOST_USER_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sw_interface_vhost_user_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_sw_interface_vhost_user_dump_t;
#define VL_API_SW_INTERFACE_VHOST_USER_DUMP_IS_CONSTANT_SIZE (1)

#define VL_API_CREATE_VHOST_USER_IF_CRC "create_vhost_user_if_c785c6fc"
#define VL_API_CREATE_VHOST_USER_IF_REPLY_CRC "create_vhost_user_if_reply_5383d31f"
#define VL_API_MODIFY_VHOST_USER_IF_CRC "modify_vhost_user_if_0e71d40b"
#define VL_API_MODIFY_VHOST_USER_IF_REPLY_CRC "modify_vhost_user_if_reply_e8d4e804"
#define VL_API_CREATE_VHOST_USER_IF_V2_CRC "create_vhost_user_if_v2_dba1cc1d"
#define VL_API_CREATE_VHOST_USER_IF_V2_REPLY_CRC "create_vhost_user_if_v2_reply_5383d31f"
#define VL_API_MODIFY_VHOST_USER_IF_V2_CRC "modify_vhost_user_if_v2_b2483771"
#define VL_API_MODIFY_VHOST_USER_IF_V2_REPLY_CRC "modify_vhost_user_if_v2_reply_e8d4e804"
#define VL_API_DELETE_VHOST_USER_IF_CRC "delete_vhost_user_if_f9e6675e"
#define VL_API_DELETE_VHOST_USER_IF_REPLY_CRC "delete_vhost_user_if_reply_e8d4e804"
#define VL_API_SW_INTERFACE_VHOST_USER_DETAILS_CRC "sw_interface_vhost_user_details_0cee1e53"
#define VL_API_SW_INTERFACE_VHOST_USER_DUMP_CRC "sw_interface_vhost_user_dump_f9e6675e"

#endif
