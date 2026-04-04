#ifndef included_pppoe_api_types_h
#define included_pppoe_api_types_h
#define VL_API_PPPOE_API_VERSION_MAJOR 2
#define VL_API_PPPOE_API_VERSION_MINOR 0
#define VL_API_PPPOE_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/interface_types.api_types.h>
#include <vnet/ethernet/ethernet_types.api_types.h>
#include <vnet/ip/ip_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_pppoe_add_del_session {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    u16 session_id;
    vl_api_address_t client_ip;
    u32 decap_vrf_id;
    vl_api_mac_address_t client_mac;
} vl_api_pppoe_add_del_session_t;
#define VL_API_PPPOE_ADD_DEL_SESSION_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pppoe_add_del_session_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_interface_index_t sw_if_index;
} vl_api_pppoe_add_del_session_reply_t;
#define VL_API_PPPOE_ADD_DEL_SESSION_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pppoe_session_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_pppoe_session_dump_t;
#define VL_API_PPPOE_SESSION_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pppoe_session_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u16 session_id;
    vl_api_address_t client_ip;
    vl_api_interface_index_t encap_if_index;
    u32 decap_vrf_id;
    vl_api_mac_address_t local_mac;
    vl_api_mac_address_t client_mac;
} vl_api_pppoe_session_details_t;
#define VL_API_PPPOE_SESSION_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pppoe_add_del_cp {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u8 is_add;
} vl_api_pppoe_add_del_cp_t;
#define VL_API_PPPOE_ADD_DEL_CP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pppoe_add_del_cp_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_pppoe_add_del_cp_reply_t;
#define VL_API_PPPOE_ADD_DEL_CP_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_PPPOE_ADD_DEL_SESSION_CRC "pppoe_add_del_session_f6fd759e"
#define VL_API_PPPOE_ADD_DEL_SESSION_REPLY_CRC "pppoe_add_del_session_reply_5383d31f"
#define VL_API_PPPOE_SESSION_DUMP_CRC "pppoe_session_dump_f9e6675e"
#define VL_API_PPPOE_SESSION_DETAILS_CRC "pppoe_session_details_4b8e8a4a"
#define VL_API_PPPOE_ADD_DEL_CP_CRC "pppoe_add_del_cp_eacd9aaa"
#define VL_API_PPPOE_ADD_DEL_CP_REPLY_CRC "pppoe_add_del_cp_reply_e8d4e804"

#endif
