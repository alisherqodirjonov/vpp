#ifndef included_bond_api_types_h
#define included_bond_api_types_h
#define VL_API_BOND_API_VERSION_MAJOR 2
#define VL_API_BOND_API_VERSION_MINOR 1
#define VL_API_BOND_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/interface_types.api_types.h>
#include <vnet/ethernet/ethernet_types.api_types.h>
typedef enum {
    BOND_API_MODE_ROUND_ROBIN = 1,
    BOND_API_MODE_ACTIVE_BACKUP = 2,
    BOND_API_MODE_XOR = 3,
    BOND_API_MODE_BROADCAST = 4,
    BOND_API_MODE_LACP = 5,
} vl_api_bond_mode_t;
typedef enum {
    BOND_API_LB_ALGO_L2 = 0,
    BOND_API_LB_ALGO_L34 = 1,
    BOND_API_LB_ALGO_L23 = 2,
    BOND_API_LB_ALGO_RR = 3,
    BOND_API_LB_ALGO_BC = 4,
    BOND_API_LB_ALGO_AB = 5,
} vl_api_bond_lb_algo_t;
typedef struct __attribute__ ((packed)) _vl_api_bond_create {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 id;
    bool use_custom_mac;
    vl_api_mac_address_t mac_address;
    vl_api_bond_mode_t mode;
    vl_api_bond_lb_algo_t lb;
    bool numa_only;
} vl_api_bond_create_t;
#define VL_API_BOND_CREATE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_bond_create_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_interface_index_t sw_if_index;
} vl_api_bond_create_reply_t;
#define VL_API_BOND_CREATE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_bond_create2 {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_bond_mode_t mode;
    vl_api_bond_lb_algo_t lb;
    bool numa_only;
    bool enable_gso;
    bool use_custom_mac;
    vl_api_mac_address_t mac_address;
    u32 id;
} vl_api_bond_create2_t;
#define VL_API_BOND_CREATE2_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_bond_create2_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_interface_index_t sw_if_index;
} vl_api_bond_create2_reply_t;
#define VL_API_BOND_CREATE2_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_bond_delete {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_bond_delete_t;
#define VL_API_BOND_DELETE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_bond_delete_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_bond_delete_reply_t;
#define VL_API_BOND_DELETE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_bond_enslave {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    vl_api_interface_index_t bond_sw_if_index;
    bool is_passive;
    bool is_long_timeout;
} vl_api_bond_enslave_t;
#define VL_API_BOND_ENSLAVE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_bond_enslave_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_bond_enslave_reply_t;
#define VL_API_BOND_ENSLAVE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_bond_add_member {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    vl_api_interface_index_t bond_sw_if_index;
    bool is_passive;
    bool is_long_timeout;
} vl_api_bond_add_member_t;
#define VL_API_BOND_ADD_MEMBER_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_bond_add_member_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_bond_add_member_reply_t;
#define VL_API_BOND_ADD_MEMBER_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_bond_detach_slave {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_bond_detach_slave_t;
#define VL_API_BOND_DETACH_SLAVE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_bond_detach_slave_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_bond_detach_slave_reply_t;
#define VL_API_BOND_DETACH_SLAVE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_bond_detach_member {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_bond_detach_member_t;
#define VL_API_BOND_DETACH_MEMBER_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_bond_detach_member_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_bond_detach_member_reply_t;
#define VL_API_BOND_DETACH_MEMBER_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sw_interface_bond_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_sw_interface_bond_dump_t;
#define VL_API_SW_INTERFACE_BOND_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sw_interface_bond_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u32 id;
    vl_api_bond_mode_t mode;
    vl_api_bond_lb_algo_t lb;
    bool numa_only;
    u32 active_slaves;
    u32 slaves;
    u8 interface_name[64];
} vl_api_sw_interface_bond_details_t;
#define VL_API_SW_INTERFACE_BOND_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sw_bond_interface_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_sw_bond_interface_dump_t;
#define VL_API_SW_BOND_INTERFACE_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sw_bond_interface_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u32 id;
    vl_api_bond_mode_t mode;
    vl_api_bond_lb_algo_t lb;
    bool numa_only;
    u32 active_members;
    u32 members;
    u8 interface_name[64];
} vl_api_sw_bond_interface_details_t;
#define VL_API_SW_BOND_INTERFACE_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sw_interface_slave_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_sw_interface_slave_dump_t;
#define VL_API_SW_INTERFACE_SLAVE_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sw_interface_slave_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u8 interface_name[64];
    bool is_passive;
    bool is_long_timeout;
    bool is_local_numa;
    u32 weight;
} vl_api_sw_interface_slave_details_t;
#define VL_API_SW_INTERFACE_SLAVE_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sw_member_interface_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_sw_member_interface_dump_t;
#define VL_API_SW_MEMBER_INTERFACE_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sw_member_interface_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u8 interface_name[64];
    bool is_passive;
    bool is_long_timeout;
    bool is_local_numa;
    u32 weight;
} vl_api_sw_member_interface_details_t;
#define VL_API_SW_MEMBER_INTERFACE_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sw_interface_set_bond_weight {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u32 weight;
} vl_api_sw_interface_set_bond_weight_t;
#define VL_API_SW_INTERFACE_SET_BOND_WEIGHT_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sw_interface_set_bond_weight_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_sw_interface_set_bond_weight_reply_t;
#define VL_API_SW_INTERFACE_SET_BOND_WEIGHT_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_BOND_CREATE_CRC "bond_create_f1dbd4ff"
#define VL_API_BOND_CREATE_REPLY_CRC "bond_create_reply_5383d31f"
#define VL_API_BOND_CREATE2_CRC "bond_create2_912fda76"
#define VL_API_BOND_CREATE2_REPLY_CRC "bond_create2_reply_5383d31f"
#define VL_API_BOND_DELETE_CRC "bond_delete_f9e6675e"
#define VL_API_BOND_DELETE_REPLY_CRC "bond_delete_reply_e8d4e804"
#define VL_API_BOND_ENSLAVE_CRC "bond_enslave_e7d14948"
#define VL_API_BOND_ENSLAVE_REPLY_CRC "bond_enslave_reply_e8d4e804"
#define VL_API_BOND_ADD_MEMBER_CRC "bond_add_member_e7d14948"
#define VL_API_BOND_ADD_MEMBER_REPLY_CRC "bond_add_member_reply_e8d4e804"
#define VL_API_BOND_DETACH_SLAVE_CRC "bond_detach_slave_f9e6675e"
#define VL_API_BOND_DETACH_SLAVE_REPLY_CRC "bond_detach_slave_reply_e8d4e804"
#define VL_API_BOND_DETACH_MEMBER_CRC "bond_detach_member_f9e6675e"
#define VL_API_BOND_DETACH_MEMBER_REPLY_CRC "bond_detach_member_reply_e8d4e804"
#define VL_API_SW_INTERFACE_BOND_DUMP_CRC "sw_interface_bond_dump_51077d14"
#define VL_API_SW_INTERFACE_BOND_DETAILS_CRC "sw_interface_bond_details_bb7c929b"
#define VL_API_SW_BOND_INTERFACE_DUMP_CRC "sw_bond_interface_dump_f9e6675e"
#define VL_API_SW_BOND_INTERFACE_DETAILS_CRC "sw_bond_interface_details_9428a69c"
#define VL_API_SW_INTERFACE_SLAVE_DUMP_CRC "sw_interface_slave_dump_f9e6675e"
#define VL_API_SW_INTERFACE_SLAVE_DETAILS_CRC "sw_interface_slave_details_3c4a0e23"
#define VL_API_SW_MEMBER_INTERFACE_DUMP_CRC "sw_member_interface_dump_f9e6675e"
#define VL_API_SW_MEMBER_INTERFACE_DETAILS_CRC "sw_member_interface_details_3c4a0e23"
#define VL_API_SW_INTERFACE_SET_BOND_WEIGHT_CRC "sw_interface_set_bond_weight_deb510a0"
#define VL_API_SW_INTERFACE_SET_BOND_WEIGHT_REPLY_CRC "sw_interface_set_bond_weight_reply_e8d4e804"

#endif
