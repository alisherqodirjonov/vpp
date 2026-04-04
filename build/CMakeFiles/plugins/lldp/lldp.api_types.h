#ifndef included_lldp_api_types_h
#define included_lldp_api_types_h
#define VL_API_LLDP_API_VERSION_MAJOR 2
#define VL_API_LLDP_API_VERSION_MINOR 0
#define VL_API_LLDP_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/interface_types.api_types.h>
#include <vnet/ip/ip_types.api_types.h>
typedef enum {
    PORT_ID_SUBTYPE_RESERVED = 0,
    PORT_ID_SUBTYPE_INTF_ALIAS = 1,
    PORT_ID_SUBTYPE_PORT_COMP = 2,
    PORT_ID_SUBTYPE_MAC_ADDR = 3,
    PORT_ID_SUBTYPE_NET_ADDR = 4,
    PORT_ID_SUBTYPE_INTF_NAME = 5,
    PORT_ID_SUBTYPE_AGENT_CIRCUIT_ID = 6,
    PORT_ID_SUBTYPE_LOCAL = 7,
} vl_api_port_id_subtype_t;
typedef enum {
    CHASSIS_ID_SUBTYPE_RESERVED = 0,
    CHASSIS_ID_SUBTYPE_CHASSIS_COMP = 1,
    CHASSIS_ID_SUBTYPE_INTF_ALIAS = 2,
    CHASSIS_ID_SUBTYPE_PORT_COMP = 3,
    CHASSIS_ID_SUBTYPE_MAC_ADDR = 4,
    CHASSIS_ID_SUBTYPE_NET_ADDR = 5,
    CHASSIS_ID_SUBTYPE_INTF_NAME = 6,
    CHASSIS_ID_SUBTYPE_LOCAL = 7,
} vl_api_chassis_id_subtype_t;
typedef struct __attribute__ ((packed)) _vl_api_lldp_config {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 tx_hold;
    u32 tx_interval;
    vl_api_string_t system_name;
} vl_api_lldp_config_t;
#define VL_API_LLDP_CONFIG_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_lldp_config_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_lldp_config_reply_t;
#define VL_API_LLDP_CONFIG_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sw_interface_set_lldp {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    vl_api_ip4_address_t mgmt_ip4;
    vl_api_ip6_address_t mgmt_ip6;
    u8 mgmt_oid[128];
    bool enable;
    vl_api_string_t port_desc;
} vl_api_sw_interface_set_lldp_t;
#define VL_API_SW_INTERFACE_SET_LLDP_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_sw_interface_set_lldp_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_sw_interface_set_lldp_reply_t;
#define VL_API_SW_INTERFACE_SET_LLDP_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lldp_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 cursor;
} vl_api_lldp_dump_t;
#define VL_API_LLDP_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lldp_dump_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 cursor;
} vl_api_lldp_dump_reply_t;
#define VL_API_LLDP_DUMP_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lldp_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    f64 last_heard;
    f64 last_sent;
    u8 chassis_id[64];
    u8 chassis_id_len;
    u8 port_id[64];
    u8 port_id_len;
    u16 ttl;
    vl_api_port_id_subtype_t port_id_subtype;
    vl_api_chassis_id_subtype_t chassis_id_subtype;
} vl_api_lldp_details_t;
#define VL_API_LLDP_DETAILS_IS_CONSTANT_SIZE (1)

#define VL_API_LLDP_CONFIG_CRC "lldp_config_c14445df"
#define VL_API_LLDP_CONFIG_REPLY_CRC "lldp_config_reply_e8d4e804"
#define VL_API_SW_INTERFACE_SET_LLDP_CRC "sw_interface_set_lldp_57afbcd4"
#define VL_API_SW_INTERFACE_SET_LLDP_REPLY_CRC "sw_interface_set_lldp_reply_e8d4e804"
#define VL_API_LLDP_DUMP_CRC "lldp_dump_f75ba505"
#define VL_API_LLDP_DUMP_REPLY_CRC "lldp_dump_reply_53b48f5d"
#define VL_API_LLDP_DETAILS_CRC "lldp_details_c2d226cd"

#endif
