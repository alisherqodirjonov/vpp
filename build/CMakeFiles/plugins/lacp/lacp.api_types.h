#ifndef included_lacp_api_types_h
#define included_lacp_api_types_h
#define VL_API_LACP_API_VERSION_MAJOR 2
#define VL_API_LACP_API_VERSION_MINOR 0
#define VL_API_LACP_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/ethernet/ethernet_types.api_types.h>
#include <vnet/interface_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_sw_interface_lacp_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_sw_interface_lacp_dump_t;
#define VL_API_SW_INTERFACE_LACP_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sw_interface_lacp_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u8 interface_name[64];
    u32 rx_state;
    u32 tx_state;
    u32 mux_state;
    u32 ptx_state;
    u8 bond_interface_name[64];
    u16 actor_system_priority;
    vl_api_mac_address_t actor_system;
    u16 actor_key;
    u16 actor_port_priority;
    u16 actor_port_number;
    u8 actor_state;
    u16 partner_system_priority;
    vl_api_mac_address_t partner_system;
    u16 partner_key;
    u16 partner_port_priority;
    u16 partner_port_number;
    u8 partner_state;
} vl_api_sw_interface_lacp_details_t;
#define VL_API_SW_INTERFACE_LACP_DETAILS_IS_CONSTANT_SIZE (1)

#define VL_API_SW_INTERFACE_LACP_DUMP_CRC "sw_interface_lacp_dump_51077d14"
#define VL_API_SW_INTERFACE_LACP_DETAILS_CRC "sw_interface_lacp_details_d9a83d2f"

#endif
