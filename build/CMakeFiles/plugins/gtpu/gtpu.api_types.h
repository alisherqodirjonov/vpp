#ifndef included_gtpu_api_types_h
#define included_gtpu_api_types_h
#define VL_API_GTPU_API_VERSION_MAJOR 2
#define VL_API_GTPU_API_VERSION_MINOR 1
#define VL_API_GTPU_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/interface_types.api_types.h>
#include <vnet/ip/ip_types.api_types.h>
typedef enum {
    GTPU_API_FORWARDING_NONE = 0,
    GTPU_API_FORWARDING_BAD_HEADER = 1,
    GTPU_API_FORWARDING_UNKNOWN_TEID = 2,
    GTPU_API_FORWARDING_UNKNOWN_TYPE = 4,
} vl_api_gtpu_forwarding_type_t;
typedef enum {
    GTPU_API_DECAP_NEXT_DROP = 0,
    GTPU_API_DECAP_NEXT_L2 = 1,
    GTPU_API_DECAP_NEXT_IP4 = 2,
    GTPU_API_DECAP_NEXT_IP6 = 3,
} vl_api_gtpu_decap_next_type_t;
typedef struct __attribute__ ((packed)) _vl_api_sw_if_counters {
    u64 packets_rx;
    u64 packets_tx;
    u64 bytes_rx;
    u64 bytes_tx;
} vl_api_sw_if_counters_t;
#define VL_API_SW_IF_COUNTERS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_tunnel_metrics {
    vl_api_interface_index_t sw_if_index;
    u32 reserved;
    vl_api_sw_if_counters_t counters;
} vl_api_tunnel_metrics_t;
#define VL_API_TUNNEL_METRICS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gtpu_add_del_tunnel {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_address_t src_address;
    vl_api_address_t dst_address;
    vl_api_interface_index_t mcast_sw_if_index;
    u32 encap_vrf_id;
    u32 decap_next_index;
    u32 teid;
    u32 tteid;
} vl_api_gtpu_add_del_tunnel_t;
#define VL_API_GTPU_ADD_DEL_TUNNEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gtpu_add_del_tunnel_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_interface_index_t sw_if_index;
} vl_api_gtpu_add_del_tunnel_reply_t;
#define VL_API_GTPU_ADD_DEL_TUNNEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gtpu_add_del_tunnel_v2 {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_address_t src_address;
    vl_api_address_t dst_address;
    vl_api_interface_index_t mcast_sw_if_index;
    u32 encap_vrf_id;
    vl_api_gtpu_decap_next_type_t decap_next_index;
    u32 teid;
    u32 tteid;
    bool pdu_extension;
    u8 qfi;
} vl_api_gtpu_add_del_tunnel_v2_t;
#define VL_API_GTPU_ADD_DEL_TUNNEL_V2_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gtpu_add_del_tunnel_v2_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_interface_index_t sw_if_index;
    vl_api_sw_if_counters_t counters;
} vl_api_gtpu_add_del_tunnel_v2_reply_t;
#define VL_API_GTPU_ADD_DEL_TUNNEL_V2_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gtpu_tunnel_update_tteid {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_address_t dst_address;
    u32 encap_vrf_id;
    u32 teid;
    u32 tteid;
} vl_api_gtpu_tunnel_update_tteid_t;
#define VL_API_GTPU_TUNNEL_UPDATE_TTEID_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gtpu_tunnel_update_tteid_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_gtpu_tunnel_update_tteid_reply_t;
#define VL_API_GTPU_TUNNEL_UPDATE_TTEID_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gtpu_tunnel_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_gtpu_tunnel_dump_t;
#define VL_API_GTPU_TUNNEL_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gtpu_tunnel_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    vl_api_address_t src_address;
    vl_api_address_t dst_address;
    vl_api_interface_index_t mcast_sw_if_index;
    u32 encap_vrf_id;
    u32 decap_next_index;
    u32 teid;
    u32 tteid;
} vl_api_gtpu_tunnel_details_t;
#define VL_API_GTPU_TUNNEL_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gtpu_tunnel_v2_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_gtpu_tunnel_v2_dump_t;
#define VL_API_GTPU_TUNNEL_V2_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gtpu_tunnel_v2_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    vl_api_address_t src_address;
    vl_api_address_t dst_address;
    vl_api_interface_index_t mcast_sw_if_index;
    u32 encap_vrf_id;
    vl_api_gtpu_decap_next_type_t decap_next_index;
    u32 teid;
    u32 tteid;
    bool pdu_extension;
    u8 qfi;
    bool is_forwarding;
    vl_api_gtpu_forwarding_type_t forwarding_type;
    vl_api_sw_if_counters_t counters;
} vl_api_gtpu_tunnel_v2_details_t;
#define VL_API_GTPU_TUNNEL_V2_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sw_interface_set_gtpu_bypass {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    bool is_ipv6;
    bool enable;
} vl_api_sw_interface_set_gtpu_bypass_t;
#define VL_API_SW_INTERFACE_SET_GTPU_BYPASS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sw_interface_set_gtpu_bypass_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_sw_interface_set_gtpu_bypass_reply_t;
#define VL_API_SW_INTERFACE_SET_GTPU_BYPASS_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gtpu_offload_rx {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 hw_if_index;
    u32 sw_if_index;
    u8 enable;
} vl_api_gtpu_offload_rx_t;
#define VL_API_GTPU_OFFLOAD_RX_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gtpu_offload_rx_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_gtpu_offload_rx_reply_t;
#define VL_API_GTPU_OFFLOAD_RX_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gtpu_add_del_forward {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_address_t dst_address;
    vl_api_gtpu_forwarding_type_t forwarding_type;
    u32 encap_vrf_id;
    vl_api_gtpu_decap_next_type_t decap_next_index;
} vl_api_gtpu_add_del_forward_t;
#define VL_API_GTPU_ADD_DEL_FORWARD_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gtpu_add_del_forward_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_interface_index_t sw_if_index;
} vl_api_gtpu_add_del_forward_reply_t;
#define VL_API_GTPU_ADD_DEL_FORWARD_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gtpu_get_transfer_counts {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index_start;
    u32 capacity;
} vl_api_gtpu_get_transfer_counts_t;
#define VL_API_GTPU_GET_TRANSFER_COUNTS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gtpu_get_transfer_counts_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 count;
    vl_api_tunnel_metrics_t tunnels[0];
} vl_api_gtpu_get_transfer_counts_reply_t;
#define VL_API_GTPU_GET_TRANSFER_COUNTS_REPLY_IS_CONSTANT_SIZE (0)

#define VL_API_GTPU_ADD_DEL_TUNNEL_CRC "gtpu_add_del_tunnel_ca983a2b"
#define VL_API_GTPU_ADD_DEL_TUNNEL_REPLY_CRC "gtpu_add_del_tunnel_reply_5383d31f"
#define VL_API_GTPU_ADD_DEL_TUNNEL_V2_CRC "gtpu_add_del_tunnel_v2_a0c30713"
#define VL_API_GTPU_ADD_DEL_TUNNEL_V2_REPLY_CRC "gtpu_add_del_tunnel_v2_reply_62b41304"
#define VL_API_GTPU_TUNNEL_UPDATE_TTEID_CRC "gtpu_tunnel_update_tteid_79f33816"
#define VL_API_GTPU_TUNNEL_UPDATE_TTEID_REPLY_CRC "gtpu_tunnel_update_tteid_reply_e8d4e804"
#define VL_API_GTPU_TUNNEL_DUMP_CRC "gtpu_tunnel_dump_f9e6675e"
#define VL_API_GTPU_TUNNEL_DETAILS_CRC "gtpu_tunnel_details_27f434ae"
#define VL_API_GTPU_TUNNEL_V2_DUMP_CRC "gtpu_tunnel_v2_dump_f9e6675e"
#define VL_API_GTPU_TUNNEL_V2_DETAILS_CRC "gtpu_tunnel_v2_details_8bf4ba92"
#define VL_API_SW_INTERFACE_SET_GTPU_BYPASS_CRC "sw_interface_set_gtpu_bypass_65247409"
#define VL_API_SW_INTERFACE_SET_GTPU_BYPASS_REPLY_CRC "sw_interface_set_gtpu_bypass_reply_e8d4e804"
#define VL_API_GTPU_OFFLOAD_RX_CRC "gtpu_offload_rx_f0b08786"
#define VL_API_GTPU_OFFLOAD_RX_REPLY_CRC "gtpu_offload_rx_reply_e8d4e804"
#define VL_API_GTPU_ADD_DEL_FORWARD_CRC "gtpu_add_del_forward_c6ccce13"
#define VL_API_GTPU_ADD_DEL_FORWARD_REPLY_CRC "gtpu_add_del_forward_reply_5383d31f"
#define VL_API_GTPU_GET_TRANSFER_COUNTS_CRC "gtpu_get_transfer_counts_61410788"
#define VL_API_GTPU_GET_TRANSFER_COUNTS_REPLY_CRC "gtpu_get_transfer_counts_reply_e35f04bc"

#endif
