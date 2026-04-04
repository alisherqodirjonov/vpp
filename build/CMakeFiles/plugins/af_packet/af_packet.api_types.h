#ifndef included_af_packet_api_types_h
#define included_af_packet_api_types_h
#define VL_API_AF_PACKET_API_VERSION_MAJOR 2
#define VL_API_AF_PACKET_API_VERSION_MINOR 0
#define VL_API_AF_PACKET_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/interface_types.api_types.h>
#include <vnet/ethernet/ethernet_types.api_types.h>
typedef enum {
    AF_PACKET_API_MODE_ETHERNET = 1,
    AF_PACKET_API_MODE_IP = 2,
} vl_api_af_packet_mode_t;
typedef enum {
    AF_PACKET_API_FLAG_QDISC_BYPASS = 1,
    AF_PACKET_API_FLAG_CKSUM_GSO = 2,
    AF_PACKET_API_FLAG_VERSION_2 = 8,
} vl_api_af_packet_flags_t;
typedef struct __attribute__ ((packed)) _vl_api_af_packet_create {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_mac_address_t hw_addr;
    bool use_random_hw_addr;
    u8 host_if_name[64];
} vl_api_af_packet_create_t;
#define VL_API_AF_PACKET_CREATE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_af_packet_create_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_interface_index_t sw_if_index;
} vl_api_af_packet_create_reply_t;
#define VL_API_AF_PACKET_CREATE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_af_packet_create_v2 {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_mac_address_t hw_addr;
    bool use_random_hw_addr;
    u8 host_if_name[64];
    u32 rx_frame_size;
    u32 tx_frame_size;
    u32 rx_frames_per_block;
    u32 tx_frames_per_block;
    u32 flags;
    u16 num_rx_queues;
} vl_api_af_packet_create_v2_t;
#define VL_API_AF_PACKET_CREATE_V2_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_af_packet_create_v2_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_interface_index_t sw_if_index;
} vl_api_af_packet_create_v2_reply_t;
#define VL_API_AF_PACKET_CREATE_V2_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_af_packet_create_v3 {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_af_packet_mode_t mode;
    vl_api_mac_address_t hw_addr;
    bool use_random_hw_addr;
    u8 host_if_name[64];
    u32 rx_frame_size;
    u32 tx_frame_size;
    u32 rx_frames_per_block;
    u32 tx_frames_per_block;
    vl_api_af_packet_flags_t flags;
    u16 num_rx_queues;
    u16 num_tx_queues;
} vl_api_af_packet_create_v3_t;
#define VL_API_AF_PACKET_CREATE_V3_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_af_packet_create_v3_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_interface_index_t sw_if_index;
} vl_api_af_packet_create_v3_reply_t;
#define VL_API_AF_PACKET_CREATE_V3_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_af_packet_delete {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u8 host_if_name[64];
} vl_api_af_packet_delete_t;
#define VL_API_AF_PACKET_DELETE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_af_packet_delete_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_af_packet_delete_reply_t;
#define VL_API_AF_PACKET_DELETE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_af_packet_set_l4_cksum_offload {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    bool set;
} vl_api_af_packet_set_l4_cksum_offload_t;
#define VL_API_AF_PACKET_SET_L4_CKSUM_OFFLOAD_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_af_packet_set_l4_cksum_offload_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_af_packet_set_l4_cksum_offload_reply_t;
#define VL_API_AF_PACKET_SET_L4_CKSUM_OFFLOAD_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_af_packet_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_af_packet_dump_t;
#define VL_API_AF_PACKET_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_af_packet_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u8 host_if_name[64];
} vl_api_af_packet_details_t;
#define VL_API_AF_PACKET_DETAILS_IS_CONSTANT_SIZE (1)

#define VL_API_AF_PACKET_CREATE_CRC "af_packet_create_a190415f"
#define VL_API_AF_PACKET_CREATE_REPLY_CRC "af_packet_create_reply_5383d31f"
#define VL_API_AF_PACKET_CREATE_V2_CRC "af_packet_create_v2_4aff0436"
#define VL_API_AF_PACKET_CREATE_V2_REPLY_CRC "af_packet_create_v2_reply_5383d31f"
#define VL_API_AF_PACKET_CREATE_V3_CRC "af_packet_create_v3_b3a809d4"
#define VL_API_AF_PACKET_CREATE_V3_REPLY_CRC "af_packet_create_v3_reply_5383d31f"
#define VL_API_AF_PACKET_DELETE_CRC "af_packet_delete_863fa648"
#define VL_API_AF_PACKET_DELETE_REPLY_CRC "af_packet_delete_reply_e8d4e804"
#define VL_API_AF_PACKET_SET_L4_CKSUM_OFFLOAD_CRC "af_packet_set_l4_cksum_offload_319cd5c8"
#define VL_API_AF_PACKET_SET_L4_CKSUM_OFFLOAD_REPLY_CRC "af_packet_set_l4_cksum_offload_reply_e8d4e804"
#define VL_API_AF_PACKET_DUMP_CRC "af_packet_dump_51077d14"
#define VL_API_AF_PACKET_DETAILS_CRC "af_packet_details_58c7c042"

#endif
