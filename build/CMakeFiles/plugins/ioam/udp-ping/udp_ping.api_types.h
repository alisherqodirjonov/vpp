#ifndef included_udp_ping_api_types_h
#define included_udp_ping_api_types_h
#define VL_API_UDP_PING_API_VERSION_MAJOR 3
#define VL_API_UDP_PING_API_VERSION_MINOR 0
#define VL_API_UDP_PING_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/ip/ip_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_udp_ping_add_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_address_t src_ip_address;
    vl_api_address_t dst_ip_address;
    u16 start_src_port;
    u16 end_src_port;
    u16 start_dst_port;
    u16 end_dst_port;
    u16 interval;
    u8 dis;
    u8 fault_det;
    u8 reserve[3];
} vl_api_udp_ping_add_del_t;
#define VL_API_UDP_PING_ADD_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_udp_ping_add_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_udp_ping_add_del_reply_t;
#define VL_API_UDP_PING_ADD_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_udp_ping_export {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool enable;
} vl_api_udp_ping_export_t;
#define VL_API_UDP_PING_EXPORT_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_udp_ping_export_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_udp_ping_export_reply_t;
#define VL_API_UDP_PING_EXPORT_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_UDP_PING_ADD_DEL_CRC "udp_ping_add_del_fa2628fc"
#define VL_API_UDP_PING_ADD_DEL_REPLY_CRC "udp_ping_add_del_reply_e8d4e804"
#define VL_API_UDP_PING_EXPORT_CRC "udp_ping_export_b3e225d2"
#define VL_API_UDP_PING_EXPORT_REPLY_CRC "udp_ping_export_reply_e8d4e804"

#endif
