#ifndef included_udp_api_types_h
#define included_udp_api_types_h
#define VL_API_UDP_API_VERSION_MAJOR 1
#define VL_API_UDP_API_VERSION_MINOR 1
#define VL_API_UDP_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/ip/ip_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_udp_encap {
    u32 table_id;
    u16 src_port;
    u16 dst_port;
    vl_api_address_t src_ip;
    vl_api_address_t dst_ip;
    u32 id;
} vl_api_udp_encap_t;
#define VL_API_UDP_ENCAP_IS_CONSTANT_SIZE (1)

typedef enum {
    UDP_API_DECAP_PROTO_IP4 = 0,
    UDP_API_DECAP_PROTO_IP6 = 1,
    UDP_API_DECAP_PROTO_MPLS = 2,
} vl_api_udp_decap_next_proto_t;
typedef struct __attribute__ ((packed)) _vl_api_udp_decap {
    u8 is_ip4;
    u16 port;
    vl_api_udp_decap_next_proto_t next_proto;
} vl_api_udp_decap_t;
#define VL_API_UDP_DECAP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_udp_encap_add {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_udp_encap_t udp_encap;
} vl_api_udp_encap_add_t;
#define VL_API_UDP_ENCAP_ADD_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_udp_encap_add_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 id;
} vl_api_udp_encap_add_reply_t;
#define VL_API_UDP_ENCAP_ADD_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_udp_encap_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 id;
} vl_api_udp_encap_del_t;
#define VL_API_UDP_ENCAP_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_udp_encap_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_udp_encap_del_reply_t;
#define VL_API_UDP_ENCAP_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_udp_encap_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_udp_encap_dump_t;
#define VL_API_UDP_ENCAP_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_udp_encap_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_udp_encap_t udp_encap;
} vl_api_udp_encap_details_t;
#define VL_API_UDP_ENCAP_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_udp_decap_add_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_udp_decap_t udp_decap;
} vl_api_udp_decap_add_del_t;
#define VL_API_UDP_DECAP_ADD_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_udp_decap_add_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_udp_decap_add_del_reply_t;
#define VL_API_UDP_DECAP_ADD_DEL_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_UDP_ENCAP_ADD_CRC "udp_encap_add_f74a60b1"
#define VL_API_UDP_ENCAP_ADD_REPLY_CRC "udp_encap_add_reply_e2fc8294"
#define VL_API_UDP_ENCAP_DEL_CRC "udp_encap_del_3a91bde5"
#define VL_API_UDP_ENCAP_DEL_REPLY_CRC "udp_encap_del_reply_e8d4e804"
#define VL_API_UDP_ENCAP_DUMP_CRC "udp_encap_dump_51077d14"
#define VL_API_UDP_ENCAP_DETAILS_CRC "udp_encap_details_8cfb9c76"
#define VL_API_UDP_DECAP_ADD_DEL_CRC "udp_decap_add_del_d14a4f47"
#define VL_API_UDP_DECAP_ADD_DEL_REPLY_CRC "udp_decap_add_del_reply_e8d4e804"

#endif
