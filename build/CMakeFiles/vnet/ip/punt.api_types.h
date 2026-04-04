#ifndef included_punt_api_types_h
#define included_punt_api_types_h
#define VL_API_PUNT_API_VERSION_MAJOR 2
#define VL_API_PUNT_API_VERSION_MINOR 2
#define VL_API_PUNT_API_VERSION_PATCH 1
/* Imported API files */
#include <vnet/ip/ip_types.api_types.h>
typedef enum {
    PUNT_API_TYPE_L4 = 0,
    PUNT_API_TYPE_IP_PROTO = 1,
    PUNT_API_TYPE_EXCEPTION = 2,
} vl_api_punt_type_t;
typedef struct __attribute__ ((packed)) _vl_api_punt_l4 {
    vl_api_address_family_t af;
    vl_api_ip_proto_t protocol;
    u16 port;
} vl_api_punt_l4_t;
#define VL_API_PUNT_L4_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_punt_ip_proto {
    vl_api_address_family_t af;
    vl_api_ip_proto_t protocol;
} vl_api_punt_ip_proto_t;
#define VL_API_PUNT_IP_PROTO_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_punt_exception {
    u32 id;
} vl_api_punt_exception_t;
#define VL_API_PUNT_EXCEPTION_IS_CONSTANT_SIZE (1)

typedef union __attribute__ ((packed)) _vl_api_punt_union {
    vl_api_punt_exception_t exception;
    vl_api_punt_l4_t l4;
    vl_api_punt_ip_proto_t ip_proto;
} vl_api_punt_union_t;
#define VL_API_PUNT_UNION_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_punt {
    vl_api_punt_type_t type;
    vl_api_punt_union_t punt;
} vl_api_punt_t;
#define VL_API_PUNT_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_punt_reason {
    u32 id;
    vl_api_string_t name;
} vl_api_punt_reason_t;
#define VL_API_PUNT_REASON_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_set_punt {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_punt_t punt;
} vl_api_set_punt_t;
#define VL_API_SET_PUNT_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_set_punt_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_set_punt_reply_t;
#define VL_API_SET_PUNT_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_punt_socket_register {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 header_version;
    vl_api_punt_t punt;
    u8 pathname[108];
} vl_api_punt_socket_register_t;
#define VL_API_PUNT_SOCKET_REGISTER_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_punt_socket_register_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u8 pathname[108];
} vl_api_punt_socket_register_reply_t;
#define VL_API_PUNT_SOCKET_REGISTER_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_punt_socket_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_punt_type_t type;
} vl_api_punt_socket_dump_t;
#define VL_API_PUNT_SOCKET_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_punt_socket_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_punt_t punt;
    u8 pathname[108];
} vl_api_punt_socket_details_t;
#define VL_API_PUNT_SOCKET_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_punt_socket_deregister {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_punt_t punt;
} vl_api_punt_socket_deregister_t;
#define VL_API_PUNT_SOCKET_DEREGISTER_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_punt_socket_deregister_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_punt_socket_deregister_reply_t;
#define VL_API_PUNT_SOCKET_DEREGISTER_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_punt_reason_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_punt_reason_t reason;
} vl_api_punt_reason_dump_t;
#define VL_API_PUNT_REASON_DUMP_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_punt_reason_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_punt_reason_t reason;
} vl_api_punt_reason_details_t;
#define VL_API_PUNT_REASON_DETAILS_IS_CONSTANT_SIZE (0)

#define VL_API_SET_PUNT_CRC "set_punt_47d0e347"
#define VL_API_SET_PUNT_REPLY_CRC "set_punt_reply_e8d4e804"
#define VL_API_PUNT_SOCKET_REGISTER_CRC "punt_socket_register_7875badb"
#define VL_API_PUNT_SOCKET_REGISTER_REPLY_CRC "punt_socket_register_reply_bd30ae90"
#define VL_API_PUNT_SOCKET_DUMP_CRC "punt_socket_dump_916fb004"
#define VL_API_PUNT_SOCKET_DETAILS_CRC "punt_socket_details_330466e4"
#define VL_API_PUNT_SOCKET_DEREGISTER_CRC "punt_socket_deregister_75afa766"
#define VL_API_PUNT_SOCKET_DEREGISTER_REPLY_CRC "punt_socket_deregister_reply_e8d4e804"
#define VL_API_PUNT_REASON_DUMP_CRC "punt_reason_dump_5c0dd4fe"
#define VL_API_PUNT_REASON_DETAILS_CRC "punt_reason_details_2c9d4a40"

#endif
