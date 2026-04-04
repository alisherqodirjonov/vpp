#ifndef included_gre_api_types_h
#define included_gre_api_types_h
#define VL_API_GRE_API_VERSION_MAJOR 2
#define VL_API_GRE_API_VERSION_MINOR 1
#define VL_API_GRE_API_VERSION_PATCH 1
/* Imported API files */
#include <vnet/interface_types.api_types.h>
#include <vnet/tunnel/tunnel_types.api_types.h>
#include <vnet/ip/ip_types.api_types.h>
typedef enum __attribute__((packed)) {
    GRE_API_TUNNEL_TYPE_L3 = 0,
    GRE_API_TUNNEL_TYPE_TEB = 1,
    GRE_API_TUNNEL_TYPE_ERSPAN = 2,
} vl_api_gre_tunnel_type_t;
STATIC_ASSERT(sizeof(vl_api_gre_tunnel_type_t) == sizeof(u8), "size of API enum gre_tunnel_type is wrong");
typedef struct __attribute__ ((packed)) _vl_api_gre_tunnel {
    vl_api_gre_tunnel_type_t type;
    vl_api_tunnel_mode_t mode;
    vl_api_tunnel_encap_decap_flags_t flags;
    u16 session_id;
    u32 instance;
    u32 outer_table_id;
    vl_api_interface_index_t sw_if_index;
    vl_api_address_t src;
    vl_api_address_t dst;
} vl_api_gre_tunnel_t;
#define VL_API_GRE_TUNNEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gre_tunnel_v2 {
    vl_api_gre_tunnel_type_t type;
    vl_api_tunnel_mode_t mode;
    vl_api_tunnel_encap_decap_flags_t flags;
    u16 session_id;
    u32 instance;
    u32 outer_table_id;
    vl_api_interface_index_t sw_if_index;
    vl_api_address_t src;
    vl_api_address_t dst;
    u32 key;
} vl_api_gre_tunnel_v2_t;
#define VL_API_GRE_TUNNEL_V2_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gre_tunnel_add_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_gre_tunnel_t tunnel;
} vl_api_gre_tunnel_add_del_t;
#define VL_API_GRE_TUNNEL_ADD_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gre_tunnel_add_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_interface_index_t sw_if_index;
} vl_api_gre_tunnel_add_del_reply_t;
#define VL_API_GRE_TUNNEL_ADD_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gre_tunnel_add_del_v2 {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_gre_tunnel_v2_t tunnel;
} vl_api_gre_tunnel_add_del_v2_t;
#define VL_API_GRE_TUNNEL_ADD_DEL_V2_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gre_tunnel_add_del_v2_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_interface_index_t sw_if_index;
} vl_api_gre_tunnel_add_del_v2_reply_t;
#define VL_API_GRE_TUNNEL_ADD_DEL_V2_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gre_tunnel_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_gre_tunnel_dump_t;
#define VL_API_GRE_TUNNEL_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gre_tunnel_dump_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_gre_tunnel_dump_reply_t;
#define VL_API_GRE_TUNNEL_DUMP_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gre_tunnel_dump_v2 {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_gre_tunnel_dump_v2_t;
#define VL_API_GRE_TUNNEL_DUMP_V2_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gre_tunnel_dump_v2_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_gre_tunnel_dump_v2_reply_t;
#define VL_API_GRE_TUNNEL_DUMP_V2_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gre_tunnel_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_gre_tunnel_t tunnel;
} vl_api_gre_tunnel_details_t;
#define VL_API_GRE_TUNNEL_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gre_tunnel_details_v2 {
    u16 _vl_msg_id;
    u32 context;
    vl_api_gre_tunnel_v2_t tunnel;
} vl_api_gre_tunnel_details_v2_t;
#define VL_API_GRE_TUNNEL_DETAILS_V2_IS_CONSTANT_SIZE (1)

#define VL_API_GRE_TUNNEL_ADD_DEL_CRC "gre_tunnel_add_del_a27d7f17"
#define VL_API_GRE_TUNNEL_ADD_DEL_REPLY_CRC "gre_tunnel_add_del_reply_5383d31f"
#define VL_API_GRE_TUNNEL_ADD_DEL_V2_CRC "gre_tunnel_add_del_v2_7d9576de"
#define VL_API_GRE_TUNNEL_ADD_DEL_V2_REPLY_CRC "gre_tunnel_add_del_v2_reply_5383d31f"
#define VL_API_GRE_TUNNEL_DUMP_CRC "gre_tunnel_dump_f9e6675e"
#define VL_API_GRE_TUNNEL_DUMP_REPLY_CRC "gre_tunnel_dump_reply_e8d4e804"
#define VL_API_GRE_TUNNEL_DUMP_V2_CRC "gre_tunnel_dump_v2_f9e6675e"
#define VL_API_GRE_TUNNEL_DUMP_V2_REPLY_CRC "gre_tunnel_dump_v2_reply_e8d4e804"
#define VL_API_GRE_TUNNEL_DETAILS_CRC "gre_tunnel_details_24435433"
#define VL_API_GRE_TUNNEL_DETAILS_V2_CRC "gre_tunnel_details_v2_65521177"

#endif
