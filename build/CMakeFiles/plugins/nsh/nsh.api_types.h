#ifndef included_nsh_api_types_h
#define included_nsh_api_types_h
#define VL_API_NSH_API_VERSION_MAJOR 1
#define VL_API_NSH_API_VERSION_MINOR 0
#define VL_API_NSH_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/interface_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_nsh_add_del_entry {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    u32 nsp_nsi;
    u8 md_type;
    u8 ver_o_c;
    u8 ttl;
    u8 length;
    u8 next_protocol;
    u32 c1;
    u32 c2;
    u32 c3;
    u32 c4;
    u8 tlv_length;
    u8 tlv[248];
} vl_api_nsh_add_del_entry_t;
#define VL_API_NSH_ADD_DEL_ENTRY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nsh_add_del_entry_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 entry_index;
} vl_api_nsh_add_del_entry_reply_t;
#define VL_API_NSH_ADD_DEL_ENTRY_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nsh_entry_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 entry_index;
} vl_api_nsh_entry_dump_t;
#define VL_API_NSH_ENTRY_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nsh_entry_details {
    u16 _vl_msg_id;
    u32 context;
    u32 entry_index;
    u32 nsp_nsi;
    u8 md_type;
    u8 ver_o_c;
    u8 ttl;
    u8 length;
    u8 next_protocol;
    u32 c1;
    u32 c2;
    u32 c3;
    u32 c4;
    u8 tlv_length;
    u8 tlv[248];
} vl_api_nsh_entry_details_t;
#define VL_API_NSH_ENTRY_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nsh_add_del_map {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    u32 nsp_nsi;
    u32 mapped_nsp_nsi;
    u32 nsh_action;
    vl_api_interface_index_t sw_if_index;
    vl_api_interface_index_t rx_sw_if_index;
    u32 next_node;
} vl_api_nsh_add_del_map_t;
#define VL_API_NSH_ADD_DEL_MAP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nsh_add_del_map_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 map_index;
} vl_api_nsh_add_del_map_reply_t;
#define VL_API_NSH_ADD_DEL_MAP_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nsh_map_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 map_index;
} vl_api_nsh_map_dump_t;
#define VL_API_NSH_MAP_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nsh_map_details {
    u16 _vl_msg_id;
    u32 context;
    u32 map_index;
    u32 nsp_nsi;
    u32 mapped_nsp_nsi;
    u32 nsh_action;
    vl_api_interface_index_t sw_if_index;
    vl_api_interface_index_t rx_sw_if_index;
    u32 next_node;
} vl_api_nsh_map_details_t;
#define VL_API_NSH_MAP_DETAILS_IS_CONSTANT_SIZE (1)

#define VL_API_NSH_ADD_DEL_ENTRY_CRC "nsh_add_del_entry_7dea480b"
#define VL_API_NSH_ADD_DEL_ENTRY_REPLY_CRC "nsh_add_del_entry_reply_6296a9eb"
#define VL_API_NSH_ENTRY_DUMP_CRC "nsh_entry_dump_cdaf8ccb"
#define VL_API_NSH_ENTRY_DETAILS_CRC "nsh_entry_details_046fb556"
#define VL_API_NSH_ADD_DEL_MAP_CRC "nsh_add_del_map_0a0f42b0"
#define VL_API_NSH_ADD_DEL_MAP_REPLY_CRC "nsh_add_del_map_reply_b2b127ef"
#define VL_API_NSH_MAP_DUMP_CRC "nsh_map_dump_8fc06b82"
#define VL_API_NSH_MAP_DETAILS_CRC "nsh_map_details_2fefcf49"

#endif
