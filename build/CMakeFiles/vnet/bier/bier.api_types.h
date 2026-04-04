#ifndef included_bier_api_types_h
#define included_bier_api_types_h
#define VL_API_BIER_API_VERSION_MAJOR 1
#define VL_API_BIER_API_VERSION_MINOR 2
#define VL_API_BIER_API_VERSION_PATCH 1
/* Imported API files */
#include <vnet/fib/fib_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_bier_table_id {
    u8 bt_set;
    u8 bt_sub_domain;
    u8 bt_hdr_len_id;
} vl_api_bier_table_id_t;
#define VL_API_BIER_TABLE_ID_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_bier_route {
    u32 br_bp;
    vl_api_bier_table_id_t br_tbl_id;
    u8 br_n_paths;
    vl_api_fib_path_t br_paths[0];
} vl_api_bier_route_t;
#define VL_API_BIER_ROUTE_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_bier_table_add_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_bier_table_id_t bt_tbl_id;
    u32 bt_label;
    bool bt_is_add;
} vl_api_bier_table_add_del_t;
#define VL_API_BIER_TABLE_ADD_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_bier_table_add_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_bier_table_add_del_reply_t;
#define VL_API_BIER_TABLE_ADD_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_bier_table_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_bier_table_dump_t;
#define VL_API_BIER_TABLE_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_bier_table_details {
    u16 _vl_msg_id;
    u32 context;
    u32 bt_label;
    vl_api_bier_table_id_t bt_tbl_id;
} vl_api_bier_table_details_t;
#define VL_API_BIER_TABLE_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_bier_route_add_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool br_is_add;
    bool br_is_replace;
    vl_api_bier_route_t br_route;
} vl_api_bier_route_add_del_t;
#define VL_API_BIER_ROUTE_ADD_DEL_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_bier_route_add_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_bier_route_add_del_reply_t;
#define VL_API_BIER_ROUTE_ADD_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_bier_route_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_bier_table_id_t br_tbl_id;
} vl_api_bier_route_dump_t;
#define VL_API_BIER_ROUTE_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_bier_route_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_bier_route_t br_route;
} vl_api_bier_route_details_t;
#define VL_API_BIER_ROUTE_DETAILS_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_bier_imp_add {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_bier_table_id_t bi_tbl_id;
    u16 bi_src;
    u8 bi_n_bytes;
    u8 bi_bytes[0];
} vl_api_bier_imp_add_t;
#define VL_API_BIER_IMP_ADD_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_bier_imp_add_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 bi_index;
} vl_api_bier_imp_add_reply_t;
#define VL_API_BIER_IMP_ADD_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_bier_imp_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 bi_index;
} vl_api_bier_imp_del_t;
#define VL_API_BIER_IMP_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_bier_imp_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_bier_imp_del_reply_t;
#define VL_API_BIER_IMP_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_bier_imp_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_bier_imp_dump_t;
#define VL_API_BIER_IMP_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_bier_imp_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_bier_table_id_t bi_tbl_id;
    u16 bi_src;
    u8 bi_n_bytes;
    u8 bi_bytes[0];
} vl_api_bier_imp_details_t;
#define VL_API_BIER_IMP_DETAILS_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_bier_disp_table_add_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 bdt_tbl_id;
    bool bdt_is_add;
} vl_api_bier_disp_table_add_del_t;
#define VL_API_BIER_DISP_TABLE_ADD_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_bier_disp_table_add_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_bier_disp_table_add_del_reply_t;
#define VL_API_BIER_DISP_TABLE_ADD_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_bier_disp_table_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_bier_disp_table_dump_t;
#define VL_API_BIER_DISP_TABLE_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_bier_disp_table_details {
    u16 _vl_msg_id;
    u32 context;
    u32 bdt_tbl_id;
} vl_api_bier_disp_table_details_t;
#define VL_API_BIER_DISP_TABLE_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_bier_disp_entry_add_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u16 bde_bp;
    u32 bde_tbl_id;
    bool bde_is_add;
    u8 bde_payload_proto;
    u8 bde_n_paths;
    vl_api_fib_path_t bde_paths[0];
} vl_api_bier_disp_entry_add_del_t;
#define VL_API_BIER_DISP_ENTRY_ADD_DEL_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_bier_disp_entry_add_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_bier_disp_entry_add_del_reply_t;
#define VL_API_BIER_DISP_ENTRY_ADD_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_bier_disp_entry_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 bde_tbl_id;
} vl_api_bier_disp_entry_dump_t;
#define VL_API_BIER_DISP_ENTRY_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_bier_disp_entry_details {
    u16 _vl_msg_id;
    u32 context;
    u16 bde_bp;
    u32 bde_tbl_id;
    bool bde_is_add;
    u8 bde_payload_proto;
    u8 bde_n_paths;
    vl_api_fib_path_t bde_paths[0];
} vl_api_bier_disp_entry_details_t;
#define VL_API_BIER_DISP_ENTRY_DETAILS_IS_CONSTANT_SIZE (0)

#define VL_API_BIER_TABLE_ADD_DEL_CRC "bier_table_add_del_35e59209"
#define VL_API_BIER_TABLE_ADD_DEL_REPLY_CRC "bier_table_add_del_reply_e8d4e804"
#define VL_API_BIER_TABLE_DUMP_CRC "bier_table_dump_51077d14"
#define VL_API_BIER_TABLE_DETAILS_CRC "bier_table_details_fc44a9dd"
#define VL_API_BIER_ROUTE_ADD_DEL_CRC "bier_route_add_del_fd02f3ea"
#define VL_API_BIER_ROUTE_ADD_DEL_REPLY_CRC "bier_route_add_del_reply_e8d4e804"
#define VL_API_BIER_ROUTE_DUMP_CRC "bier_route_dump_38339846"
#define VL_API_BIER_ROUTE_DETAILS_CRC "bier_route_details_4008caee"
#define VL_API_BIER_IMP_ADD_CRC "bier_imp_add_3856dc3d"
#define VL_API_BIER_IMP_ADD_REPLY_CRC "bier_imp_add_reply_d49c5793"
#define VL_API_BIER_IMP_DEL_CRC "bier_imp_del_7d45edf6"
#define VL_API_BIER_IMP_DEL_REPLY_CRC "bier_imp_del_reply_e8d4e804"
#define VL_API_BIER_IMP_DUMP_CRC "bier_imp_dump_51077d14"
#define VL_API_BIER_IMP_DETAILS_CRC "bier_imp_details_b76192df"
#define VL_API_BIER_DISP_TABLE_ADD_DEL_CRC "bier_disp_table_add_del_889657ac"
#define VL_API_BIER_DISP_TABLE_ADD_DEL_REPLY_CRC "bier_disp_table_add_del_reply_e8d4e804"
#define VL_API_BIER_DISP_TABLE_DUMP_CRC "bier_disp_table_dump_51077d14"
#define VL_API_BIER_DISP_TABLE_DETAILS_CRC "bier_disp_table_details_d27942c0"
#define VL_API_BIER_DISP_ENTRY_ADD_DEL_CRC "bier_disp_entry_add_del_9eb80cb4"
#define VL_API_BIER_DISP_ENTRY_ADD_DEL_REPLY_CRC "bier_disp_entry_add_del_reply_e8d4e804"
#define VL_API_BIER_DISP_ENTRY_DUMP_CRC "bier_disp_entry_dump_b5fa54ad"
#define VL_API_BIER_DISP_ENTRY_DETAILS_CRC "bier_disp_entry_details_84c218f1"

#endif
