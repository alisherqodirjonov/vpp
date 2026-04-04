#ifndef included_lisp_gpe_api_types_h
#define included_lisp_gpe_api_types_h
#define VL_API_LISP_GPE_API_VERSION_MAJOR 2
#define VL_API_LISP_GPE_API_VERSION_MINOR 0
#define VL_API_LISP_GPE_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/interface_types.api_types.h>
#include <lisp/lisp-cp/lisp_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_gpe_locator {
    u8 weight;
    vl_api_address_t addr;
} vl_api_gpe_locator_t;
#define VL_API_GPE_LOCATOR_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gpe_fwd_entry {
    u32 fwd_entry_index;
    u32 dp_table;
    vl_api_eid_t leid;
    vl_api_eid_t reid;
    u32 vni;
    u8 action;
} vl_api_gpe_fwd_entry_t;
#define VL_API_GPE_FWD_ENTRY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gpe_native_fwd_rpath {
    u32 fib_index;
    vl_api_interface_index_t nh_sw_if_index;
    vl_api_address_t nh_addr;
} vl_api_gpe_native_fwd_rpath_t;
#define VL_API_GPE_NATIVE_FWD_RPATH_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gpe_add_del_fwd_entry {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_eid_t rmt_eid;
    vl_api_eid_t lcl_eid;
    u32 vni;
    u32 dp_table;
    u8 action;
    u32 loc_num;
    vl_api_gpe_locator_t locs[0];
} vl_api_gpe_add_del_fwd_entry_t;
#define VL_API_GPE_ADD_DEL_FWD_ENTRY_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_gpe_add_del_fwd_entry_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 fwd_entry_index;
} vl_api_gpe_add_del_fwd_entry_reply_t;
#define VL_API_GPE_ADD_DEL_FWD_ENTRY_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gpe_enable_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_enable;
} vl_api_gpe_enable_disable_t;
#define VL_API_GPE_ENABLE_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gpe_enable_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_gpe_enable_disable_reply_t;
#define VL_API_GPE_ENABLE_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gpe_add_del_iface {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    bool is_l2;
    u32 dp_table;
    u32 vni;
} vl_api_gpe_add_del_iface_t;
#define VL_API_GPE_ADD_DEL_IFACE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gpe_add_del_iface_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_gpe_add_del_iface_reply_t;
#define VL_API_GPE_ADD_DEL_IFACE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gpe_fwd_entry_vnis_get {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_gpe_fwd_entry_vnis_get_t;
#define VL_API_GPE_FWD_ENTRY_VNIS_GET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gpe_fwd_entry_vnis_get_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 count;
    u32 vnis[0];
} vl_api_gpe_fwd_entry_vnis_get_reply_t;
#define VL_API_GPE_FWD_ENTRY_VNIS_GET_REPLY_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_gpe_fwd_entries_get {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 vni;
} vl_api_gpe_fwd_entries_get_t;
#define VL_API_GPE_FWD_ENTRIES_GET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gpe_fwd_entries_get_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 count;
    vl_api_gpe_fwd_entry_t entries[0];
} vl_api_gpe_fwd_entries_get_reply_t;
#define VL_API_GPE_FWD_ENTRIES_GET_REPLY_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_gpe_fwd_entry_path_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 fwd_entry_index;
} vl_api_gpe_fwd_entry_path_dump_t;
#define VL_API_GPE_FWD_ENTRY_PATH_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gpe_fwd_entry_path_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_gpe_locator_t lcl_loc;
    vl_api_gpe_locator_t rmt_loc;
} vl_api_gpe_fwd_entry_path_details_t;
#define VL_API_GPE_FWD_ENTRY_PATH_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gpe_set_encap_mode {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_vxlan;
} vl_api_gpe_set_encap_mode_t;
#define VL_API_GPE_SET_ENCAP_MODE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gpe_set_encap_mode_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_gpe_set_encap_mode_reply_t;
#define VL_API_GPE_SET_ENCAP_MODE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gpe_get_encap_mode {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_gpe_get_encap_mode_t;
#define VL_API_GPE_GET_ENCAP_MODE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gpe_get_encap_mode_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u8 encap_mode;
} vl_api_gpe_get_encap_mode_reply_t;
#define VL_API_GPE_GET_ENCAP_MODE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gpe_add_del_native_fwd_rpath {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    u32 table_id;
    vl_api_interface_index_t nh_sw_if_index;
    vl_api_address_t nh_addr;
} vl_api_gpe_add_del_native_fwd_rpath_t;
#define VL_API_GPE_ADD_DEL_NATIVE_FWD_RPATH_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gpe_add_del_native_fwd_rpath_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_gpe_add_del_native_fwd_rpath_reply_t;
#define VL_API_GPE_ADD_DEL_NATIVE_FWD_RPATH_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gpe_native_fwd_rpaths_get {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_ip4;
} vl_api_gpe_native_fwd_rpaths_get_t;
#define VL_API_GPE_NATIVE_FWD_RPATHS_GET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_gpe_native_fwd_rpaths_get_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 count;
    vl_api_gpe_native_fwd_rpath_t entries[0];
} vl_api_gpe_native_fwd_rpaths_get_reply_t;
#define VL_API_GPE_NATIVE_FWD_RPATHS_GET_REPLY_IS_CONSTANT_SIZE (0)

#define VL_API_GPE_ADD_DEL_FWD_ENTRY_CRC "gpe_add_del_fwd_entry_f0847644"
#define VL_API_GPE_ADD_DEL_FWD_ENTRY_REPLY_CRC "gpe_add_del_fwd_entry_reply_efe5f176"
#define VL_API_GPE_ENABLE_DISABLE_CRC "gpe_enable_disable_c264d7bf"
#define VL_API_GPE_ENABLE_DISABLE_REPLY_CRC "gpe_enable_disable_reply_e8d4e804"
#define VL_API_GPE_ADD_DEL_IFACE_CRC "gpe_add_del_iface_3ccff273"
#define VL_API_GPE_ADD_DEL_IFACE_REPLY_CRC "gpe_add_del_iface_reply_e8d4e804"
#define VL_API_GPE_FWD_ENTRY_VNIS_GET_CRC "gpe_fwd_entry_vnis_get_51077d14"
#define VL_API_GPE_FWD_ENTRY_VNIS_GET_REPLY_CRC "gpe_fwd_entry_vnis_get_reply_aa70da20"
#define VL_API_GPE_FWD_ENTRIES_GET_CRC "gpe_fwd_entries_get_8d1f2fe9"
#define VL_API_GPE_FWD_ENTRIES_GET_REPLY_CRC "gpe_fwd_entries_get_reply_c4844876"
#define VL_API_GPE_FWD_ENTRY_PATH_DUMP_CRC "gpe_fwd_entry_path_dump_39bce980"
#define VL_API_GPE_FWD_ENTRY_PATH_DETAILS_CRC "gpe_fwd_entry_path_details_483df51a"
#define VL_API_GPE_SET_ENCAP_MODE_CRC "gpe_set_encap_mode_bd819eac"
#define VL_API_GPE_SET_ENCAP_MODE_REPLY_CRC "gpe_set_encap_mode_reply_e8d4e804"
#define VL_API_GPE_GET_ENCAP_MODE_CRC "gpe_get_encap_mode_51077d14"
#define VL_API_GPE_GET_ENCAP_MODE_REPLY_CRC "gpe_get_encap_mode_reply_36e3f7ca"
#define VL_API_GPE_ADD_DEL_NATIVE_FWD_RPATH_CRC "gpe_add_del_native_fwd_rpath_43fc8b54"
#define VL_API_GPE_ADD_DEL_NATIVE_FWD_RPATH_REPLY_CRC "gpe_add_del_native_fwd_rpath_reply_e8d4e804"
#define VL_API_GPE_NATIVE_FWD_RPATHS_GET_CRC "gpe_native_fwd_rpaths_get_f652ceb4"
#define VL_API_GPE_NATIVE_FWD_RPATHS_GET_REPLY_CRC "gpe_native_fwd_rpaths_get_reply_7a1ca5a2"

#endif
