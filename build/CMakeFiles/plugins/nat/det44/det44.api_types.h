#ifndef included_det44_api_types_h
#define included_det44_api_types_h
#define VL_API_DET44_API_VERSION_MAJOR 1
#define VL_API_DET44_API_VERSION_MINOR 0
#define VL_API_DET44_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/ip/ip_types.api_types.h>
#include <vnet/interface_types.api_types.h>
#include <nat/lib/nat_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_det44_plugin_enable_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 inside_vrf;
    u32 outside_vrf;
    bool enable;
} vl_api_det44_plugin_enable_disable_t;
#define VL_API_DET44_PLUGIN_ENABLE_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_det44_plugin_enable_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_det44_plugin_enable_disable_reply_t;
#define VL_API_DET44_PLUGIN_ENABLE_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_det44_interface_add_del_feature {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    bool is_inside;
    vl_api_interface_index_t sw_if_index;
} vl_api_det44_interface_add_del_feature_t;
#define VL_API_DET44_INTERFACE_ADD_DEL_FEATURE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_det44_interface_add_del_feature_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_det44_interface_add_del_feature_reply_t;
#define VL_API_DET44_INTERFACE_ADD_DEL_FEATURE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_det44_interface_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_det44_interface_dump_t;
#define VL_API_DET44_INTERFACE_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_det44_interface_details {
    u16 _vl_msg_id;
    u32 context;
    bool is_inside;
    bool is_outside;
    vl_api_interface_index_t sw_if_index;
} vl_api_det44_interface_details_t;
#define VL_API_DET44_INTERFACE_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_det44_add_del_map {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_ip4_address_t in_addr;
    u8 in_plen;
    vl_api_ip4_address_t out_addr;
    u8 out_plen;
} vl_api_det44_add_del_map_t;
#define VL_API_DET44_ADD_DEL_MAP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_det44_add_del_map_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_det44_add_del_map_reply_t;
#define VL_API_DET44_ADD_DEL_MAP_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_det44_forward {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_ip4_address_t in_addr;
} vl_api_det44_forward_t;
#define VL_API_DET44_FORWARD_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_det44_forward_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u16 out_port_lo;
    u16 out_port_hi;
    vl_api_ip4_address_t out_addr;
} vl_api_det44_forward_reply_t;
#define VL_API_DET44_FORWARD_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_det44_reverse {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u16 out_port;
    vl_api_ip4_address_t out_addr;
} vl_api_det44_reverse_t;
#define VL_API_DET44_REVERSE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_det44_reverse_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_ip4_address_t in_addr;
} vl_api_det44_reverse_reply_t;
#define VL_API_DET44_REVERSE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_det44_map_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_det44_map_dump_t;
#define VL_API_DET44_MAP_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_det44_map_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_ip4_address_t in_addr;
    u8 in_plen;
    vl_api_ip4_address_t out_addr;
    u8 out_plen;
    u32 sharing_ratio;
    u16 ports_per_host;
    u32 ses_num;
} vl_api_det44_map_details_t;
#define VL_API_DET44_MAP_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_det44_close_session_out {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_ip4_address_t out_addr;
    u16 out_port;
    vl_api_ip4_address_t ext_addr;
    u16 ext_port;
} vl_api_det44_close_session_out_t;
#define VL_API_DET44_CLOSE_SESSION_OUT_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_det44_close_session_out_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_det44_close_session_out_reply_t;
#define VL_API_DET44_CLOSE_SESSION_OUT_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_det44_close_session_in {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_ip4_address_t in_addr;
    u16 in_port;
    vl_api_ip4_address_t ext_addr;
    u16 ext_port;
} vl_api_det44_close_session_in_t;
#define VL_API_DET44_CLOSE_SESSION_IN_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_det44_close_session_in_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_det44_close_session_in_reply_t;
#define VL_API_DET44_CLOSE_SESSION_IN_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_det44_session_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_ip4_address_t user_addr;
} vl_api_det44_session_dump_t;
#define VL_API_DET44_SESSION_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_det44_session_details {
    u16 _vl_msg_id;
    u32 context;
    u16 in_port;
    vl_api_ip4_address_t ext_addr;
    u16 ext_port;
    u16 out_port;
    u8 state;
    u32 expire;
} vl_api_det44_session_details_t;
#define VL_API_DET44_SESSION_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_det44_set_timeouts {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 udp;
    u32 tcp_established;
    u32 tcp_transitory;
    u32 icmp;
} vl_api_det44_set_timeouts_t;
#define VL_API_DET44_SET_TIMEOUTS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_det44_set_timeouts_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_det44_set_timeouts_reply_t;
#define VL_API_DET44_SET_TIMEOUTS_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_det44_get_timeouts {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_det44_get_timeouts_t;
#define VL_API_DET44_GET_TIMEOUTS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_det44_get_timeouts_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 udp;
    u32 tcp_established;
    u32 tcp_transitory;
    u32 icmp;
} vl_api_det44_get_timeouts_reply_t;
#define VL_API_DET44_GET_TIMEOUTS_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat_det_add_del_map {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_ip4_address_t in_addr;
    u8 in_plen;
    vl_api_ip4_address_t out_addr;
    u8 out_plen;
} vl_api_nat_det_add_del_map_t;
#define VL_API_NAT_DET_ADD_DEL_MAP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat_det_add_del_map_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_nat_det_add_del_map_reply_t;
#define VL_API_NAT_DET_ADD_DEL_MAP_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat_det_forward {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_ip4_address_t in_addr;
} vl_api_nat_det_forward_t;
#define VL_API_NAT_DET_FORWARD_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat_det_forward_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u16 out_port_lo;
    u16 out_port_hi;
    vl_api_ip4_address_t out_addr;
} vl_api_nat_det_forward_reply_t;
#define VL_API_NAT_DET_FORWARD_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat_det_reverse {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u16 out_port;
    vl_api_ip4_address_t out_addr;
} vl_api_nat_det_reverse_t;
#define VL_API_NAT_DET_REVERSE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat_det_reverse_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_ip4_address_t in_addr;
} vl_api_nat_det_reverse_reply_t;
#define VL_API_NAT_DET_REVERSE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat_det_map_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_nat_det_map_dump_t;
#define VL_API_NAT_DET_MAP_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat_det_map_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_ip4_address_t in_addr;
    u8 in_plen;
    vl_api_ip4_address_t out_addr;
    u8 out_plen;
    u32 sharing_ratio;
    u16 ports_per_host;
    u32 ses_num;
} vl_api_nat_det_map_details_t;
#define VL_API_NAT_DET_MAP_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat_det_close_session_out {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_ip4_address_t out_addr;
    u16 out_port;
    vl_api_ip4_address_t ext_addr;
    u16 ext_port;
} vl_api_nat_det_close_session_out_t;
#define VL_API_NAT_DET_CLOSE_SESSION_OUT_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat_det_close_session_out_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_nat_det_close_session_out_reply_t;
#define VL_API_NAT_DET_CLOSE_SESSION_OUT_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat_det_close_session_in {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_ip4_address_t in_addr;
    u16 in_port;
    vl_api_ip4_address_t ext_addr;
    u16 ext_port;
} vl_api_nat_det_close_session_in_t;
#define VL_API_NAT_DET_CLOSE_SESSION_IN_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat_det_close_session_in_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_nat_det_close_session_in_reply_t;
#define VL_API_NAT_DET_CLOSE_SESSION_IN_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat_det_session_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_ip4_address_t user_addr;
} vl_api_nat_det_session_dump_t;
#define VL_API_NAT_DET_SESSION_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat_det_session_details {
    u16 _vl_msg_id;
    u32 context;
    u16 in_port;
    vl_api_ip4_address_t ext_addr;
    u16 ext_port;
    u16 out_port;
    u8 state;
    u32 expire;
} vl_api_nat_det_session_details_t;
#define VL_API_NAT_DET_SESSION_DETAILS_IS_CONSTANT_SIZE (1)

#define VL_API_DET44_PLUGIN_ENABLE_DISABLE_CRC "det44_plugin_enable_disable_617b6bf8"
#define VL_API_DET44_PLUGIN_ENABLE_DISABLE_REPLY_CRC "det44_plugin_enable_disable_reply_e8d4e804"
#define VL_API_DET44_INTERFACE_ADD_DEL_FEATURE_CRC "det44_interface_add_del_feature_dc17a836"
#define VL_API_DET44_INTERFACE_ADD_DEL_FEATURE_REPLY_CRC "det44_interface_add_del_feature_reply_e8d4e804"
#define VL_API_DET44_INTERFACE_DUMP_CRC "det44_interface_dump_51077d14"
#define VL_API_DET44_INTERFACE_DETAILS_CRC "det44_interface_details_e60cc5be"
#define VL_API_DET44_ADD_DEL_MAP_CRC "det44_add_del_map_1150a190"
#define VL_API_DET44_ADD_DEL_MAP_REPLY_CRC "det44_add_del_map_reply_e8d4e804"
#define VL_API_DET44_FORWARD_CRC "det44_forward_7f8a89cd"
#define VL_API_DET44_FORWARD_REPLY_CRC "det44_forward_reply_a8ccbdc0"
#define VL_API_DET44_REVERSE_CRC "det44_reverse_a7573fe1"
#define VL_API_DET44_REVERSE_REPLY_CRC "det44_reverse_reply_34066d48"
#define VL_API_DET44_MAP_DUMP_CRC "det44_map_dump_51077d14"
#define VL_API_DET44_MAP_DETAILS_CRC "det44_map_details_ad91dc83"
#define VL_API_DET44_CLOSE_SESSION_OUT_CRC "det44_close_session_out_f6b259d1"
#define VL_API_DET44_CLOSE_SESSION_OUT_REPLY_CRC "det44_close_session_out_reply_e8d4e804"
#define VL_API_DET44_CLOSE_SESSION_IN_CRC "det44_close_session_in_3c68e073"
#define VL_API_DET44_CLOSE_SESSION_IN_REPLY_CRC "det44_close_session_in_reply_e8d4e804"
#define VL_API_DET44_SESSION_DUMP_CRC "det44_session_dump_e45a3af7"
#define VL_API_DET44_SESSION_DETAILS_CRC "det44_session_details_27f3c171"
#define VL_API_DET44_SET_TIMEOUTS_CRC "det44_set_timeouts_d4746b16"
#define VL_API_DET44_SET_TIMEOUTS_REPLY_CRC "det44_set_timeouts_reply_e8d4e804"
#define VL_API_DET44_GET_TIMEOUTS_CRC "det44_get_timeouts_51077d14"
#define VL_API_DET44_GET_TIMEOUTS_REPLY_CRC "det44_get_timeouts_reply_3c4df4e1"
#define VL_API_NAT_DET_ADD_DEL_MAP_CRC "nat_det_add_del_map_1150a190"
#define VL_API_NAT_DET_ADD_DEL_MAP_REPLY_CRC "nat_det_add_del_map_reply_e8d4e804"
#define VL_API_NAT_DET_FORWARD_CRC "nat_det_forward_7f8a89cd"
#define VL_API_NAT_DET_FORWARD_REPLY_CRC "nat_det_forward_reply_a8ccbdc0"
#define VL_API_NAT_DET_REVERSE_CRC "nat_det_reverse_a7573fe1"
#define VL_API_NAT_DET_REVERSE_REPLY_CRC "nat_det_reverse_reply_34066d48"
#define VL_API_NAT_DET_MAP_DUMP_CRC "nat_det_map_dump_51077d14"
#define VL_API_NAT_DET_MAP_DETAILS_CRC "nat_det_map_details_ad91dc83"
#define VL_API_NAT_DET_CLOSE_SESSION_OUT_CRC "nat_det_close_session_out_f6b259d1"
#define VL_API_NAT_DET_CLOSE_SESSION_OUT_REPLY_CRC "nat_det_close_session_out_reply_e8d4e804"
#define VL_API_NAT_DET_CLOSE_SESSION_IN_CRC "nat_det_close_session_in_3c68e073"
#define VL_API_NAT_DET_CLOSE_SESSION_IN_REPLY_CRC "nat_det_close_session_in_reply_e8d4e804"
#define VL_API_NAT_DET_SESSION_DUMP_CRC "nat_det_session_dump_e45a3af7"
#define VL_API_NAT_DET_SESSION_DETAILS_CRC "nat_det_session_details_27f3c171"

#endif
