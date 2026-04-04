#ifndef included_ipsec_api_types_h
#define included_ipsec_api_types_h
#define VL_API_IPSEC_API_VERSION_MAJOR 5
#define VL_API_IPSEC_API_VERSION_MINOR 0
#define VL_API_IPSEC_API_VERSION_PATCH 2
/* Imported API files */
#include <vnet/ipsec/ipsec_types.api_types.h>
#include <vnet/interface_types.api_types.h>
#include <vnet/ip/ip_types.api_types.h>
#include <vnet/interface_types.api_types.h>
#include <vnet/tunnel/tunnel_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_ipsec_tunnel_protect {
    vl_api_interface_index_t sw_if_index;
    vl_api_address_t nh;
    u32 sa_out;
    u8 n_sa_in;
    u32 sa_in[0];
} vl_api_ipsec_tunnel_protect_t;
#define VL_API_IPSEC_TUNNEL_PROTECT_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_itf {
    u32 user_instance;
    vl_api_tunnel_mode_t mode;
    vl_api_interface_index_t sw_if_index;
} vl_api_ipsec_itf_t;
#define VL_API_IPSEC_ITF_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_spd_add_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    u32 spd_id;
} vl_api_ipsec_spd_add_del_t;
#define VL_API_IPSEC_SPD_ADD_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_spd_add_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_ipsec_spd_add_del_reply_t;
#define VL_API_IPSEC_SPD_ADD_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_interface_add_del_spd {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_interface_index_t sw_if_index;
    u32 spd_id;
} vl_api_ipsec_interface_add_del_spd_t;
#define VL_API_IPSEC_INTERFACE_ADD_DEL_SPD_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_interface_add_del_spd_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_ipsec_interface_add_del_spd_reply_t;
#define VL_API_IPSEC_INTERFACE_ADD_DEL_SPD_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_spd_entry_add_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_ipsec_spd_entry_t entry;
} vl_api_ipsec_spd_entry_add_del_t;
#define VL_API_IPSEC_SPD_ENTRY_ADD_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_spd_entry_add_del_v2 {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_ipsec_spd_entry_v2_t entry;
} vl_api_ipsec_spd_entry_add_del_v2_t;
#define VL_API_IPSEC_SPD_ENTRY_ADD_DEL_V2_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_spd_entry_add_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 stat_index;
} vl_api_ipsec_spd_entry_add_del_reply_t;
#define VL_API_IPSEC_SPD_ENTRY_ADD_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_spd_entry_add_del_v2_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 stat_index;
} vl_api_ipsec_spd_entry_add_del_v2_reply_t;
#define VL_API_IPSEC_SPD_ENTRY_ADD_DEL_V2_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_spds_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_ipsec_spds_dump_t;
#define VL_API_IPSEC_SPDS_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_spds_details {
    u16 _vl_msg_id;
    u32 context;
    u32 spd_id;
    u32 npolicies;
} vl_api_ipsec_spds_details_t;
#define VL_API_IPSEC_SPDS_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_spd_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 spd_id;
    u32 sa_id;
} vl_api_ipsec_spd_dump_t;
#define VL_API_IPSEC_SPD_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_spd_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_ipsec_spd_entry_t entry;
} vl_api_ipsec_spd_details_t;
#define VL_API_IPSEC_SPD_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_sad_entry_add_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_ipsec_sad_entry_t entry;
} vl_api_ipsec_sad_entry_add_del_t;
#define VL_API_IPSEC_SAD_ENTRY_ADD_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_sad_entry_add_del_v2 {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_ipsec_sad_entry_v2_t entry;
} vl_api_ipsec_sad_entry_add_del_v2_t;
#define VL_API_IPSEC_SAD_ENTRY_ADD_DEL_V2_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_sad_entry_add_del_v3 {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_ipsec_sad_entry_v3_t entry;
} vl_api_ipsec_sad_entry_add_del_v3_t;
#define VL_API_IPSEC_SAD_ENTRY_ADD_DEL_V3_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_sad_entry_add {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_ipsec_sad_entry_v3_t entry;
} vl_api_ipsec_sad_entry_add_t;
#define VL_API_IPSEC_SAD_ENTRY_ADD_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_sad_entry_add_v2 {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_ipsec_sad_entry_v4_t entry;
} vl_api_ipsec_sad_entry_add_v2_t;
#define VL_API_IPSEC_SAD_ENTRY_ADD_V2_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_sad_entry_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 id;
} vl_api_ipsec_sad_entry_del_t;
#define VL_API_IPSEC_SAD_ENTRY_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_sad_entry_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_ipsec_sad_entry_del_reply_t;
#define VL_API_IPSEC_SAD_ENTRY_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_sad_bind {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 sa_id;
    u32 worker;
} vl_api_ipsec_sad_bind_t;
#define VL_API_IPSEC_SAD_BIND_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_sad_bind_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_ipsec_sad_bind_reply_t;
#define VL_API_IPSEC_SAD_BIND_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_sad_unbind {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 sa_id;
} vl_api_ipsec_sad_unbind_t;
#define VL_API_IPSEC_SAD_UNBIND_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_sad_unbind_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_ipsec_sad_unbind_reply_t;
#define VL_API_IPSEC_SAD_UNBIND_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_sad_entry_update {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 sad_id;
    bool is_tun;
    vl_api_tunnel_t tunnel;
    u16 udp_src_port;
    u16 udp_dst_port;
} vl_api_ipsec_sad_entry_update_t;
#define VL_API_IPSEC_SAD_ENTRY_UPDATE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_sad_entry_update_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_ipsec_sad_entry_update_reply_t;
#define VL_API_IPSEC_SAD_ENTRY_UPDATE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_sad_entry_add_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 stat_index;
} vl_api_ipsec_sad_entry_add_del_reply_t;
#define VL_API_IPSEC_SAD_ENTRY_ADD_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_sad_entry_add_del_v2_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 stat_index;
} vl_api_ipsec_sad_entry_add_del_v2_reply_t;
#define VL_API_IPSEC_SAD_ENTRY_ADD_DEL_V2_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_sad_entry_add_del_v3_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 stat_index;
} vl_api_ipsec_sad_entry_add_del_v3_reply_t;
#define VL_API_IPSEC_SAD_ENTRY_ADD_DEL_V3_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_sad_entry_add_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 stat_index;
} vl_api_ipsec_sad_entry_add_reply_t;
#define VL_API_IPSEC_SAD_ENTRY_ADD_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_sad_entry_add_v2_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 stat_index;
} vl_api_ipsec_sad_entry_add_v2_reply_t;
#define VL_API_IPSEC_SAD_ENTRY_ADD_V2_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_tunnel_protect_update {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_ipsec_tunnel_protect_t tunnel;
} vl_api_ipsec_tunnel_protect_update_t;
#define VL_API_IPSEC_TUNNEL_PROTECT_UPDATE_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_tunnel_protect_update_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_ipsec_tunnel_protect_update_reply_t;
#define VL_API_IPSEC_TUNNEL_PROTECT_UPDATE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_tunnel_protect_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    vl_api_address_t nh;
} vl_api_ipsec_tunnel_protect_del_t;
#define VL_API_IPSEC_TUNNEL_PROTECT_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_tunnel_protect_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_ipsec_tunnel_protect_del_reply_t;
#define VL_API_IPSEC_TUNNEL_PROTECT_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_tunnel_protect_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_ipsec_tunnel_protect_dump_t;
#define VL_API_IPSEC_TUNNEL_PROTECT_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_tunnel_protect_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_ipsec_tunnel_protect_t tun;
} vl_api_ipsec_tunnel_protect_details_t;
#define VL_API_IPSEC_TUNNEL_PROTECT_DETAILS_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_spd_interface_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 spd_index;
    u8 spd_index_valid;
} vl_api_ipsec_spd_interface_dump_t;
#define VL_API_IPSEC_SPD_INTERFACE_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_spd_interface_details {
    u16 _vl_msg_id;
    u32 context;
    u32 spd_index;
    vl_api_interface_index_t sw_if_index;
} vl_api_ipsec_spd_interface_details_t;
#define VL_API_IPSEC_SPD_INTERFACE_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_itf_create {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_ipsec_itf_t itf;
} vl_api_ipsec_itf_create_t;
#define VL_API_IPSEC_ITF_CREATE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_itf_create_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_interface_index_t sw_if_index;
} vl_api_ipsec_itf_create_reply_t;
#define VL_API_IPSEC_ITF_CREATE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_itf_delete {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_ipsec_itf_delete_t;
#define VL_API_IPSEC_ITF_DELETE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_itf_delete_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_ipsec_itf_delete_reply_t;
#define VL_API_IPSEC_ITF_DELETE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_itf_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_ipsec_itf_dump_t;
#define VL_API_IPSEC_ITF_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_itf_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_ipsec_itf_t itf;
} vl_api_ipsec_itf_details_t;
#define VL_API_IPSEC_ITF_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_sa_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 sa_id;
} vl_api_ipsec_sa_dump_t;
#define VL_API_IPSEC_SA_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_sa_v2_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 sa_id;
} vl_api_ipsec_sa_v2_dump_t;
#define VL_API_IPSEC_SA_V2_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_sa_v3_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 sa_id;
} vl_api_ipsec_sa_v3_dump_t;
#define VL_API_IPSEC_SA_V3_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_sa_v4_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 sa_id;
} vl_api_ipsec_sa_v4_dump_t;
#define VL_API_IPSEC_SA_V4_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_sa_v5_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 sa_id;
} vl_api_ipsec_sa_v5_dump_t;
#define VL_API_IPSEC_SA_V5_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_sa_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_ipsec_sad_entry_t entry;
    vl_api_interface_index_t sw_if_index;
    u32 salt;
    u64 seq_outbound;
    u64 last_seq_inbound;
    u64 replay_window;
    u32 stat_index;
} vl_api_ipsec_sa_details_t;
#define VL_API_IPSEC_SA_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_sa_v2_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_ipsec_sad_entry_v2_t entry;
    vl_api_interface_index_t sw_if_index;
    u32 salt;
    u64 seq_outbound;
    u64 last_seq_inbound;
    u64 replay_window;
    u32 stat_index;
} vl_api_ipsec_sa_v2_details_t;
#define VL_API_IPSEC_SA_V2_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_sa_v3_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_ipsec_sad_entry_v3_t entry;
    vl_api_interface_index_t sw_if_index;
    u64 seq_outbound;
    u64 last_seq_inbound;
    u64 replay_window;
    u32 stat_index;
} vl_api_ipsec_sa_v3_details_t;
#define VL_API_IPSEC_SA_V3_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_sa_v4_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_ipsec_sad_entry_v3_t entry;
    vl_api_interface_index_t sw_if_index;
    u64 seq_outbound;
    u64 last_seq_inbound;
    u64 replay_window;
    u32 thread_index;
    u32 stat_index;
} vl_api_ipsec_sa_v4_details_t;
#define VL_API_IPSEC_SA_V4_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_sa_v5_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_ipsec_sad_entry_v4_t entry;
    vl_api_interface_index_t sw_if_index;
    u64 seq_outbound;
    u64 last_seq_inbound;
    u64 replay_window;
    u32 thread_index;
    u32 stat_index;
} vl_api_ipsec_sa_v5_details_t;
#define VL_API_IPSEC_SA_V5_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_backend_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_ipsec_backend_dump_t;
#define VL_API_IPSEC_BACKEND_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_backend_details {
    u16 _vl_msg_id;
    u32 context;
    u8 name[128];
    vl_api_ipsec_proto_t protocol;
    u8 index;
    bool active;
} vl_api_ipsec_backend_details_t;
#define VL_API_IPSEC_BACKEND_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_select_backend {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_ipsec_proto_t protocol;
    u8 index;
} vl_api_ipsec_select_backend_t;
#define VL_API_IPSEC_SELECT_BACKEND_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_select_backend_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_ipsec_select_backend_reply_t;
#define VL_API_IPSEC_SELECT_BACKEND_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_set_async_mode {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool async_enable;
} vl_api_ipsec_set_async_mode_t;
#define VL_API_IPSEC_SET_ASYNC_MODE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_set_async_mode_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_ipsec_set_async_mode_reply_t;
#define VL_API_IPSEC_SET_ASYNC_MODE_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_IPSEC_SPD_ADD_DEL_CRC "ipsec_spd_add_del_20e89a95"
#define VL_API_IPSEC_SPD_ADD_DEL_REPLY_CRC "ipsec_spd_add_del_reply_e8d4e804"
#define VL_API_IPSEC_INTERFACE_ADD_DEL_SPD_CRC "ipsec_interface_add_del_spd_80f80cbb"
#define VL_API_IPSEC_INTERFACE_ADD_DEL_SPD_REPLY_CRC "ipsec_interface_add_del_spd_reply_e8d4e804"
#define VL_API_IPSEC_SPD_ENTRY_ADD_DEL_CRC "ipsec_spd_entry_add_del_338b7411"
#define VL_API_IPSEC_SPD_ENTRY_ADD_DEL_V2_CRC "ipsec_spd_entry_add_del_v2_7bfe69fc"
#define VL_API_IPSEC_SPD_ENTRY_ADD_DEL_REPLY_CRC "ipsec_spd_entry_add_del_reply_9ffac24b"
#define VL_API_IPSEC_SPD_ENTRY_ADD_DEL_V2_REPLY_CRC "ipsec_spd_entry_add_del_v2_reply_9ffac24b"
#define VL_API_IPSEC_SPDS_DUMP_CRC "ipsec_spds_dump_51077d14"
#define VL_API_IPSEC_SPDS_DETAILS_CRC "ipsec_spds_details_a04bb254"
#define VL_API_IPSEC_SPD_DUMP_CRC "ipsec_spd_dump_afefbf7d"
#define VL_API_IPSEC_SPD_DETAILS_CRC "ipsec_spd_details_5813d7a2"
#define VL_API_IPSEC_SAD_ENTRY_ADD_DEL_CRC "ipsec_sad_entry_add_del_ab64b5c6"
#define VL_API_IPSEC_SAD_ENTRY_ADD_DEL_V2_CRC "ipsec_sad_entry_add_del_v2_aca78b27"
#define VL_API_IPSEC_SAD_ENTRY_ADD_DEL_V3_CRC "ipsec_sad_entry_add_del_v3_c77ebd92"
#define VL_API_IPSEC_SAD_ENTRY_ADD_CRC "ipsec_sad_entry_add_50229353"
#define VL_API_IPSEC_SAD_ENTRY_ADD_V2_CRC "ipsec_sad_entry_add_v2_9611297a"
#define VL_API_IPSEC_SAD_ENTRY_DEL_CRC "ipsec_sad_entry_del_3a91bde5"
#define VL_API_IPSEC_SAD_ENTRY_DEL_REPLY_CRC "ipsec_sad_entry_del_reply_e8d4e804"
#define VL_API_IPSEC_SAD_BIND_CRC "ipsec_sad_bind_0649c0d9"
#define VL_API_IPSEC_SAD_BIND_REPLY_CRC "ipsec_sad_bind_reply_e8d4e804"
#define VL_API_IPSEC_SAD_UNBIND_CRC "ipsec_sad_unbind_2076c2f4"
#define VL_API_IPSEC_SAD_UNBIND_REPLY_CRC "ipsec_sad_unbind_reply_e8d4e804"
#define VL_API_IPSEC_SAD_ENTRY_UPDATE_CRC "ipsec_sad_entry_update_1412af86"
#define VL_API_IPSEC_SAD_ENTRY_UPDATE_REPLY_CRC "ipsec_sad_entry_update_reply_e8d4e804"
#define VL_API_IPSEC_SAD_ENTRY_ADD_DEL_REPLY_CRC "ipsec_sad_entry_add_del_reply_9ffac24b"
#define VL_API_IPSEC_SAD_ENTRY_ADD_DEL_V2_REPLY_CRC "ipsec_sad_entry_add_del_v2_reply_9ffac24b"
#define VL_API_IPSEC_SAD_ENTRY_ADD_DEL_V3_REPLY_CRC "ipsec_sad_entry_add_del_v3_reply_9ffac24b"
#define VL_API_IPSEC_SAD_ENTRY_ADD_REPLY_CRC "ipsec_sad_entry_add_reply_9ffac24b"
#define VL_API_IPSEC_SAD_ENTRY_ADD_V2_REPLY_CRC "ipsec_sad_entry_add_v2_reply_9ffac24b"
#define VL_API_IPSEC_TUNNEL_PROTECT_UPDATE_CRC "ipsec_tunnel_protect_update_30d5f133"
#define VL_API_IPSEC_TUNNEL_PROTECT_UPDATE_REPLY_CRC "ipsec_tunnel_protect_update_reply_e8d4e804"
#define VL_API_IPSEC_TUNNEL_PROTECT_DEL_CRC "ipsec_tunnel_protect_del_cd239930"
#define VL_API_IPSEC_TUNNEL_PROTECT_DEL_REPLY_CRC "ipsec_tunnel_protect_del_reply_e8d4e804"
#define VL_API_IPSEC_TUNNEL_PROTECT_DUMP_CRC "ipsec_tunnel_protect_dump_f9e6675e"
#define VL_API_IPSEC_TUNNEL_PROTECT_DETAILS_CRC "ipsec_tunnel_protect_details_21663a50"
#define VL_API_IPSEC_SPD_INTERFACE_DUMP_CRC "ipsec_spd_interface_dump_8971de19"
#define VL_API_IPSEC_SPD_INTERFACE_DETAILS_CRC "ipsec_spd_interface_details_7a0bcf3e"
#define VL_API_IPSEC_ITF_CREATE_CRC "ipsec_itf_create_6f50b3bc"
#define VL_API_IPSEC_ITF_CREATE_REPLY_CRC "ipsec_itf_create_reply_5383d31f"
#define VL_API_IPSEC_ITF_DELETE_CRC "ipsec_itf_delete_f9e6675e"
#define VL_API_IPSEC_ITF_DELETE_REPLY_CRC "ipsec_itf_delete_reply_e8d4e804"
#define VL_API_IPSEC_ITF_DUMP_CRC "ipsec_itf_dump_f9e6675e"
#define VL_API_IPSEC_ITF_DETAILS_CRC "ipsec_itf_details_548a73b8"
#define VL_API_IPSEC_SA_DUMP_CRC "ipsec_sa_dump_2076c2f4"
#define VL_API_IPSEC_SA_V2_DUMP_CRC "ipsec_sa_v2_dump_2076c2f4"
#define VL_API_IPSEC_SA_V3_DUMP_CRC "ipsec_sa_v3_dump_2076c2f4"
#define VL_API_IPSEC_SA_V4_DUMP_CRC "ipsec_sa_v4_dump_2076c2f4"
#define VL_API_IPSEC_SA_V5_DUMP_CRC "ipsec_sa_v5_dump_2076c2f4"
#define VL_API_IPSEC_SA_DETAILS_CRC "ipsec_sa_details_345d14a7"
#define VL_API_IPSEC_SA_V2_DETAILS_CRC "ipsec_sa_v2_details_e2130051"
#define VL_API_IPSEC_SA_V3_DETAILS_CRC "ipsec_sa_v3_details_2fc991ee"
#define VL_API_IPSEC_SA_V4_DETAILS_CRC "ipsec_sa_v4_details_87a322d7"
#define VL_API_IPSEC_SA_V5_DETAILS_CRC "ipsec_sa_v5_details_3cfecfbd"
#define VL_API_IPSEC_BACKEND_DUMP_CRC "ipsec_backend_dump_51077d14"
#define VL_API_IPSEC_BACKEND_DETAILS_CRC "ipsec_backend_details_ee601c29"
#define VL_API_IPSEC_SELECT_BACKEND_CRC "ipsec_select_backend_5bcfd3b7"
#define VL_API_IPSEC_SELECT_BACKEND_REPLY_CRC "ipsec_select_backend_reply_e8d4e804"
#define VL_API_IPSEC_SET_ASYNC_MODE_CRC "ipsec_set_async_mode_a6465f7c"
#define VL_API_IPSEC_SET_ASYNC_MODE_REPLY_CRC "ipsec_set_async_mode_reply_e8d4e804"

#endif
