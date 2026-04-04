/*
 * VLIB API definitions 2026-04-04 08:31:59
 * Input file: af_packet.api
 * Automatically generated: please edit the input file NOT this file!
 */

#include <stdbool.h>
#if defined(vl_msg_id)||defined(vl_union_id) \
    || defined(vl_printfun) ||defined(vl_endianfun) \
    || defined(vl_api_version)||defined(vl_typedefs) \
    || defined(vl_msg_name)||defined(vl_msg_name_crc_list) \
    || defined(vl_api_version_tuple) || defined(vl_calcsizefun)
/* ok, something was selected */
#else
#warning no content included from af_packet.api
#endif

#define VL_API_PACKED(x) x __attribute__ ((packed))

/*
 * Note: VL_API_MAX_ARRAY_SIZE is set to an arbitrarily large limit.
 *
 * However, any message with a ~2 billion element array is likely to break the
 * api handling long before this limit causes array element endian issues.
 *
 * Applications should be written to create reasonable api messages.
 */
#define VL_API_MAX_ARRAY_SIZE 0x7fffffff

/* Imported API files */
#ifndef vl_api_version
#include <vnet/interface_types.api.h>
#include <vnet/ethernet/ethernet_types.api.h>
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_AF_PACKET_CREATE, vl_api_af_packet_create_t_handler)
vl_msg_id(VL_API_AF_PACKET_CREATE_REPLY, vl_api_af_packet_create_reply_t_handler)
vl_msg_id(VL_API_AF_PACKET_CREATE_V2, vl_api_af_packet_create_v2_t_handler)
vl_msg_id(VL_API_AF_PACKET_CREATE_V2_REPLY, vl_api_af_packet_create_v2_reply_t_handler)
vl_msg_id(VL_API_AF_PACKET_CREATE_V3, vl_api_af_packet_create_v3_t_handler)
vl_msg_id(VL_API_AF_PACKET_CREATE_V3_REPLY, vl_api_af_packet_create_v3_reply_t_handler)
vl_msg_id(VL_API_AF_PACKET_DELETE, vl_api_af_packet_delete_t_handler)
vl_msg_id(VL_API_AF_PACKET_DELETE_REPLY, vl_api_af_packet_delete_reply_t_handler)
vl_msg_id(VL_API_AF_PACKET_SET_L4_CKSUM_OFFLOAD, vl_api_af_packet_set_l4_cksum_offload_t_handler)
vl_msg_id(VL_API_AF_PACKET_SET_L4_CKSUM_OFFLOAD_REPLY, vl_api_af_packet_set_l4_cksum_offload_reply_t_handler)
vl_msg_id(VL_API_AF_PACKET_DUMP, vl_api_af_packet_dump_t_handler)
vl_msg_id(VL_API_AF_PACKET_DETAILS, vl_api_af_packet_details_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_af_packet_create_t, 1)
vl_msg_name(vl_api_af_packet_create_reply_t, 1)
vl_msg_name(vl_api_af_packet_create_v2_t, 1)
vl_msg_name(vl_api_af_packet_create_v2_reply_t, 1)
vl_msg_name(vl_api_af_packet_create_v3_t, 1)
vl_msg_name(vl_api_af_packet_create_v3_reply_t, 1)
vl_msg_name(vl_api_af_packet_delete_t, 1)
vl_msg_name(vl_api_af_packet_delete_reply_t, 1)
vl_msg_name(vl_api_af_packet_set_l4_cksum_offload_t, 1)
vl_msg_name(vl_api_af_packet_set_l4_cksum_offload_reply_t, 1)
vl_msg_name(vl_api_af_packet_dump_t, 1)
vl_msg_name(vl_api_af_packet_details_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_af_packet \
_(VL_API_AF_PACKET_CREATE, af_packet_create, a190415f) \
_(VL_API_AF_PACKET_CREATE_REPLY, af_packet_create_reply, 5383d31f) \
_(VL_API_AF_PACKET_CREATE_V2, af_packet_create_v2, 4aff0436) \
_(VL_API_AF_PACKET_CREATE_V2_REPLY, af_packet_create_v2_reply, 5383d31f) \
_(VL_API_AF_PACKET_CREATE_V3, af_packet_create_v3, b3a809d4) \
_(VL_API_AF_PACKET_CREATE_V3_REPLY, af_packet_create_v3_reply, 5383d31f) \
_(VL_API_AF_PACKET_DELETE, af_packet_delete, 863fa648) \
_(VL_API_AF_PACKET_DELETE_REPLY, af_packet_delete_reply, e8d4e804) \
_(VL_API_AF_PACKET_SET_L4_CKSUM_OFFLOAD, af_packet_set_l4_cksum_offload, 319cd5c8) \
_(VL_API_AF_PACKET_SET_L4_CKSUM_OFFLOAD_REPLY, af_packet_set_l4_cksum_offload_reply, e8d4e804) \
_(VL_API_AF_PACKET_DUMP, af_packet_dump, 51077d14) \
_(VL_API_AF_PACKET_DETAILS, af_packet_details, 58c7c042) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "af_packet.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_af_packet_printfun_types
#define included_af_packet_printfun_types

static inline u8 *format_vl_api_af_packet_mode_t (u8 *s, va_list * args)
{
    vl_api_af_packet_mode_t *a = va_arg (*args, vl_api_af_packet_mode_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 1:
        return format(s, "AF_PACKET_API_MODE_ETHERNET");
    case 2:
        return format(s, "AF_PACKET_API_MODE_IP");
    }
    return s;
}

static inline u8 *format_vl_api_af_packet_flags_t (u8 *s, va_list * args)
{
    vl_api_af_packet_flags_t *a = va_arg (*args, vl_api_af_packet_flags_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 1:
        return format(s, "AF_PACKET_API_FLAG_QDISC_BYPASS");
    case 2:
        return format(s, "AF_PACKET_API_FLAG_CKSUM_GSO");
    case 8:
        return format(s, "AF_PACKET_API_FLAG_VERSION_2");
    }
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_af_packet_printfun
#define included_af_packet_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "af_packet.api_tojson.h"
#include "af_packet.api_fromjson.h"

static inline u8 *vl_api_af_packet_create_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_af_packet_create_t *a = va_arg (*args, vl_api_af_packet_create_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_af_packet_create_t: */
    s = format(s, "vl_api_af_packet_create_t:");
    s = format(s, "\n%Uhw_addr: %U", format_white_space, indent, format_vl_api_mac_address_t, &a->hw_addr, indent);
    s = format(s, "\n%Uuse_random_hw_addr: %u", format_white_space, indent, a->use_random_hw_addr);
    s = format(s, "\n%Uhost_if_name: %s", format_white_space, indent, a->host_if_name);
    return s;
}

static inline u8 *vl_api_af_packet_create_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_af_packet_create_reply_t *a = va_arg (*args, vl_api_af_packet_create_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_af_packet_create_reply_t: */
    s = format(s, "vl_api_af_packet_create_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_af_packet_create_v2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_af_packet_create_v2_t *a = va_arg (*args, vl_api_af_packet_create_v2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_af_packet_create_v2_t: */
    s = format(s, "vl_api_af_packet_create_v2_t:");
    s = format(s, "\n%Uhw_addr: %U", format_white_space, indent, format_vl_api_mac_address_t, &a->hw_addr, indent);
    s = format(s, "\n%Uuse_random_hw_addr: %u", format_white_space, indent, a->use_random_hw_addr);
    s = format(s, "\n%Uhost_if_name: %s", format_white_space, indent, a->host_if_name);
    s = format(s, "\n%Urx_frame_size: %u", format_white_space, indent, a->rx_frame_size);
    s = format(s, "\n%Utx_frame_size: %u", format_white_space, indent, a->tx_frame_size);
    s = format(s, "\n%Urx_frames_per_block: %u", format_white_space, indent, a->rx_frames_per_block);
    s = format(s, "\n%Utx_frames_per_block: %u", format_white_space, indent, a->tx_frames_per_block);
    s = format(s, "\n%Uflags: %u", format_white_space, indent, a->flags);
    s = format(s, "\n%Unum_rx_queues: %u", format_white_space, indent, a->num_rx_queues);
    return s;
}

static inline u8 *vl_api_af_packet_create_v2_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_af_packet_create_v2_reply_t *a = va_arg (*args, vl_api_af_packet_create_v2_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_af_packet_create_v2_reply_t: */
    s = format(s, "vl_api_af_packet_create_v2_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_af_packet_create_v3_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_af_packet_create_v3_t *a = va_arg (*args, vl_api_af_packet_create_v3_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_af_packet_create_v3_t: */
    s = format(s, "vl_api_af_packet_create_v3_t:");
    s = format(s, "\n%Umode: %U", format_white_space, indent, format_vl_api_af_packet_mode_t, &a->mode, indent);
    s = format(s, "\n%Uhw_addr: %U", format_white_space, indent, format_vl_api_mac_address_t, &a->hw_addr, indent);
    s = format(s, "\n%Uuse_random_hw_addr: %u", format_white_space, indent, a->use_random_hw_addr);
    s = format(s, "\n%Uhost_if_name: %s", format_white_space, indent, a->host_if_name);
    s = format(s, "\n%Urx_frame_size: %u", format_white_space, indent, a->rx_frame_size);
    s = format(s, "\n%Utx_frame_size: %u", format_white_space, indent, a->tx_frame_size);
    s = format(s, "\n%Urx_frames_per_block: %u", format_white_space, indent, a->rx_frames_per_block);
    s = format(s, "\n%Utx_frames_per_block: %u", format_white_space, indent, a->tx_frames_per_block);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_af_packet_flags_t, &a->flags, indent);
    s = format(s, "\n%Unum_rx_queues: %u", format_white_space, indent, a->num_rx_queues);
    s = format(s, "\n%Unum_tx_queues: %u", format_white_space, indent, a->num_tx_queues);
    return s;
}

static inline u8 *vl_api_af_packet_create_v3_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_af_packet_create_v3_reply_t *a = va_arg (*args, vl_api_af_packet_create_v3_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_af_packet_create_v3_reply_t: */
    s = format(s, "vl_api_af_packet_create_v3_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_af_packet_delete_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_af_packet_delete_t *a = va_arg (*args, vl_api_af_packet_delete_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_af_packet_delete_t: */
    s = format(s, "vl_api_af_packet_delete_t:");
    s = format(s, "\n%Uhost_if_name: %s", format_white_space, indent, a->host_if_name);
    return s;
}

static inline u8 *vl_api_af_packet_delete_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_af_packet_delete_reply_t *a = va_arg (*args, vl_api_af_packet_delete_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_af_packet_delete_reply_t: */
    s = format(s, "vl_api_af_packet_delete_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_af_packet_set_l4_cksum_offload_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_af_packet_set_l4_cksum_offload_t *a = va_arg (*args, vl_api_af_packet_set_l4_cksum_offload_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_af_packet_set_l4_cksum_offload_t: */
    s = format(s, "vl_api_af_packet_set_l4_cksum_offload_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uset: %u", format_white_space, indent, a->set);
    return s;
}

static inline u8 *vl_api_af_packet_set_l4_cksum_offload_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_af_packet_set_l4_cksum_offload_reply_t *a = va_arg (*args, vl_api_af_packet_set_l4_cksum_offload_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_af_packet_set_l4_cksum_offload_reply_t: */
    s = format(s, "vl_api_af_packet_set_l4_cksum_offload_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_af_packet_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_af_packet_dump_t *a = va_arg (*args, vl_api_af_packet_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_af_packet_dump_t: */
    s = format(s, "vl_api_af_packet_dump_t:");
    return s;
}

static inline u8 *vl_api_af_packet_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_af_packet_details_t *a = va_arg (*args, vl_api_af_packet_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_af_packet_details_t: */
    s = format(s, "vl_api_af_packet_details_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uhost_if_name: %s", format_white_space, indent, a->host_if_name);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_af_packet_endianfun
#define included_af_packet_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_af_packet_mode_t_endian (vl_api_af_packet_mode_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_af_packet_flags_t_endian (vl_api_af_packet_flags_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_af_packet_create_t_endian (vl_api_af_packet_create_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_mac_address_t_endian(&a->hw_addr, to_net);
    /* a->use_random_hw_addr = a->use_random_hw_addr (no-op) */
    /* a->host_if_name = a->host_if_name (no-op) */
}

static inline void vl_api_af_packet_create_reply_t_endian (vl_api_af_packet_create_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_af_packet_create_v2_t_endian (vl_api_af_packet_create_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_mac_address_t_endian(&a->hw_addr, to_net);
    /* a->use_random_hw_addr = a->use_random_hw_addr (no-op) */
    /* a->host_if_name = a->host_if_name (no-op) */
    a->rx_frame_size = clib_net_to_host_u32(a->rx_frame_size);
    a->tx_frame_size = clib_net_to_host_u32(a->tx_frame_size);
    a->rx_frames_per_block = clib_net_to_host_u32(a->rx_frames_per_block);
    a->tx_frames_per_block = clib_net_to_host_u32(a->tx_frames_per_block);
    a->flags = clib_net_to_host_u32(a->flags);
    a->num_rx_queues = clib_net_to_host_u16(a->num_rx_queues);
}

static inline void vl_api_af_packet_create_v2_reply_t_endian (vl_api_af_packet_create_v2_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_af_packet_create_v3_t_endian (vl_api_af_packet_create_v3_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_af_packet_mode_t_endian(&a->mode, to_net);
    vl_api_mac_address_t_endian(&a->hw_addr, to_net);
    /* a->use_random_hw_addr = a->use_random_hw_addr (no-op) */
    /* a->host_if_name = a->host_if_name (no-op) */
    a->rx_frame_size = clib_net_to_host_u32(a->rx_frame_size);
    a->tx_frame_size = clib_net_to_host_u32(a->tx_frame_size);
    a->rx_frames_per_block = clib_net_to_host_u32(a->rx_frames_per_block);
    a->tx_frames_per_block = clib_net_to_host_u32(a->tx_frames_per_block);
    vl_api_af_packet_flags_t_endian(&a->flags, to_net);
    a->num_rx_queues = clib_net_to_host_u16(a->num_rx_queues);
    a->num_tx_queues = clib_net_to_host_u16(a->num_tx_queues);
}

static inline void vl_api_af_packet_create_v3_reply_t_endian (vl_api_af_packet_create_v3_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_af_packet_delete_t_endian (vl_api_af_packet_delete_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->host_if_name = a->host_if_name (no-op) */
}

static inline void vl_api_af_packet_delete_reply_t_endian (vl_api_af_packet_delete_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_af_packet_set_l4_cksum_offload_t_endian (vl_api_af_packet_set_l4_cksum_offload_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->set = a->set (no-op) */
}

static inline void vl_api_af_packet_set_l4_cksum_offload_reply_t_endian (vl_api_af_packet_set_l4_cksum_offload_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_af_packet_dump_t_endian (vl_api_af_packet_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_af_packet_details_t_endian (vl_api_af_packet_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->host_if_name = a->host_if_name (no-op) */
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_af_packet_calcsizefun
#define included_af_packet_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_af_packet_mode_t_calc_size (vl_api_af_packet_mode_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_af_packet_flags_t_calc_size (vl_api_af_packet_flags_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_af_packet_create_t_calc_size (vl_api_af_packet_create_t *a)
{
      return sizeof(*a) - sizeof(a->hw_addr) + vl_api_mac_address_t_calc_size(&a->hw_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_af_packet_create_reply_t_calc_size (vl_api_af_packet_create_reply_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_af_packet_create_v2_t_calc_size (vl_api_af_packet_create_v2_t *a)
{
      return sizeof(*a) - sizeof(a->hw_addr) + vl_api_mac_address_t_calc_size(&a->hw_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_af_packet_create_v2_reply_t_calc_size (vl_api_af_packet_create_v2_reply_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_af_packet_create_v3_t_calc_size (vl_api_af_packet_create_v3_t *a)
{
      return sizeof(*a) - sizeof(a->mode) + vl_api_af_packet_mode_t_calc_size(&a->mode) - sizeof(a->hw_addr) + vl_api_mac_address_t_calc_size(&a->hw_addr) - sizeof(a->flags) + vl_api_af_packet_flags_t_calc_size(&a->flags);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_af_packet_create_v3_reply_t_calc_size (vl_api_af_packet_create_v3_reply_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_af_packet_delete_t_calc_size (vl_api_af_packet_delete_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_af_packet_delete_reply_t_calc_size (vl_api_af_packet_delete_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_af_packet_set_l4_cksum_offload_t_calc_size (vl_api_af_packet_set_l4_cksum_offload_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_af_packet_set_l4_cksum_offload_reply_t_calc_size (vl_api_af_packet_set_l4_cksum_offload_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_af_packet_dump_t_calc_size (vl_api_af_packet_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_af_packet_details_t_calc_size (vl_api_af_packet_details_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(af_packet.api, 2, 0, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(af_packet.api, 0x720ee900)

#endif

