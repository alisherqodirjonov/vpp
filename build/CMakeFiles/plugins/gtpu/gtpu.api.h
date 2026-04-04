/*
 * VLIB API definitions 2026-04-04 08:31:59
 * Input file: gtpu.api
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
#warning no content included from gtpu.api
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
#include <vnet/ip/ip_types.api.h>
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_GTPU_ADD_DEL_TUNNEL, vl_api_gtpu_add_del_tunnel_t_handler)
vl_msg_id(VL_API_GTPU_ADD_DEL_TUNNEL_REPLY, vl_api_gtpu_add_del_tunnel_reply_t_handler)
vl_msg_id(VL_API_GTPU_ADD_DEL_TUNNEL_V2, vl_api_gtpu_add_del_tunnel_v2_t_handler)
vl_msg_id(VL_API_GTPU_ADD_DEL_TUNNEL_V2_REPLY, vl_api_gtpu_add_del_tunnel_v2_reply_t_handler)
vl_msg_id(VL_API_GTPU_TUNNEL_UPDATE_TTEID, vl_api_gtpu_tunnel_update_tteid_t_handler)
vl_msg_id(VL_API_GTPU_TUNNEL_UPDATE_TTEID_REPLY, vl_api_gtpu_tunnel_update_tteid_reply_t_handler)
vl_msg_id(VL_API_GTPU_TUNNEL_DUMP, vl_api_gtpu_tunnel_dump_t_handler)
vl_msg_id(VL_API_GTPU_TUNNEL_DETAILS, vl_api_gtpu_tunnel_details_t_handler)
vl_msg_id(VL_API_GTPU_TUNNEL_V2_DUMP, vl_api_gtpu_tunnel_v2_dump_t_handler)
vl_msg_id(VL_API_GTPU_TUNNEL_V2_DETAILS, vl_api_gtpu_tunnel_v2_details_t_handler)
vl_msg_id(VL_API_SW_INTERFACE_SET_GTPU_BYPASS, vl_api_sw_interface_set_gtpu_bypass_t_handler)
vl_msg_id(VL_API_SW_INTERFACE_SET_GTPU_BYPASS_REPLY, vl_api_sw_interface_set_gtpu_bypass_reply_t_handler)
vl_msg_id(VL_API_GTPU_OFFLOAD_RX, vl_api_gtpu_offload_rx_t_handler)
vl_msg_id(VL_API_GTPU_OFFLOAD_RX_REPLY, vl_api_gtpu_offload_rx_reply_t_handler)
vl_msg_id(VL_API_GTPU_ADD_DEL_FORWARD, vl_api_gtpu_add_del_forward_t_handler)
vl_msg_id(VL_API_GTPU_ADD_DEL_FORWARD_REPLY, vl_api_gtpu_add_del_forward_reply_t_handler)
vl_msg_id(VL_API_GTPU_GET_TRANSFER_COUNTS, vl_api_gtpu_get_transfer_counts_t_handler)
vl_msg_id(VL_API_GTPU_GET_TRANSFER_COUNTS_REPLY, vl_api_gtpu_get_transfer_counts_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_gtpu_add_del_tunnel_t, 1)
vl_msg_name(vl_api_gtpu_add_del_tunnel_reply_t, 1)
vl_msg_name(vl_api_gtpu_add_del_tunnel_v2_t, 1)
vl_msg_name(vl_api_gtpu_add_del_tunnel_v2_reply_t, 1)
vl_msg_name(vl_api_gtpu_tunnel_update_tteid_t, 1)
vl_msg_name(vl_api_gtpu_tunnel_update_tteid_reply_t, 1)
vl_msg_name(vl_api_gtpu_tunnel_dump_t, 1)
vl_msg_name(vl_api_gtpu_tunnel_details_t, 1)
vl_msg_name(vl_api_gtpu_tunnel_v2_dump_t, 1)
vl_msg_name(vl_api_gtpu_tunnel_v2_details_t, 1)
vl_msg_name(vl_api_sw_interface_set_gtpu_bypass_t, 1)
vl_msg_name(vl_api_sw_interface_set_gtpu_bypass_reply_t, 1)
vl_msg_name(vl_api_gtpu_offload_rx_t, 1)
vl_msg_name(vl_api_gtpu_offload_rx_reply_t, 1)
vl_msg_name(vl_api_gtpu_add_del_forward_t, 1)
vl_msg_name(vl_api_gtpu_add_del_forward_reply_t, 1)
vl_msg_name(vl_api_gtpu_get_transfer_counts_t, 1)
vl_msg_name(vl_api_gtpu_get_transfer_counts_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_gtpu \
_(VL_API_GTPU_ADD_DEL_TUNNEL, gtpu_add_del_tunnel, ca983a2b) \
_(VL_API_GTPU_ADD_DEL_TUNNEL_REPLY, gtpu_add_del_tunnel_reply, 5383d31f) \
_(VL_API_GTPU_ADD_DEL_TUNNEL_V2, gtpu_add_del_tunnel_v2, a0c30713) \
_(VL_API_GTPU_ADD_DEL_TUNNEL_V2_REPLY, gtpu_add_del_tunnel_v2_reply, 62b41304) \
_(VL_API_GTPU_TUNNEL_UPDATE_TTEID, gtpu_tunnel_update_tteid, 79f33816) \
_(VL_API_GTPU_TUNNEL_UPDATE_TTEID_REPLY, gtpu_tunnel_update_tteid_reply, e8d4e804) \
_(VL_API_GTPU_TUNNEL_DUMP, gtpu_tunnel_dump, f9e6675e) \
_(VL_API_GTPU_TUNNEL_DETAILS, gtpu_tunnel_details, 27f434ae) \
_(VL_API_GTPU_TUNNEL_V2_DUMP, gtpu_tunnel_v2_dump, f9e6675e) \
_(VL_API_GTPU_TUNNEL_V2_DETAILS, gtpu_tunnel_v2_details, 8bf4ba92) \
_(VL_API_SW_INTERFACE_SET_GTPU_BYPASS, sw_interface_set_gtpu_bypass, 65247409) \
_(VL_API_SW_INTERFACE_SET_GTPU_BYPASS_REPLY, sw_interface_set_gtpu_bypass_reply, e8d4e804) \
_(VL_API_GTPU_OFFLOAD_RX, gtpu_offload_rx, f0b08786) \
_(VL_API_GTPU_OFFLOAD_RX_REPLY, gtpu_offload_rx_reply, e8d4e804) \
_(VL_API_GTPU_ADD_DEL_FORWARD, gtpu_add_del_forward, c6ccce13) \
_(VL_API_GTPU_ADD_DEL_FORWARD_REPLY, gtpu_add_del_forward_reply, 5383d31f) \
_(VL_API_GTPU_GET_TRANSFER_COUNTS, gtpu_get_transfer_counts, 61410788) \
_(VL_API_GTPU_GET_TRANSFER_COUNTS_REPLY, gtpu_get_transfer_counts_reply, e35f04bc) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "gtpu.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_gtpu_printfun_types
#define included_gtpu_printfun_types

static inline u8 *format_vl_api_gtpu_forwarding_type_t (u8 *s, va_list * args)
{
    vl_api_gtpu_forwarding_type_t *a = va_arg (*args, vl_api_gtpu_forwarding_type_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "GTPU_API_FORWARDING_NONE");
    case 1:
        return format(s, "GTPU_API_FORWARDING_BAD_HEADER");
    case 2:
        return format(s, "GTPU_API_FORWARDING_UNKNOWN_TEID");
    case 4:
        return format(s, "GTPU_API_FORWARDING_UNKNOWN_TYPE");
    }
    return s;
}

static inline u8 *format_vl_api_gtpu_decap_next_type_t (u8 *s, va_list * args)
{
    vl_api_gtpu_decap_next_type_t *a = va_arg (*args, vl_api_gtpu_decap_next_type_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "GTPU_API_DECAP_NEXT_DROP");
    case 1:
        return format(s, "GTPU_API_DECAP_NEXT_L2");
    case 2:
        return format(s, "GTPU_API_DECAP_NEXT_IP4");
    case 3:
        return format(s, "GTPU_API_DECAP_NEXT_IP6");
    }
    return s;
}

static inline u8 *format_vl_api_sw_if_counters_t (u8 *s, va_list * args)
{
    vl_api_sw_if_counters_t *a = va_arg (*args, vl_api_sw_if_counters_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Upackets_rx: %llu", format_white_space, indent, a->packets_rx);
    s = format(s, "\n%Upackets_tx: %llu", format_white_space, indent, a->packets_tx);
    s = format(s, "\n%Ubytes_rx: %llu", format_white_space, indent, a->bytes_rx);
    s = format(s, "\n%Ubytes_tx: %llu", format_white_space, indent, a->bytes_tx);
    return s;
}

static inline u8 *format_vl_api_tunnel_metrics_t (u8 *s, va_list * args)
{
    vl_api_tunnel_metrics_t *a = va_arg (*args, vl_api_tunnel_metrics_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Ureserved: %u", format_white_space, indent, a->reserved);
    s = format(s, "\n%Ucounters: %U", format_white_space, indent, format_vl_api_sw_if_counters_t, &a->counters, indent);
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_gtpu_printfun
#define included_gtpu_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "gtpu.api_tojson.h"
#include "gtpu.api_fromjson.h"

static inline u8 *vl_api_gtpu_add_del_tunnel_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_gtpu_add_del_tunnel_t *a = va_arg (*args, vl_api_gtpu_add_del_tunnel_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_gtpu_add_del_tunnel_t: */
    s = format(s, "vl_api_gtpu_add_del_tunnel_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Usrc_address: %U", format_white_space, indent, format_vl_api_address_t, &a->src_address, indent);
    s = format(s, "\n%Udst_address: %U", format_white_space, indent, format_vl_api_address_t, &a->dst_address, indent);
    s = format(s, "\n%Umcast_sw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->mcast_sw_if_index, indent);
    s = format(s, "\n%Uencap_vrf_id: %u", format_white_space, indent, a->encap_vrf_id);
    s = format(s, "\n%Udecap_next_index: %u", format_white_space, indent, a->decap_next_index);
    s = format(s, "\n%Uteid: %u", format_white_space, indent, a->teid);
    s = format(s, "\n%Utteid: %u", format_white_space, indent, a->tteid);
    return s;
}

static inline u8 *vl_api_gtpu_add_del_tunnel_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_gtpu_add_del_tunnel_reply_t *a = va_arg (*args, vl_api_gtpu_add_del_tunnel_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_gtpu_add_del_tunnel_reply_t: */
    s = format(s, "vl_api_gtpu_add_del_tunnel_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_gtpu_add_del_tunnel_v2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_gtpu_add_del_tunnel_v2_t *a = va_arg (*args, vl_api_gtpu_add_del_tunnel_v2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_gtpu_add_del_tunnel_v2_t: */
    s = format(s, "vl_api_gtpu_add_del_tunnel_v2_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Usrc_address: %U", format_white_space, indent, format_vl_api_address_t, &a->src_address, indent);
    s = format(s, "\n%Udst_address: %U", format_white_space, indent, format_vl_api_address_t, &a->dst_address, indent);
    s = format(s, "\n%Umcast_sw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->mcast_sw_if_index, indent);
    s = format(s, "\n%Uencap_vrf_id: %u", format_white_space, indent, a->encap_vrf_id);
    s = format(s, "\n%Udecap_next_index: %U", format_white_space, indent, format_vl_api_gtpu_decap_next_type_t, &a->decap_next_index, indent);
    s = format(s, "\n%Uteid: %u", format_white_space, indent, a->teid);
    s = format(s, "\n%Utteid: %u", format_white_space, indent, a->tteid);
    s = format(s, "\n%Updu_extension: %u", format_white_space, indent, a->pdu_extension);
    s = format(s, "\n%Uqfi: %u", format_white_space, indent, a->qfi);
    return s;
}

static inline u8 *vl_api_gtpu_add_del_tunnel_v2_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_gtpu_add_del_tunnel_v2_reply_t *a = va_arg (*args, vl_api_gtpu_add_del_tunnel_v2_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_gtpu_add_del_tunnel_v2_reply_t: */
    s = format(s, "vl_api_gtpu_add_del_tunnel_v2_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Ucounters: %U", format_white_space, indent, format_vl_api_sw_if_counters_t, &a->counters, indent);
    return s;
}

static inline u8 *vl_api_gtpu_tunnel_update_tteid_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_gtpu_tunnel_update_tteid_t *a = va_arg (*args, vl_api_gtpu_tunnel_update_tteid_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_gtpu_tunnel_update_tteid_t: */
    s = format(s, "vl_api_gtpu_tunnel_update_tteid_t:");
    s = format(s, "\n%Udst_address: %U", format_white_space, indent, format_vl_api_address_t, &a->dst_address, indent);
    s = format(s, "\n%Uencap_vrf_id: %u", format_white_space, indent, a->encap_vrf_id);
    s = format(s, "\n%Uteid: %u", format_white_space, indent, a->teid);
    s = format(s, "\n%Utteid: %u", format_white_space, indent, a->tteid);
    return s;
}

static inline u8 *vl_api_gtpu_tunnel_update_tteid_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_gtpu_tunnel_update_tteid_reply_t *a = va_arg (*args, vl_api_gtpu_tunnel_update_tteid_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_gtpu_tunnel_update_tteid_reply_t: */
    s = format(s, "vl_api_gtpu_tunnel_update_tteid_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_gtpu_tunnel_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_gtpu_tunnel_dump_t *a = va_arg (*args, vl_api_gtpu_tunnel_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_gtpu_tunnel_dump_t: */
    s = format(s, "vl_api_gtpu_tunnel_dump_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_gtpu_tunnel_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_gtpu_tunnel_details_t *a = va_arg (*args, vl_api_gtpu_tunnel_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_gtpu_tunnel_details_t: */
    s = format(s, "vl_api_gtpu_tunnel_details_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Usrc_address: %U", format_white_space, indent, format_vl_api_address_t, &a->src_address, indent);
    s = format(s, "\n%Udst_address: %U", format_white_space, indent, format_vl_api_address_t, &a->dst_address, indent);
    s = format(s, "\n%Umcast_sw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->mcast_sw_if_index, indent);
    s = format(s, "\n%Uencap_vrf_id: %u", format_white_space, indent, a->encap_vrf_id);
    s = format(s, "\n%Udecap_next_index: %u", format_white_space, indent, a->decap_next_index);
    s = format(s, "\n%Uteid: %u", format_white_space, indent, a->teid);
    s = format(s, "\n%Utteid: %u", format_white_space, indent, a->tteid);
    return s;
}

static inline u8 *vl_api_gtpu_tunnel_v2_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_gtpu_tunnel_v2_dump_t *a = va_arg (*args, vl_api_gtpu_tunnel_v2_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_gtpu_tunnel_v2_dump_t: */
    s = format(s, "vl_api_gtpu_tunnel_v2_dump_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_gtpu_tunnel_v2_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_gtpu_tunnel_v2_details_t *a = va_arg (*args, vl_api_gtpu_tunnel_v2_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_gtpu_tunnel_v2_details_t: */
    s = format(s, "vl_api_gtpu_tunnel_v2_details_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Usrc_address: %U", format_white_space, indent, format_vl_api_address_t, &a->src_address, indent);
    s = format(s, "\n%Udst_address: %U", format_white_space, indent, format_vl_api_address_t, &a->dst_address, indent);
    s = format(s, "\n%Umcast_sw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->mcast_sw_if_index, indent);
    s = format(s, "\n%Uencap_vrf_id: %u", format_white_space, indent, a->encap_vrf_id);
    s = format(s, "\n%Udecap_next_index: %U", format_white_space, indent, format_vl_api_gtpu_decap_next_type_t, &a->decap_next_index, indent);
    s = format(s, "\n%Uteid: %u", format_white_space, indent, a->teid);
    s = format(s, "\n%Utteid: %u", format_white_space, indent, a->tteid);
    s = format(s, "\n%Updu_extension: %u", format_white_space, indent, a->pdu_extension);
    s = format(s, "\n%Uqfi: %u", format_white_space, indent, a->qfi);
    s = format(s, "\n%Uis_forwarding: %u", format_white_space, indent, a->is_forwarding);
    s = format(s, "\n%Uforwarding_type: %U", format_white_space, indent, format_vl_api_gtpu_forwarding_type_t, &a->forwarding_type, indent);
    s = format(s, "\n%Ucounters: %U", format_white_space, indent, format_vl_api_sw_if_counters_t, &a->counters, indent);
    return s;
}

static inline u8 *vl_api_sw_interface_set_gtpu_bypass_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sw_interface_set_gtpu_bypass_t *a = va_arg (*args, vl_api_sw_interface_set_gtpu_bypass_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sw_interface_set_gtpu_bypass_t: */
    s = format(s, "vl_api_sw_interface_set_gtpu_bypass_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uis_ipv6: %u", format_white_space, indent, a->is_ipv6);
    s = format(s, "\n%Uenable: %u", format_white_space, indent, a->enable);
    return s;
}

static inline u8 *vl_api_sw_interface_set_gtpu_bypass_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sw_interface_set_gtpu_bypass_reply_t *a = va_arg (*args, vl_api_sw_interface_set_gtpu_bypass_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sw_interface_set_gtpu_bypass_reply_t: */
    s = format(s, "vl_api_sw_interface_set_gtpu_bypass_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_gtpu_offload_rx_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_gtpu_offload_rx_t *a = va_arg (*args, vl_api_gtpu_offload_rx_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_gtpu_offload_rx_t: */
    s = format(s, "vl_api_gtpu_offload_rx_t:");
    s = format(s, "\n%Uhw_if_index: %u", format_white_space, indent, a->hw_if_index);
    s = format(s, "\n%Usw_if_index: %u", format_white_space, indent, a->sw_if_index);
    s = format(s, "\n%Uenable: %u", format_white_space, indent, a->enable);
    return s;
}

static inline u8 *vl_api_gtpu_offload_rx_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_gtpu_offload_rx_reply_t *a = va_arg (*args, vl_api_gtpu_offload_rx_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_gtpu_offload_rx_reply_t: */
    s = format(s, "vl_api_gtpu_offload_rx_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_gtpu_add_del_forward_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_gtpu_add_del_forward_t *a = va_arg (*args, vl_api_gtpu_add_del_forward_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_gtpu_add_del_forward_t: */
    s = format(s, "vl_api_gtpu_add_del_forward_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Udst_address: %U", format_white_space, indent, format_vl_api_address_t, &a->dst_address, indent);
    s = format(s, "\n%Uforwarding_type: %U", format_white_space, indent, format_vl_api_gtpu_forwarding_type_t, &a->forwarding_type, indent);
    s = format(s, "\n%Uencap_vrf_id: %u", format_white_space, indent, a->encap_vrf_id);
    s = format(s, "\n%Udecap_next_index: %U", format_white_space, indent, format_vl_api_gtpu_decap_next_type_t, &a->decap_next_index, indent);
    return s;
}

static inline u8 *vl_api_gtpu_add_del_forward_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_gtpu_add_del_forward_reply_t *a = va_arg (*args, vl_api_gtpu_add_del_forward_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_gtpu_add_del_forward_reply_t: */
    s = format(s, "vl_api_gtpu_add_del_forward_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_gtpu_get_transfer_counts_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_gtpu_get_transfer_counts_t *a = va_arg (*args, vl_api_gtpu_get_transfer_counts_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_gtpu_get_transfer_counts_t: */
    s = format(s, "vl_api_gtpu_get_transfer_counts_t:");
    s = format(s, "\n%Usw_if_index_start: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index_start, indent);
    s = format(s, "\n%Ucapacity: %u", format_white_space, indent, a->capacity);
    return s;
}

static inline u8 *vl_api_gtpu_get_transfer_counts_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_gtpu_get_transfer_counts_reply_t *a = va_arg (*args, vl_api_gtpu_get_transfer_counts_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_gtpu_get_transfer_counts_reply_t: */
    s = format(s, "vl_api_gtpu_get_transfer_counts_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ucount: %u", format_white_space, indent, a->count);
    for (i = 0; i < a->count; i++) {
        s = format(s, "\n%Utunnels: %U",
                   format_white_space, indent, format_vl_api_tunnel_metrics_t, &a->tunnels[i], indent);
    }
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_gtpu_endianfun
#define included_gtpu_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_gtpu_forwarding_type_t_endian (vl_api_gtpu_forwarding_type_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_gtpu_decap_next_type_t_endian (vl_api_gtpu_decap_next_type_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_sw_if_counters_t_endian (vl_api_sw_if_counters_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->packets_rx = clib_net_to_host_u64(a->packets_rx);
    a->packets_tx = clib_net_to_host_u64(a->packets_tx);
    a->bytes_rx = clib_net_to_host_u64(a->bytes_rx);
    a->bytes_tx = clib_net_to_host_u64(a->bytes_tx);
}

static inline void vl_api_tunnel_metrics_t_endian (vl_api_tunnel_metrics_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    a->reserved = clib_net_to_host_u32(a->reserved);
    vl_api_sw_if_counters_t_endian(&a->counters, to_net);
}

static inline void vl_api_gtpu_add_del_tunnel_t_endian (vl_api_gtpu_add_del_tunnel_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_address_t_endian(&a->src_address, to_net);
    vl_api_address_t_endian(&a->dst_address, to_net);
    vl_api_interface_index_t_endian(&a->mcast_sw_if_index, to_net);
    a->encap_vrf_id = clib_net_to_host_u32(a->encap_vrf_id);
    a->decap_next_index = clib_net_to_host_u32(a->decap_next_index);
    a->teid = clib_net_to_host_u32(a->teid);
    a->tteid = clib_net_to_host_u32(a->tteid);
}

static inline void vl_api_gtpu_add_del_tunnel_reply_t_endian (vl_api_gtpu_add_del_tunnel_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_gtpu_add_del_tunnel_v2_t_endian (vl_api_gtpu_add_del_tunnel_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_address_t_endian(&a->src_address, to_net);
    vl_api_address_t_endian(&a->dst_address, to_net);
    vl_api_interface_index_t_endian(&a->mcast_sw_if_index, to_net);
    a->encap_vrf_id = clib_net_to_host_u32(a->encap_vrf_id);
    vl_api_gtpu_decap_next_type_t_endian(&a->decap_next_index, to_net);
    a->teid = clib_net_to_host_u32(a->teid);
    a->tteid = clib_net_to_host_u32(a->tteid);
    /* a->pdu_extension = a->pdu_extension (no-op) */
    /* a->qfi = a->qfi (no-op) */
}

static inline void vl_api_gtpu_add_del_tunnel_v2_reply_t_endian (vl_api_gtpu_add_del_tunnel_v2_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    vl_api_sw_if_counters_t_endian(&a->counters, to_net);
}

static inline void vl_api_gtpu_tunnel_update_tteid_t_endian (vl_api_gtpu_tunnel_update_tteid_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_address_t_endian(&a->dst_address, to_net);
    a->encap_vrf_id = clib_net_to_host_u32(a->encap_vrf_id);
    a->teid = clib_net_to_host_u32(a->teid);
    a->tteid = clib_net_to_host_u32(a->tteid);
}

static inline void vl_api_gtpu_tunnel_update_tteid_reply_t_endian (vl_api_gtpu_tunnel_update_tteid_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_gtpu_tunnel_dump_t_endian (vl_api_gtpu_tunnel_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_gtpu_tunnel_details_t_endian (vl_api_gtpu_tunnel_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    vl_api_address_t_endian(&a->src_address, to_net);
    vl_api_address_t_endian(&a->dst_address, to_net);
    vl_api_interface_index_t_endian(&a->mcast_sw_if_index, to_net);
    a->encap_vrf_id = clib_net_to_host_u32(a->encap_vrf_id);
    a->decap_next_index = clib_net_to_host_u32(a->decap_next_index);
    a->teid = clib_net_to_host_u32(a->teid);
    a->tteid = clib_net_to_host_u32(a->tteid);
}

static inline void vl_api_gtpu_tunnel_v2_dump_t_endian (vl_api_gtpu_tunnel_v2_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_gtpu_tunnel_v2_details_t_endian (vl_api_gtpu_tunnel_v2_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    vl_api_address_t_endian(&a->src_address, to_net);
    vl_api_address_t_endian(&a->dst_address, to_net);
    vl_api_interface_index_t_endian(&a->mcast_sw_if_index, to_net);
    a->encap_vrf_id = clib_net_to_host_u32(a->encap_vrf_id);
    vl_api_gtpu_decap_next_type_t_endian(&a->decap_next_index, to_net);
    a->teid = clib_net_to_host_u32(a->teid);
    a->tteid = clib_net_to_host_u32(a->tteid);
    /* a->pdu_extension = a->pdu_extension (no-op) */
    /* a->qfi = a->qfi (no-op) */
    /* a->is_forwarding = a->is_forwarding (no-op) */
    vl_api_gtpu_forwarding_type_t_endian(&a->forwarding_type, to_net);
    vl_api_sw_if_counters_t_endian(&a->counters, to_net);
}

static inline void vl_api_sw_interface_set_gtpu_bypass_t_endian (vl_api_sw_interface_set_gtpu_bypass_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->is_ipv6 = a->is_ipv6 (no-op) */
    /* a->enable = a->enable (no-op) */
}

static inline void vl_api_sw_interface_set_gtpu_bypass_reply_t_endian (vl_api_sw_interface_set_gtpu_bypass_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_gtpu_offload_rx_t_endian (vl_api_gtpu_offload_rx_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->hw_if_index = clib_net_to_host_u32(a->hw_if_index);
    a->sw_if_index = clib_net_to_host_u32(a->sw_if_index);
    /* a->enable = a->enable (no-op) */
}

static inline void vl_api_gtpu_offload_rx_reply_t_endian (vl_api_gtpu_offload_rx_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_gtpu_add_del_forward_t_endian (vl_api_gtpu_add_del_forward_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_address_t_endian(&a->dst_address, to_net);
    vl_api_gtpu_forwarding_type_t_endian(&a->forwarding_type, to_net);
    a->encap_vrf_id = clib_net_to_host_u32(a->encap_vrf_id);
    vl_api_gtpu_decap_next_type_t_endian(&a->decap_next_index, to_net);
}

static inline void vl_api_gtpu_add_del_forward_reply_t_endian (vl_api_gtpu_add_del_forward_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_gtpu_get_transfer_counts_t_endian (vl_api_gtpu_get_transfer_counts_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index_start, to_net);
    a->capacity = clib_net_to_host_u32(a->capacity);
}

static inline void vl_api_gtpu_get_transfer_counts_reply_t_endian (vl_api_gtpu_get_transfer_counts_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->count = clib_net_to_host_u32(a->count);
    u32 count = to_net ? clib_net_to_host_u32(a->count) : a->count;
    for (i = 0; i < count; i++) {
        vl_api_tunnel_metrics_t_endian(&a->tunnels[i], to_net);
    }
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_gtpu_calcsizefun
#define included_gtpu_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_gtpu_forwarding_type_t_calc_size (vl_api_gtpu_forwarding_type_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gtpu_decap_next_type_t_calc_size (vl_api_gtpu_decap_next_type_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sw_if_counters_t_calc_size (vl_api_sw_if_counters_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_tunnel_metrics_t_calc_size (vl_api_tunnel_metrics_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->counters) + vl_api_sw_if_counters_t_calc_size(&a->counters);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gtpu_add_del_tunnel_t_calc_size (vl_api_gtpu_add_del_tunnel_t *a)
{
      return sizeof(*a) - sizeof(a->src_address) + vl_api_address_t_calc_size(&a->src_address) - sizeof(a->dst_address) + vl_api_address_t_calc_size(&a->dst_address) - sizeof(a->mcast_sw_if_index) + vl_api_interface_index_t_calc_size(&a->mcast_sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gtpu_add_del_tunnel_reply_t_calc_size (vl_api_gtpu_add_del_tunnel_reply_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gtpu_add_del_tunnel_v2_t_calc_size (vl_api_gtpu_add_del_tunnel_v2_t *a)
{
      return sizeof(*a) - sizeof(a->src_address) + vl_api_address_t_calc_size(&a->src_address) - sizeof(a->dst_address) + vl_api_address_t_calc_size(&a->dst_address) - sizeof(a->mcast_sw_if_index) + vl_api_interface_index_t_calc_size(&a->mcast_sw_if_index) - sizeof(a->decap_next_index) + vl_api_gtpu_decap_next_type_t_calc_size(&a->decap_next_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gtpu_add_del_tunnel_v2_reply_t_calc_size (vl_api_gtpu_add_del_tunnel_v2_reply_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->counters) + vl_api_sw_if_counters_t_calc_size(&a->counters);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gtpu_tunnel_update_tteid_t_calc_size (vl_api_gtpu_tunnel_update_tteid_t *a)
{
      return sizeof(*a) - sizeof(a->dst_address) + vl_api_address_t_calc_size(&a->dst_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gtpu_tunnel_update_tteid_reply_t_calc_size (vl_api_gtpu_tunnel_update_tteid_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gtpu_tunnel_dump_t_calc_size (vl_api_gtpu_tunnel_dump_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gtpu_tunnel_details_t_calc_size (vl_api_gtpu_tunnel_details_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->src_address) + vl_api_address_t_calc_size(&a->src_address) - sizeof(a->dst_address) + vl_api_address_t_calc_size(&a->dst_address) - sizeof(a->mcast_sw_if_index) + vl_api_interface_index_t_calc_size(&a->mcast_sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gtpu_tunnel_v2_dump_t_calc_size (vl_api_gtpu_tunnel_v2_dump_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gtpu_tunnel_v2_details_t_calc_size (vl_api_gtpu_tunnel_v2_details_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->src_address) + vl_api_address_t_calc_size(&a->src_address) - sizeof(a->dst_address) + vl_api_address_t_calc_size(&a->dst_address) - sizeof(a->mcast_sw_if_index) + vl_api_interface_index_t_calc_size(&a->mcast_sw_if_index) - sizeof(a->decap_next_index) + vl_api_gtpu_decap_next_type_t_calc_size(&a->decap_next_index) - sizeof(a->forwarding_type) + vl_api_gtpu_forwarding_type_t_calc_size(&a->forwarding_type) - sizeof(a->counters) + vl_api_sw_if_counters_t_calc_size(&a->counters);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sw_interface_set_gtpu_bypass_t_calc_size (vl_api_sw_interface_set_gtpu_bypass_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sw_interface_set_gtpu_bypass_reply_t_calc_size (vl_api_sw_interface_set_gtpu_bypass_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gtpu_offload_rx_t_calc_size (vl_api_gtpu_offload_rx_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gtpu_offload_rx_reply_t_calc_size (vl_api_gtpu_offload_rx_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gtpu_add_del_forward_t_calc_size (vl_api_gtpu_add_del_forward_t *a)
{
      return sizeof(*a) - sizeof(a->dst_address) + vl_api_address_t_calc_size(&a->dst_address) - sizeof(a->forwarding_type) + vl_api_gtpu_forwarding_type_t_calc_size(&a->forwarding_type) - sizeof(a->decap_next_index) + vl_api_gtpu_decap_next_type_t_calc_size(&a->decap_next_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gtpu_add_del_forward_reply_t_calc_size (vl_api_gtpu_add_del_forward_reply_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gtpu_get_transfer_counts_t_calc_size (vl_api_gtpu_get_transfer_counts_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index_start) + vl_api_interface_index_t_calc_size(&a->sw_if_index_start);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gtpu_get_transfer_counts_reply_t_calc_size (vl_api_gtpu_get_transfer_counts_reply_t *a)
{
      return sizeof(*a) + clib_net_to_host_u32(a->count) * sizeof(a->tunnels[0]);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(gtpu.api, 2, 1, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(gtpu.api, 0xa3ac80d3)

#endif

