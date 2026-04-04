/*
 * VLIB API definitions 2026-04-04 08:31:58
 * Input file: sr.api
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
#warning no content included from sr.api
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
#include <vnet/srv6/sr_types.api.h>
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_SR_LOCALSID_ADD_DEL, vl_api_sr_localsid_add_del_t_handler)
vl_msg_id(VL_API_SR_LOCALSID_ADD_DEL_REPLY, vl_api_sr_localsid_add_del_reply_t_handler)
vl_msg_id(VL_API_SR_POLICY_ADD, vl_api_sr_policy_add_t_handler)
vl_msg_id(VL_API_SR_POLICY_ADD_REPLY, vl_api_sr_policy_add_reply_t_handler)
vl_msg_id(VL_API_SR_POLICY_MOD, vl_api_sr_policy_mod_t_handler)
vl_msg_id(VL_API_SR_POLICY_MOD_REPLY, vl_api_sr_policy_mod_reply_t_handler)
vl_msg_id(VL_API_SR_POLICY_ADD_V2, vl_api_sr_policy_add_v2_t_handler)
vl_msg_id(VL_API_SR_POLICY_ADD_V2_REPLY, vl_api_sr_policy_add_v2_reply_t_handler)
vl_msg_id(VL_API_SR_POLICY_MOD_V2, vl_api_sr_policy_mod_v2_t_handler)
vl_msg_id(VL_API_SR_POLICY_MOD_V2_REPLY, vl_api_sr_policy_mod_v2_reply_t_handler)
vl_msg_id(VL_API_SR_POLICY_DEL, vl_api_sr_policy_del_t_handler)
vl_msg_id(VL_API_SR_POLICY_DEL_REPLY, vl_api_sr_policy_del_reply_t_handler)
vl_msg_id(VL_API_SR_SET_ENCAP_SOURCE, vl_api_sr_set_encap_source_t_handler)
vl_msg_id(VL_API_SR_SET_ENCAP_SOURCE_REPLY, vl_api_sr_set_encap_source_reply_t_handler)
vl_msg_id(VL_API_SR_SET_ENCAP_HOP_LIMIT, vl_api_sr_set_encap_hop_limit_t_handler)
vl_msg_id(VL_API_SR_SET_ENCAP_HOP_LIMIT_REPLY, vl_api_sr_set_encap_hop_limit_reply_t_handler)
vl_msg_id(VL_API_SR_STEERING_ADD_DEL, vl_api_sr_steering_add_del_t_handler)
vl_msg_id(VL_API_SR_STEERING_ADD_DEL_REPLY, vl_api_sr_steering_add_del_reply_t_handler)
vl_msg_id(VL_API_SR_LOCALSIDS_DUMP, vl_api_sr_localsids_dump_t_handler)
vl_msg_id(VL_API_SR_LOCALSIDS_DETAILS, vl_api_sr_localsids_details_t_handler)
vl_msg_id(VL_API_SR_LOCALSIDS_WITH_PACKET_STATS_DUMP, vl_api_sr_localsids_with_packet_stats_dump_t_handler)
vl_msg_id(VL_API_SR_LOCALSIDS_WITH_PACKET_STATS_DETAILS, vl_api_sr_localsids_with_packet_stats_details_t_handler)
vl_msg_id(VL_API_SR_POLICIES_DUMP, vl_api_sr_policies_dump_t_handler)
vl_msg_id(VL_API_SR_POLICIES_DETAILS, vl_api_sr_policies_details_t_handler)
vl_msg_id(VL_API_SR_POLICIES_V2_DUMP, vl_api_sr_policies_v2_dump_t_handler)
vl_msg_id(VL_API_SR_POLICIES_V2_DETAILS, vl_api_sr_policies_v2_details_t_handler)
vl_msg_id(VL_API_SR_POLICIES_WITH_SL_INDEX_DUMP, vl_api_sr_policies_with_sl_index_dump_t_handler)
vl_msg_id(VL_API_SR_POLICIES_WITH_SL_INDEX_DETAILS, vl_api_sr_policies_with_sl_index_details_t_handler)
vl_msg_id(VL_API_SR_STEERING_POL_DUMP, vl_api_sr_steering_pol_dump_t_handler)
vl_msg_id(VL_API_SR_STEERING_POL_DETAILS, vl_api_sr_steering_pol_details_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_sr_localsid_add_del_t, 1)
vl_msg_name(vl_api_sr_localsid_add_del_reply_t, 1)
vl_msg_name(vl_api_sr_policy_add_t, 1)
vl_msg_name(vl_api_sr_policy_add_reply_t, 1)
vl_msg_name(vl_api_sr_policy_mod_t, 1)
vl_msg_name(vl_api_sr_policy_mod_reply_t, 1)
vl_msg_name(vl_api_sr_policy_add_v2_t, 1)
vl_msg_name(vl_api_sr_policy_add_v2_reply_t, 1)
vl_msg_name(vl_api_sr_policy_mod_v2_t, 1)
vl_msg_name(vl_api_sr_policy_mod_v2_reply_t, 1)
vl_msg_name(vl_api_sr_policy_del_t, 1)
vl_msg_name(vl_api_sr_policy_del_reply_t, 1)
vl_msg_name(vl_api_sr_set_encap_source_t, 1)
vl_msg_name(vl_api_sr_set_encap_source_reply_t, 1)
vl_msg_name(vl_api_sr_set_encap_hop_limit_t, 1)
vl_msg_name(vl_api_sr_set_encap_hop_limit_reply_t, 1)
vl_msg_name(vl_api_sr_steering_add_del_t, 1)
vl_msg_name(vl_api_sr_steering_add_del_reply_t, 1)
vl_msg_name(vl_api_sr_localsids_dump_t, 1)
vl_msg_name(vl_api_sr_localsids_details_t, 1)
vl_msg_name(vl_api_sr_localsids_with_packet_stats_dump_t, 1)
vl_msg_name(vl_api_sr_localsids_with_packet_stats_details_t, 1)
vl_msg_name(vl_api_sr_policies_dump_t, 1)
vl_msg_name(vl_api_sr_policies_details_t, 1)
vl_msg_name(vl_api_sr_policies_v2_dump_t, 1)
vl_msg_name(vl_api_sr_policies_v2_details_t, 1)
vl_msg_name(vl_api_sr_policies_with_sl_index_dump_t, 1)
vl_msg_name(vl_api_sr_policies_with_sl_index_details_t, 1)
vl_msg_name(vl_api_sr_steering_pol_dump_t, 1)
vl_msg_name(vl_api_sr_steering_pol_details_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_sr \
_(VL_API_SR_LOCALSID_ADD_DEL, sr_localsid_add_del, 5a36c324) \
_(VL_API_SR_LOCALSID_ADD_DEL_REPLY, sr_localsid_add_del_reply, e8d4e804) \
_(VL_API_SR_POLICY_ADD, sr_policy_add, 44ac92e8) \
_(VL_API_SR_POLICY_ADD_REPLY, sr_policy_add_reply, e8d4e804) \
_(VL_API_SR_POLICY_MOD, sr_policy_mod, b97bb56e) \
_(VL_API_SR_POLICY_MOD_REPLY, sr_policy_mod_reply, e8d4e804) \
_(VL_API_SR_POLICY_ADD_V2, sr_policy_add_v2, f6297f36) \
_(VL_API_SR_POLICY_ADD_V2_REPLY, sr_policy_add_v2_reply, e8d4e804) \
_(VL_API_SR_POLICY_MOD_V2, sr_policy_mod_v2, c0544823) \
_(VL_API_SR_POLICY_MOD_V2_REPLY, sr_policy_mod_v2_reply, e8d4e804) \
_(VL_API_SR_POLICY_DEL, sr_policy_del, cb4d48d5) \
_(VL_API_SR_POLICY_DEL_REPLY, sr_policy_del_reply, e8d4e804) \
_(VL_API_SR_SET_ENCAP_SOURCE, sr_set_encap_source, d3bad5e1) \
_(VL_API_SR_SET_ENCAP_SOURCE_REPLY, sr_set_encap_source_reply, e8d4e804) \
_(VL_API_SR_SET_ENCAP_HOP_LIMIT, sr_set_encap_hop_limit, aa75d7d0) \
_(VL_API_SR_SET_ENCAP_HOP_LIMIT_REPLY, sr_set_encap_hop_limit_reply, e8d4e804) \
_(VL_API_SR_STEERING_ADD_DEL, sr_steering_add_del, e46b0a0f) \
_(VL_API_SR_STEERING_ADD_DEL_REPLY, sr_steering_add_del_reply, e8d4e804) \
_(VL_API_SR_LOCALSIDS_DUMP, sr_localsids_dump, 51077d14) \
_(VL_API_SR_LOCALSIDS_DETAILS, sr_localsids_details, 2e9221b9) \
_(VL_API_SR_LOCALSIDS_WITH_PACKET_STATS_DUMP, sr_localsids_with_packet_stats_dump, 51077d14) \
_(VL_API_SR_LOCALSIDS_WITH_PACKET_STATS_DETAILS, sr_localsids_with_packet_stats_details, ce0b1ce0) \
_(VL_API_SR_POLICIES_DUMP, sr_policies_dump, 51077d14) \
_(VL_API_SR_POLICIES_DETAILS, sr_policies_details, db6ff2a1) \
_(VL_API_SR_POLICIES_V2_DUMP, sr_policies_v2_dump, 51077d14) \
_(VL_API_SR_POLICIES_V2_DETAILS, sr_policies_v2_details, 96dcb699) \
_(VL_API_SR_POLICIES_WITH_SL_INDEX_DUMP, sr_policies_with_sl_index_dump, 51077d14) \
_(VL_API_SR_POLICIES_WITH_SL_INDEX_DETAILS, sr_policies_with_sl_index_details, ca2e9bc8) \
_(VL_API_SR_STEERING_POL_DUMP, sr_steering_pol_dump, 51077d14) \
_(VL_API_SR_STEERING_POL_DETAILS, sr_steering_pol_details, d41258c9) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "sr.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_sr_printfun_types
#define included_sr_printfun_types

static inline u8 *format_vl_api_srv6_sid_list_t (u8 *s, va_list * args)
{
    vl_api_srv6_sid_list_t *a = va_arg (*args, vl_api_srv6_sid_list_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Unum_sids: %u", format_white_space, indent, a->num_sids);
    s = format(s, "\n%Uweight: %u", format_white_space, indent, a->weight);
    for (i = 0; i < 16; i++) {
        s = format(s, "\n%Usids: %U",
                   format_white_space, indent, format_vl_api_ip6_address_t, &a->sids[i], indent);
    }
    return s;
}

static inline u8 *format_vl_api_srv6_sid_list_with_sl_index_t (u8 *s, va_list * args)
{
    vl_api_srv6_sid_list_with_sl_index_t *a = va_arg (*args, vl_api_srv6_sid_list_with_sl_index_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Unum_sids: %u", format_white_space, indent, a->num_sids);
    s = format(s, "\n%Uweight: %u", format_white_space, indent, a->weight);
    s = format(s, "\n%Usl_index: %u", format_white_space, indent, a->sl_index);
    for (i = 0; i < 16; i++) {
        s = format(s, "\n%Usids: %U",
                   format_white_space, indent, format_vl_api_ip6_address_t, &a->sids[i], indent);
    }
    return s;
}

static inline u8 *format_vl_api_sr_policy_type_t (u8 *s, va_list * args)
{
    vl_api_sr_policy_type_t *a = va_arg (*args, vl_api_sr_policy_type_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "SR_API_POLICY_TYPE_DEFAULT");
    case 1:
        return format(s, "SR_API_POLICY_TYPE_SPRAY");
    case 2:
        return format(s, "SR_API_POLICY_TYPE_TEF");
    }
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_sr_printfun
#define included_sr_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "sr.api_tojson.h"
#include "sr.api_fromjson.h"

static inline u8 *vl_api_sr_localsid_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_localsid_add_del_t *a = va_arg (*args, vl_api_sr_localsid_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_localsid_add_del_t: */
    s = format(s, "vl_api_sr_localsid_add_del_t:");
    s = format(s, "\n%Uis_del: %u", format_white_space, indent, a->is_del);
    s = format(s, "\n%Ulocalsid: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->localsid, indent);
    s = format(s, "\n%Uend_psp: %u", format_white_space, indent, a->end_psp);
    s = format(s, "\n%Ubehavior: %U", format_white_space, indent, format_vl_api_sr_behavior_t, &a->behavior, indent);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uvlan_index: %u", format_white_space, indent, a->vlan_index);
    s = format(s, "\n%Ufib_table: %u", format_white_space, indent, a->fib_table);
    s = format(s, "\n%Unh_addr: %U", format_white_space, indent, format_vl_api_address_t, &a->nh_addr, indent);
    return s;
}

static inline u8 *vl_api_sr_localsid_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_localsid_add_del_reply_t *a = va_arg (*args, vl_api_sr_localsid_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_localsid_add_del_reply_t: */
    s = format(s, "vl_api_sr_localsid_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_sr_policy_add_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_policy_add_t *a = va_arg (*args, vl_api_sr_policy_add_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_policy_add_t: */
    s = format(s, "vl_api_sr_policy_add_t:");
    s = format(s, "\n%Ubsid_addr: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->bsid_addr, indent);
    s = format(s, "\n%Uweight: %u", format_white_space, indent, a->weight);
    s = format(s, "\n%Uis_encap: %u", format_white_space, indent, a->is_encap);
    s = format(s, "\n%Uis_spray: %u", format_white_space, indent, a->is_spray);
    s = format(s, "\n%Ufib_table: %u", format_white_space, indent, a->fib_table);
    s = format(s, "\n%Usids: %U", format_white_space, indent, format_vl_api_srv6_sid_list_t, &a->sids, indent);
    return s;
}

static inline u8 *vl_api_sr_policy_add_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_policy_add_reply_t *a = va_arg (*args, vl_api_sr_policy_add_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_policy_add_reply_t: */
    s = format(s, "vl_api_sr_policy_add_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_sr_policy_mod_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_policy_mod_t *a = va_arg (*args, vl_api_sr_policy_mod_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_policy_mod_t: */
    s = format(s, "vl_api_sr_policy_mod_t:");
    s = format(s, "\n%Ubsid_addr: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->bsid_addr, indent);
    s = format(s, "\n%Usr_policy_index: %u", format_white_space, indent, a->sr_policy_index);
    s = format(s, "\n%Ufib_table: %u", format_white_space, indent, a->fib_table);
    s = format(s, "\n%Uoperation: %U", format_white_space, indent, format_vl_api_sr_policy_op_t, &a->operation, indent);
    s = format(s, "\n%Usl_index: %u", format_white_space, indent, a->sl_index);
    s = format(s, "\n%Uweight: %u", format_white_space, indent, a->weight);
    s = format(s, "\n%Usids: %U", format_white_space, indent, format_vl_api_srv6_sid_list_t, &a->sids, indent);
    return s;
}

static inline u8 *vl_api_sr_policy_mod_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_policy_mod_reply_t *a = va_arg (*args, vl_api_sr_policy_mod_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_policy_mod_reply_t: */
    s = format(s, "vl_api_sr_policy_mod_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_sr_policy_add_v2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_policy_add_v2_t *a = va_arg (*args, vl_api_sr_policy_add_v2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_policy_add_v2_t: */
    s = format(s, "vl_api_sr_policy_add_v2_t:");
    s = format(s, "\n%Ubsid_addr: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->bsid_addr, indent);
    s = format(s, "\n%Uweight: %u", format_white_space, indent, a->weight);
    s = format(s, "\n%Uis_encap: %u", format_white_space, indent, a->is_encap);
    s = format(s, "\n%Utype: %U", format_white_space, indent, format_vl_api_sr_policy_type_t, &a->type, indent);
    s = format(s, "\n%Ufib_table: %u", format_white_space, indent, a->fib_table);
    s = format(s, "\n%Usids: %U", format_white_space, indent, format_vl_api_srv6_sid_list_t, &a->sids, indent);
    s = format(s, "\n%Uencap_src: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->encap_src, indent);
    return s;
}

static inline u8 *vl_api_sr_policy_add_v2_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_policy_add_v2_reply_t *a = va_arg (*args, vl_api_sr_policy_add_v2_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_policy_add_v2_reply_t: */
    s = format(s, "vl_api_sr_policy_add_v2_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_sr_policy_mod_v2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_policy_mod_v2_t *a = va_arg (*args, vl_api_sr_policy_mod_v2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_policy_mod_v2_t: */
    s = format(s, "vl_api_sr_policy_mod_v2_t:");
    s = format(s, "\n%Ubsid_addr: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->bsid_addr, indent);
    s = format(s, "\n%Usr_policy_index: %u", format_white_space, indent, a->sr_policy_index);
    s = format(s, "\n%Ufib_table: %u", format_white_space, indent, a->fib_table);
    s = format(s, "\n%Uoperation: %U", format_white_space, indent, format_vl_api_sr_policy_op_t, &a->operation, indent);
    s = format(s, "\n%Usl_index: %u", format_white_space, indent, a->sl_index);
    s = format(s, "\n%Uweight: %u", format_white_space, indent, a->weight);
    s = format(s, "\n%Usids: %U", format_white_space, indent, format_vl_api_srv6_sid_list_t, &a->sids, indent);
    s = format(s, "\n%Uencap_src: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->encap_src, indent);
    return s;
}

static inline u8 *vl_api_sr_policy_mod_v2_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_policy_mod_v2_reply_t *a = va_arg (*args, vl_api_sr_policy_mod_v2_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_policy_mod_v2_reply_t: */
    s = format(s, "vl_api_sr_policy_mod_v2_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_sr_policy_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_policy_del_t *a = va_arg (*args, vl_api_sr_policy_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_policy_del_t: */
    s = format(s, "vl_api_sr_policy_del_t:");
    s = format(s, "\n%Ubsid_addr: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->bsid_addr, indent);
    s = format(s, "\n%Usr_policy_index: %u", format_white_space, indent, a->sr_policy_index);
    return s;
}

static inline u8 *vl_api_sr_policy_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_policy_del_reply_t *a = va_arg (*args, vl_api_sr_policy_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_policy_del_reply_t: */
    s = format(s, "vl_api_sr_policy_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_sr_set_encap_source_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_set_encap_source_t *a = va_arg (*args, vl_api_sr_set_encap_source_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_set_encap_source_t: */
    s = format(s, "vl_api_sr_set_encap_source_t:");
    s = format(s, "\n%Uencaps_source: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->encaps_source, indent);
    return s;
}

static inline u8 *vl_api_sr_set_encap_source_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_set_encap_source_reply_t *a = va_arg (*args, vl_api_sr_set_encap_source_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_set_encap_source_reply_t: */
    s = format(s, "vl_api_sr_set_encap_source_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_sr_set_encap_hop_limit_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_set_encap_hop_limit_t *a = va_arg (*args, vl_api_sr_set_encap_hop_limit_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_set_encap_hop_limit_t: */
    s = format(s, "vl_api_sr_set_encap_hop_limit_t:");
    s = format(s, "\n%Uhop_limit: %u", format_white_space, indent, a->hop_limit);
    return s;
}

static inline u8 *vl_api_sr_set_encap_hop_limit_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_set_encap_hop_limit_reply_t *a = va_arg (*args, vl_api_sr_set_encap_hop_limit_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_set_encap_hop_limit_reply_t: */
    s = format(s, "vl_api_sr_set_encap_hop_limit_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_sr_steering_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_steering_add_del_t *a = va_arg (*args, vl_api_sr_steering_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_steering_add_del_t: */
    s = format(s, "vl_api_sr_steering_add_del_t:");
    s = format(s, "\n%Uis_del: %u", format_white_space, indent, a->is_del);
    s = format(s, "\n%Ubsid_addr: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->bsid_addr, indent);
    s = format(s, "\n%Usr_policy_index: %u", format_white_space, indent, a->sr_policy_index);
    s = format(s, "\n%Utable_id: %u", format_white_space, indent, a->table_id);
    s = format(s, "\n%Uprefix: %U", format_white_space, indent, format_vl_api_prefix_t, &a->prefix, indent);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Utraffic_type: %U", format_white_space, indent, format_vl_api_sr_steer_t, &a->traffic_type, indent);
    return s;
}

static inline u8 *vl_api_sr_steering_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_steering_add_del_reply_t *a = va_arg (*args, vl_api_sr_steering_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_steering_add_del_reply_t: */
    s = format(s, "vl_api_sr_steering_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_sr_localsids_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_localsids_dump_t *a = va_arg (*args, vl_api_sr_localsids_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_localsids_dump_t: */
    s = format(s, "vl_api_sr_localsids_dump_t:");
    return s;
}

static inline u8 *vl_api_sr_localsids_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_localsids_details_t *a = va_arg (*args, vl_api_sr_localsids_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_localsids_details_t: */
    s = format(s, "vl_api_sr_localsids_details_t:");
    s = format(s, "\n%Uaddr: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->addr, indent);
    s = format(s, "\n%Uend_psp: %u", format_white_space, indent, a->end_psp);
    s = format(s, "\n%Ubehavior: %U", format_white_space, indent, format_vl_api_sr_behavior_t, &a->behavior, indent);
    s = format(s, "\n%Ufib_table: %u", format_white_space, indent, a->fib_table);
    s = format(s, "\n%Uvlan_index: %u", format_white_space, indent, a->vlan_index);
    s = format(s, "\n%Uxconnect_nh_addr: %U", format_white_space, indent, format_vl_api_address_t, &a->xconnect_nh_addr, indent);
    s = format(s, "\n%Uxconnect_iface_or_vrf_table: %u", format_white_space, indent, a->xconnect_iface_or_vrf_table);
    return s;
}

static inline u8 *vl_api_sr_localsids_with_packet_stats_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_localsids_with_packet_stats_dump_t *a = va_arg (*args, vl_api_sr_localsids_with_packet_stats_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_localsids_with_packet_stats_dump_t: */
    s = format(s, "vl_api_sr_localsids_with_packet_stats_dump_t:");
    return s;
}

static inline u8 *vl_api_sr_localsids_with_packet_stats_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_localsids_with_packet_stats_details_t *a = va_arg (*args, vl_api_sr_localsids_with_packet_stats_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_localsids_with_packet_stats_details_t: */
    s = format(s, "vl_api_sr_localsids_with_packet_stats_details_t:");
    s = format(s, "\n%Uaddr: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->addr, indent);
    s = format(s, "\n%Uend_psp: %u", format_white_space, indent, a->end_psp);
    s = format(s, "\n%Ubehavior: %U", format_white_space, indent, format_vl_api_sr_behavior_t, &a->behavior, indent);
    s = format(s, "\n%Ufib_table: %u", format_white_space, indent, a->fib_table);
    s = format(s, "\n%Uvlan_index: %u", format_white_space, indent, a->vlan_index);
    s = format(s, "\n%Uxconnect_nh_addr: %U", format_white_space, indent, format_vl_api_address_t, &a->xconnect_nh_addr, indent);
    s = format(s, "\n%Uxconnect_iface_or_vrf_table: %u", format_white_space, indent, a->xconnect_iface_or_vrf_table);
    s = format(s, "\n%Ugood_traffic_bytes: %llu", format_white_space, indent, a->good_traffic_bytes);
    s = format(s, "\n%Ugood_traffic_pkt_count: %llu", format_white_space, indent, a->good_traffic_pkt_count);
    s = format(s, "\n%Ubad_traffic_bytes: %llu", format_white_space, indent, a->bad_traffic_bytes);
    s = format(s, "\n%Ubad_traffic_pkt_count: %llu", format_white_space, indent, a->bad_traffic_pkt_count);
    return s;
}

static inline u8 *vl_api_sr_policies_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_policies_dump_t *a = va_arg (*args, vl_api_sr_policies_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_policies_dump_t: */
    s = format(s, "vl_api_sr_policies_dump_t:");
    return s;
}

static inline u8 *vl_api_sr_policies_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_policies_details_t *a = va_arg (*args, vl_api_sr_policies_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_policies_details_t: */
    s = format(s, "vl_api_sr_policies_details_t:");
    s = format(s, "\n%Ubsid: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->bsid, indent);
    s = format(s, "\n%Uis_spray: %u", format_white_space, indent, a->is_spray);
    s = format(s, "\n%Uis_encap: %u", format_white_space, indent, a->is_encap);
    s = format(s, "\n%Ufib_table: %u", format_white_space, indent, a->fib_table);
    s = format(s, "\n%Unum_sid_lists: %u", format_white_space, indent, a->num_sid_lists);
    for (i = 0; i < a->num_sid_lists; i++) {
        s = format(s, "\n%Usid_lists: %U",
                   format_white_space, indent, format_vl_api_srv6_sid_list_t, &a->sid_lists[i], indent);
    }
    return s;
}

static inline u8 *vl_api_sr_policies_v2_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_policies_v2_dump_t *a = va_arg (*args, vl_api_sr_policies_v2_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_policies_v2_dump_t: */
    s = format(s, "vl_api_sr_policies_v2_dump_t:");
    return s;
}

static inline u8 *vl_api_sr_policies_v2_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_policies_v2_details_t *a = va_arg (*args, vl_api_sr_policies_v2_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_policies_v2_details_t: */
    s = format(s, "vl_api_sr_policies_v2_details_t:");
    s = format(s, "\n%Ubsid: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->bsid, indent);
    s = format(s, "\n%Uencap_src: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->encap_src, indent);
    s = format(s, "\n%Utype: %U", format_white_space, indent, format_vl_api_sr_policy_type_t, &a->type, indent);
    s = format(s, "\n%Uis_encap: %u", format_white_space, indent, a->is_encap);
    s = format(s, "\n%Ufib_table: %u", format_white_space, indent, a->fib_table);
    s = format(s, "\n%Unum_sid_lists: %u", format_white_space, indent, a->num_sid_lists);
    for (i = 0; i < a->num_sid_lists; i++) {
        s = format(s, "\n%Usid_lists: %U",
                   format_white_space, indent, format_vl_api_srv6_sid_list_t, &a->sid_lists[i], indent);
    }
    return s;
}

static inline u8 *vl_api_sr_policies_with_sl_index_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_policies_with_sl_index_dump_t *a = va_arg (*args, vl_api_sr_policies_with_sl_index_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_policies_with_sl_index_dump_t: */
    s = format(s, "vl_api_sr_policies_with_sl_index_dump_t:");
    return s;
}

static inline u8 *vl_api_sr_policies_with_sl_index_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_policies_with_sl_index_details_t *a = va_arg (*args, vl_api_sr_policies_with_sl_index_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_policies_with_sl_index_details_t: */
    s = format(s, "vl_api_sr_policies_with_sl_index_details_t:");
    s = format(s, "\n%Ubsid: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->bsid, indent);
    s = format(s, "\n%Uis_spray: %u", format_white_space, indent, a->is_spray);
    s = format(s, "\n%Uis_encap: %u", format_white_space, indent, a->is_encap);
    s = format(s, "\n%Ufib_table: %u", format_white_space, indent, a->fib_table);
    s = format(s, "\n%Unum_sid_lists: %u", format_white_space, indent, a->num_sid_lists);
    for (i = 0; i < a->num_sid_lists; i++) {
        s = format(s, "\n%Usid_lists: %U",
                   format_white_space, indent, format_vl_api_srv6_sid_list_with_sl_index_t, &a->sid_lists[i], indent);
    }
    return s;
}

static inline u8 *vl_api_sr_steering_pol_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_steering_pol_dump_t *a = va_arg (*args, vl_api_sr_steering_pol_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_steering_pol_dump_t: */
    s = format(s, "vl_api_sr_steering_pol_dump_t:");
    return s;
}

static inline u8 *vl_api_sr_steering_pol_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_steering_pol_details_t *a = va_arg (*args, vl_api_sr_steering_pol_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_steering_pol_details_t: */
    s = format(s, "vl_api_sr_steering_pol_details_t:");
    s = format(s, "\n%Utraffic_type: %U", format_white_space, indent, format_vl_api_sr_steer_t, &a->traffic_type, indent);
    s = format(s, "\n%Ufib_table: %u", format_white_space, indent, a->fib_table);
    s = format(s, "\n%Uprefix: %U", format_white_space, indent, format_vl_api_prefix_t, &a->prefix, indent);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Ubsid: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->bsid, indent);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_sr_endianfun
#define included_sr_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_srv6_sid_list_t_endian (vl_api_srv6_sid_list_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->num_sids = a->num_sids (no-op) */
    a->weight = clib_net_to_host_u32(a->weight);
    for (i = 0; i < 16; i++) {
        vl_api_ip6_address_t_endian(&a->sids[i], to_net);
    }
}

static inline void vl_api_srv6_sid_list_with_sl_index_t_endian (vl_api_srv6_sid_list_with_sl_index_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->num_sids = a->num_sids (no-op) */
    a->weight = clib_net_to_host_u32(a->weight);
    a->sl_index = clib_net_to_host_u32(a->sl_index);
    for (i = 0; i < 16; i++) {
        vl_api_ip6_address_t_endian(&a->sids[i], to_net);
    }
}

static inline void vl_api_sr_policy_type_t_endian (vl_api_sr_policy_type_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->sr_policy_type = a->sr_policy_type (no-op) */
}

static inline void vl_api_sr_localsid_add_del_t_endian (vl_api_sr_localsid_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_del = a->is_del (no-op) */
    vl_api_ip6_address_t_endian(&a->localsid, to_net);
    /* a->end_psp = a->end_psp (no-op) */
    vl_api_sr_behavior_t_endian(&a->behavior, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    a->vlan_index = clib_net_to_host_u32(a->vlan_index);
    a->fib_table = clib_net_to_host_u32(a->fib_table);
    vl_api_address_t_endian(&a->nh_addr, to_net);
}

static inline void vl_api_sr_localsid_add_del_reply_t_endian (vl_api_sr_localsid_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_sr_policy_add_t_endian (vl_api_sr_policy_add_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip6_address_t_endian(&a->bsid_addr, to_net);
    a->weight = clib_net_to_host_u32(a->weight);
    /* a->is_encap = a->is_encap (no-op) */
    /* a->is_spray = a->is_spray (no-op) */
    a->fib_table = clib_net_to_host_u32(a->fib_table);
    vl_api_srv6_sid_list_t_endian(&a->sids, to_net);
}

static inline void vl_api_sr_policy_add_reply_t_endian (vl_api_sr_policy_add_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_sr_policy_mod_t_endian (vl_api_sr_policy_mod_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip6_address_t_endian(&a->bsid_addr, to_net);
    a->sr_policy_index = clib_net_to_host_u32(a->sr_policy_index);
    a->fib_table = clib_net_to_host_u32(a->fib_table);
    vl_api_sr_policy_op_t_endian(&a->operation, to_net);
    a->sl_index = clib_net_to_host_u32(a->sl_index);
    a->weight = clib_net_to_host_u32(a->weight);
    vl_api_srv6_sid_list_t_endian(&a->sids, to_net);
}

static inline void vl_api_sr_policy_mod_reply_t_endian (vl_api_sr_policy_mod_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_sr_policy_add_v2_t_endian (vl_api_sr_policy_add_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip6_address_t_endian(&a->bsid_addr, to_net);
    a->weight = clib_net_to_host_u32(a->weight);
    /* a->is_encap = a->is_encap (no-op) */
    vl_api_sr_policy_type_t_endian(&a->type, to_net);
    a->fib_table = clib_net_to_host_u32(a->fib_table);
    vl_api_srv6_sid_list_t_endian(&a->sids, to_net);
    vl_api_ip6_address_t_endian(&a->encap_src, to_net);
}

static inline void vl_api_sr_policy_add_v2_reply_t_endian (vl_api_sr_policy_add_v2_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_sr_policy_mod_v2_t_endian (vl_api_sr_policy_mod_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip6_address_t_endian(&a->bsid_addr, to_net);
    a->sr_policy_index = clib_net_to_host_u32(a->sr_policy_index);
    a->fib_table = clib_net_to_host_u32(a->fib_table);
    vl_api_sr_policy_op_t_endian(&a->operation, to_net);
    a->sl_index = clib_net_to_host_u32(a->sl_index);
    a->weight = clib_net_to_host_u32(a->weight);
    vl_api_srv6_sid_list_t_endian(&a->sids, to_net);
    vl_api_ip6_address_t_endian(&a->encap_src, to_net);
}

static inline void vl_api_sr_policy_mod_v2_reply_t_endian (vl_api_sr_policy_mod_v2_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_sr_policy_del_t_endian (vl_api_sr_policy_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip6_address_t_endian(&a->bsid_addr, to_net);
    a->sr_policy_index = clib_net_to_host_u32(a->sr_policy_index);
}

static inline void vl_api_sr_policy_del_reply_t_endian (vl_api_sr_policy_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_sr_set_encap_source_t_endian (vl_api_sr_set_encap_source_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip6_address_t_endian(&a->encaps_source, to_net);
}

static inline void vl_api_sr_set_encap_source_reply_t_endian (vl_api_sr_set_encap_source_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_sr_set_encap_hop_limit_t_endian (vl_api_sr_set_encap_hop_limit_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->hop_limit = a->hop_limit (no-op) */
}

static inline void vl_api_sr_set_encap_hop_limit_reply_t_endian (vl_api_sr_set_encap_hop_limit_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_sr_steering_add_del_t_endian (vl_api_sr_steering_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_del = a->is_del (no-op) */
    vl_api_ip6_address_t_endian(&a->bsid_addr, to_net);
    a->sr_policy_index = clib_net_to_host_u32(a->sr_policy_index);
    a->table_id = clib_net_to_host_u32(a->table_id);
    vl_api_prefix_t_endian(&a->prefix, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    vl_api_sr_steer_t_endian(&a->traffic_type, to_net);
}

static inline void vl_api_sr_steering_add_del_reply_t_endian (vl_api_sr_steering_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_sr_localsids_dump_t_endian (vl_api_sr_localsids_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_sr_localsids_details_t_endian (vl_api_sr_localsids_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip6_address_t_endian(&a->addr, to_net);
    /* a->end_psp = a->end_psp (no-op) */
    vl_api_sr_behavior_t_endian(&a->behavior, to_net);
    a->fib_table = clib_net_to_host_u32(a->fib_table);
    a->vlan_index = clib_net_to_host_u32(a->vlan_index);
    vl_api_address_t_endian(&a->xconnect_nh_addr, to_net);
    a->xconnect_iface_or_vrf_table = clib_net_to_host_u32(a->xconnect_iface_or_vrf_table);
}

static inline void vl_api_sr_localsids_with_packet_stats_dump_t_endian (vl_api_sr_localsids_with_packet_stats_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_sr_localsids_with_packet_stats_details_t_endian (vl_api_sr_localsids_with_packet_stats_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip6_address_t_endian(&a->addr, to_net);
    /* a->end_psp = a->end_psp (no-op) */
    vl_api_sr_behavior_t_endian(&a->behavior, to_net);
    a->fib_table = clib_net_to_host_u32(a->fib_table);
    a->vlan_index = clib_net_to_host_u32(a->vlan_index);
    vl_api_address_t_endian(&a->xconnect_nh_addr, to_net);
    a->xconnect_iface_or_vrf_table = clib_net_to_host_u32(a->xconnect_iface_or_vrf_table);
    a->good_traffic_bytes = clib_net_to_host_u64(a->good_traffic_bytes);
    a->good_traffic_pkt_count = clib_net_to_host_u64(a->good_traffic_pkt_count);
    a->bad_traffic_bytes = clib_net_to_host_u64(a->bad_traffic_bytes);
    a->bad_traffic_pkt_count = clib_net_to_host_u64(a->bad_traffic_pkt_count);
}

static inline void vl_api_sr_policies_dump_t_endian (vl_api_sr_policies_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_sr_policies_details_t_endian (vl_api_sr_policies_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip6_address_t_endian(&a->bsid, to_net);
    /* a->is_spray = a->is_spray (no-op) */
    /* a->is_encap = a->is_encap (no-op) */
    a->fib_table = clib_net_to_host_u32(a->fib_table);
    /* a->num_sid_lists = a->num_sid_lists (no-op) */
    u32 count = a->num_sid_lists;
    for (i = 0; i < count; i++) {
        vl_api_srv6_sid_list_t_endian(&a->sid_lists[i], to_net);
    }
}

static inline void vl_api_sr_policies_v2_dump_t_endian (vl_api_sr_policies_v2_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_sr_policies_v2_details_t_endian (vl_api_sr_policies_v2_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip6_address_t_endian(&a->bsid, to_net);
    vl_api_ip6_address_t_endian(&a->encap_src, to_net);
    vl_api_sr_policy_type_t_endian(&a->type, to_net);
    /* a->is_encap = a->is_encap (no-op) */
    a->fib_table = clib_net_to_host_u32(a->fib_table);
    /* a->num_sid_lists = a->num_sid_lists (no-op) */
    u32 count = a->num_sid_lists;
    for (i = 0; i < count; i++) {
        vl_api_srv6_sid_list_t_endian(&a->sid_lists[i], to_net);
    }
}

static inline void vl_api_sr_policies_with_sl_index_dump_t_endian (vl_api_sr_policies_with_sl_index_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_sr_policies_with_sl_index_details_t_endian (vl_api_sr_policies_with_sl_index_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip6_address_t_endian(&a->bsid, to_net);
    /* a->is_spray = a->is_spray (no-op) */
    /* a->is_encap = a->is_encap (no-op) */
    a->fib_table = clib_net_to_host_u32(a->fib_table);
    /* a->num_sid_lists = a->num_sid_lists (no-op) */
    u32 count = a->num_sid_lists;
    for (i = 0; i < count; i++) {
        vl_api_srv6_sid_list_with_sl_index_t_endian(&a->sid_lists[i], to_net);
    }
}

static inline void vl_api_sr_steering_pol_dump_t_endian (vl_api_sr_steering_pol_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_sr_steering_pol_details_t_endian (vl_api_sr_steering_pol_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_sr_steer_t_endian(&a->traffic_type, to_net);
    a->fib_table = clib_net_to_host_u32(a->fib_table);
    vl_api_prefix_t_endian(&a->prefix, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    vl_api_ip6_address_t_endian(&a->bsid, to_net);
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_sr_calcsizefun
#define included_sr_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_srv6_sid_list_t_calc_size (vl_api_srv6_sid_list_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_srv6_sid_list_with_sl_index_t_calc_size (vl_api_srv6_sid_list_with_sl_index_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_policy_type_t_calc_size (vl_api_sr_policy_type_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_localsid_add_del_t_calc_size (vl_api_sr_localsid_add_del_t *a)
{
      return sizeof(*a) - sizeof(a->localsid) + vl_api_ip6_address_t_calc_size(&a->localsid) - sizeof(a->behavior) + vl_api_sr_behavior_t_calc_size(&a->behavior) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->nh_addr) + vl_api_address_t_calc_size(&a->nh_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_localsid_add_del_reply_t_calc_size (vl_api_sr_localsid_add_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_policy_add_t_calc_size (vl_api_sr_policy_add_t *a)
{
      return sizeof(*a) - sizeof(a->bsid_addr) + vl_api_ip6_address_t_calc_size(&a->bsid_addr) - sizeof(a->sids) + vl_api_srv6_sid_list_t_calc_size(&a->sids);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_policy_add_reply_t_calc_size (vl_api_sr_policy_add_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_policy_mod_t_calc_size (vl_api_sr_policy_mod_t *a)
{
      return sizeof(*a) - sizeof(a->bsid_addr) + vl_api_ip6_address_t_calc_size(&a->bsid_addr) - sizeof(a->operation) + vl_api_sr_policy_op_t_calc_size(&a->operation) - sizeof(a->sids) + vl_api_srv6_sid_list_t_calc_size(&a->sids);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_policy_mod_reply_t_calc_size (vl_api_sr_policy_mod_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_policy_add_v2_t_calc_size (vl_api_sr_policy_add_v2_t *a)
{
      return sizeof(*a) - sizeof(a->bsid_addr) + vl_api_ip6_address_t_calc_size(&a->bsid_addr) - sizeof(a->type) + vl_api_sr_policy_type_t_calc_size(&a->type) - sizeof(a->sids) + vl_api_srv6_sid_list_t_calc_size(&a->sids) - sizeof(a->encap_src) + vl_api_ip6_address_t_calc_size(&a->encap_src);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_policy_add_v2_reply_t_calc_size (vl_api_sr_policy_add_v2_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_policy_mod_v2_t_calc_size (vl_api_sr_policy_mod_v2_t *a)
{
      return sizeof(*a) - sizeof(a->bsid_addr) + vl_api_ip6_address_t_calc_size(&a->bsid_addr) - sizeof(a->operation) + vl_api_sr_policy_op_t_calc_size(&a->operation) - sizeof(a->sids) + vl_api_srv6_sid_list_t_calc_size(&a->sids) - sizeof(a->encap_src) + vl_api_ip6_address_t_calc_size(&a->encap_src);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_policy_mod_v2_reply_t_calc_size (vl_api_sr_policy_mod_v2_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_policy_del_t_calc_size (vl_api_sr_policy_del_t *a)
{
      return sizeof(*a) - sizeof(a->bsid_addr) + vl_api_ip6_address_t_calc_size(&a->bsid_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_policy_del_reply_t_calc_size (vl_api_sr_policy_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_set_encap_source_t_calc_size (vl_api_sr_set_encap_source_t *a)
{
      return sizeof(*a) - sizeof(a->encaps_source) + vl_api_ip6_address_t_calc_size(&a->encaps_source);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_set_encap_source_reply_t_calc_size (vl_api_sr_set_encap_source_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_set_encap_hop_limit_t_calc_size (vl_api_sr_set_encap_hop_limit_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_set_encap_hop_limit_reply_t_calc_size (vl_api_sr_set_encap_hop_limit_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_steering_add_del_t_calc_size (vl_api_sr_steering_add_del_t *a)
{
      return sizeof(*a) - sizeof(a->bsid_addr) + vl_api_ip6_address_t_calc_size(&a->bsid_addr) - sizeof(a->prefix) + vl_api_prefix_t_calc_size(&a->prefix) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->traffic_type) + vl_api_sr_steer_t_calc_size(&a->traffic_type);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_steering_add_del_reply_t_calc_size (vl_api_sr_steering_add_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_localsids_dump_t_calc_size (vl_api_sr_localsids_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_localsids_details_t_calc_size (vl_api_sr_localsids_details_t *a)
{
      return sizeof(*a) - sizeof(a->addr) + vl_api_ip6_address_t_calc_size(&a->addr) - sizeof(a->behavior) + vl_api_sr_behavior_t_calc_size(&a->behavior) - sizeof(a->xconnect_nh_addr) + vl_api_address_t_calc_size(&a->xconnect_nh_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_localsids_with_packet_stats_dump_t_calc_size (vl_api_sr_localsids_with_packet_stats_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_localsids_with_packet_stats_details_t_calc_size (vl_api_sr_localsids_with_packet_stats_details_t *a)
{
      return sizeof(*a) - sizeof(a->addr) + vl_api_ip6_address_t_calc_size(&a->addr) - sizeof(a->behavior) + vl_api_sr_behavior_t_calc_size(&a->behavior) - sizeof(a->xconnect_nh_addr) + vl_api_address_t_calc_size(&a->xconnect_nh_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_policies_dump_t_calc_size (vl_api_sr_policies_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_policies_details_t_calc_size (vl_api_sr_policies_details_t *a)
{
      return sizeof(*a) - sizeof(a->bsid) + vl_api_ip6_address_t_calc_size(&a->bsid) + a->num_sid_lists * sizeof(a->sid_lists[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_policies_v2_dump_t_calc_size (vl_api_sr_policies_v2_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_policies_v2_details_t_calc_size (vl_api_sr_policies_v2_details_t *a)
{
      return sizeof(*a) - sizeof(a->bsid) + vl_api_ip6_address_t_calc_size(&a->bsid) - sizeof(a->encap_src) + vl_api_ip6_address_t_calc_size(&a->encap_src) - sizeof(a->type) + vl_api_sr_policy_type_t_calc_size(&a->type) + a->num_sid_lists * sizeof(a->sid_lists[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_policies_with_sl_index_dump_t_calc_size (vl_api_sr_policies_with_sl_index_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_policies_with_sl_index_details_t_calc_size (vl_api_sr_policies_with_sl_index_details_t *a)
{
      return sizeof(*a) - sizeof(a->bsid) + vl_api_ip6_address_t_calc_size(&a->bsid) + a->num_sid_lists * sizeof(a->sid_lists[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_steering_pol_dump_t_calc_size (vl_api_sr_steering_pol_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_steering_pol_details_t_calc_size (vl_api_sr_steering_pol_details_t *a)
{
      return sizeof(*a) - sizeof(a->traffic_type) + vl_api_sr_steer_t_calc_size(&a->traffic_type) - sizeof(a->prefix) + vl_api_prefix_t_calc_size(&a->prefix) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->bsid) + vl_api_ip6_address_t_calc_size(&a->bsid);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(sr.api, 2, 1, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(sr.api, 0xf0cc4ec6)

#endif

