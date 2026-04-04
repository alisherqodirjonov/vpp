/*
 * VLIB API definitions 2026-04-04 08:31:59
 * Input file: cnat.api
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
#warning no content included from cnat.api
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
#include <vnet/ip/ip_types.api.h>
#include <vnet/fib/fib_types.api.h>
#include <vnet/interface_types.api.h>
#include <vnet/ip/ip.api.h>
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_CNAT_TRANSLATION_UPDATE, vl_api_cnat_translation_update_t_handler)
vl_msg_id(VL_API_CNAT_TRANSLATION_UPDATE_REPLY, vl_api_cnat_translation_update_reply_t_handler)
vl_msg_id(VL_API_CNAT_TRANSLATION_DEL, vl_api_cnat_translation_del_t_handler)
vl_msg_id(VL_API_CNAT_TRANSLATION_DEL_REPLY, vl_api_cnat_translation_del_reply_t_handler)
vl_msg_id(VL_API_CNAT_TRANSLATION_DETAILS, vl_api_cnat_translation_details_t_handler)
vl_msg_id(VL_API_CNAT_TRANSLATION_DUMP, vl_api_cnat_translation_dump_t_handler)
vl_msg_id(VL_API_CNAT_SESSION_PURGE, vl_api_cnat_session_purge_t_handler)
vl_msg_id(VL_API_CNAT_SESSION_PURGE_REPLY, vl_api_cnat_session_purge_reply_t_handler)
vl_msg_id(VL_API_CNAT_SESSION_DETAILS, vl_api_cnat_session_details_t_handler)
vl_msg_id(VL_API_CNAT_SESSION_DUMP, vl_api_cnat_session_dump_t_handler)
vl_msg_id(VL_API_CNAT_SET_SNAT_ADDRESSES, vl_api_cnat_set_snat_addresses_t_handler)
vl_msg_id(VL_API_CNAT_SET_SNAT_ADDRESSES_REPLY, vl_api_cnat_set_snat_addresses_reply_t_handler)
vl_msg_id(VL_API_CNAT_GET_SNAT_ADDRESSES, vl_api_cnat_get_snat_addresses_t_handler)
vl_msg_id(VL_API_CNAT_GET_SNAT_ADDRESSES_REPLY, vl_api_cnat_get_snat_addresses_reply_t_handler)
vl_msg_id(VL_API_CNAT_SNAT_POLICY_ADD_DEL_EXCLUDE_PFX, vl_api_cnat_snat_policy_add_del_exclude_pfx_t_handler)
vl_msg_id(VL_API_CNAT_SNAT_POLICY_ADD_DEL_EXCLUDE_PFX_REPLY, vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t_handler)
vl_msg_id(VL_API_CNAT_SNAT_POLICY_ADD_DEL_IF, vl_api_cnat_snat_policy_add_del_if_t_handler)
vl_msg_id(VL_API_CNAT_SNAT_POLICY_ADD_DEL_IF_REPLY, vl_api_cnat_snat_policy_add_del_if_reply_t_handler)
vl_msg_id(VL_API_CNAT_SET_SNAT_POLICY, vl_api_cnat_set_snat_policy_t_handler)
vl_msg_id(VL_API_CNAT_SET_SNAT_POLICY_REPLY, vl_api_cnat_set_snat_policy_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_cnat_translation_update_t, 1)
vl_msg_name(vl_api_cnat_translation_update_reply_t, 1)
vl_msg_name(vl_api_cnat_translation_del_t, 1)
vl_msg_name(vl_api_cnat_translation_del_reply_t, 1)
vl_msg_name(vl_api_cnat_translation_details_t, 1)
vl_msg_name(vl_api_cnat_translation_dump_t, 1)
vl_msg_name(vl_api_cnat_session_purge_t, 1)
vl_msg_name(vl_api_cnat_session_purge_reply_t, 1)
vl_msg_name(vl_api_cnat_session_details_t, 1)
vl_msg_name(vl_api_cnat_session_dump_t, 1)
vl_msg_name(vl_api_cnat_set_snat_addresses_t, 1)
vl_msg_name(vl_api_cnat_set_snat_addresses_reply_t, 1)
vl_msg_name(vl_api_cnat_get_snat_addresses_t, 1)
vl_msg_name(vl_api_cnat_get_snat_addresses_reply_t, 1)
vl_msg_name(vl_api_cnat_snat_policy_add_del_exclude_pfx_t, 1)
vl_msg_name(vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t, 1)
vl_msg_name(vl_api_cnat_snat_policy_add_del_if_t, 1)
vl_msg_name(vl_api_cnat_snat_policy_add_del_if_reply_t, 1)
vl_msg_name(vl_api_cnat_set_snat_policy_t, 1)
vl_msg_name(vl_api_cnat_set_snat_policy_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_cnat \
_(VL_API_CNAT_TRANSLATION_UPDATE, cnat_translation_update, f8d40bc5) \
_(VL_API_CNAT_TRANSLATION_UPDATE_REPLY, cnat_translation_update_reply, e2fc8294) \
_(VL_API_CNAT_TRANSLATION_DEL, cnat_translation_del, 3a91bde5) \
_(VL_API_CNAT_TRANSLATION_DEL_REPLY, cnat_translation_del_reply, e8d4e804) \
_(VL_API_CNAT_TRANSLATION_DETAILS, cnat_translation_details, 1a5140b7) \
_(VL_API_CNAT_TRANSLATION_DUMP, cnat_translation_dump, 51077d14) \
_(VL_API_CNAT_SESSION_PURGE, cnat_session_purge, 51077d14) \
_(VL_API_CNAT_SESSION_PURGE_REPLY, cnat_session_purge_reply, e8d4e804) \
_(VL_API_CNAT_SESSION_DETAILS, cnat_session_details, 7e5017c7) \
_(VL_API_CNAT_SESSION_DUMP, cnat_session_dump, 51077d14) \
_(VL_API_CNAT_SET_SNAT_ADDRESSES, cnat_set_snat_addresses, d997e96c) \
_(VL_API_CNAT_SET_SNAT_ADDRESSES_REPLY, cnat_set_snat_addresses_reply, e8d4e804) \
_(VL_API_CNAT_GET_SNAT_ADDRESSES, cnat_get_snat_addresses, 51077d14) \
_(VL_API_CNAT_GET_SNAT_ADDRESSES_REPLY, cnat_get_snat_addresses_reply, 879513c1) \
_(VL_API_CNAT_SNAT_POLICY_ADD_DEL_EXCLUDE_PFX, cnat_snat_policy_add_del_exclude_pfx, e26dd79a) \
_(VL_API_CNAT_SNAT_POLICY_ADD_DEL_EXCLUDE_PFX_REPLY, cnat_snat_policy_add_del_exclude_pfx_reply, e8d4e804) \
_(VL_API_CNAT_SNAT_POLICY_ADD_DEL_IF, cnat_snat_policy_add_del_if, 4ebb8d02) \
_(VL_API_CNAT_SNAT_POLICY_ADD_DEL_IF_REPLY, cnat_snat_policy_add_del_if_reply, e8d4e804) \
_(VL_API_CNAT_SET_SNAT_POLICY, cnat_set_snat_policy, d3e6eaf4) \
_(VL_API_CNAT_SET_SNAT_POLICY_REPLY, cnat_set_snat_policy_reply, e8d4e804) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "cnat.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_cnat_printfun_types
#define included_cnat_printfun_types

static inline u8 *format_vl_api_cnat_translation_flags_t (u8 *s, va_list * args)
{
    vl_api_cnat_translation_flags_t *a = va_arg (*args, vl_api_cnat_translation_flags_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 1:
        return format(s, "CNAT_TRANSLATION_ALLOC_PORT");
    case 4:
        return format(s, "CNAT_TRANSLATION_NO_RETURN_SESSION");
    }
    return s;
}

static inline u8 *format_vl_api_cnat_endpoint_tuple_flags_t (u8 *s, va_list * args)
{
    vl_api_cnat_endpoint_tuple_flags_t *a = va_arg (*args, vl_api_cnat_endpoint_tuple_flags_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 1:
        return format(s, "CNAT_EPT_NO_NAT");
    }
    return s;
}

static inline u8 *format_vl_api_cnat_lb_type_t (u8 *s, va_list * args)
{
    vl_api_cnat_lb_type_t *a = va_arg (*args, vl_api_cnat_lb_type_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "CNAT_LB_TYPE_DEFAULT");
    case 1:
        return format(s, "CNAT_LB_TYPE_MAGLEV");
    }
    return s;
}

static inline u8 *format_vl_api_cnat_endpoint_t (u8 *s, va_list * args)
{
    vl_api_cnat_endpoint_t *a = va_arg (*args, vl_api_cnat_endpoint_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Uaddr: %U", format_white_space, indent, format_vl_api_address_t, &a->addr, indent);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uif_af: %U", format_white_space, indent, format_vl_api_address_family_t, &a->if_af, indent);
    s = format(s, "\n%Uport: %u", format_white_space, indent, a->port);
    return s;
}

static inline u8 *format_vl_api_cnat_endpoint_tuple_t (u8 *s, va_list * args)
{
    vl_api_cnat_endpoint_tuple_t *a = va_arg (*args, vl_api_cnat_endpoint_tuple_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Udst_ep: %U", format_white_space, indent, format_vl_api_cnat_endpoint_t, &a->dst_ep, indent);
    s = format(s, "\n%Usrc_ep: %U", format_white_space, indent, format_vl_api_cnat_endpoint_t, &a->src_ep, indent);
    s = format(s, "\n%Uflags: %u", format_white_space, indent, a->flags);
    return s;
}

static inline u8 *format_vl_api_cnat_translation_t (u8 *s, va_list * args)
{
    vl_api_cnat_translation_t *a = va_arg (*args, vl_api_cnat_translation_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Uvip: %U", format_white_space, indent, format_vl_api_cnat_endpoint_t, &a->vip, indent);
    s = format(s, "\n%Uid: %u", format_white_space, indent, a->id);
    s = format(s, "\n%Uip_proto: %U", format_white_space, indent, format_vl_api_ip_proto_t, &a->ip_proto, indent);
    s = format(s, "\n%Uis_real_ip: %u", format_white_space, indent, a->is_real_ip);
    s = format(s, "\n%Uflags: %u", format_white_space, indent, a->flags);
    s = format(s, "\n%Ulb_type: %U", format_white_space, indent, format_vl_api_cnat_lb_type_t, &a->lb_type, indent);
    s = format(s, "\n%Un_paths: %u", format_white_space, indent, a->n_paths);
    s = format(s, "\n%Uflow_hash_config: %U", format_white_space, indent, format_vl_api_ip_flow_hash_config_v2_t, &a->flow_hash_config, indent);
    for (i = 0; i < a->n_paths; i++) {
        s = format(s, "\n%Upaths: %U",
                   format_white_space, indent, format_vl_api_cnat_endpoint_tuple_t, &a->paths[i], indent);
    }
    return s;
}

static inline u8 *format_vl_api_cnat_session_t (u8 *s, va_list * args)
{
    vl_api_cnat_session_t *a = va_arg (*args, vl_api_cnat_session_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Usrc: %U", format_white_space, indent, format_vl_api_cnat_endpoint_t, &a->src, indent);
    s = format(s, "\n%Udst: %U", format_white_space, indent, format_vl_api_cnat_endpoint_t, &a->dst, indent);
    s = format(s, "\n%Unew: %U", format_white_space, indent, format_vl_api_cnat_endpoint_t, &a->new, indent);
    s = format(s, "\n%Uip_proto: %U", format_white_space, indent, format_vl_api_ip_proto_t, &a->ip_proto, indent);
    s = format(s, "\n%Ulocation: %u", format_white_space, indent, a->location);
    s = format(s, "\n%Utimestamp: %.2f", format_white_space, indent, a->timestamp);
    return s;
}

static inline u8 *format_vl_api_cnat_snat_policy_table_t (u8 *s, va_list * args)
{
    vl_api_cnat_snat_policy_table_t *a = va_arg (*args, vl_api_cnat_snat_policy_table_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "CNAT_POLICY_INCLUDE_V4");
    case 1:
        return format(s, "CNAT_POLICY_INCLUDE_V6");
    case 2:
        return format(s, "CNAT_POLICY_POD");
    case 3:
        return format(s, "CNAT_POLICY_HOST");
    }
    return s;
}

static inline u8 *format_vl_api_cnat_snat_policies_t (u8 *s, va_list * args)
{
    vl_api_cnat_snat_policies_t *a = va_arg (*args, vl_api_cnat_snat_policies_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "CNAT_POLICY_NONE");
    case 1:
        return format(s, "CNAT_POLICY_IF_PFX");
    case 2:
        return format(s, "CNAT_POLICY_K8S");
    }
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_cnat_printfun
#define included_cnat_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "cnat.api_tojson.h"
#include "cnat.api_fromjson.h"

static inline u8 *vl_api_cnat_translation_update_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_cnat_translation_update_t *a = va_arg (*args, vl_api_cnat_translation_update_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_cnat_translation_update_t: */
    s = format(s, "vl_api_cnat_translation_update_t:");
    s = format(s, "\n%Utranslation: %U", format_white_space, indent, format_vl_api_cnat_translation_t, &a->translation, indent);
    return s;
}

static inline u8 *vl_api_cnat_translation_update_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_cnat_translation_update_reply_t *a = va_arg (*args, vl_api_cnat_translation_update_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_cnat_translation_update_reply_t: */
    s = format(s, "vl_api_cnat_translation_update_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uid: %u", format_white_space, indent, a->id);
    return s;
}

static inline u8 *vl_api_cnat_translation_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_cnat_translation_del_t *a = va_arg (*args, vl_api_cnat_translation_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_cnat_translation_del_t: */
    s = format(s, "vl_api_cnat_translation_del_t:");
    s = format(s, "\n%Uid: %u", format_white_space, indent, a->id);
    return s;
}

static inline u8 *vl_api_cnat_translation_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_cnat_translation_del_reply_t *a = va_arg (*args, vl_api_cnat_translation_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_cnat_translation_del_reply_t: */
    s = format(s, "vl_api_cnat_translation_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_cnat_translation_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_cnat_translation_details_t *a = va_arg (*args, vl_api_cnat_translation_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_cnat_translation_details_t: */
    s = format(s, "vl_api_cnat_translation_details_t:");
    s = format(s, "\n%Utranslation: %U", format_white_space, indent, format_vl_api_cnat_translation_t, &a->translation, indent);
    return s;
}

static inline u8 *vl_api_cnat_translation_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_cnat_translation_dump_t *a = va_arg (*args, vl_api_cnat_translation_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_cnat_translation_dump_t: */
    s = format(s, "vl_api_cnat_translation_dump_t:");
    return s;
}

static inline u8 *vl_api_cnat_session_purge_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_cnat_session_purge_t *a = va_arg (*args, vl_api_cnat_session_purge_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_cnat_session_purge_t: */
    s = format(s, "vl_api_cnat_session_purge_t:");
    return s;
}

static inline u8 *vl_api_cnat_session_purge_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_cnat_session_purge_reply_t *a = va_arg (*args, vl_api_cnat_session_purge_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_cnat_session_purge_reply_t: */
    s = format(s, "vl_api_cnat_session_purge_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_cnat_session_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_cnat_session_details_t *a = va_arg (*args, vl_api_cnat_session_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_cnat_session_details_t: */
    s = format(s, "vl_api_cnat_session_details_t:");
    s = format(s, "\n%Usession: %U", format_white_space, indent, format_vl_api_cnat_session_t, &a->session, indent);
    return s;
}

static inline u8 *vl_api_cnat_session_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_cnat_session_dump_t *a = va_arg (*args, vl_api_cnat_session_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_cnat_session_dump_t: */
    s = format(s, "vl_api_cnat_session_dump_t:");
    return s;
}

static inline u8 *vl_api_cnat_set_snat_addresses_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_cnat_set_snat_addresses_t *a = va_arg (*args, vl_api_cnat_set_snat_addresses_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_cnat_set_snat_addresses_t: */
    s = format(s, "vl_api_cnat_set_snat_addresses_t:");
    s = format(s, "\n%Usnat_ip4: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->snat_ip4, indent);
    s = format(s, "\n%Usnat_ip6: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->snat_ip6, indent);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_cnat_set_snat_addresses_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_cnat_set_snat_addresses_reply_t *a = va_arg (*args, vl_api_cnat_set_snat_addresses_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_cnat_set_snat_addresses_reply_t: */
    s = format(s, "vl_api_cnat_set_snat_addresses_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_cnat_get_snat_addresses_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_cnat_get_snat_addresses_t *a = va_arg (*args, vl_api_cnat_get_snat_addresses_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_cnat_get_snat_addresses_t: */
    s = format(s, "vl_api_cnat_get_snat_addresses_t:");
    return s;
}

static inline u8 *vl_api_cnat_get_snat_addresses_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_cnat_get_snat_addresses_reply_t *a = va_arg (*args, vl_api_cnat_get_snat_addresses_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_cnat_get_snat_addresses_reply_t: */
    s = format(s, "vl_api_cnat_get_snat_addresses_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uid: %u", format_white_space, indent, a->id);
    s = format(s, "\n%Usnat_ip4: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->snat_ip4, indent);
    s = format(s, "\n%Usnat_ip6: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->snat_ip6, indent);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_cnat_snat_policy_add_del_exclude_pfx_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_cnat_snat_policy_add_del_exclude_pfx_t *a = va_arg (*args, vl_api_cnat_snat_policy_add_del_exclude_pfx_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_cnat_snat_policy_add_del_exclude_pfx_t: */
    s = format(s, "vl_api_cnat_snat_policy_add_del_exclude_pfx_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uprefix: %U", format_white_space, indent, format_vl_api_prefix_t, &a->prefix, indent);
    return s;
}

static inline u8 *vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t *a = va_arg (*args, vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t: */
    s = format(s, "vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_cnat_snat_policy_add_del_if_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_cnat_snat_policy_add_del_if_t *a = va_arg (*args, vl_api_cnat_snat_policy_add_del_if_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_cnat_snat_policy_add_del_if_t: */
    s = format(s, "vl_api_cnat_snat_policy_add_del_if_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Utable: %U", format_white_space, indent, format_vl_api_cnat_snat_policy_table_t, &a->table, indent);
    return s;
}

static inline u8 *vl_api_cnat_snat_policy_add_del_if_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_cnat_snat_policy_add_del_if_reply_t *a = va_arg (*args, vl_api_cnat_snat_policy_add_del_if_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_cnat_snat_policy_add_del_if_reply_t: */
    s = format(s, "vl_api_cnat_snat_policy_add_del_if_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_cnat_set_snat_policy_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_cnat_set_snat_policy_t *a = va_arg (*args, vl_api_cnat_set_snat_policy_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_cnat_set_snat_policy_t: */
    s = format(s, "vl_api_cnat_set_snat_policy_t:");
    s = format(s, "\n%Upolicy: %U", format_white_space, indent, format_vl_api_cnat_snat_policies_t, &a->policy, indent);
    return s;
}

static inline u8 *vl_api_cnat_set_snat_policy_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_cnat_set_snat_policy_reply_t *a = va_arg (*args, vl_api_cnat_set_snat_policy_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_cnat_set_snat_policy_reply_t: */
    s = format(s, "vl_api_cnat_set_snat_policy_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_cnat_endianfun
#define included_cnat_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_cnat_translation_flags_t_endian (vl_api_cnat_translation_flags_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->cnat_translation_flags = a->cnat_translation_flags (no-op) */
}

static inline void vl_api_cnat_endpoint_tuple_flags_t_endian (vl_api_cnat_endpoint_tuple_flags_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->cnat_endpoint_tuple_flags = a->cnat_endpoint_tuple_flags (no-op) */
}

static inline void vl_api_cnat_lb_type_t_endian (vl_api_cnat_lb_type_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->cnat_lb_type = a->cnat_lb_type (no-op) */
}

static inline void vl_api_cnat_endpoint_t_endian (vl_api_cnat_endpoint_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_address_t_endian(&a->addr, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    vl_api_address_family_t_endian(&a->if_af, to_net);
    a->port = clib_net_to_host_u16(a->port);
}

static inline void vl_api_cnat_endpoint_tuple_t_endian (vl_api_cnat_endpoint_tuple_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_cnat_endpoint_t_endian(&a->dst_ep, to_net);
    vl_api_cnat_endpoint_t_endian(&a->src_ep, to_net);
    /* a->flags = a->flags (no-op) */
}

static inline void vl_api_cnat_translation_t_endian (vl_api_cnat_translation_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_cnat_endpoint_t_endian(&a->vip, to_net);
    a->id = clib_net_to_host_u32(a->id);
    vl_api_ip_proto_t_endian(&a->ip_proto, to_net);
    /* a->is_real_ip = a->is_real_ip (no-op) */
    /* a->flags = a->flags (no-op) */
    vl_api_cnat_lb_type_t_endian(&a->lb_type, to_net);
    a->n_paths = clib_net_to_host_u32(a->n_paths);
    vl_api_ip_flow_hash_config_v2_t_endian(&a->flow_hash_config, to_net);
    u32 count = to_net ? clib_net_to_host_u32(a->n_paths) : a->n_paths;
    for (i = 0; i < count; i++) {
        vl_api_cnat_endpoint_tuple_t_endian(&a->paths[i], to_net);
    }
}

static inline void vl_api_cnat_session_t_endian (vl_api_cnat_session_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_cnat_endpoint_t_endian(&a->src, to_net);
    vl_api_cnat_endpoint_t_endian(&a->dst, to_net);
    vl_api_cnat_endpoint_t_endian(&a->new, to_net);
    vl_api_ip_proto_t_endian(&a->ip_proto, to_net);
    /* a->location = a->location (no-op) */
    a->timestamp = clib_net_to_host_f64(a->timestamp);
}

static inline void vl_api_cnat_snat_policy_table_t_endian (vl_api_cnat_snat_policy_table_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->cnat_snat_policy_table = a->cnat_snat_policy_table (no-op) */
}

static inline void vl_api_cnat_snat_policies_t_endian (vl_api_cnat_snat_policies_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->cnat_snat_policies = a->cnat_snat_policies (no-op) */
}

static inline void vl_api_cnat_translation_update_t_endian (vl_api_cnat_translation_update_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_cnat_translation_t_endian(&a->translation, to_net);
}

static inline void vl_api_cnat_translation_update_reply_t_endian (vl_api_cnat_translation_update_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->id = clib_net_to_host_u32(a->id);
}

static inline void vl_api_cnat_translation_del_t_endian (vl_api_cnat_translation_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->id = clib_net_to_host_u32(a->id);
}

static inline void vl_api_cnat_translation_del_reply_t_endian (vl_api_cnat_translation_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_cnat_translation_details_t_endian (vl_api_cnat_translation_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_cnat_translation_t_endian(&a->translation, to_net);
}

static inline void vl_api_cnat_translation_dump_t_endian (vl_api_cnat_translation_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_cnat_session_purge_t_endian (vl_api_cnat_session_purge_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_cnat_session_purge_reply_t_endian (vl_api_cnat_session_purge_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_cnat_session_details_t_endian (vl_api_cnat_session_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_cnat_session_t_endian(&a->session, to_net);
}

static inline void vl_api_cnat_session_dump_t_endian (vl_api_cnat_session_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_cnat_set_snat_addresses_t_endian (vl_api_cnat_set_snat_addresses_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->snat_ip4, to_net);
    vl_api_ip6_address_t_endian(&a->snat_ip6, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_cnat_set_snat_addresses_reply_t_endian (vl_api_cnat_set_snat_addresses_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_cnat_get_snat_addresses_t_endian (vl_api_cnat_get_snat_addresses_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_cnat_get_snat_addresses_reply_t_endian (vl_api_cnat_get_snat_addresses_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->id = clib_net_to_host_u32(a->id);
    vl_api_ip4_address_t_endian(&a->snat_ip4, to_net);
    vl_api_ip6_address_t_endian(&a->snat_ip6, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_cnat_snat_policy_add_del_exclude_pfx_t_endian (vl_api_cnat_snat_policy_add_del_exclude_pfx_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_prefix_t_endian(&a->prefix, to_net);
}

static inline void vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t_endian (vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_cnat_snat_policy_add_del_if_t_endian (vl_api_cnat_snat_policy_add_del_if_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->is_add = a->is_add (no-op) */
    vl_api_cnat_snat_policy_table_t_endian(&a->table, to_net);
}

static inline void vl_api_cnat_snat_policy_add_del_if_reply_t_endian (vl_api_cnat_snat_policy_add_del_if_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_cnat_set_snat_policy_t_endian (vl_api_cnat_set_snat_policy_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_cnat_snat_policies_t_endian(&a->policy, to_net);
}

static inline void vl_api_cnat_set_snat_policy_reply_t_endian (vl_api_cnat_set_snat_policy_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_cnat_calcsizefun
#define included_cnat_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_cnat_translation_flags_t_calc_size (vl_api_cnat_translation_flags_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_cnat_endpoint_tuple_flags_t_calc_size (vl_api_cnat_endpoint_tuple_flags_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_cnat_lb_type_t_calc_size (vl_api_cnat_lb_type_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_cnat_endpoint_t_calc_size (vl_api_cnat_endpoint_t *a)
{
      return sizeof(*a) - sizeof(a->addr) + vl_api_address_t_calc_size(&a->addr) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->if_af) + vl_api_address_family_t_calc_size(&a->if_af);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_cnat_endpoint_tuple_t_calc_size (vl_api_cnat_endpoint_tuple_t *a)
{
      return sizeof(*a) - sizeof(a->dst_ep) + vl_api_cnat_endpoint_t_calc_size(&a->dst_ep) - sizeof(a->src_ep) + vl_api_cnat_endpoint_t_calc_size(&a->src_ep);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_cnat_translation_t_calc_size (vl_api_cnat_translation_t *a)
{
      return sizeof(*a) - sizeof(a->vip) + vl_api_cnat_endpoint_t_calc_size(&a->vip) - sizeof(a->ip_proto) + vl_api_ip_proto_t_calc_size(&a->ip_proto) - sizeof(a->lb_type) + vl_api_cnat_lb_type_t_calc_size(&a->lb_type) - sizeof(a->flow_hash_config) + vl_api_ip_flow_hash_config_v2_t_calc_size(&a->flow_hash_config) + clib_net_to_host_u32(a->n_paths) * sizeof(a->paths[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_cnat_session_t_calc_size (vl_api_cnat_session_t *a)
{
      return sizeof(*a) - sizeof(a->src) + vl_api_cnat_endpoint_t_calc_size(&a->src) - sizeof(a->dst) + vl_api_cnat_endpoint_t_calc_size(&a->dst) - sizeof(a->new) + vl_api_cnat_endpoint_t_calc_size(&a->new) - sizeof(a->ip_proto) + vl_api_ip_proto_t_calc_size(&a->ip_proto);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_cnat_snat_policy_table_t_calc_size (vl_api_cnat_snat_policy_table_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_cnat_snat_policies_t_calc_size (vl_api_cnat_snat_policies_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_cnat_translation_update_t_calc_size (vl_api_cnat_translation_update_t *a)
{
      return sizeof(*a) - sizeof(a->translation) + vl_api_cnat_translation_t_calc_size(&a->translation);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_cnat_translation_update_reply_t_calc_size (vl_api_cnat_translation_update_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_cnat_translation_del_t_calc_size (vl_api_cnat_translation_del_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_cnat_translation_del_reply_t_calc_size (vl_api_cnat_translation_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_cnat_translation_details_t_calc_size (vl_api_cnat_translation_details_t *a)
{
      return sizeof(*a) - sizeof(a->translation) + vl_api_cnat_translation_t_calc_size(&a->translation);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_cnat_translation_dump_t_calc_size (vl_api_cnat_translation_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_cnat_session_purge_t_calc_size (vl_api_cnat_session_purge_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_cnat_session_purge_reply_t_calc_size (vl_api_cnat_session_purge_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_cnat_session_details_t_calc_size (vl_api_cnat_session_details_t *a)
{
      return sizeof(*a) - sizeof(a->session) + vl_api_cnat_session_t_calc_size(&a->session);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_cnat_session_dump_t_calc_size (vl_api_cnat_session_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_cnat_set_snat_addresses_t_calc_size (vl_api_cnat_set_snat_addresses_t *a)
{
      return sizeof(*a) - sizeof(a->snat_ip4) + vl_api_ip4_address_t_calc_size(&a->snat_ip4) - sizeof(a->snat_ip6) + vl_api_ip6_address_t_calc_size(&a->snat_ip6) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_cnat_set_snat_addresses_reply_t_calc_size (vl_api_cnat_set_snat_addresses_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_cnat_get_snat_addresses_t_calc_size (vl_api_cnat_get_snat_addresses_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_cnat_get_snat_addresses_reply_t_calc_size (vl_api_cnat_get_snat_addresses_reply_t *a)
{
      return sizeof(*a) - sizeof(a->snat_ip4) + vl_api_ip4_address_t_calc_size(&a->snat_ip4) - sizeof(a->snat_ip6) + vl_api_ip6_address_t_calc_size(&a->snat_ip6) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_cnat_snat_policy_add_del_exclude_pfx_t_calc_size (vl_api_cnat_snat_policy_add_del_exclude_pfx_t *a)
{
      return sizeof(*a) - sizeof(a->prefix) + vl_api_prefix_t_calc_size(&a->prefix);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t_calc_size (vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_cnat_snat_policy_add_del_if_t_calc_size (vl_api_cnat_snat_policy_add_del_if_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->table) + vl_api_cnat_snat_policy_table_t_calc_size(&a->table);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_cnat_snat_policy_add_del_if_reply_t_calc_size (vl_api_cnat_snat_policy_add_del_if_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_cnat_set_snat_policy_t_calc_size (vl_api_cnat_set_snat_policy_t *a)
{
      return sizeof(*a) - sizeof(a->policy) + vl_api_cnat_snat_policies_t_calc_size(&a->policy);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_cnat_set_snat_policy_reply_t_calc_size (vl_api_cnat_set_snat_policy_reply_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(cnat.api, 0, 3, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(cnat.api, 0x10708a40)

#endif

