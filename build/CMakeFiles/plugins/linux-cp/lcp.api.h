/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: lcp.api
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
#warning no content included from lcp.api
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
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_LCP_DEFAULT_NS_SET, vl_api_lcp_default_ns_set_t_handler)
vl_msg_id(VL_API_LCP_DEFAULT_NS_SET_REPLY, vl_api_lcp_default_ns_set_reply_t_handler)
vl_msg_id(VL_API_LCP_DEFAULT_NS_GET, vl_api_lcp_default_ns_get_t_handler)
vl_msg_id(VL_API_LCP_DEFAULT_NS_GET_REPLY, vl_api_lcp_default_ns_get_reply_t_handler)
vl_msg_id(VL_API_LCP_ITF_PAIR_ADD_DEL, vl_api_lcp_itf_pair_add_del_t_handler)
vl_msg_id(VL_API_LCP_ITF_PAIR_ADD_DEL_REPLY, vl_api_lcp_itf_pair_add_del_reply_t_handler)
vl_msg_id(VL_API_LCP_ITF_PAIR_ADD_DEL_V2, vl_api_lcp_itf_pair_add_del_v2_t_handler)
vl_msg_id(VL_API_LCP_ITF_PAIR_ADD_DEL_V2_REPLY, vl_api_lcp_itf_pair_add_del_v2_reply_t_handler)
vl_msg_id(VL_API_LCP_ITF_PAIR_ADD_DEL_V3, vl_api_lcp_itf_pair_add_del_v3_t_handler)
vl_msg_id(VL_API_LCP_ITF_PAIR_ADD_DEL_V3_REPLY, vl_api_lcp_itf_pair_add_del_v3_reply_t_handler)
vl_msg_id(VL_API_LCP_ITF_PAIR_GET, vl_api_lcp_itf_pair_get_t_handler)
vl_msg_id(VL_API_LCP_ITF_PAIR_GET_REPLY, vl_api_lcp_itf_pair_get_reply_t_handler)
vl_msg_id(VL_API_LCP_ITF_PAIR_GET_V2, vl_api_lcp_itf_pair_get_v2_t_handler)
vl_msg_id(VL_API_LCP_ITF_PAIR_GET_V2_REPLY, vl_api_lcp_itf_pair_get_v2_reply_t_handler)
vl_msg_id(VL_API_LCP_ITF_PAIR_DETAILS, vl_api_lcp_itf_pair_details_t_handler)
vl_msg_id(VL_API_LCP_ETHERTYPE_ENABLE, vl_api_lcp_ethertype_enable_t_handler)
vl_msg_id(VL_API_LCP_ETHERTYPE_ENABLE_REPLY, vl_api_lcp_ethertype_enable_reply_t_handler)
vl_msg_id(VL_API_LCP_ETHERTYPE_GET, vl_api_lcp_ethertype_get_t_handler)
vl_msg_id(VL_API_LCP_ETHERTYPE_GET_REPLY, vl_api_lcp_ethertype_get_reply_t_handler)
vl_msg_id(VL_API_LCP_ITF_PAIR_REPLACE_BEGIN, vl_api_lcp_itf_pair_replace_begin_t_handler)
vl_msg_id(VL_API_LCP_ITF_PAIR_REPLACE_BEGIN_REPLY, vl_api_lcp_itf_pair_replace_begin_reply_t_handler)
vl_msg_id(VL_API_LCP_ITF_PAIR_REPLACE_END, vl_api_lcp_itf_pair_replace_end_t_handler)
vl_msg_id(VL_API_LCP_ITF_PAIR_REPLACE_END_REPLY, vl_api_lcp_itf_pair_replace_end_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_lcp_default_ns_set_t, 1)
vl_msg_name(vl_api_lcp_default_ns_set_reply_t, 1)
vl_msg_name(vl_api_lcp_default_ns_get_t, 1)
vl_msg_name(vl_api_lcp_default_ns_get_reply_t, 1)
vl_msg_name(vl_api_lcp_itf_pair_add_del_t, 1)
vl_msg_name(vl_api_lcp_itf_pair_add_del_reply_t, 1)
vl_msg_name(vl_api_lcp_itf_pair_add_del_v2_t, 1)
vl_msg_name(vl_api_lcp_itf_pair_add_del_v2_reply_t, 1)
vl_msg_name(vl_api_lcp_itf_pair_add_del_v3_t, 1)
vl_msg_name(vl_api_lcp_itf_pair_add_del_v3_reply_t, 1)
vl_msg_name(vl_api_lcp_itf_pair_get_t, 1)
vl_msg_name(vl_api_lcp_itf_pair_get_reply_t, 1)
vl_msg_name(vl_api_lcp_itf_pair_get_v2_t, 1)
vl_msg_name(vl_api_lcp_itf_pair_get_v2_reply_t, 1)
vl_msg_name(vl_api_lcp_itf_pair_details_t, 1)
vl_msg_name(vl_api_lcp_ethertype_enable_t, 1)
vl_msg_name(vl_api_lcp_ethertype_enable_reply_t, 1)
vl_msg_name(vl_api_lcp_ethertype_get_t, 1)
vl_msg_name(vl_api_lcp_ethertype_get_reply_t, 1)
vl_msg_name(vl_api_lcp_itf_pair_replace_begin_t, 1)
vl_msg_name(vl_api_lcp_itf_pair_replace_begin_reply_t, 1)
vl_msg_name(vl_api_lcp_itf_pair_replace_end_t, 1)
vl_msg_name(vl_api_lcp_itf_pair_replace_end_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_lcp \
_(VL_API_LCP_DEFAULT_NS_SET, lcp_default_ns_set, 69749409) \
_(VL_API_LCP_DEFAULT_NS_SET_REPLY, lcp_default_ns_set_reply, e8d4e804) \
_(VL_API_LCP_DEFAULT_NS_GET, lcp_default_ns_get, 51077d14) \
_(VL_API_LCP_DEFAULT_NS_GET_REPLY, lcp_default_ns_get_reply, 5102feee) \
_(VL_API_LCP_ITF_PAIR_ADD_DEL, lcp_itf_pair_add_del, 40482b80) \
_(VL_API_LCP_ITF_PAIR_ADD_DEL_REPLY, lcp_itf_pair_add_del_reply, e8d4e804) \
_(VL_API_LCP_ITF_PAIR_ADD_DEL_V2, lcp_itf_pair_add_del_v2, 40482b80) \
_(VL_API_LCP_ITF_PAIR_ADD_DEL_V2_REPLY, lcp_itf_pair_add_del_v2_reply, 39452f52) \
_(VL_API_LCP_ITF_PAIR_ADD_DEL_V3, lcp_itf_pair_add_del_v3, 40482b80) \
_(VL_API_LCP_ITF_PAIR_ADD_DEL_V3_REPLY, lcp_itf_pair_add_del_v3_reply, c2502663) \
_(VL_API_LCP_ITF_PAIR_GET, lcp_itf_pair_get, f75ba505) \
_(VL_API_LCP_ITF_PAIR_GET_REPLY, lcp_itf_pair_get_reply, 53b48f5d) \
_(VL_API_LCP_ITF_PAIR_GET_V2, lcp_itf_pair_get_v2, 47250981) \
_(VL_API_LCP_ITF_PAIR_GET_V2_REPLY, lcp_itf_pair_get_v2_reply, 53b48f5d) \
_(VL_API_LCP_ITF_PAIR_DETAILS, lcp_itf_pair_details, 8b5481af) \
_(VL_API_LCP_ETHERTYPE_ENABLE, lcp_ethertype_enable, f893dae1) \
_(VL_API_LCP_ETHERTYPE_ENABLE_REPLY, lcp_ethertype_enable_reply, e8d4e804) \
_(VL_API_LCP_ETHERTYPE_GET, lcp_ethertype_get, 51077d14) \
_(VL_API_LCP_ETHERTYPE_GET_REPLY, lcp_ethertype_get_reply, db48c31e) \
_(VL_API_LCP_ITF_PAIR_REPLACE_BEGIN, lcp_itf_pair_replace_begin, 51077d14) \
_(VL_API_LCP_ITF_PAIR_REPLACE_BEGIN_REPLY, lcp_itf_pair_replace_begin_reply, e8d4e804) \
_(VL_API_LCP_ITF_PAIR_REPLACE_END, lcp_itf_pair_replace_end, 51077d14) \
_(VL_API_LCP_ITF_PAIR_REPLACE_END_REPLY, lcp_itf_pair_replace_end_reply, e8d4e804) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "lcp.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_lcp_printfun_types
#define included_lcp_printfun_types

static inline u8 *format_vl_api_lcp_itf_host_type_t (u8 *s, va_list * args)
{
    vl_api_lcp_itf_host_type_t *a = va_arg (*args, vl_api_lcp_itf_host_type_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "LCP_API_ITF_HOST_TAP");
    case 1:
        return format(s, "LCP_API_ITF_HOST_TUN");
    }
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_lcp_printfun
#define included_lcp_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "lcp.api_tojson.h"
#include "lcp.api_fromjson.h"

static inline u8 *vl_api_lcp_default_ns_set_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lcp_default_ns_set_t *a = va_arg (*args, vl_api_lcp_default_ns_set_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lcp_default_ns_set_t: */
    s = format(s, "vl_api_lcp_default_ns_set_t:");
    s = format(s, "\n%Unetns: %s", format_white_space, indent, a->netns);
    return s;
}

static inline u8 *vl_api_lcp_default_ns_set_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lcp_default_ns_set_reply_t *a = va_arg (*args, vl_api_lcp_default_ns_set_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lcp_default_ns_set_reply_t: */
    s = format(s, "vl_api_lcp_default_ns_set_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_lcp_default_ns_get_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lcp_default_ns_get_t *a = va_arg (*args, vl_api_lcp_default_ns_get_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lcp_default_ns_get_t: */
    s = format(s, "vl_api_lcp_default_ns_get_t:");
    return s;
}

static inline u8 *vl_api_lcp_default_ns_get_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lcp_default_ns_get_reply_t *a = va_arg (*args, vl_api_lcp_default_ns_get_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lcp_default_ns_get_reply_t: */
    s = format(s, "vl_api_lcp_default_ns_get_reply_t:");
    s = format(s, "\n%Unetns: %s", format_white_space, indent, a->netns);
    return s;
}

static inline u8 *vl_api_lcp_itf_pair_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lcp_itf_pair_add_del_t *a = va_arg (*args, vl_api_lcp_itf_pair_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lcp_itf_pair_add_del_t: */
    s = format(s, "vl_api_lcp_itf_pair_add_del_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uhost_if_name: %s", format_white_space, indent, a->host_if_name);
    s = format(s, "\n%Uhost_if_type: %U", format_white_space, indent, format_vl_api_lcp_itf_host_type_t, &a->host_if_type, indent);
    s = format(s, "\n%Unetns: %s", format_white_space, indent, a->netns);
    return s;
}

static inline u8 *vl_api_lcp_itf_pair_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lcp_itf_pair_add_del_reply_t *a = va_arg (*args, vl_api_lcp_itf_pair_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lcp_itf_pair_add_del_reply_t: */
    s = format(s, "vl_api_lcp_itf_pair_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_lcp_itf_pair_add_del_v2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lcp_itf_pair_add_del_v2_t *a = va_arg (*args, vl_api_lcp_itf_pair_add_del_v2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lcp_itf_pair_add_del_v2_t: */
    s = format(s, "vl_api_lcp_itf_pair_add_del_v2_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uhost_if_name: %s", format_white_space, indent, a->host_if_name);
    s = format(s, "\n%Uhost_if_type: %U", format_white_space, indent, format_vl_api_lcp_itf_host_type_t, &a->host_if_type, indent);
    s = format(s, "\n%Unetns: %s", format_white_space, indent, a->netns);
    return s;
}

static inline u8 *vl_api_lcp_itf_pair_add_del_v2_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lcp_itf_pair_add_del_v2_reply_t *a = va_arg (*args, vl_api_lcp_itf_pair_add_del_v2_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lcp_itf_pair_add_del_v2_reply_t: */
    s = format(s, "vl_api_lcp_itf_pair_add_del_v2_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uhost_sw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->host_sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_lcp_itf_pair_add_del_v3_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lcp_itf_pair_add_del_v3_t *a = va_arg (*args, vl_api_lcp_itf_pair_add_del_v3_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lcp_itf_pair_add_del_v3_t: */
    s = format(s, "vl_api_lcp_itf_pair_add_del_v3_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uhost_if_name: %s", format_white_space, indent, a->host_if_name);
    s = format(s, "\n%Uhost_if_type: %U", format_white_space, indent, format_vl_api_lcp_itf_host_type_t, &a->host_if_type, indent);
    s = format(s, "\n%Unetns: %s", format_white_space, indent, a->netns);
    return s;
}

static inline u8 *vl_api_lcp_itf_pair_add_del_v3_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lcp_itf_pair_add_del_v3_reply_t *a = va_arg (*args, vl_api_lcp_itf_pair_add_del_v3_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lcp_itf_pair_add_del_v3_reply_t: */
    s = format(s, "vl_api_lcp_itf_pair_add_del_v3_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uvif_index: %u", format_white_space, indent, a->vif_index);
    s = format(s, "\n%Uhost_sw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->host_sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_lcp_itf_pair_get_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lcp_itf_pair_get_t *a = va_arg (*args, vl_api_lcp_itf_pair_get_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lcp_itf_pair_get_t: */
    s = format(s, "vl_api_lcp_itf_pair_get_t:");
    s = format(s, "\n%Ucursor: %u", format_white_space, indent, a->cursor);
    return s;
}

static inline u8 *vl_api_lcp_itf_pair_get_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lcp_itf_pair_get_reply_t *a = va_arg (*args, vl_api_lcp_itf_pair_get_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lcp_itf_pair_get_reply_t: */
    s = format(s, "vl_api_lcp_itf_pair_get_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ucursor: %u", format_white_space, indent, a->cursor);
    return s;
}

static inline u8 *vl_api_lcp_itf_pair_get_v2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lcp_itf_pair_get_v2_t *a = va_arg (*args, vl_api_lcp_itf_pair_get_v2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lcp_itf_pair_get_v2_t: */
    s = format(s, "vl_api_lcp_itf_pair_get_v2_t:");
    s = format(s, "\n%Ucursor: %u", format_white_space, indent, a->cursor);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_lcp_itf_pair_get_v2_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lcp_itf_pair_get_v2_reply_t *a = va_arg (*args, vl_api_lcp_itf_pair_get_v2_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lcp_itf_pair_get_v2_reply_t: */
    s = format(s, "vl_api_lcp_itf_pair_get_v2_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ucursor: %u", format_white_space, indent, a->cursor);
    return s;
}

static inline u8 *vl_api_lcp_itf_pair_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lcp_itf_pair_details_t *a = va_arg (*args, vl_api_lcp_itf_pair_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lcp_itf_pair_details_t: */
    s = format(s, "vl_api_lcp_itf_pair_details_t:");
    s = format(s, "\n%Uphy_sw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->phy_sw_if_index, indent);
    s = format(s, "\n%Uhost_sw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->host_sw_if_index, indent);
    s = format(s, "\n%Uvif_index: %u", format_white_space, indent, a->vif_index);
    s = format(s, "\n%Uhost_if_name: %s", format_white_space, indent, a->host_if_name);
    s = format(s, "\n%Uhost_if_type: %U", format_white_space, indent, format_vl_api_lcp_itf_host_type_t, &a->host_if_type, indent);
    s = format(s, "\n%Unetns: %s", format_white_space, indent, a->netns);
    return s;
}

static inline u8 *vl_api_lcp_ethertype_enable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lcp_ethertype_enable_t *a = va_arg (*args, vl_api_lcp_ethertype_enable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lcp_ethertype_enable_t: */
    s = format(s, "vl_api_lcp_ethertype_enable_t:");
    s = format(s, "\n%Uethertype: %u", format_white_space, indent, a->ethertype);
    return s;
}

static inline u8 *vl_api_lcp_ethertype_enable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lcp_ethertype_enable_reply_t *a = va_arg (*args, vl_api_lcp_ethertype_enable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lcp_ethertype_enable_reply_t: */
    s = format(s, "vl_api_lcp_ethertype_enable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_lcp_ethertype_get_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lcp_ethertype_get_t *a = va_arg (*args, vl_api_lcp_ethertype_get_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lcp_ethertype_get_t: */
    s = format(s, "vl_api_lcp_ethertype_get_t:");
    return s;
}

static inline u8 *vl_api_lcp_ethertype_get_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lcp_ethertype_get_reply_t *a = va_arg (*args, vl_api_lcp_ethertype_get_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lcp_ethertype_get_reply_t: */
    s = format(s, "vl_api_lcp_ethertype_get_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ucount: %u", format_white_space, indent, a->count);
    for (i = 0; i < a->count; i++) {
        s = format(s, "\n%Uethertypes: %u",
                   format_white_space, indent, a->ethertypes[i]);
    }
    return s;
}

static inline u8 *vl_api_lcp_itf_pair_replace_begin_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lcp_itf_pair_replace_begin_t *a = va_arg (*args, vl_api_lcp_itf_pair_replace_begin_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lcp_itf_pair_replace_begin_t: */
    s = format(s, "vl_api_lcp_itf_pair_replace_begin_t:");
    return s;
}

static inline u8 *vl_api_lcp_itf_pair_replace_begin_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lcp_itf_pair_replace_begin_reply_t *a = va_arg (*args, vl_api_lcp_itf_pair_replace_begin_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lcp_itf_pair_replace_begin_reply_t: */
    s = format(s, "vl_api_lcp_itf_pair_replace_begin_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_lcp_itf_pair_replace_end_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lcp_itf_pair_replace_end_t *a = va_arg (*args, vl_api_lcp_itf_pair_replace_end_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lcp_itf_pair_replace_end_t: */
    s = format(s, "vl_api_lcp_itf_pair_replace_end_t:");
    return s;
}

static inline u8 *vl_api_lcp_itf_pair_replace_end_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lcp_itf_pair_replace_end_reply_t *a = va_arg (*args, vl_api_lcp_itf_pair_replace_end_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lcp_itf_pair_replace_end_reply_t: */
    s = format(s, "vl_api_lcp_itf_pair_replace_end_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_lcp_endianfun
#define included_lcp_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_lcp_itf_host_type_t_endian (vl_api_lcp_itf_host_type_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->lcp_itf_host_type = a->lcp_itf_host_type (no-op) */
}

static inline void vl_api_lcp_default_ns_set_t_endian (vl_api_lcp_default_ns_set_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->netns = a->netns (no-op) */
}

static inline void vl_api_lcp_default_ns_set_reply_t_endian (vl_api_lcp_default_ns_set_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_lcp_default_ns_get_t_endian (vl_api_lcp_default_ns_get_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_lcp_default_ns_get_reply_t_endian (vl_api_lcp_default_ns_get_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    /* a->netns = a->netns (no-op) */
}

static inline void vl_api_lcp_itf_pair_add_del_t_endian (vl_api_lcp_itf_pair_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->host_if_name = a->host_if_name (no-op) */
    vl_api_lcp_itf_host_type_t_endian(&a->host_if_type, to_net);
    /* a->netns = a->netns (no-op) */
}

static inline void vl_api_lcp_itf_pair_add_del_reply_t_endian (vl_api_lcp_itf_pair_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_lcp_itf_pair_add_del_v2_t_endian (vl_api_lcp_itf_pair_add_del_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->host_if_name = a->host_if_name (no-op) */
    vl_api_lcp_itf_host_type_t_endian(&a->host_if_type, to_net);
    /* a->netns = a->netns (no-op) */
}

static inline void vl_api_lcp_itf_pair_add_del_v2_reply_t_endian (vl_api_lcp_itf_pair_add_del_v2_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_interface_index_t_endian(&a->host_sw_if_index, to_net);
}

static inline void vl_api_lcp_itf_pair_add_del_v3_t_endian (vl_api_lcp_itf_pair_add_del_v3_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->host_if_name = a->host_if_name (no-op) */
    vl_api_lcp_itf_host_type_t_endian(&a->host_if_type, to_net);
    /* a->netns = a->netns (no-op) */
}

static inline void vl_api_lcp_itf_pair_add_del_v3_reply_t_endian (vl_api_lcp_itf_pair_add_del_v3_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->vif_index = clib_net_to_host_u32(a->vif_index);
    vl_api_interface_index_t_endian(&a->host_sw_if_index, to_net);
}

static inline void vl_api_lcp_itf_pair_get_t_endian (vl_api_lcp_itf_pair_get_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->cursor = clib_net_to_host_u32(a->cursor);
}

static inline void vl_api_lcp_itf_pair_get_reply_t_endian (vl_api_lcp_itf_pair_get_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->cursor = clib_net_to_host_u32(a->cursor);
}

static inline void vl_api_lcp_itf_pair_get_v2_t_endian (vl_api_lcp_itf_pair_get_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->cursor = clib_net_to_host_u32(a->cursor);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_lcp_itf_pair_get_v2_reply_t_endian (vl_api_lcp_itf_pair_get_v2_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->cursor = clib_net_to_host_u32(a->cursor);
}

static inline void vl_api_lcp_itf_pair_details_t_endian (vl_api_lcp_itf_pair_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->phy_sw_if_index, to_net);
    vl_api_interface_index_t_endian(&a->host_sw_if_index, to_net);
    a->vif_index = clib_net_to_host_u32(a->vif_index);
    /* a->host_if_name = a->host_if_name (no-op) */
    vl_api_lcp_itf_host_type_t_endian(&a->host_if_type, to_net);
    /* a->netns = a->netns (no-op) */
}

static inline void vl_api_lcp_ethertype_enable_t_endian (vl_api_lcp_ethertype_enable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->ethertype = clib_net_to_host_u16(a->ethertype);
}

static inline void vl_api_lcp_ethertype_enable_reply_t_endian (vl_api_lcp_ethertype_enable_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_lcp_ethertype_get_t_endian (vl_api_lcp_ethertype_get_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_lcp_ethertype_get_reply_t_endian (vl_api_lcp_ethertype_get_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->count = clib_net_to_host_u16(a->count);
    u32 count = to_net ? clib_net_to_host_u16(a->count) : a->count;
    ASSERT((u32)count <= (u32)VL_API_MAX_ARRAY_SIZE);
    for (i = 0; i < count; i++) {
        a->ethertypes[i] = clib_net_to_host_u16(a->ethertypes[i]);
    }
}

static inline void vl_api_lcp_itf_pair_replace_begin_t_endian (vl_api_lcp_itf_pair_replace_begin_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_lcp_itf_pair_replace_begin_reply_t_endian (vl_api_lcp_itf_pair_replace_begin_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_lcp_itf_pair_replace_end_t_endian (vl_api_lcp_itf_pair_replace_end_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_lcp_itf_pair_replace_end_reply_t_endian (vl_api_lcp_itf_pair_replace_end_reply_t *a, bool to_net)
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
#ifndef included_lcp_calcsizefun
#define included_lcp_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_lcp_itf_host_type_t_calc_size (vl_api_lcp_itf_host_type_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lcp_default_ns_set_t_calc_size (vl_api_lcp_default_ns_set_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lcp_default_ns_set_reply_t_calc_size (vl_api_lcp_default_ns_set_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lcp_default_ns_get_t_calc_size (vl_api_lcp_default_ns_get_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lcp_default_ns_get_reply_t_calc_size (vl_api_lcp_default_ns_get_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lcp_itf_pair_add_del_t_calc_size (vl_api_lcp_itf_pair_add_del_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->host_if_type) + vl_api_lcp_itf_host_type_t_calc_size(&a->host_if_type);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lcp_itf_pair_add_del_reply_t_calc_size (vl_api_lcp_itf_pair_add_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lcp_itf_pair_add_del_v2_t_calc_size (vl_api_lcp_itf_pair_add_del_v2_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->host_if_type) + vl_api_lcp_itf_host_type_t_calc_size(&a->host_if_type);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lcp_itf_pair_add_del_v2_reply_t_calc_size (vl_api_lcp_itf_pair_add_del_v2_reply_t *a)
{
      return sizeof(*a) - sizeof(a->host_sw_if_index) + vl_api_interface_index_t_calc_size(&a->host_sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lcp_itf_pair_add_del_v3_t_calc_size (vl_api_lcp_itf_pair_add_del_v3_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->host_if_type) + vl_api_lcp_itf_host_type_t_calc_size(&a->host_if_type);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lcp_itf_pair_add_del_v3_reply_t_calc_size (vl_api_lcp_itf_pair_add_del_v3_reply_t *a)
{
      return sizeof(*a) - sizeof(a->host_sw_if_index) + vl_api_interface_index_t_calc_size(&a->host_sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lcp_itf_pair_get_t_calc_size (vl_api_lcp_itf_pair_get_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lcp_itf_pair_get_reply_t_calc_size (vl_api_lcp_itf_pair_get_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lcp_itf_pair_get_v2_t_calc_size (vl_api_lcp_itf_pair_get_v2_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lcp_itf_pair_get_v2_reply_t_calc_size (vl_api_lcp_itf_pair_get_v2_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lcp_itf_pair_details_t_calc_size (vl_api_lcp_itf_pair_details_t *a)
{
      return sizeof(*a) - sizeof(a->phy_sw_if_index) + vl_api_interface_index_t_calc_size(&a->phy_sw_if_index) - sizeof(a->host_sw_if_index) + vl_api_interface_index_t_calc_size(&a->host_sw_if_index) - sizeof(a->host_if_type) + vl_api_lcp_itf_host_type_t_calc_size(&a->host_if_type);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lcp_ethertype_enable_t_calc_size (vl_api_lcp_ethertype_enable_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lcp_ethertype_enable_reply_t_calc_size (vl_api_lcp_ethertype_enable_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lcp_ethertype_get_t_calc_size (vl_api_lcp_ethertype_get_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lcp_ethertype_get_reply_t_calc_size (vl_api_lcp_ethertype_get_reply_t *a)
{
      return sizeof(*a) + clib_net_to_host_u16(a->count) * sizeof(a->ethertypes[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lcp_itf_pair_replace_begin_t_calc_size (vl_api_lcp_itf_pair_replace_begin_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lcp_itf_pair_replace_begin_reply_t_calc_size (vl_api_lcp_itf_pair_replace_begin_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lcp_itf_pair_replace_end_t_calc_size (vl_api_lcp_itf_pair_replace_end_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lcp_itf_pair_replace_end_reply_t_calc_size (vl_api_lcp_itf_pair_replace_end_reply_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(lcp.api, 1, 0, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(lcp.api, 0xa76b917e)

#endif

