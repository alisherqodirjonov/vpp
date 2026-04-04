/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: pnat.api
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
#warning no content included from pnat.api
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
vl_msg_id(VL_API_PNAT_BINDING_ADD, vl_api_pnat_binding_add_t_handler)
vl_msg_id(VL_API_PNAT_BINDING_ADD_REPLY, vl_api_pnat_binding_add_reply_t_handler)
vl_msg_id(VL_API_PNAT_BINDING_ADD_V2, vl_api_pnat_binding_add_v2_t_handler)
vl_msg_id(VL_API_PNAT_BINDING_ADD_V2_REPLY, vl_api_pnat_binding_add_v2_reply_t_handler)
vl_msg_id(VL_API_PNAT_BINDING_DEL, vl_api_pnat_binding_del_t_handler)
vl_msg_id(VL_API_PNAT_BINDING_DEL_REPLY, vl_api_pnat_binding_del_reply_t_handler)
vl_msg_id(VL_API_PNAT_BINDING_ATTACH, vl_api_pnat_binding_attach_t_handler)
vl_msg_id(VL_API_PNAT_BINDING_ATTACH_REPLY, vl_api_pnat_binding_attach_reply_t_handler)
vl_msg_id(VL_API_PNAT_BINDING_DETACH, vl_api_pnat_binding_detach_t_handler)
vl_msg_id(VL_API_PNAT_BINDING_DETACH_REPLY, vl_api_pnat_binding_detach_reply_t_handler)
vl_msg_id(VL_API_PNAT_BINDINGS_GET, vl_api_pnat_bindings_get_t_handler)
vl_msg_id(VL_API_PNAT_BINDINGS_GET_REPLY, vl_api_pnat_bindings_get_reply_t_handler)
vl_msg_id(VL_API_PNAT_BINDINGS_DETAILS, vl_api_pnat_bindings_details_t_handler)
vl_msg_id(VL_API_PNAT_INTERFACES_GET, vl_api_pnat_interfaces_get_t_handler)
vl_msg_id(VL_API_PNAT_INTERFACES_GET_REPLY, vl_api_pnat_interfaces_get_reply_t_handler)
vl_msg_id(VL_API_PNAT_INTERFACES_DETAILS, vl_api_pnat_interfaces_details_t_handler)
vl_msg_id(VL_API_PNAT_FLOW_LOOKUP, vl_api_pnat_flow_lookup_t_handler)
vl_msg_id(VL_API_PNAT_FLOW_LOOKUP_REPLY, vl_api_pnat_flow_lookup_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_pnat_binding_add_t, 1)
vl_msg_name(vl_api_pnat_binding_add_reply_t, 1)
vl_msg_name(vl_api_pnat_binding_add_v2_t, 1)
vl_msg_name(vl_api_pnat_binding_add_v2_reply_t, 1)
vl_msg_name(vl_api_pnat_binding_del_t, 1)
vl_msg_name(vl_api_pnat_binding_del_reply_t, 1)
vl_msg_name(vl_api_pnat_binding_attach_t, 1)
vl_msg_name(vl_api_pnat_binding_attach_reply_t, 1)
vl_msg_name(vl_api_pnat_binding_detach_t, 1)
vl_msg_name(vl_api_pnat_binding_detach_reply_t, 1)
vl_msg_name(vl_api_pnat_bindings_get_t, 1)
vl_msg_name(vl_api_pnat_bindings_get_reply_t, 1)
vl_msg_name(vl_api_pnat_bindings_details_t, 1)
vl_msg_name(vl_api_pnat_interfaces_get_t, 1)
vl_msg_name(vl_api_pnat_interfaces_get_reply_t, 1)
vl_msg_name(vl_api_pnat_interfaces_details_t, 1)
vl_msg_name(vl_api_pnat_flow_lookup_t, 1)
vl_msg_name(vl_api_pnat_flow_lookup_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_pnat \
_(VL_API_PNAT_BINDING_ADD, pnat_binding_add, 946ee0b7) \
_(VL_API_PNAT_BINDING_ADD_REPLY, pnat_binding_add_reply, 4cd980a7) \
_(VL_API_PNAT_BINDING_ADD_V2, pnat_binding_add_v2, 946ee0b7) \
_(VL_API_PNAT_BINDING_ADD_V2_REPLY, pnat_binding_add_v2_reply, 4cd980a7) \
_(VL_API_PNAT_BINDING_DEL, pnat_binding_del, 9259df7b) \
_(VL_API_PNAT_BINDING_DEL_REPLY, pnat_binding_del_reply, e8d4e804) \
_(VL_API_PNAT_BINDING_ATTACH, pnat_binding_attach, 6e074232) \
_(VL_API_PNAT_BINDING_ATTACH_REPLY, pnat_binding_attach_reply, e8d4e804) \
_(VL_API_PNAT_BINDING_DETACH, pnat_binding_detach, 6e074232) \
_(VL_API_PNAT_BINDING_DETACH_REPLY, pnat_binding_detach_reply, e8d4e804) \
_(VL_API_PNAT_BINDINGS_GET, pnat_bindings_get, f75ba505) \
_(VL_API_PNAT_BINDINGS_GET_REPLY, pnat_bindings_get_reply, 53b48f5d) \
_(VL_API_PNAT_BINDINGS_DETAILS, pnat_bindings_details, 08fb2815) \
_(VL_API_PNAT_INTERFACES_GET, pnat_interfaces_get, f75ba505) \
_(VL_API_PNAT_INTERFACES_GET_REPLY, pnat_interfaces_get_reply, 53b48f5d) \
_(VL_API_PNAT_INTERFACES_DETAILS, pnat_interfaces_details, 4cb09493) \
_(VL_API_PNAT_FLOW_LOOKUP, pnat_flow_lookup, 1ef8747c) \
_(VL_API_PNAT_FLOW_LOOKUP_REPLY, pnat_flow_lookup_reply, 4cd980a7) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "pnat.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_pnat_printfun_types
#define included_pnat_printfun_types

static inline u8 *format_vl_api_pnat_mask_t (u8 *s, va_list * args)
{
    vl_api_pnat_mask_t *a = va_arg (*args, vl_api_pnat_mask_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 1:
        return format(s, "PNAT_SA");
    case 2:
        return format(s, "PNAT_DA");
    case 4:
        return format(s, "PNAT_SPORT");
    case 8:
        return format(s, "PNAT_DPORT");
    case 16:
        return format(s, "PNAT_COPY_BYTE");
    case 32:
        return format(s, "PNAT_CLEAR_BYTE");
    case 64:
        return format(s, "PNAT_PROTO");
    }
    return s;
}

static inline u8 *format_vl_api_pnat_attachment_point_t (u8 *s, va_list * args)
{
    vl_api_pnat_attachment_point_t *a = va_arg (*args, vl_api_pnat_attachment_point_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "PNAT_IP4_INPUT");
    case 1:
        return format(s, "PNAT_IP4_OUTPUT");
    case 2:
        return format(s, "PNAT_ATTACHMENT_POINT_MAX");
    }
    return s;
}

static inline u8 *format_vl_api_pnat_match_tuple_t (u8 *s, va_list * args)
{
    vl_api_pnat_match_tuple_t *a = va_arg (*args, vl_api_pnat_match_tuple_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Usrc: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->src, indent);
    s = format(s, "\n%Udst: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->dst, indent);
    s = format(s, "\n%Uproto: %U", format_white_space, indent, format_vl_api_ip_proto_t, &a->proto, indent);
    s = format(s, "\n%Usport: %u", format_white_space, indent, a->sport);
    s = format(s, "\n%Udport: %u", format_white_space, indent, a->dport);
    s = format(s, "\n%Umask: %U", format_white_space, indent, format_vl_api_pnat_mask_t, &a->mask, indent);
    return s;
}

static inline u8 *format_vl_api_pnat_rewrite_tuple_t (u8 *s, va_list * args)
{
    vl_api_pnat_rewrite_tuple_t *a = va_arg (*args, vl_api_pnat_rewrite_tuple_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Usrc: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->src, indent);
    s = format(s, "\n%Udst: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->dst, indent);
    s = format(s, "\n%Usport: %u", format_white_space, indent, a->sport);
    s = format(s, "\n%Udport: %u", format_white_space, indent, a->dport);
    s = format(s, "\n%Umask: %U", format_white_space, indent, format_vl_api_pnat_mask_t, &a->mask, indent);
    s = format(s, "\n%Ufrom_offset: %u", format_white_space, indent, a->from_offset);
    s = format(s, "\n%Uto_offset: %u", format_white_space, indent, a->to_offset);
    s = format(s, "\n%Uclear_offset: %u", format_white_space, indent, a->clear_offset);
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_pnat_printfun
#define included_pnat_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "pnat.api_tojson.h"
#include "pnat.api_fromjson.h"

static inline u8 *vl_api_pnat_binding_add_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pnat_binding_add_t *a = va_arg (*args, vl_api_pnat_binding_add_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pnat_binding_add_t: */
    s = format(s, "vl_api_pnat_binding_add_t:");
    s = format(s, "\n%Umatch: %U", format_white_space, indent, format_vl_api_pnat_match_tuple_t, &a->match, indent);
    s = format(s, "\n%Urewrite: %U", format_white_space, indent, format_vl_api_pnat_rewrite_tuple_t, &a->rewrite, indent);
    return s;
}

static inline u8 *vl_api_pnat_binding_add_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pnat_binding_add_reply_t *a = va_arg (*args, vl_api_pnat_binding_add_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pnat_binding_add_reply_t: */
    s = format(s, "vl_api_pnat_binding_add_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ubinding_index: %u", format_white_space, indent, a->binding_index);
    return s;
}

static inline u8 *vl_api_pnat_binding_add_v2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pnat_binding_add_v2_t *a = va_arg (*args, vl_api_pnat_binding_add_v2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pnat_binding_add_v2_t: */
    s = format(s, "vl_api_pnat_binding_add_v2_t:");
    s = format(s, "\n%Umatch: %U", format_white_space, indent, format_vl_api_pnat_match_tuple_t, &a->match, indent);
    s = format(s, "\n%Urewrite: %U", format_white_space, indent, format_vl_api_pnat_rewrite_tuple_t, &a->rewrite, indent);
    return s;
}

static inline u8 *vl_api_pnat_binding_add_v2_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pnat_binding_add_v2_reply_t *a = va_arg (*args, vl_api_pnat_binding_add_v2_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pnat_binding_add_v2_reply_t: */
    s = format(s, "vl_api_pnat_binding_add_v2_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ubinding_index: %u", format_white_space, indent, a->binding_index);
    return s;
}

static inline u8 *vl_api_pnat_binding_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pnat_binding_del_t *a = va_arg (*args, vl_api_pnat_binding_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pnat_binding_del_t: */
    s = format(s, "vl_api_pnat_binding_del_t:");
    s = format(s, "\n%Ubinding_index: %u", format_white_space, indent, a->binding_index);
    return s;
}

static inline u8 *vl_api_pnat_binding_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pnat_binding_del_reply_t *a = va_arg (*args, vl_api_pnat_binding_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pnat_binding_del_reply_t: */
    s = format(s, "vl_api_pnat_binding_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_pnat_binding_attach_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pnat_binding_attach_t *a = va_arg (*args, vl_api_pnat_binding_attach_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pnat_binding_attach_t: */
    s = format(s, "vl_api_pnat_binding_attach_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uattachment: %U", format_white_space, indent, format_vl_api_pnat_attachment_point_t, &a->attachment, indent);
    s = format(s, "\n%Ubinding_index: %u", format_white_space, indent, a->binding_index);
    return s;
}

static inline u8 *vl_api_pnat_binding_attach_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pnat_binding_attach_reply_t *a = va_arg (*args, vl_api_pnat_binding_attach_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pnat_binding_attach_reply_t: */
    s = format(s, "vl_api_pnat_binding_attach_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_pnat_binding_detach_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pnat_binding_detach_t *a = va_arg (*args, vl_api_pnat_binding_detach_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pnat_binding_detach_t: */
    s = format(s, "vl_api_pnat_binding_detach_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uattachment: %U", format_white_space, indent, format_vl_api_pnat_attachment_point_t, &a->attachment, indent);
    s = format(s, "\n%Ubinding_index: %u", format_white_space, indent, a->binding_index);
    return s;
}

static inline u8 *vl_api_pnat_binding_detach_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pnat_binding_detach_reply_t *a = va_arg (*args, vl_api_pnat_binding_detach_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pnat_binding_detach_reply_t: */
    s = format(s, "vl_api_pnat_binding_detach_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_pnat_bindings_get_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pnat_bindings_get_t *a = va_arg (*args, vl_api_pnat_bindings_get_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pnat_bindings_get_t: */
    s = format(s, "vl_api_pnat_bindings_get_t:");
    s = format(s, "\n%Ucursor: %u", format_white_space, indent, a->cursor);
    return s;
}

static inline u8 *vl_api_pnat_bindings_get_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pnat_bindings_get_reply_t *a = va_arg (*args, vl_api_pnat_bindings_get_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pnat_bindings_get_reply_t: */
    s = format(s, "vl_api_pnat_bindings_get_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ucursor: %u", format_white_space, indent, a->cursor);
    return s;
}

static inline u8 *vl_api_pnat_bindings_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pnat_bindings_details_t *a = va_arg (*args, vl_api_pnat_bindings_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pnat_bindings_details_t: */
    s = format(s, "vl_api_pnat_bindings_details_t:");
    s = format(s, "\n%Umatch: %U", format_white_space, indent, format_vl_api_pnat_match_tuple_t, &a->match, indent);
    s = format(s, "\n%Urewrite: %U", format_white_space, indent, format_vl_api_pnat_rewrite_tuple_t, &a->rewrite, indent);
    return s;
}

static inline u8 *vl_api_pnat_interfaces_get_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pnat_interfaces_get_t *a = va_arg (*args, vl_api_pnat_interfaces_get_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pnat_interfaces_get_t: */
    s = format(s, "vl_api_pnat_interfaces_get_t:");
    s = format(s, "\n%Ucursor: %u", format_white_space, indent, a->cursor);
    return s;
}

static inline u8 *vl_api_pnat_interfaces_get_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pnat_interfaces_get_reply_t *a = va_arg (*args, vl_api_pnat_interfaces_get_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pnat_interfaces_get_reply_t: */
    s = format(s, "vl_api_pnat_interfaces_get_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ucursor: %u", format_white_space, indent, a->cursor);
    return s;
}

static inline u8 *vl_api_pnat_interfaces_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pnat_interfaces_details_t *a = va_arg (*args, vl_api_pnat_interfaces_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pnat_interfaces_details_t: */
    s = format(s, "vl_api_pnat_interfaces_details_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    for (i = 0; i < 2; i++) {
        s = format(s, "\n%Uenabled: %u",
                   format_white_space, indent, a->enabled[i]);
    }
    for (i = 0; i < 2; i++) {
        s = format(s, "\n%Ulookup_mask: %U",
                   format_white_space, indent, format_vl_api_pnat_mask_t, &a->lookup_mask[i], indent);
    }
    return s;
}

static inline u8 *vl_api_pnat_flow_lookup_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pnat_flow_lookup_t *a = va_arg (*args, vl_api_pnat_flow_lookup_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pnat_flow_lookup_t: */
    s = format(s, "vl_api_pnat_flow_lookup_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uattachment: %U", format_white_space, indent, format_vl_api_pnat_attachment_point_t, &a->attachment, indent);
    s = format(s, "\n%Umatch: %U", format_white_space, indent, format_vl_api_pnat_match_tuple_t, &a->match, indent);
    return s;
}

static inline u8 *vl_api_pnat_flow_lookup_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pnat_flow_lookup_reply_t *a = va_arg (*args, vl_api_pnat_flow_lookup_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pnat_flow_lookup_reply_t: */
    s = format(s, "vl_api_pnat_flow_lookup_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ubinding_index: %u", format_white_space, indent, a->binding_index);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_pnat_endianfun
#define included_pnat_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_pnat_mask_t_endian (vl_api_pnat_mask_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_pnat_attachment_point_t_endian (vl_api_pnat_attachment_point_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_pnat_match_tuple_t_endian (vl_api_pnat_match_tuple_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_ip4_address_t_endian(&a->src, to_net);
    vl_api_ip4_address_t_endian(&a->dst, to_net);
    vl_api_ip_proto_t_endian(&a->proto, to_net);
    a->sport = clib_net_to_host_u16(a->sport);
    a->dport = clib_net_to_host_u16(a->dport);
    vl_api_pnat_mask_t_endian(&a->mask, to_net);
}

static inline void vl_api_pnat_rewrite_tuple_t_endian (vl_api_pnat_rewrite_tuple_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_ip4_address_t_endian(&a->src, to_net);
    vl_api_ip4_address_t_endian(&a->dst, to_net);
    a->sport = clib_net_to_host_u16(a->sport);
    a->dport = clib_net_to_host_u16(a->dport);
    vl_api_pnat_mask_t_endian(&a->mask, to_net);
    /* a->from_offset = a->from_offset (no-op) */
    /* a->to_offset = a->to_offset (no-op) */
    /* a->clear_offset = a->clear_offset (no-op) */
}

static inline void vl_api_pnat_binding_add_t_endian (vl_api_pnat_binding_add_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_pnat_match_tuple_t_endian(&a->match, to_net);
    vl_api_pnat_rewrite_tuple_t_endian(&a->rewrite, to_net);
}

static inline void vl_api_pnat_binding_add_reply_t_endian (vl_api_pnat_binding_add_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->binding_index = clib_net_to_host_u32(a->binding_index);
}

static inline void vl_api_pnat_binding_add_v2_t_endian (vl_api_pnat_binding_add_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_pnat_match_tuple_t_endian(&a->match, to_net);
    vl_api_pnat_rewrite_tuple_t_endian(&a->rewrite, to_net);
}

static inline void vl_api_pnat_binding_add_v2_reply_t_endian (vl_api_pnat_binding_add_v2_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->binding_index = clib_net_to_host_u32(a->binding_index);
}

static inline void vl_api_pnat_binding_del_t_endian (vl_api_pnat_binding_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->binding_index = clib_net_to_host_u32(a->binding_index);
}

static inline void vl_api_pnat_binding_del_reply_t_endian (vl_api_pnat_binding_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_pnat_binding_attach_t_endian (vl_api_pnat_binding_attach_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    vl_api_pnat_attachment_point_t_endian(&a->attachment, to_net);
    a->binding_index = clib_net_to_host_u32(a->binding_index);
}

static inline void vl_api_pnat_binding_attach_reply_t_endian (vl_api_pnat_binding_attach_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_pnat_binding_detach_t_endian (vl_api_pnat_binding_detach_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    vl_api_pnat_attachment_point_t_endian(&a->attachment, to_net);
    a->binding_index = clib_net_to_host_u32(a->binding_index);
}

static inline void vl_api_pnat_binding_detach_reply_t_endian (vl_api_pnat_binding_detach_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_pnat_bindings_get_t_endian (vl_api_pnat_bindings_get_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->cursor = clib_net_to_host_u32(a->cursor);
}

static inline void vl_api_pnat_bindings_get_reply_t_endian (vl_api_pnat_bindings_get_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->cursor = clib_net_to_host_u32(a->cursor);
}

static inline void vl_api_pnat_bindings_details_t_endian (vl_api_pnat_bindings_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_pnat_match_tuple_t_endian(&a->match, to_net);
    vl_api_pnat_rewrite_tuple_t_endian(&a->rewrite, to_net);
}

static inline void vl_api_pnat_interfaces_get_t_endian (vl_api_pnat_interfaces_get_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->cursor = clib_net_to_host_u32(a->cursor);
}

static inline void vl_api_pnat_interfaces_get_reply_t_endian (vl_api_pnat_interfaces_get_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->cursor = clib_net_to_host_u32(a->cursor);
}

static inline void vl_api_pnat_interfaces_details_t_endian (vl_api_pnat_interfaces_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->enabled = a->enabled (no-op) */
    for (i = 0; i < 2; i++) {
        vl_api_pnat_mask_t_endian(&a->lookup_mask[i], to_net);
    }
}

static inline void vl_api_pnat_flow_lookup_t_endian (vl_api_pnat_flow_lookup_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    vl_api_pnat_attachment_point_t_endian(&a->attachment, to_net);
    vl_api_pnat_match_tuple_t_endian(&a->match, to_net);
}

static inline void vl_api_pnat_flow_lookup_reply_t_endian (vl_api_pnat_flow_lookup_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->binding_index = clib_net_to_host_u32(a->binding_index);
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_pnat_calcsizefun
#define included_pnat_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_pnat_mask_t_calc_size (vl_api_pnat_mask_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pnat_attachment_point_t_calc_size (vl_api_pnat_attachment_point_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pnat_match_tuple_t_calc_size (vl_api_pnat_match_tuple_t *a)
{
      return sizeof(*a) - sizeof(a->src) + vl_api_ip4_address_t_calc_size(&a->src) - sizeof(a->dst) + vl_api_ip4_address_t_calc_size(&a->dst) - sizeof(a->proto) + vl_api_ip_proto_t_calc_size(&a->proto) - sizeof(a->mask) + vl_api_pnat_mask_t_calc_size(&a->mask);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pnat_rewrite_tuple_t_calc_size (vl_api_pnat_rewrite_tuple_t *a)
{
      return sizeof(*a) - sizeof(a->src) + vl_api_ip4_address_t_calc_size(&a->src) - sizeof(a->dst) + vl_api_ip4_address_t_calc_size(&a->dst) - sizeof(a->mask) + vl_api_pnat_mask_t_calc_size(&a->mask);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pnat_binding_add_t_calc_size (vl_api_pnat_binding_add_t *a)
{
      return sizeof(*a) - sizeof(a->match) + vl_api_pnat_match_tuple_t_calc_size(&a->match) - sizeof(a->rewrite) + vl_api_pnat_rewrite_tuple_t_calc_size(&a->rewrite);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pnat_binding_add_reply_t_calc_size (vl_api_pnat_binding_add_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pnat_binding_add_v2_t_calc_size (vl_api_pnat_binding_add_v2_t *a)
{
      return sizeof(*a) - sizeof(a->match) + vl_api_pnat_match_tuple_t_calc_size(&a->match) - sizeof(a->rewrite) + vl_api_pnat_rewrite_tuple_t_calc_size(&a->rewrite);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pnat_binding_add_v2_reply_t_calc_size (vl_api_pnat_binding_add_v2_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pnat_binding_del_t_calc_size (vl_api_pnat_binding_del_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pnat_binding_del_reply_t_calc_size (vl_api_pnat_binding_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pnat_binding_attach_t_calc_size (vl_api_pnat_binding_attach_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->attachment) + vl_api_pnat_attachment_point_t_calc_size(&a->attachment);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pnat_binding_attach_reply_t_calc_size (vl_api_pnat_binding_attach_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pnat_binding_detach_t_calc_size (vl_api_pnat_binding_detach_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->attachment) + vl_api_pnat_attachment_point_t_calc_size(&a->attachment);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pnat_binding_detach_reply_t_calc_size (vl_api_pnat_binding_detach_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pnat_bindings_get_t_calc_size (vl_api_pnat_bindings_get_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pnat_bindings_get_reply_t_calc_size (vl_api_pnat_bindings_get_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pnat_bindings_details_t_calc_size (vl_api_pnat_bindings_details_t *a)
{
      return sizeof(*a) - sizeof(a->match) + vl_api_pnat_match_tuple_t_calc_size(&a->match) - sizeof(a->rewrite) + vl_api_pnat_rewrite_tuple_t_calc_size(&a->rewrite);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pnat_interfaces_get_t_calc_size (vl_api_pnat_interfaces_get_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pnat_interfaces_get_reply_t_calc_size (vl_api_pnat_interfaces_get_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pnat_interfaces_details_t_calc_size (vl_api_pnat_interfaces_details_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pnat_flow_lookup_t_calc_size (vl_api_pnat_flow_lookup_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->attachment) + vl_api_pnat_attachment_point_t_calc_size(&a->attachment) - sizeof(a->match) + vl_api_pnat_match_tuple_t_calc_size(&a->match);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pnat_flow_lookup_reply_t_calc_size (vl_api_pnat_flow_lookup_reply_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(pnat.api, 0, 1, 1)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(pnat.api, 0xec06ec84)

#endif

