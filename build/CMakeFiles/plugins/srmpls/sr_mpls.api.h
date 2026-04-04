/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: sr_mpls.api
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
#warning no content included from sr_mpls.api
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
vl_msg_id(VL_API_SR_MPLS_POLICY_ADD, vl_api_sr_mpls_policy_add_t_handler)
vl_msg_id(VL_API_SR_MPLS_POLICY_ADD_REPLY, vl_api_sr_mpls_policy_add_reply_t_handler)
vl_msg_id(VL_API_SR_MPLS_POLICY_MOD, vl_api_sr_mpls_policy_mod_t_handler)
vl_msg_id(VL_API_SR_MPLS_POLICY_MOD_REPLY, vl_api_sr_mpls_policy_mod_reply_t_handler)
vl_msg_id(VL_API_SR_MPLS_POLICY_DEL, vl_api_sr_mpls_policy_del_t_handler)
vl_msg_id(VL_API_SR_MPLS_POLICY_DEL_REPLY, vl_api_sr_mpls_policy_del_reply_t_handler)
vl_msg_id(VL_API_SR_MPLS_STEERING_ADD_DEL, vl_api_sr_mpls_steering_add_del_t_handler)
vl_msg_id(VL_API_SR_MPLS_STEERING_ADD_DEL_REPLY, vl_api_sr_mpls_steering_add_del_reply_t_handler)
vl_msg_id(VL_API_SR_MPLS_POLICY_ASSIGN_ENDPOINT_COLOR, vl_api_sr_mpls_policy_assign_endpoint_color_t_handler)
vl_msg_id(VL_API_SR_MPLS_POLICY_ASSIGN_ENDPOINT_COLOR_REPLY, vl_api_sr_mpls_policy_assign_endpoint_color_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_sr_mpls_policy_add_t, 1)
vl_msg_name(vl_api_sr_mpls_policy_add_reply_t, 1)
vl_msg_name(vl_api_sr_mpls_policy_mod_t, 1)
vl_msg_name(vl_api_sr_mpls_policy_mod_reply_t, 1)
vl_msg_name(vl_api_sr_mpls_policy_del_t, 1)
vl_msg_name(vl_api_sr_mpls_policy_del_reply_t, 1)
vl_msg_name(vl_api_sr_mpls_steering_add_del_t, 1)
vl_msg_name(vl_api_sr_mpls_steering_add_del_reply_t, 1)
vl_msg_name(vl_api_sr_mpls_policy_assign_endpoint_color_t, 1)
vl_msg_name(vl_api_sr_mpls_policy_assign_endpoint_color_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_sr_mpls \
_(VL_API_SR_MPLS_POLICY_ADD, sr_mpls_policy_add, a1a70c70) \
_(VL_API_SR_MPLS_POLICY_ADD_REPLY, sr_mpls_policy_add_reply, e8d4e804) \
_(VL_API_SR_MPLS_POLICY_MOD, sr_mpls_policy_mod, 88482c17) \
_(VL_API_SR_MPLS_POLICY_MOD_REPLY, sr_mpls_policy_mod_reply, e8d4e804) \
_(VL_API_SR_MPLS_POLICY_DEL, sr_mpls_policy_del, e29d34fa) \
_(VL_API_SR_MPLS_POLICY_DEL_REPLY, sr_mpls_policy_del_reply, e8d4e804) \
_(VL_API_SR_MPLS_STEERING_ADD_DEL, sr_mpls_steering_add_del, 64acff63) \
_(VL_API_SR_MPLS_STEERING_ADD_DEL_REPLY, sr_mpls_steering_add_del_reply, e8d4e804) \
_(VL_API_SR_MPLS_POLICY_ASSIGN_ENDPOINT_COLOR, sr_mpls_policy_assign_endpoint_color, 0e7eb978) \
_(VL_API_SR_MPLS_POLICY_ASSIGN_ENDPOINT_COLOR_REPLY, sr_mpls_policy_assign_endpoint_color_reply, e8d4e804) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "sr_mpls.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_sr_mpls_printfun_types
#define included_sr_mpls_printfun_types


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_sr_mpls_printfun
#define included_sr_mpls_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "sr_mpls.api_tojson.h"
#include "sr_mpls.api_fromjson.h"

static inline u8 *vl_api_sr_mpls_policy_add_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_mpls_policy_add_t *a = va_arg (*args, vl_api_sr_mpls_policy_add_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_mpls_policy_add_t: */
    s = format(s, "vl_api_sr_mpls_policy_add_t:");
    s = format(s, "\n%Ubsid: %u", format_white_space, indent, a->bsid);
    s = format(s, "\n%Uweight: %u", format_white_space, indent, a->weight);
    s = format(s, "\n%Uis_spray: %u", format_white_space, indent, a->is_spray);
    s = format(s, "\n%Un_segments: %u", format_white_space, indent, a->n_segments);
    for (i = 0; i < a->n_segments; i++) {
        s = format(s, "\n%Usegments: %u",
                   format_white_space, indent, a->segments[i]);
    }
    return s;
}

static inline u8 *vl_api_sr_mpls_policy_add_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_mpls_policy_add_reply_t *a = va_arg (*args, vl_api_sr_mpls_policy_add_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_mpls_policy_add_reply_t: */
    s = format(s, "vl_api_sr_mpls_policy_add_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_sr_mpls_policy_mod_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_mpls_policy_mod_t *a = va_arg (*args, vl_api_sr_mpls_policy_mod_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_mpls_policy_mod_t: */
    s = format(s, "vl_api_sr_mpls_policy_mod_t:");
    s = format(s, "\n%Ubsid: %u", format_white_space, indent, a->bsid);
    s = format(s, "\n%Uoperation: %U", format_white_space, indent, format_vl_api_sr_policy_op_t, &a->operation, indent);
    s = format(s, "\n%Usl_index: %u", format_white_space, indent, a->sl_index);
    s = format(s, "\n%Uweight: %u", format_white_space, indent, a->weight);
    s = format(s, "\n%Un_segments: %u", format_white_space, indent, a->n_segments);
    for (i = 0; i < a->n_segments; i++) {
        s = format(s, "\n%Usegments: %u",
                   format_white_space, indent, a->segments[i]);
    }
    return s;
}

static inline u8 *vl_api_sr_mpls_policy_mod_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_mpls_policy_mod_reply_t *a = va_arg (*args, vl_api_sr_mpls_policy_mod_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_mpls_policy_mod_reply_t: */
    s = format(s, "vl_api_sr_mpls_policy_mod_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_sr_mpls_policy_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_mpls_policy_del_t *a = va_arg (*args, vl_api_sr_mpls_policy_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_mpls_policy_del_t: */
    s = format(s, "vl_api_sr_mpls_policy_del_t:");
    s = format(s, "\n%Ubsid: %u", format_white_space, indent, a->bsid);
    return s;
}

static inline u8 *vl_api_sr_mpls_policy_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_mpls_policy_del_reply_t *a = va_arg (*args, vl_api_sr_mpls_policy_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_mpls_policy_del_reply_t: */
    s = format(s, "vl_api_sr_mpls_policy_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_sr_mpls_steering_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_mpls_steering_add_del_t *a = va_arg (*args, vl_api_sr_mpls_steering_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_mpls_steering_add_del_t: */
    s = format(s, "vl_api_sr_mpls_steering_add_del_t:");
    s = format(s, "\n%Uis_del: %u", format_white_space, indent, a->is_del);
    s = format(s, "\n%Ubsid: %u", format_white_space, indent, a->bsid);
    s = format(s, "\n%Utable_id: %u", format_white_space, indent, a->table_id);
    s = format(s, "\n%Uprefix: %U", format_white_space, indent, format_vl_api_prefix_t, &a->prefix, indent);
    s = format(s, "\n%Umask_width: %u", format_white_space, indent, a->mask_width);
    s = format(s, "\n%Unext_hop: %U", format_white_space, indent, format_vl_api_address_t, &a->next_hop, indent);
    s = format(s, "\n%Ucolor: %u", format_white_space, indent, a->color);
    s = format(s, "\n%Uco_bits: %u", format_white_space, indent, a->co_bits);
    s = format(s, "\n%Uvpn_label: %u", format_white_space, indent, a->vpn_label);
    return s;
}

static inline u8 *vl_api_sr_mpls_steering_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_mpls_steering_add_del_reply_t *a = va_arg (*args, vl_api_sr_mpls_steering_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_mpls_steering_add_del_reply_t: */
    s = format(s, "vl_api_sr_mpls_steering_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_sr_mpls_policy_assign_endpoint_color_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_mpls_policy_assign_endpoint_color_t *a = va_arg (*args, vl_api_sr_mpls_policy_assign_endpoint_color_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_mpls_policy_assign_endpoint_color_t: */
    s = format(s, "vl_api_sr_mpls_policy_assign_endpoint_color_t:");
    s = format(s, "\n%Ubsid: %u", format_white_space, indent, a->bsid);
    s = format(s, "\n%Uendpoint: %U", format_white_space, indent, format_vl_api_address_t, &a->endpoint, indent);
    s = format(s, "\n%Ucolor: %u", format_white_space, indent, a->color);
    return s;
}

static inline u8 *vl_api_sr_mpls_policy_assign_endpoint_color_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_mpls_policy_assign_endpoint_color_reply_t *a = va_arg (*args, vl_api_sr_mpls_policy_assign_endpoint_color_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_mpls_policy_assign_endpoint_color_reply_t: */
    s = format(s, "vl_api_sr_mpls_policy_assign_endpoint_color_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_sr_mpls_endianfun
#define included_sr_mpls_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_sr_mpls_policy_add_t_endian (vl_api_sr_mpls_policy_add_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->bsid = clib_net_to_host_u32(a->bsid);
    a->weight = clib_net_to_host_u32(a->weight);
    /* a->is_spray = a->is_spray (no-op) */
    /* a->n_segments = a->n_segments (no-op) */
    u32 count = a->n_segments;
    ASSERT((u32)count <= (u32)VL_API_MAX_ARRAY_SIZE);
    for (i = 0; i < count; i++) {
        a->segments[i] = clib_net_to_host_u32(a->segments[i]);
    }
}

static inline void vl_api_sr_mpls_policy_add_reply_t_endian (vl_api_sr_mpls_policy_add_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_sr_mpls_policy_mod_t_endian (vl_api_sr_mpls_policy_mod_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->bsid = clib_net_to_host_u32(a->bsid);
    vl_api_sr_policy_op_t_endian(&a->operation, to_net);
    a->sl_index = clib_net_to_host_u32(a->sl_index);
    a->weight = clib_net_to_host_u32(a->weight);
    /* a->n_segments = a->n_segments (no-op) */
    u32 count = a->n_segments;
    ASSERT((u32)count <= (u32)VL_API_MAX_ARRAY_SIZE);
    for (i = 0; i < count; i++) {
        a->segments[i] = clib_net_to_host_u32(a->segments[i]);
    }
}

static inline void vl_api_sr_mpls_policy_mod_reply_t_endian (vl_api_sr_mpls_policy_mod_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_sr_mpls_policy_del_t_endian (vl_api_sr_mpls_policy_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->bsid = clib_net_to_host_u32(a->bsid);
}

static inline void vl_api_sr_mpls_policy_del_reply_t_endian (vl_api_sr_mpls_policy_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_sr_mpls_steering_add_del_t_endian (vl_api_sr_mpls_steering_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_del = a->is_del (no-op) */
    a->bsid = clib_net_to_host_u32(a->bsid);
    a->table_id = clib_net_to_host_u32(a->table_id);
    vl_api_prefix_t_endian(&a->prefix, to_net);
    a->mask_width = clib_net_to_host_u32(a->mask_width);
    vl_api_address_t_endian(&a->next_hop, to_net);
    a->color = clib_net_to_host_u32(a->color);
    /* a->co_bits = a->co_bits (no-op) */
    a->vpn_label = clib_net_to_host_u32(a->vpn_label);
}

static inline void vl_api_sr_mpls_steering_add_del_reply_t_endian (vl_api_sr_mpls_steering_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_sr_mpls_policy_assign_endpoint_color_t_endian (vl_api_sr_mpls_policy_assign_endpoint_color_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->bsid = clib_net_to_host_u32(a->bsid);
    vl_api_address_t_endian(&a->endpoint, to_net);
    a->color = clib_net_to_host_u32(a->color);
}

static inline void vl_api_sr_mpls_policy_assign_endpoint_color_reply_t_endian (vl_api_sr_mpls_policy_assign_endpoint_color_reply_t *a, bool to_net)
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
#ifndef included_sr_mpls_calcsizefun
#define included_sr_mpls_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_mpls_policy_add_t_calc_size (vl_api_sr_mpls_policy_add_t *a)
{
      return sizeof(*a) + a->n_segments * sizeof(a->segments[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_mpls_policy_add_reply_t_calc_size (vl_api_sr_mpls_policy_add_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_mpls_policy_mod_t_calc_size (vl_api_sr_mpls_policy_mod_t *a)
{
      return sizeof(*a) - sizeof(a->operation) + vl_api_sr_policy_op_t_calc_size(&a->operation) + a->n_segments * sizeof(a->segments[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_mpls_policy_mod_reply_t_calc_size (vl_api_sr_mpls_policy_mod_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_mpls_policy_del_t_calc_size (vl_api_sr_mpls_policy_del_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_mpls_policy_del_reply_t_calc_size (vl_api_sr_mpls_policy_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_mpls_steering_add_del_t_calc_size (vl_api_sr_mpls_steering_add_del_t *a)
{
      return sizeof(*a) - sizeof(a->prefix) + vl_api_prefix_t_calc_size(&a->prefix) - sizeof(a->next_hop) + vl_api_address_t_calc_size(&a->next_hop);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_mpls_steering_add_del_reply_t_calc_size (vl_api_sr_mpls_steering_add_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_mpls_policy_assign_endpoint_color_t_calc_size (vl_api_sr_mpls_policy_assign_endpoint_color_t *a)
{
      return sizeof(*a) - sizeof(a->endpoint) + vl_api_address_t_calc_size(&a->endpoint);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_mpls_policy_assign_endpoint_color_reply_t_calc_size (vl_api_sr_mpls_policy_assign_endpoint_color_reply_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(sr_mpls.api, 3, 0, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(sr_mpls.api, 0xd1279a74)

#endif

