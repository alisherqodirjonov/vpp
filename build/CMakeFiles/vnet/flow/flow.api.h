/*
 * VLIB API definitions 2026-04-04 08:31:58
 * Input file: flow.api
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
#warning no content included from flow.api
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
#include <vnet/flow/flow_types.api.h>
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_FLOW_ADD, vl_api_flow_add_t_handler)
vl_msg_id(VL_API_FLOW_ADD_V2, vl_api_flow_add_v2_t_handler)
vl_msg_id(VL_API_FLOW_ADD_REPLY, vl_api_flow_add_reply_t_handler)
vl_msg_id(VL_API_FLOW_ADD_V2_REPLY, vl_api_flow_add_v2_reply_t_handler)
vl_msg_id(VL_API_FLOW_DEL, vl_api_flow_del_t_handler)
vl_msg_id(VL_API_FLOW_DEL_REPLY, vl_api_flow_del_reply_t_handler)
vl_msg_id(VL_API_FLOW_ENABLE, vl_api_flow_enable_t_handler)
vl_msg_id(VL_API_FLOW_ENABLE_REPLY, vl_api_flow_enable_reply_t_handler)
vl_msg_id(VL_API_FLOW_DISABLE, vl_api_flow_disable_t_handler)
vl_msg_id(VL_API_FLOW_DISABLE_REPLY, vl_api_flow_disable_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_flow_add_t, 1)
vl_msg_name(vl_api_flow_add_v2_t, 1)
vl_msg_name(vl_api_flow_add_reply_t, 1)
vl_msg_name(vl_api_flow_add_v2_reply_t, 1)
vl_msg_name(vl_api_flow_del_t, 1)
vl_msg_name(vl_api_flow_del_reply_t, 1)
vl_msg_name(vl_api_flow_enable_t, 1)
vl_msg_name(vl_api_flow_enable_reply_t, 1)
vl_msg_name(vl_api_flow_disable_t, 1)
vl_msg_name(vl_api_flow_disable_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_flow \
_(VL_API_FLOW_ADD, flow_add, f946ed84) \
_(VL_API_FLOW_ADD_V2, flow_add_v2, 5b757558) \
_(VL_API_FLOW_ADD_REPLY, flow_add_reply, 8587dc85) \
_(VL_API_FLOW_ADD_V2_REPLY, flow_add_v2_reply, 8587dc85) \
_(VL_API_FLOW_DEL, flow_del, b6b9b02c) \
_(VL_API_FLOW_DEL_REPLY, flow_del_reply, e8d4e804) \
_(VL_API_FLOW_ENABLE, flow_enable, 2024be69) \
_(VL_API_FLOW_ENABLE_REPLY, flow_enable_reply, e8d4e804) \
_(VL_API_FLOW_DISABLE, flow_disable, 2024be69) \
_(VL_API_FLOW_DISABLE_REPLY, flow_disable_reply, e8d4e804) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "flow.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_flow_printfun_types
#define included_flow_printfun_types


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_flow_printfun
#define included_flow_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "flow.api_tojson.h"
#include "flow.api_fromjson.h"

static inline u8 *vl_api_flow_add_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_flow_add_t *a = va_arg (*args, vl_api_flow_add_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_flow_add_t: */
    s = format(s, "vl_api_flow_add_t:");
    s = format(s, "\n%Uflow: %U", format_white_space, indent, format_vl_api_flow_rule_t, &a->flow, indent);
    return s;
}

static inline u8 *vl_api_flow_add_v2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_flow_add_v2_t *a = va_arg (*args, vl_api_flow_add_v2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_flow_add_v2_t: */
    s = format(s, "vl_api_flow_add_v2_t:");
    s = format(s, "\n%Uflow: %U", format_white_space, indent, format_vl_api_flow_rule_v2_t, &a->flow, indent);
    return s;
}

static inline u8 *vl_api_flow_add_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_flow_add_reply_t *a = va_arg (*args, vl_api_flow_add_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_flow_add_reply_t: */
    s = format(s, "vl_api_flow_add_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uflow_index: %u", format_white_space, indent, a->flow_index);
    return s;
}

static inline u8 *vl_api_flow_add_v2_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_flow_add_v2_reply_t *a = va_arg (*args, vl_api_flow_add_v2_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_flow_add_v2_reply_t: */
    s = format(s, "vl_api_flow_add_v2_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uflow_index: %u", format_white_space, indent, a->flow_index);
    return s;
}

static inline u8 *vl_api_flow_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_flow_del_t *a = va_arg (*args, vl_api_flow_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_flow_del_t: */
    s = format(s, "vl_api_flow_del_t:");
    s = format(s, "\n%Uflow_index: %u", format_white_space, indent, a->flow_index);
    return s;
}

static inline u8 *vl_api_flow_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_flow_del_reply_t *a = va_arg (*args, vl_api_flow_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_flow_del_reply_t: */
    s = format(s, "vl_api_flow_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_flow_enable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_flow_enable_t *a = va_arg (*args, vl_api_flow_enable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_flow_enable_t: */
    s = format(s, "vl_api_flow_enable_t:");
    s = format(s, "\n%Uflow_index: %u", format_white_space, indent, a->flow_index);
    s = format(s, "\n%Uhw_if_index: %u", format_white_space, indent, a->hw_if_index);
    return s;
}

static inline u8 *vl_api_flow_enable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_flow_enable_reply_t *a = va_arg (*args, vl_api_flow_enable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_flow_enable_reply_t: */
    s = format(s, "vl_api_flow_enable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_flow_disable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_flow_disable_t *a = va_arg (*args, vl_api_flow_disable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_flow_disable_t: */
    s = format(s, "vl_api_flow_disable_t:");
    s = format(s, "\n%Uflow_index: %u", format_white_space, indent, a->flow_index);
    s = format(s, "\n%Uhw_if_index: %u", format_white_space, indent, a->hw_if_index);
    return s;
}

static inline u8 *vl_api_flow_disable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_flow_disable_reply_t *a = va_arg (*args, vl_api_flow_disable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_flow_disable_reply_t: */
    s = format(s, "vl_api_flow_disable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_flow_endianfun
#define included_flow_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_flow_add_t_endian (vl_api_flow_add_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_flow_rule_t_endian(&a->flow, to_net);
}

static inline void vl_api_flow_add_v2_t_endian (vl_api_flow_add_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_flow_rule_v2_t_endian(&a->flow, to_net);
}

static inline void vl_api_flow_add_reply_t_endian (vl_api_flow_add_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->flow_index = clib_net_to_host_u32(a->flow_index);
}

static inline void vl_api_flow_add_v2_reply_t_endian (vl_api_flow_add_v2_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->flow_index = clib_net_to_host_u32(a->flow_index);
}

static inline void vl_api_flow_del_t_endian (vl_api_flow_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->flow_index = clib_net_to_host_u32(a->flow_index);
}

static inline void vl_api_flow_del_reply_t_endian (vl_api_flow_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_flow_enable_t_endian (vl_api_flow_enable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->flow_index = clib_net_to_host_u32(a->flow_index);
    a->hw_if_index = clib_net_to_host_u32(a->hw_if_index);
}

static inline void vl_api_flow_enable_reply_t_endian (vl_api_flow_enable_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_flow_disable_t_endian (vl_api_flow_disable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->flow_index = clib_net_to_host_u32(a->flow_index);
    a->hw_if_index = clib_net_to_host_u32(a->hw_if_index);
}

static inline void vl_api_flow_disable_reply_t_endian (vl_api_flow_disable_reply_t *a, bool to_net)
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
#ifndef included_flow_calcsizefun
#define included_flow_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_flow_add_t_calc_size (vl_api_flow_add_t *a)
{
      return sizeof(*a) - sizeof(a->flow) + vl_api_flow_rule_t_calc_size(&a->flow);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flow_add_v2_t_calc_size (vl_api_flow_add_v2_t *a)
{
      return sizeof(*a) - sizeof(a->flow) + vl_api_flow_rule_v2_t_calc_size(&a->flow);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flow_add_reply_t_calc_size (vl_api_flow_add_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flow_add_v2_reply_t_calc_size (vl_api_flow_add_v2_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flow_del_t_calc_size (vl_api_flow_del_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flow_del_reply_t_calc_size (vl_api_flow_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flow_enable_t_calc_size (vl_api_flow_enable_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flow_enable_reply_t_calc_size (vl_api_flow_enable_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flow_disable_t_calc_size (vl_api_flow_disable_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flow_disable_reply_t_calc_size (vl_api_flow_disable_reply_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(flow.api, 1, 0, 3)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(flow.api, 0x5ab59c04)

#endif

