/*
 * VLIB API definitions 2026-04-04 08:31:59
 * Input file: ioam_vxlan_gpe.api
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
#warning no content included from ioam_vxlan_gpe.api
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
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_VXLAN_GPE_IOAM_ENABLE, vl_api_vxlan_gpe_ioam_enable_t_handler)
vl_msg_id(VL_API_VXLAN_GPE_IOAM_ENABLE_REPLY, vl_api_vxlan_gpe_ioam_enable_reply_t_handler)
vl_msg_id(VL_API_VXLAN_GPE_IOAM_DISABLE, vl_api_vxlan_gpe_ioam_disable_t_handler)
vl_msg_id(VL_API_VXLAN_GPE_IOAM_DISABLE_REPLY, vl_api_vxlan_gpe_ioam_disable_reply_t_handler)
vl_msg_id(VL_API_VXLAN_GPE_IOAM_VNI_ENABLE, vl_api_vxlan_gpe_ioam_vni_enable_t_handler)
vl_msg_id(VL_API_VXLAN_GPE_IOAM_VNI_ENABLE_REPLY, vl_api_vxlan_gpe_ioam_vni_enable_reply_t_handler)
vl_msg_id(VL_API_VXLAN_GPE_IOAM_VNI_DISABLE, vl_api_vxlan_gpe_ioam_vni_disable_t_handler)
vl_msg_id(VL_API_VXLAN_GPE_IOAM_VNI_DISABLE_REPLY, vl_api_vxlan_gpe_ioam_vni_disable_reply_t_handler)
vl_msg_id(VL_API_VXLAN_GPE_IOAM_TRANSIT_ENABLE, vl_api_vxlan_gpe_ioam_transit_enable_t_handler)
vl_msg_id(VL_API_VXLAN_GPE_IOAM_TRANSIT_ENABLE_REPLY, vl_api_vxlan_gpe_ioam_transit_enable_reply_t_handler)
vl_msg_id(VL_API_VXLAN_GPE_IOAM_TRANSIT_DISABLE, vl_api_vxlan_gpe_ioam_transit_disable_t_handler)
vl_msg_id(VL_API_VXLAN_GPE_IOAM_TRANSIT_DISABLE_REPLY, vl_api_vxlan_gpe_ioam_transit_disable_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_vxlan_gpe_ioam_enable_t, 1)
vl_msg_name(vl_api_vxlan_gpe_ioam_enable_reply_t, 1)
vl_msg_name(vl_api_vxlan_gpe_ioam_disable_t, 1)
vl_msg_name(vl_api_vxlan_gpe_ioam_disable_reply_t, 1)
vl_msg_name(vl_api_vxlan_gpe_ioam_vni_enable_t, 1)
vl_msg_name(vl_api_vxlan_gpe_ioam_vni_enable_reply_t, 1)
vl_msg_name(vl_api_vxlan_gpe_ioam_vni_disable_t, 1)
vl_msg_name(vl_api_vxlan_gpe_ioam_vni_disable_reply_t, 1)
vl_msg_name(vl_api_vxlan_gpe_ioam_transit_enable_t, 1)
vl_msg_name(vl_api_vxlan_gpe_ioam_transit_enable_reply_t, 1)
vl_msg_name(vl_api_vxlan_gpe_ioam_transit_disable_t, 1)
vl_msg_name(vl_api_vxlan_gpe_ioam_transit_disable_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_ioam_vxlan_gpe \
_(VL_API_VXLAN_GPE_IOAM_ENABLE, vxlan_gpe_ioam_enable, 2481bef7) \
_(VL_API_VXLAN_GPE_IOAM_ENABLE_REPLY, vxlan_gpe_ioam_enable_reply, e8d4e804) \
_(VL_API_VXLAN_GPE_IOAM_DISABLE, vxlan_gpe_ioam_disable, 6b16a45e) \
_(VL_API_VXLAN_GPE_IOAM_DISABLE_REPLY, vxlan_gpe_ioam_disable_reply, e8d4e804) \
_(VL_API_VXLAN_GPE_IOAM_VNI_ENABLE, vxlan_gpe_ioam_vni_enable, 0fbb5fb1) \
_(VL_API_VXLAN_GPE_IOAM_VNI_ENABLE_REPLY, vxlan_gpe_ioam_vni_enable_reply, e8d4e804) \
_(VL_API_VXLAN_GPE_IOAM_VNI_DISABLE, vxlan_gpe_ioam_vni_disable, 0fbb5fb1) \
_(VL_API_VXLAN_GPE_IOAM_VNI_DISABLE_REPLY, vxlan_gpe_ioam_vni_disable_reply, e8d4e804) \
_(VL_API_VXLAN_GPE_IOAM_TRANSIT_ENABLE, vxlan_gpe_ioam_transit_enable, 3d3ec657) \
_(VL_API_VXLAN_GPE_IOAM_TRANSIT_ENABLE_REPLY, vxlan_gpe_ioam_transit_enable_reply, e8d4e804) \
_(VL_API_VXLAN_GPE_IOAM_TRANSIT_DISABLE, vxlan_gpe_ioam_transit_disable, 3d3ec657) \
_(VL_API_VXLAN_GPE_IOAM_TRANSIT_DISABLE_REPLY, vxlan_gpe_ioam_transit_disable_reply, e8d4e804) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "ioam_vxlan_gpe.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_ioam_vxlan_gpe_printfun_types
#define included_ioam_vxlan_gpe_printfun_types


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_ioam_vxlan_gpe_printfun
#define included_ioam_vxlan_gpe_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "ioam_vxlan_gpe.api_tojson.h"
#include "ioam_vxlan_gpe.api_fromjson.h"

static inline u8 *vl_api_vxlan_gpe_ioam_enable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vxlan_gpe_ioam_enable_t *a = va_arg (*args, vl_api_vxlan_gpe_ioam_enable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vxlan_gpe_ioam_enable_t: */
    s = format(s, "vl_api_vxlan_gpe_ioam_enable_t:");
    s = format(s, "\n%Uid: %u", format_white_space, indent, a->id);
    s = format(s, "\n%Utrace_ppc: %u", format_white_space, indent, a->trace_ppc);
    s = format(s, "\n%Upow_enable: %u", format_white_space, indent, a->pow_enable);
    s = format(s, "\n%Utrace_enable: %u", format_white_space, indent, a->trace_enable);
    return s;
}

static inline u8 *vl_api_vxlan_gpe_ioam_enable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vxlan_gpe_ioam_enable_reply_t *a = va_arg (*args, vl_api_vxlan_gpe_ioam_enable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vxlan_gpe_ioam_enable_reply_t: */
    s = format(s, "vl_api_vxlan_gpe_ioam_enable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_vxlan_gpe_ioam_disable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vxlan_gpe_ioam_disable_t *a = va_arg (*args, vl_api_vxlan_gpe_ioam_disable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vxlan_gpe_ioam_disable_t: */
    s = format(s, "vl_api_vxlan_gpe_ioam_disable_t:");
    s = format(s, "\n%Uid: %u", format_white_space, indent, a->id);
    return s;
}

static inline u8 *vl_api_vxlan_gpe_ioam_disable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vxlan_gpe_ioam_disable_reply_t *a = va_arg (*args, vl_api_vxlan_gpe_ioam_disable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vxlan_gpe_ioam_disable_reply_t: */
    s = format(s, "vl_api_vxlan_gpe_ioam_disable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_vxlan_gpe_ioam_vni_enable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vxlan_gpe_ioam_vni_enable_t *a = va_arg (*args, vl_api_vxlan_gpe_ioam_vni_enable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vxlan_gpe_ioam_vni_enable_t: */
    s = format(s, "vl_api_vxlan_gpe_ioam_vni_enable_t:");
    s = format(s, "\n%Uvni: %u", format_white_space, indent, a->vni);
    s = format(s, "\n%Ulocal: %U", format_white_space, indent, format_vl_api_address_t, &a->local, indent);
    s = format(s, "\n%Uremote: %U", format_white_space, indent, format_vl_api_address_t, &a->remote, indent);
    return s;
}

static inline u8 *vl_api_vxlan_gpe_ioam_vni_enable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vxlan_gpe_ioam_vni_enable_reply_t *a = va_arg (*args, vl_api_vxlan_gpe_ioam_vni_enable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vxlan_gpe_ioam_vni_enable_reply_t: */
    s = format(s, "vl_api_vxlan_gpe_ioam_vni_enable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_vxlan_gpe_ioam_vni_disable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vxlan_gpe_ioam_vni_disable_t *a = va_arg (*args, vl_api_vxlan_gpe_ioam_vni_disable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vxlan_gpe_ioam_vni_disable_t: */
    s = format(s, "vl_api_vxlan_gpe_ioam_vni_disable_t:");
    s = format(s, "\n%Uvni: %u", format_white_space, indent, a->vni);
    s = format(s, "\n%Ulocal: %U", format_white_space, indent, format_vl_api_address_t, &a->local, indent);
    s = format(s, "\n%Uremote: %U", format_white_space, indent, format_vl_api_address_t, &a->remote, indent);
    return s;
}

static inline u8 *vl_api_vxlan_gpe_ioam_vni_disable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vxlan_gpe_ioam_vni_disable_reply_t *a = va_arg (*args, vl_api_vxlan_gpe_ioam_vni_disable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vxlan_gpe_ioam_vni_disable_reply_t: */
    s = format(s, "vl_api_vxlan_gpe_ioam_vni_disable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_vxlan_gpe_ioam_transit_enable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vxlan_gpe_ioam_transit_enable_t *a = va_arg (*args, vl_api_vxlan_gpe_ioam_transit_enable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vxlan_gpe_ioam_transit_enable_t: */
    s = format(s, "vl_api_vxlan_gpe_ioam_transit_enable_t:");
    s = format(s, "\n%Uouter_fib_index: %u", format_white_space, indent, a->outer_fib_index);
    s = format(s, "\n%Udst_addr: %U", format_white_space, indent, format_vl_api_address_t, &a->dst_addr, indent);
    return s;
}

static inline u8 *vl_api_vxlan_gpe_ioam_transit_enable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vxlan_gpe_ioam_transit_enable_reply_t *a = va_arg (*args, vl_api_vxlan_gpe_ioam_transit_enable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vxlan_gpe_ioam_transit_enable_reply_t: */
    s = format(s, "vl_api_vxlan_gpe_ioam_transit_enable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_vxlan_gpe_ioam_transit_disable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vxlan_gpe_ioam_transit_disable_t *a = va_arg (*args, vl_api_vxlan_gpe_ioam_transit_disable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vxlan_gpe_ioam_transit_disable_t: */
    s = format(s, "vl_api_vxlan_gpe_ioam_transit_disable_t:");
    s = format(s, "\n%Uouter_fib_index: %u", format_white_space, indent, a->outer_fib_index);
    s = format(s, "\n%Udst_addr: %U", format_white_space, indent, format_vl_api_address_t, &a->dst_addr, indent);
    return s;
}

static inline u8 *vl_api_vxlan_gpe_ioam_transit_disable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vxlan_gpe_ioam_transit_disable_reply_t *a = va_arg (*args, vl_api_vxlan_gpe_ioam_transit_disable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vxlan_gpe_ioam_transit_disable_reply_t: */
    s = format(s, "vl_api_vxlan_gpe_ioam_transit_disable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_ioam_vxlan_gpe_endianfun
#define included_ioam_vxlan_gpe_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_vxlan_gpe_ioam_enable_t_endian (vl_api_vxlan_gpe_ioam_enable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->id = clib_net_to_host_u16(a->id);
    /* a->trace_ppc = a->trace_ppc (no-op) */
    /* a->pow_enable = a->pow_enable (no-op) */
    /* a->trace_enable = a->trace_enable (no-op) */
}

static inline void vl_api_vxlan_gpe_ioam_enable_reply_t_endian (vl_api_vxlan_gpe_ioam_enable_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_vxlan_gpe_ioam_disable_t_endian (vl_api_vxlan_gpe_ioam_disable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->id = clib_net_to_host_u16(a->id);
}

static inline void vl_api_vxlan_gpe_ioam_disable_reply_t_endian (vl_api_vxlan_gpe_ioam_disable_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_vxlan_gpe_ioam_vni_enable_t_endian (vl_api_vxlan_gpe_ioam_vni_enable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->vni = clib_net_to_host_u32(a->vni);
    vl_api_address_t_endian(&a->local, to_net);
    vl_api_address_t_endian(&a->remote, to_net);
}

static inline void vl_api_vxlan_gpe_ioam_vni_enable_reply_t_endian (vl_api_vxlan_gpe_ioam_vni_enable_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_vxlan_gpe_ioam_vni_disable_t_endian (vl_api_vxlan_gpe_ioam_vni_disable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->vni = clib_net_to_host_u32(a->vni);
    vl_api_address_t_endian(&a->local, to_net);
    vl_api_address_t_endian(&a->remote, to_net);
}

static inline void vl_api_vxlan_gpe_ioam_vni_disable_reply_t_endian (vl_api_vxlan_gpe_ioam_vni_disable_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_vxlan_gpe_ioam_transit_enable_t_endian (vl_api_vxlan_gpe_ioam_transit_enable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->outer_fib_index = clib_net_to_host_u32(a->outer_fib_index);
    vl_api_address_t_endian(&a->dst_addr, to_net);
}

static inline void vl_api_vxlan_gpe_ioam_transit_enable_reply_t_endian (vl_api_vxlan_gpe_ioam_transit_enable_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_vxlan_gpe_ioam_transit_disable_t_endian (vl_api_vxlan_gpe_ioam_transit_disable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->outer_fib_index = clib_net_to_host_u32(a->outer_fib_index);
    vl_api_address_t_endian(&a->dst_addr, to_net);
}

static inline void vl_api_vxlan_gpe_ioam_transit_disable_reply_t_endian (vl_api_vxlan_gpe_ioam_transit_disable_reply_t *a, bool to_net)
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
#ifndef included_ioam_vxlan_gpe_calcsizefun
#define included_ioam_vxlan_gpe_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_vxlan_gpe_ioam_enable_t_calc_size (vl_api_vxlan_gpe_ioam_enable_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vxlan_gpe_ioam_enable_reply_t_calc_size (vl_api_vxlan_gpe_ioam_enable_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vxlan_gpe_ioam_disable_t_calc_size (vl_api_vxlan_gpe_ioam_disable_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vxlan_gpe_ioam_disable_reply_t_calc_size (vl_api_vxlan_gpe_ioam_disable_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vxlan_gpe_ioam_vni_enable_t_calc_size (vl_api_vxlan_gpe_ioam_vni_enable_t *a)
{
      return sizeof(*a) - sizeof(a->local) + vl_api_address_t_calc_size(&a->local) - sizeof(a->remote) + vl_api_address_t_calc_size(&a->remote);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vxlan_gpe_ioam_vni_enable_reply_t_calc_size (vl_api_vxlan_gpe_ioam_vni_enable_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vxlan_gpe_ioam_vni_disable_t_calc_size (vl_api_vxlan_gpe_ioam_vni_disable_t *a)
{
      return sizeof(*a) - sizeof(a->local) + vl_api_address_t_calc_size(&a->local) - sizeof(a->remote) + vl_api_address_t_calc_size(&a->remote);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vxlan_gpe_ioam_vni_disable_reply_t_calc_size (vl_api_vxlan_gpe_ioam_vni_disable_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vxlan_gpe_ioam_transit_enable_t_calc_size (vl_api_vxlan_gpe_ioam_transit_enable_t *a)
{
      return sizeof(*a) - sizeof(a->dst_addr) + vl_api_address_t_calc_size(&a->dst_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vxlan_gpe_ioam_transit_enable_reply_t_calc_size (vl_api_vxlan_gpe_ioam_transit_enable_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vxlan_gpe_ioam_transit_disable_t_calc_size (vl_api_vxlan_gpe_ioam_transit_disable_t *a)
{
      return sizeof(*a) - sizeof(a->dst_addr) + vl_api_address_t_calc_size(&a->dst_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vxlan_gpe_ioam_transit_disable_reply_t_calc_size (vl_api_vxlan_gpe_ioam_transit_disable_reply_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(ioam_vxlan_gpe.api, 1, 0, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(ioam_vxlan_gpe.api, 0xb9e086eb)

#endif

