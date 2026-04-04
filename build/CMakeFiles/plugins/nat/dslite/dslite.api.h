/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: dslite.api
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
#warning no content included from dslite.api
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
#include <vnet/interface_types.api.h>
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_DSLITE_ADD_DEL_POOL_ADDR_RANGE, vl_api_dslite_add_del_pool_addr_range_t_handler)
vl_msg_id(VL_API_DSLITE_ADD_DEL_POOL_ADDR_RANGE_REPLY, vl_api_dslite_add_del_pool_addr_range_reply_t_handler)
vl_msg_id(VL_API_DSLITE_ADDRESS_DUMP, vl_api_dslite_address_dump_t_handler)
vl_msg_id(VL_API_DSLITE_ADDRESS_DETAILS, vl_api_dslite_address_details_t_handler)
vl_msg_id(VL_API_DSLITE_SET_AFTR_ADDR, vl_api_dslite_set_aftr_addr_t_handler)
vl_msg_id(VL_API_DSLITE_SET_AFTR_ADDR_REPLY, vl_api_dslite_set_aftr_addr_reply_t_handler)
vl_msg_id(VL_API_DSLITE_GET_AFTR_ADDR, vl_api_dslite_get_aftr_addr_t_handler)
vl_msg_id(VL_API_DSLITE_GET_AFTR_ADDR_REPLY, vl_api_dslite_get_aftr_addr_reply_t_handler)
vl_msg_id(VL_API_DSLITE_SET_B4_ADDR, vl_api_dslite_set_b4_addr_t_handler)
vl_msg_id(VL_API_DSLITE_SET_B4_ADDR_REPLY, vl_api_dslite_set_b4_addr_reply_t_handler)
vl_msg_id(VL_API_DSLITE_GET_B4_ADDR, vl_api_dslite_get_b4_addr_t_handler)
vl_msg_id(VL_API_DSLITE_GET_B4_ADDR_REPLY, vl_api_dslite_get_b4_addr_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_dslite_add_del_pool_addr_range_t, 1)
vl_msg_name(vl_api_dslite_add_del_pool_addr_range_reply_t, 1)
vl_msg_name(vl_api_dslite_address_dump_t, 1)
vl_msg_name(vl_api_dslite_address_details_t, 1)
vl_msg_name(vl_api_dslite_set_aftr_addr_t, 1)
vl_msg_name(vl_api_dslite_set_aftr_addr_reply_t, 1)
vl_msg_name(vl_api_dslite_get_aftr_addr_t, 1)
vl_msg_name(vl_api_dslite_get_aftr_addr_reply_t, 1)
vl_msg_name(vl_api_dslite_set_b4_addr_t, 1)
vl_msg_name(vl_api_dslite_set_b4_addr_reply_t, 1)
vl_msg_name(vl_api_dslite_get_b4_addr_t, 1)
vl_msg_name(vl_api_dslite_get_b4_addr_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_dslite \
_(VL_API_DSLITE_ADD_DEL_POOL_ADDR_RANGE, dslite_add_del_pool_addr_range, de2a5b02) \
_(VL_API_DSLITE_ADD_DEL_POOL_ADDR_RANGE_REPLY, dslite_add_del_pool_addr_range_reply, e8d4e804) \
_(VL_API_DSLITE_ADDRESS_DUMP, dslite_address_dump, 51077d14) \
_(VL_API_DSLITE_ADDRESS_DETAILS, dslite_address_details, ec26d648) \
_(VL_API_DSLITE_SET_AFTR_ADDR, dslite_set_aftr_addr, 78b50fdf) \
_(VL_API_DSLITE_SET_AFTR_ADDR_REPLY, dslite_set_aftr_addr_reply, e8d4e804) \
_(VL_API_DSLITE_GET_AFTR_ADDR, dslite_get_aftr_addr, 51077d14) \
_(VL_API_DSLITE_GET_AFTR_ADDR_REPLY, dslite_get_aftr_addr_reply, 8e23608e) \
_(VL_API_DSLITE_SET_B4_ADDR, dslite_set_b4_addr, 78b50fdf) \
_(VL_API_DSLITE_SET_B4_ADDR_REPLY, dslite_set_b4_addr_reply, e8d4e804) \
_(VL_API_DSLITE_GET_B4_ADDR, dslite_get_b4_addr, 51077d14) \
_(VL_API_DSLITE_GET_B4_ADDR_REPLY, dslite_get_b4_addr_reply, 8e23608e) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "dslite.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_dslite_printfun_types
#define included_dslite_printfun_types


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_dslite_printfun
#define included_dslite_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "dslite.api_tojson.h"
#include "dslite.api_fromjson.h"

static inline u8 *vl_api_dslite_add_del_pool_addr_range_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_dslite_add_del_pool_addr_range_t *a = va_arg (*args, vl_api_dslite_add_del_pool_addr_range_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_dslite_add_del_pool_addr_range_t: */
    s = format(s, "vl_api_dslite_add_del_pool_addr_range_t:");
    s = format(s, "\n%Ustart_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->start_addr, indent);
    s = format(s, "\n%Uend_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->end_addr, indent);
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    return s;
}

static inline u8 *vl_api_dslite_add_del_pool_addr_range_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_dslite_add_del_pool_addr_range_reply_t *a = va_arg (*args, vl_api_dslite_add_del_pool_addr_range_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_dslite_add_del_pool_addr_range_reply_t: */
    s = format(s, "vl_api_dslite_add_del_pool_addr_range_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_dslite_address_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_dslite_address_dump_t *a = va_arg (*args, vl_api_dslite_address_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_dslite_address_dump_t: */
    s = format(s, "vl_api_dslite_address_dump_t:");
    return s;
}

static inline u8 *vl_api_dslite_address_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_dslite_address_details_t *a = va_arg (*args, vl_api_dslite_address_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_dslite_address_details_t: */
    s = format(s, "vl_api_dslite_address_details_t:");
    s = format(s, "\n%Uip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ip_address, indent);
    return s;
}

static inline u8 *vl_api_dslite_set_aftr_addr_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_dslite_set_aftr_addr_t *a = va_arg (*args, vl_api_dslite_set_aftr_addr_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_dslite_set_aftr_addr_t: */
    s = format(s, "vl_api_dslite_set_aftr_addr_t:");
    s = format(s, "\n%Uip4_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ip4_addr, indent);
    s = format(s, "\n%Uip6_addr: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->ip6_addr, indent);
    return s;
}

static inline u8 *vl_api_dslite_set_aftr_addr_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_dslite_set_aftr_addr_reply_t *a = va_arg (*args, vl_api_dslite_set_aftr_addr_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_dslite_set_aftr_addr_reply_t: */
    s = format(s, "vl_api_dslite_set_aftr_addr_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_dslite_get_aftr_addr_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_dslite_get_aftr_addr_t *a = va_arg (*args, vl_api_dslite_get_aftr_addr_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_dslite_get_aftr_addr_t: */
    s = format(s, "vl_api_dslite_get_aftr_addr_t:");
    return s;
}

static inline u8 *vl_api_dslite_get_aftr_addr_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_dslite_get_aftr_addr_reply_t *a = va_arg (*args, vl_api_dslite_get_aftr_addr_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_dslite_get_aftr_addr_reply_t: */
    s = format(s, "vl_api_dslite_get_aftr_addr_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uip4_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ip4_addr, indent);
    s = format(s, "\n%Uip6_addr: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->ip6_addr, indent);
    return s;
}

static inline u8 *vl_api_dslite_set_b4_addr_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_dslite_set_b4_addr_t *a = va_arg (*args, vl_api_dslite_set_b4_addr_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_dslite_set_b4_addr_t: */
    s = format(s, "vl_api_dslite_set_b4_addr_t:");
    s = format(s, "\n%Uip4_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ip4_addr, indent);
    s = format(s, "\n%Uip6_addr: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->ip6_addr, indent);
    return s;
}

static inline u8 *vl_api_dslite_set_b4_addr_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_dslite_set_b4_addr_reply_t *a = va_arg (*args, vl_api_dslite_set_b4_addr_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_dslite_set_b4_addr_reply_t: */
    s = format(s, "vl_api_dslite_set_b4_addr_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_dslite_get_b4_addr_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_dslite_get_b4_addr_t *a = va_arg (*args, vl_api_dslite_get_b4_addr_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_dslite_get_b4_addr_t: */
    s = format(s, "vl_api_dslite_get_b4_addr_t:");
    return s;
}

static inline u8 *vl_api_dslite_get_b4_addr_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_dslite_get_b4_addr_reply_t *a = va_arg (*args, vl_api_dslite_get_b4_addr_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_dslite_get_b4_addr_reply_t: */
    s = format(s, "vl_api_dslite_get_b4_addr_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uip4_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ip4_addr, indent);
    s = format(s, "\n%Uip6_addr: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->ip6_addr, indent);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_dslite_endianfun
#define included_dslite_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_dslite_add_del_pool_addr_range_t_endian (vl_api_dslite_add_del_pool_addr_range_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->start_addr, to_net);
    vl_api_ip4_address_t_endian(&a->end_addr, to_net);
    /* a->is_add = a->is_add (no-op) */
}

static inline void vl_api_dslite_add_del_pool_addr_range_reply_t_endian (vl_api_dslite_add_del_pool_addr_range_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_dslite_address_dump_t_endian (vl_api_dslite_address_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_dslite_address_details_t_endian (vl_api_dslite_address_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->ip_address, to_net);
}

static inline void vl_api_dslite_set_aftr_addr_t_endian (vl_api_dslite_set_aftr_addr_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->ip4_addr, to_net);
    vl_api_ip6_address_t_endian(&a->ip6_addr, to_net);
}

static inline void vl_api_dslite_set_aftr_addr_reply_t_endian (vl_api_dslite_set_aftr_addr_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_dslite_get_aftr_addr_t_endian (vl_api_dslite_get_aftr_addr_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_dslite_get_aftr_addr_reply_t_endian (vl_api_dslite_get_aftr_addr_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_ip4_address_t_endian(&a->ip4_addr, to_net);
    vl_api_ip6_address_t_endian(&a->ip6_addr, to_net);
}

static inline void vl_api_dslite_set_b4_addr_t_endian (vl_api_dslite_set_b4_addr_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->ip4_addr, to_net);
    vl_api_ip6_address_t_endian(&a->ip6_addr, to_net);
}

static inline void vl_api_dslite_set_b4_addr_reply_t_endian (vl_api_dslite_set_b4_addr_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_dslite_get_b4_addr_t_endian (vl_api_dslite_get_b4_addr_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_dslite_get_b4_addr_reply_t_endian (vl_api_dslite_get_b4_addr_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_ip4_address_t_endian(&a->ip4_addr, to_net);
    vl_api_ip6_address_t_endian(&a->ip6_addr, to_net);
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_dslite_calcsizefun
#define included_dslite_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_dslite_add_del_pool_addr_range_t_calc_size (vl_api_dslite_add_del_pool_addr_range_t *a)
{
      return sizeof(*a) - sizeof(a->start_addr) + vl_api_ip4_address_t_calc_size(&a->start_addr) - sizeof(a->end_addr) + vl_api_ip4_address_t_calc_size(&a->end_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_dslite_add_del_pool_addr_range_reply_t_calc_size (vl_api_dslite_add_del_pool_addr_range_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_dslite_address_dump_t_calc_size (vl_api_dslite_address_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_dslite_address_details_t_calc_size (vl_api_dslite_address_details_t *a)
{
      return sizeof(*a) - sizeof(a->ip_address) + vl_api_ip4_address_t_calc_size(&a->ip_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_dslite_set_aftr_addr_t_calc_size (vl_api_dslite_set_aftr_addr_t *a)
{
      return sizeof(*a) - sizeof(a->ip4_addr) + vl_api_ip4_address_t_calc_size(&a->ip4_addr) - sizeof(a->ip6_addr) + vl_api_ip6_address_t_calc_size(&a->ip6_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_dslite_set_aftr_addr_reply_t_calc_size (vl_api_dslite_set_aftr_addr_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_dslite_get_aftr_addr_t_calc_size (vl_api_dslite_get_aftr_addr_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_dslite_get_aftr_addr_reply_t_calc_size (vl_api_dslite_get_aftr_addr_reply_t *a)
{
      return sizeof(*a) - sizeof(a->ip4_addr) + vl_api_ip4_address_t_calc_size(&a->ip4_addr) - sizeof(a->ip6_addr) + vl_api_ip6_address_t_calc_size(&a->ip6_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_dslite_set_b4_addr_t_calc_size (vl_api_dslite_set_b4_addr_t *a)
{
      return sizeof(*a) - sizeof(a->ip4_addr) + vl_api_ip4_address_t_calc_size(&a->ip4_addr) - sizeof(a->ip6_addr) + vl_api_ip6_address_t_calc_size(&a->ip6_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_dslite_set_b4_addr_reply_t_calc_size (vl_api_dslite_set_b4_addr_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_dslite_get_b4_addr_t_calc_size (vl_api_dslite_get_b4_addr_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_dslite_get_b4_addr_reply_t_calc_size (vl_api_dslite_get_b4_addr_reply_t *a)
{
      return sizeof(*a) - sizeof(a->ip4_addr) + vl_api_ip4_address_t_calc_size(&a->ip4_addr) - sizeof(a->ip6_addr) + vl_api_ip6_address_t_calc_size(&a->ip6_addr);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(dslite.api, 1, 0, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(dslite.api, 0x4bc15f82)

#endif

