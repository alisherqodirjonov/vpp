/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: nsim.api
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
#warning no content included from nsim.api
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
vl_msg_id(VL_API_NSIM_CROSS_CONNECT_ENABLE_DISABLE, vl_api_nsim_cross_connect_enable_disable_t_handler)
vl_msg_id(VL_API_NSIM_CROSS_CONNECT_ENABLE_DISABLE_REPLY, vl_api_nsim_cross_connect_enable_disable_reply_t_handler)
vl_msg_id(VL_API_NSIM_OUTPUT_FEATURE_ENABLE_DISABLE, vl_api_nsim_output_feature_enable_disable_t_handler)
vl_msg_id(VL_API_NSIM_OUTPUT_FEATURE_ENABLE_DISABLE_REPLY, vl_api_nsim_output_feature_enable_disable_reply_t_handler)
vl_msg_id(VL_API_NSIM_CONFIGURE, vl_api_nsim_configure_t_handler)
vl_msg_id(VL_API_NSIM_CONFIGURE_REPLY, vl_api_nsim_configure_reply_t_handler)
vl_msg_id(VL_API_NSIM_CONFIGURE2, vl_api_nsim_configure2_t_handler)
vl_msg_id(VL_API_NSIM_CONFIGURE2_REPLY, vl_api_nsim_configure2_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_nsim_cross_connect_enable_disable_t, 1)
vl_msg_name(vl_api_nsim_cross_connect_enable_disable_reply_t, 1)
vl_msg_name(vl_api_nsim_output_feature_enable_disable_t, 1)
vl_msg_name(vl_api_nsim_output_feature_enable_disable_reply_t, 1)
vl_msg_name(vl_api_nsim_configure_t, 1)
vl_msg_name(vl_api_nsim_configure_reply_t, 1)
vl_msg_name(vl_api_nsim_configure2_t, 1)
vl_msg_name(vl_api_nsim_configure2_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_nsim \
_(VL_API_NSIM_CROSS_CONNECT_ENABLE_DISABLE, nsim_cross_connect_enable_disable, 9c3ead86) \
_(VL_API_NSIM_CROSS_CONNECT_ENABLE_DISABLE_REPLY, nsim_cross_connect_enable_disable_reply, e8d4e804) \
_(VL_API_NSIM_OUTPUT_FEATURE_ENABLE_DISABLE, nsim_output_feature_enable_disable, 3865946c) \
_(VL_API_NSIM_OUTPUT_FEATURE_ENABLE_DISABLE_REPLY, nsim_output_feature_enable_disable_reply, e8d4e804) \
_(VL_API_NSIM_CONFIGURE, nsim_configure, 16ed400f) \
_(VL_API_NSIM_CONFIGURE_REPLY, nsim_configure_reply, e8d4e804) \
_(VL_API_NSIM_CONFIGURE2, nsim_configure2, 64de8ed3) \
_(VL_API_NSIM_CONFIGURE2_REPLY, nsim_configure2_reply, e8d4e804) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "nsim.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_nsim_printfun_types
#define included_nsim_printfun_types


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_nsim_printfun
#define included_nsim_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "nsim.api_tojson.h"
#include "nsim.api_fromjson.h"

static inline u8 *vl_api_nsim_cross_connect_enable_disable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nsim_cross_connect_enable_disable_t *a = va_arg (*args, vl_api_nsim_cross_connect_enable_disable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nsim_cross_connect_enable_disable_t: */
    s = format(s, "vl_api_nsim_cross_connect_enable_disable_t:");
    s = format(s, "\n%Uenable_disable: %u", format_white_space, indent, a->enable_disable);
    s = format(s, "\n%Usw_if_index0: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index0, indent);
    s = format(s, "\n%Usw_if_index1: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index1, indent);
    return s;
}

static inline u8 *vl_api_nsim_cross_connect_enable_disable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nsim_cross_connect_enable_disable_reply_t *a = va_arg (*args, vl_api_nsim_cross_connect_enable_disable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nsim_cross_connect_enable_disable_reply_t: */
    s = format(s, "vl_api_nsim_cross_connect_enable_disable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nsim_output_feature_enable_disable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nsim_output_feature_enable_disable_t *a = va_arg (*args, vl_api_nsim_output_feature_enable_disable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nsim_output_feature_enable_disable_t: */
    s = format(s, "vl_api_nsim_output_feature_enable_disable_t:");
    s = format(s, "\n%Uenable_disable: %u", format_white_space, indent, a->enable_disable);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_nsim_output_feature_enable_disable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nsim_output_feature_enable_disable_reply_t *a = va_arg (*args, vl_api_nsim_output_feature_enable_disable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nsim_output_feature_enable_disable_reply_t: */
    s = format(s, "vl_api_nsim_output_feature_enable_disable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nsim_configure_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nsim_configure_t *a = va_arg (*args, vl_api_nsim_configure_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nsim_configure_t: */
    s = format(s, "vl_api_nsim_configure_t:");
    s = format(s, "\n%Udelay_in_usec: %u", format_white_space, indent, a->delay_in_usec);
    s = format(s, "\n%Uaverage_packet_size: %u", format_white_space, indent, a->average_packet_size);
    s = format(s, "\n%Ubandwidth_in_bits_per_second: %llu", format_white_space, indent, a->bandwidth_in_bits_per_second);
    s = format(s, "\n%Upackets_per_drop: %u", format_white_space, indent, a->packets_per_drop);
    return s;
}

static inline u8 *vl_api_nsim_configure_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nsim_configure_reply_t *a = va_arg (*args, vl_api_nsim_configure_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nsim_configure_reply_t: */
    s = format(s, "vl_api_nsim_configure_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nsim_configure2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nsim_configure2_t *a = va_arg (*args, vl_api_nsim_configure2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nsim_configure2_t: */
    s = format(s, "vl_api_nsim_configure2_t:");
    s = format(s, "\n%Udelay_in_usec: %u", format_white_space, indent, a->delay_in_usec);
    s = format(s, "\n%Uaverage_packet_size: %u", format_white_space, indent, a->average_packet_size);
    s = format(s, "\n%Ubandwidth_in_bits_per_second: %llu", format_white_space, indent, a->bandwidth_in_bits_per_second);
    s = format(s, "\n%Upackets_per_drop: %u", format_white_space, indent, a->packets_per_drop);
    s = format(s, "\n%Upackets_per_reorder: %u", format_white_space, indent, a->packets_per_reorder);
    return s;
}

static inline u8 *vl_api_nsim_configure2_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nsim_configure2_reply_t *a = va_arg (*args, vl_api_nsim_configure2_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nsim_configure2_reply_t: */
    s = format(s, "vl_api_nsim_configure2_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_nsim_endianfun
#define included_nsim_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_nsim_cross_connect_enable_disable_t_endian (vl_api_nsim_cross_connect_enable_disable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->enable_disable = a->enable_disable (no-op) */
    vl_api_interface_index_t_endian(&a->sw_if_index0, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index1, to_net);
}

static inline void vl_api_nsim_cross_connect_enable_disable_reply_t_endian (vl_api_nsim_cross_connect_enable_disable_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nsim_output_feature_enable_disable_t_endian (vl_api_nsim_output_feature_enable_disable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->enable_disable = a->enable_disable (no-op) */
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_nsim_output_feature_enable_disable_reply_t_endian (vl_api_nsim_output_feature_enable_disable_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nsim_configure_t_endian (vl_api_nsim_configure_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->delay_in_usec = clib_net_to_host_u32(a->delay_in_usec);
    a->average_packet_size = clib_net_to_host_u32(a->average_packet_size);
    a->bandwidth_in_bits_per_second = clib_net_to_host_u64(a->bandwidth_in_bits_per_second);
    a->packets_per_drop = clib_net_to_host_u32(a->packets_per_drop);
}

static inline void vl_api_nsim_configure_reply_t_endian (vl_api_nsim_configure_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nsim_configure2_t_endian (vl_api_nsim_configure2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->delay_in_usec = clib_net_to_host_u32(a->delay_in_usec);
    a->average_packet_size = clib_net_to_host_u32(a->average_packet_size);
    a->bandwidth_in_bits_per_second = clib_net_to_host_u64(a->bandwidth_in_bits_per_second);
    a->packets_per_drop = clib_net_to_host_u32(a->packets_per_drop);
    a->packets_per_reorder = clib_net_to_host_u32(a->packets_per_reorder);
}

static inline void vl_api_nsim_configure2_reply_t_endian (vl_api_nsim_configure2_reply_t *a, bool to_net)
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
#ifndef included_nsim_calcsizefun
#define included_nsim_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_nsim_cross_connect_enable_disable_t_calc_size (vl_api_nsim_cross_connect_enable_disable_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index0) + vl_api_interface_index_t_calc_size(&a->sw_if_index0) - sizeof(a->sw_if_index1) + vl_api_interface_index_t_calc_size(&a->sw_if_index1);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nsim_cross_connect_enable_disable_reply_t_calc_size (vl_api_nsim_cross_connect_enable_disable_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nsim_output_feature_enable_disable_t_calc_size (vl_api_nsim_output_feature_enable_disable_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nsim_output_feature_enable_disable_reply_t_calc_size (vl_api_nsim_output_feature_enable_disable_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nsim_configure_t_calc_size (vl_api_nsim_configure_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nsim_configure_reply_t_calc_size (vl_api_nsim_configure_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nsim_configure2_t_calc_size (vl_api_nsim_configure2_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nsim_configure2_reply_t_calc_size (vl_api_nsim_configure2_reply_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(nsim.api, 2, 2, 1)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(nsim.api, 0xf1cc8e8)

#endif

