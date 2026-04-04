/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: stn.api
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
#warning no content included from stn.api
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
vl_msg_id(VL_API_STN_ADD_DEL_RULE, vl_api_stn_add_del_rule_t_handler)
vl_msg_id(VL_API_STN_ADD_DEL_RULE_REPLY, vl_api_stn_add_del_rule_reply_t_handler)
vl_msg_id(VL_API_STN_RULES_DUMP, vl_api_stn_rules_dump_t_handler)
vl_msg_id(VL_API_STN_RULES_DETAILS, vl_api_stn_rules_details_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_stn_add_del_rule_t, 1)
vl_msg_name(vl_api_stn_add_del_rule_reply_t, 1)
vl_msg_name(vl_api_stn_rules_dump_t, 1)
vl_msg_name(vl_api_stn_rules_details_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_stn \
_(VL_API_STN_ADD_DEL_RULE, stn_add_del_rule, 224c6edd) \
_(VL_API_STN_ADD_DEL_RULE_REPLY, stn_add_del_rule_reply, e8d4e804) \
_(VL_API_STN_RULES_DUMP, stn_rules_dump, 51077d14) \
_(VL_API_STN_RULES_DETAILS, stn_rules_details, a51935a6) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "stn.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_stn_printfun_types
#define included_stn_printfun_types


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_stn_printfun
#define included_stn_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "stn.api_tojson.h"
#include "stn.api_fromjson.h"

static inline u8 *vl_api_stn_add_del_rule_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_stn_add_del_rule_t *a = va_arg (*args, vl_api_stn_add_del_rule_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_stn_add_del_rule_t: */
    s = format(s, "vl_api_stn_add_del_rule_t:");
    s = format(s, "\n%Uip_address: %U", format_white_space, indent, format_vl_api_address_t, &a->ip_address, indent);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    return s;
}

static inline u8 *vl_api_stn_add_del_rule_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_stn_add_del_rule_reply_t *a = va_arg (*args, vl_api_stn_add_del_rule_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_stn_add_del_rule_reply_t: */
    s = format(s, "vl_api_stn_add_del_rule_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_stn_rules_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_stn_rules_dump_t *a = va_arg (*args, vl_api_stn_rules_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_stn_rules_dump_t: */
    s = format(s, "vl_api_stn_rules_dump_t:");
    return s;
}

static inline u8 *vl_api_stn_rules_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_stn_rules_details_t *a = va_arg (*args, vl_api_stn_rules_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_stn_rules_details_t: */
    s = format(s, "vl_api_stn_rules_details_t:");
    s = format(s, "\n%Uip_address: %U", format_white_space, indent, format_vl_api_address_t, &a->ip_address, indent);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_stn_endianfun
#define included_stn_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_stn_add_del_rule_t_endian (vl_api_stn_add_del_rule_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_address_t_endian(&a->ip_address, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->is_add = a->is_add (no-op) */
}

static inline void vl_api_stn_add_del_rule_reply_t_endian (vl_api_stn_add_del_rule_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_stn_rules_dump_t_endian (vl_api_stn_rules_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_stn_rules_details_t_endian (vl_api_stn_rules_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_address_t_endian(&a->ip_address, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_stn_calcsizefun
#define included_stn_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_stn_add_del_rule_t_calc_size (vl_api_stn_add_del_rule_t *a)
{
      return sizeof(*a) - sizeof(a->ip_address) + vl_api_address_t_calc_size(&a->ip_address) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_stn_add_del_rule_reply_t_calc_size (vl_api_stn_add_del_rule_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_stn_rules_dump_t_calc_size (vl_api_stn_rules_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_stn_rules_details_t_calc_size (vl_api_stn_rules_details_t *a)
{
      return sizeof(*a) - sizeof(a->ip_address) + vl_api_address_t_calc_size(&a->ip_address) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(stn.api, 2, 0, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(stn.api, 0x80cc51b1)

#endif

