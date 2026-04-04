/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: lisp_types.api
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
#warning no content included from lisp_types.api
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
#include <vnet/ethernet/ethernet_types.api.h>
#include <vnet/ip/ip_types.api.h>
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
#endif
/****** Message names ******/

#ifdef vl_msg_name
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_lisp_types 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "lisp_types.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_lisp_types_printfun_types
#define included_lisp_types_printfun_types

static inline u8 *format_vl_api_local_locator_t (u8 *s, va_list * args)
{
    vl_api_local_locator_t *a = va_arg (*args, vl_api_local_locator_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Upriority: %u", format_white_space, indent, a->priority);
    s = format(s, "\n%Uweight: %u", format_white_space, indent, a->weight);
    return s;
}

static inline u8 *format_vl_api_remote_locator_t (u8 *s, va_list * args)
{
    vl_api_remote_locator_t *a = va_arg (*args, vl_api_remote_locator_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Upriority: %u", format_white_space, indent, a->priority);
    s = format(s, "\n%Uweight: %u", format_white_space, indent, a->weight);
    s = format(s, "\n%Uip_address: %U", format_white_space, indent, format_vl_api_address_t, &a->ip_address, indent);
    return s;
}

static inline u8 *format_vl_api_eid_type_t (u8 *s, va_list * args)
{
    vl_api_eid_type_t *a = va_arg (*args, vl_api_eid_type_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "EID_TYPE_API_PREFIX");
    case 1:
        return format(s, "EID_TYPE_API_MAC");
    case 2:
        return format(s, "EID_TYPE_API_NSH");
    }
    return s;
}

static inline u8 *format_vl_api_nsh_t (u8 *s, va_list * args)
{
    vl_api_nsh_t *a = va_arg (*args, vl_api_nsh_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Uspi: %u", format_white_space, indent, a->spi);
    s = format(s, "\n%Usi: %u", format_white_space, indent, a->si);
    return s;
}

static inline u8 *format_vl_api_eid_address_t (u8 *s, va_list * args)
{
    vl_api_eid_address_t *a = va_arg (*args, vl_api_eid_address_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Uprefix: %U", format_white_space, indent, format_vl_api_prefix_t, &a->prefix, indent);
    s = format(s, "\n%Umac: %U", format_white_space, indent, format_vl_api_mac_address_t, &a->mac, indent);
    s = format(s, "\n%Unsh: %U", format_white_space, indent, format_vl_api_nsh_t, &a->nsh, indent);
    return s;
}

static inline u8 *format_vl_api_eid_t (u8 *s, va_list * args)
{
    vl_api_eid_t *a = va_arg (*args, vl_api_eid_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Utype: %U", format_white_space, indent, format_vl_api_eid_type_t, &a->type, indent);
    s = format(s, "\n%Uaddress: %U", format_white_space, indent, format_vl_api_eid_address_t, &a->address, indent);
    return s;
}

static inline u8 *format_vl_api_hmac_key_id_t (u8 *s, va_list * args)
{
    vl_api_hmac_key_id_t *a = va_arg (*args, vl_api_hmac_key_id_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "KEY_ID_API_HMAC_NO_KEY");
    case 1:
        return format(s, "KEY_ID_API_HMAC_SHA_1_96");
    case 2:
        return format(s, "KEY_ID_API_HMAC_SHA_256_128");
    }
    return s;
}

static inline u8 *format_vl_api_hmac_key_t (u8 *s, va_list * args)
{
    vl_api_hmac_key_t *a = va_arg (*args, vl_api_hmac_key_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Uid: %U", format_white_space, indent, format_vl_api_hmac_key_id_t, &a->id, indent);
    s = format(s, "\n%Ukey: %U", format_white_space, indent, format_hex_bytes, a, 64);
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_lisp_types_printfun
#define included_lisp_types_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "lisp_types.api_tojson.h"
#include "lisp_types.api_fromjson.h"


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_lisp_types_endianfun
#define included_lisp_types_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_local_locator_t_endian (vl_api_local_locator_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->priority = a->priority (no-op) */
    /* a->weight = a->weight (no-op) */
}

static inline void vl_api_remote_locator_t_endian (vl_api_remote_locator_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->priority = a->priority (no-op) */
    /* a->weight = a->weight (no-op) */
    vl_api_address_t_endian(&a->ip_address, to_net);
}

static inline void vl_api_eid_type_t_endian (vl_api_eid_type_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->eid_type = a->eid_type (no-op) */
}

static inline void vl_api_nsh_t_endian (vl_api_nsh_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->spi = clib_net_to_host_u32(a->spi);
    /* a->si = a->si (no-op) */
}

static inline void vl_api_eid_address_t_endian (vl_api_eid_address_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_prefix_t_endian(&a->prefix, to_net);
    vl_api_mac_address_t_endian(&a->mac, to_net);
    vl_api_nsh_t_endian(&a->nsh, to_net);
}

static inline void vl_api_eid_t_endian (vl_api_eid_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_eid_type_t_endian(&a->type, to_net);
    vl_api_eid_address_t_endian(&a->address, to_net);
}

static inline void vl_api_hmac_key_id_t_endian (vl_api_hmac_key_id_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->hmac_key_id = a->hmac_key_id (no-op) */
}

static inline void vl_api_hmac_key_t_endian (vl_api_hmac_key_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_hmac_key_id_t_endian(&a->id, to_net);
    /* a->key = a->key (no-op) */
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_lisp_types_calcsizefun
#define included_lisp_types_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_local_locator_t_calc_size (vl_api_local_locator_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_remote_locator_t_calc_size (vl_api_remote_locator_t *a)
{
      return sizeof(*a) - sizeof(a->ip_address) + vl_api_address_t_calc_size(&a->ip_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_eid_type_t_calc_size (vl_api_eid_type_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nsh_t_calc_size (vl_api_nsh_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_eid_address_t_calc_size (vl_api_eid_address_t *a)
{
      return sizeof(*a) - sizeof(a->prefix) + vl_api_prefix_t_calc_size(&a->prefix) - sizeof(a->mac) + vl_api_mac_address_t_calc_size(&a->mac) - sizeof(a->nsh) + vl_api_nsh_t_calc_size(&a->nsh);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_eid_t_calc_size (vl_api_eid_t *a)
{
      return sizeof(*a) - sizeof(a->type) + vl_api_eid_type_t_calc_size(&a->type) - sizeof(a->address) + vl_api_eid_address_t_calc_size(&a->address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_hmac_key_id_t_calc_size (vl_api_hmac_key_id_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_hmac_key_t_calc_size (vl_api_hmac_key_t *a)
{
      return sizeof(*a) - sizeof(a->id) + vl_api_hmac_key_id_t_calc_size(&a->id);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(lisp_types.api, 1, 0, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(lisp_types.api, 0xab74455)

#endif

