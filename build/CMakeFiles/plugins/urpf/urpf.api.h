/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: urpf.api
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
#warning no content included from urpf.api
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
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_URPF_UPDATE, vl_api_urpf_update_t_handler)
vl_msg_id(VL_API_URPF_UPDATE_REPLY, vl_api_urpf_update_reply_t_handler)
vl_msg_id(VL_API_URPF_UPDATE_V2, vl_api_urpf_update_v2_t_handler)
vl_msg_id(VL_API_URPF_UPDATE_V2_REPLY, vl_api_urpf_update_v2_reply_t_handler)
vl_msg_id(VL_API_URPF_INTERFACE_DUMP, vl_api_urpf_interface_dump_t_handler)
vl_msg_id(VL_API_URPF_INTERFACE_DETAILS, vl_api_urpf_interface_details_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_urpf_update_t, 1)
vl_msg_name(vl_api_urpf_update_reply_t, 1)
vl_msg_name(vl_api_urpf_update_v2_t, 1)
vl_msg_name(vl_api_urpf_update_v2_reply_t, 1)
vl_msg_name(vl_api_urpf_interface_dump_t, 1)
vl_msg_name(vl_api_urpf_interface_details_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_urpf \
_(VL_API_URPF_UPDATE, urpf_update, cc274cd1) \
_(VL_API_URPF_UPDATE_REPLY, urpf_update_reply, e8d4e804) \
_(VL_API_URPF_UPDATE_V2, urpf_update_v2, b873d028) \
_(VL_API_URPF_UPDATE_V2_REPLY, urpf_update_v2_reply, e8d4e804) \
_(VL_API_URPF_INTERFACE_DUMP, urpf_interface_dump, f9e6675e) \
_(VL_API_URPF_INTERFACE_DETAILS, urpf_interface_details, f94b5374) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "urpf.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_urpf_printfun_types
#define included_urpf_printfun_types

static inline u8 *format_vl_api_urpf_mode_t (u8 *s, va_list * args)
{
    vl_api_urpf_mode_t *a = va_arg (*args, vl_api_urpf_mode_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "URPF_API_MODE_OFF");
    case 1:
        return format(s, "URPF_API_MODE_LOOSE");
    case 2:
        return format(s, "URPF_API_MODE_STRICT");
    }
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_urpf_printfun
#define included_urpf_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "urpf.api_tojson.h"
#include "urpf.api_fromjson.h"

static inline u8 *vl_api_urpf_update_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_urpf_update_t *a = va_arg (*args, vl_api_urpf_update_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_urpf_update_t: */
    s = format(s, "vl_api_urpf_update_t:");
    s = format(s, "\n%Uis_input: %u", format_white_space, indent, a->is_input);
    s = format(s, "\n%Umode: %U", format_white_space, indent, format_vl_api_urpf_mode_t, &a->mode, indent);
    s = format(s, "\n%Uaf: %U", format_white_space, indent, format_vl_api_address_family_t, &a->af, indent);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_urpf_update_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_urpf_update_reply_t *a = va_arg (*args, vl_api_urpf_update_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_urpf_update_reply_t: */
    s = format(s, "vl_api_urpf_update_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_urpf_update_v2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_urpf_update_v2_t *a = va_arg (*args, vl_api_urpf_update_v2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_urpf_update_v2_t: */
    s = format(s, "vl_api_urpf_update_v2_t:");
    s = format(s, "\n%Uis_input: %u", format_white_space, indent, a->is_input);
    s = format(s, "\n%Umode: %U", format_white_space, indent, format_vl_api_urpf_mode_t, &a->mode, indent);
    s = format(s, "\n%Uaf: %U", format_white_space, indent, format_vl_api_address_family_t, &a->af, indent);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Utable_id: %u", format_white_space, indent, a->table_id);
    return s;
}

static inline u8 *vl_api_urpf_update_v2_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_urpf_update_v2_reply_t *a = va_arg (*args, vl_api_urpf_update_v2_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_urpf_update_v2_reply_t: */
    s = format(s, "vl_api_urpf_update_v2_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_urpf_interface_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_urpf_interface_dump_t *a = va_arg (*args, vl_api_urpf_interface_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_urpf_interface_dump_t: */
    s = format(s, "vl_api_urpf_interface_dump_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_urpf_interface_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_urpf_interface_details_t *a = va_arg (*args, vl_api_urpf_interface_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_urpf_interface_details_t: */
    s = format(s, "vl_api_urpf_interface_details_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uis_input: %u", format_white_space, indent, a->is_input);
    s = format(s, "\n%Umode: %U", format_white_space, indent, format_vl_api_urpf_mode_t, &a->mode, indent);
    s = format(s, "\n%Uaf: %U", format_white_space, indent, format_vl_api_address_family_t, &a->af, indent);
    s = format(s, "\n%Utable_id: %u", format_white_space, indent, a->table_id);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_urpf_endianfun
#define included_urpf_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_urpf_mode_t_endian (vl_api_urpf_mode_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->urpf_mode = a->urpf_mode (no-op) */
}

static inline void vl_api_urpf_update_t_endian (vl_api_urpf_update_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_input = a->is_input (no-op) */
    vl_api_urpf_mode_t_endian(&a->mode, to_net);
    vl_api_address_family_t_endian(&a->af, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_urpf_update_reply_t_endian (vl_api_urpf_update_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_urpf_update_v2_t_endian (vl_api_urpf_update_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_input = a->is_input (no-op) */
    vl_api_urpf_mode_t_endian(&a->mode, to_net);
    vl_api_address_family_t_endian(&a->af, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    a->table_id = clib_net_to_host_u32(a->table_id);
}

static inline void vl_api_urpf_update_v2_reply_t_endian (vl_api_urpf_update_v2_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_urpf_interface_dump_t_endian (vl_api_urpf_interface_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_urpf_interface_details_t_endian (vl_api_urpf_interface_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->is_input = a->is_input (no-op) */
    vl_api_urpf_mode_t_endian(&a->mode, to_net);
    vl_api_address_family_t_endian(&a->af, to_net);
    a->table_id = clib_net_to_host_u32(a->table_id);
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_urpf_calcsizefun
#define included_urpf_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_urpf_mode_t_calc_size (vl_api_urpf_mode_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_urpf_update_t_calc_size (vl_api_urpf_update_t *a)
{
      return sizeof(*a) - sizeof(a->mode) + vl_api_urpf_mode_t_calc_size(&a->mode) - sizeof(a->af) + vl_api_address_family_t_calc_size(&a->af) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_urpf_update_reply_t_calc_size (vl_api_urpf_update_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_urpf_update_v2_t_calc_size (vl_api_urpf_update_v2_t *a)
{
      return sizeof(*a) - sizeof(a->mode) + vl_api_urpf_mode_t_calc_size(&a->mode) - sizeof(a->af) + vl_api_address_family_t_calc_size(&a->af) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_urpf_update_v2_reply_t_calc_size (vl_api_urpf_update_v2_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_urpf_interface_dump_t_calc_size (vl_api_urpf_interface_dump_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_urpf_interface_details_t_calc_size (vl_api_urpf_interface_details_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->mode) + vl_api_urpf_mode_t_calc_size(&a->mode) - sizeof(a->af) + vl_api_address_family_t_calc_size(&a->af);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(urpf.api, 1, 0, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(urpf.api, 0xabec9cd)

#endif

