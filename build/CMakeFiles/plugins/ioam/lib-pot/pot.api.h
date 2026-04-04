/*
 * VLIB API definitions 2026-04-04 08:31:59
 * Input file: pot.api
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
#warning no content included from pot.api
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
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_POT_PROFILE_ADD, vl_api_pot_profile_add_t_handler)
vl_msg_id(VL_API_POT_PROFILE_ADD_REPLY, vl_api_pot_profile_add_reply_t_handler)
vl_msg_id(VL_API_POT_PROFILE_ACTIVATE, vl_api_pot_profile_activate_t_handler)
vl_msg_id(VL_API_POT_PROFILE_ACTIVATE_REPLY, vl_api_pot_profile_activate_reply_t_handler)
vl_msg_id(VL_API_POT_PROFILE_DEL, vl_api_pot_profile_del_t_handler)
vl_msg_id(VL_API_POT_PROFILE_DEL_REPLY, vl_api_pot_profile_del_reply_t_handler)
vl_msg_id(VL_API_POT_PROFILE_SHOW_CONFIG_DUMP, vl_api_pot_profile_show_config_dump_t_handler)
vl_msg_id(VL_API_POT_PROFILE_SHOW_CONFIG_DETAILS, vl_api_pot_profile_show_config_details_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_pot_profile_add_t, 1)
vl_msg_name(vl_api_pot_profile_add_reply_t, 1)
vl_msg_name(vl_api_pot_profile_activate_t, 1)
vl_msg_name(vl_api_pot_profile_activate_reply_t, 1)
vl_msg_name(vl_api_pot_profile_del_t, 1)
vl_msg_name(vl_api_pot_profile_del_reply_t, 1)
vl_msg_name(vl_api_pot_profile_show_config_dump_t, 1)
vl_msg_name(vl_api_pot_profile_show_config_details_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_pot \
_(VL_API_POT_PROFILE_ADD, pot_profile_add, ad5da3a3) \
_(VL_API_POT_PROFILE_ADD_REPLY, pot_profile_add_reply, e8d4e804) \
_(VL_API_POT_PROFILE_ACTIVATE, pot_profile_activate, 0770af98) \
_(VL_API_POT_PROFILE_ACTIVATE_REPLY, pot_profile_activate_reply, e8d4e804) \
_(VL_API_POT_PROFILE_DEL, pot_profile_del, cd63f53b) \
_(VL_API_POT_PROFILE_DEL_REPLY, pot_profile_del_reply, e8d4e804) \
_(VL_API_POT_PROFILE_SHOW_CONFIG_DUMP, pot_profile_show_config_dump, 005b7d59) \
_(VL_API_POT_PROFILE_SHOW_CONFIG_DETAILS, pot_profile_show_config_details, b7ce0618) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "pot.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_pot_printfun_types
#define included_pot_printfun_types


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_pot_printfun
#define included_pot_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "pot.api_tojson.h"
#include "pot.api_fromjson.h"

static inline u8 *vl_api_pot_profile_add_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pot_profile_add_t *a = va_arg (*args, vl_api_pot_profile_add_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pot_profile_add_t: */
    s = format(s, "vl_api_pot_profile_add_t:");
    s = format(s, "\n%Uid: %u", format_white_space, indent, a->id);
    s = format(s, "\n%Uvalidator: %u", format_white_space, indent, a->validator);
    s = format(s, "\n%Usecret_key: %llu", format_white_space, indent, a->secret_key);
    s = format(s, "\n%Usecret_share: %llu", format_white_space, indent, a->secret_share);
    s = format(s, "\n%Uprime: %llu", format_white_space, indent, a->prime);
    s = format(s, "\n%Umax_bits: %u", format_white_space, indent, a->max_bits);
    s = format(s, "\n%Ulpc: %llu", format_white_space, indent, a->lpc);
    s = format(s, "\n%Upolynomial_public: %llu", format_white_space, indent, a->polynomial_public);
    if (vl_api_string_len(&a->list_name) > 0) {
        s = format(s, "\n%Ulist_name: %U", format_white_space, indent, vl_api_format_string, (&a->list_name));
    } else {
        s = format(s, "\n%Ulist_name:", format_white_space, indent);
    }
    return s;
}

static inline u8 *vl_api_pot_profile_add_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pot_profile_add_reply_t *a = va_arg (*args, vl_api_pot_profile_add_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pot_profile_add_reply_t: */
    s = format(s, "vl_api_pot_profile_add_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_pot_profile_activate_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pot_profile_activate_t *a = va_arg (*args, vl_api_pot_profile_activate_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pot_profile_activate_t: */
    s = format(s, "vl_api_pot_profile_activate_t:");
    s = format(s, "\n%Uid: %u", format_white_space, indent, a->id);
    if (vl_api_string_len(&a->list_name) > 0) {
        s = format(s, "\n%Ulist_name: %U", format_white_space, indent, vl_api_format_string, (&a->list_name));
    } else {
        s = format(s, "\n%Ulist_name:", format_white_space, indent);
    }
    return s;
}

static inline u8 *vl_api_pot_profile_activate_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pot_profile_activate_reply_t *a = va_arg (*args, vl_api_pot_profile_activate_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pot_profile_activate_reply_t: */
    s = format(s, "vl_api_pot_profile_activate_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_pot_profile_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pot_profile_del_t *a = va_arg (*args, vl_api_pot_profile_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pot_profile_del_t: */
    s = format(s, "vl_api_pot_profile_del_t:");
    if (vl_api_string_len(&a->list_name) > 0) {
        s = format(s, "\n%Ulist_name: %U", format_white_space, indent, vl_api_format_string, (&a->list_name));
    } else {
        s = format(s, "\n%Ulist_name:", format_white_space, indent);
    }
    return s;
}

static inline u8 *vl_api_pot_profile_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pot_profile_del_reply_t *a = va_arg (*args, vl_api_pot_profile_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pot_profile_del_reply_t: */
    s = format(s, "vl_api_pot_profile_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_pot_profile_show_config_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pot_profile_show_config_dump_t *a = va_arg (*args, vl_api_pot_profile_show_config_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pot_profile_show_config_dump_t: */
    s = format(s, "vl_api_pot_profile_show_config_dump_t:");
    s = format(s, "\n%Uid: %u", format_white_space, indent, a->id);
    return s;
}

static inline u8 *vl_api_pot_profile_show_config_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pot_profile_show_config_details_t *a = va_arg (*args, vl_api_pot_profile_show_config_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pot_profile_show_config_details_t: */
    s = format(s, "vl_api_pot_profile_show_config_details_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uid: %u", format_white_space, indent, a->id);
    s = format(s, "\n%Uvalidator: %u", format_white_space, indent, a->validator);
    s = format(s, "\n%Usecret_key: %llu", format_white_space, indent, a->secret_key);
    s = format(s, "\n%Usecret_share: %llu", format_white_space, indent, a->secret_share);
    s = format(s, "\n%Uprime: %llu", format_white_space, indent, a->prime);
    s = format(s, "\n%Ubit_mask: %llu", format_white_space, indent, a->bit_mask);
    s = format(s, "\n%Ulpc: %llu", format_white_space, indent, a->lpc);
    s = format(s, "\n%Upolynomial_public: %llu", format_white_space, indent, a->polynomial_public);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_pot_endianfun
#define included_pot_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_pot_profile_add_t_endian (vl_api_pot_profile_add_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->id = a->id (no-op) */
    /* a->validator = a->validator (no-op) */
    a->secret_key = clib_net_to_host_u64(a->secret_key);
    a->secret_share = clib_net_to_host_u64(a->secret_share);
    a->prime = clib_net_to_host_u64(a->prime);
    /* a->max_bits = a->max_bits (no-op) */
    a->lpc = clib_net_to_host_u64(a->lpc);
    a->polynomial_public = clib_net_to_host_u64(a->polynomial_public);
    /* a->list_name = a->list_name (no-op) */
}

static inline void vl_api_pot_profile_add_reply_t_endian (vl_api_pot_profile_add_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_pot_profile_activate_t_endian (vl_api_pot_profile_activate_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->id = a->id (no-op) */
    /* a->list_name = a->list_name (no-op) */
}

static inline void vl_api_pot_profile_activate_reply_t_endian (vl_api_pot_profile_activate_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_pot_profile_del_t_endian (vl_api_pot_profile_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->list_name = a->list_name (no-op) */
}

static inline void vl_api_pot_profile_del_reply_t_endian (vl_api_pot_profile_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_pot_profile_show_config_dump_t_endian (vl_api_pot_profile_show_config_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->id = a->id (no-op) */
}

static inline void vl_api_pot_profile_show_config_details_t_endian (vl_api_pot_profile_show_config_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    /* a->id = a->id (no-op) */
    /* a->validator = a->validator (no-op) */
    a->secret_key = clib_net_to_host_u64(a->secret_key);
    a->secret_share = clib_net_to_host_u64(a->secret_share);
    a->prime = clib_net_to_host_u64(a->prime);
    a->bit_mask = clib_net_to_host_u64(a->bit_mask);
    a->lpc = clib_net_to_host_u64(a->lpc);
    a->polynomial_public = clib_net_to_host_u64(a->polynomial_public);
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_pot_calcsizefun
#define included_pot_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_pot_profile_add_t_calc_size (vl_api_pot_profile_add_t *a)
{
      return sizeof(*a) + vl_api_string_len(&a->list_name);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pot_profile_add_reply_t_calc_size (vl_api_pot_profile_add_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pot_profile_activate_t_calc_size (vl_api_pot_profile_activate_t *a)
{
      return sizeof(*a) + vl_api_string_len(&a->list_name);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pot_profile_activate_reply_t_calc_size (vl_api_pot_profile_activate_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pot_profile_del_t_calc_size (vl_api_pot_profile_del_t *a)
{
      return sizeof(*a) + vl_api_string_len(&a->list_name);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pot_profile_del_reply_t_calc_size (vl_api_pot_profile_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pot_profile_show_config_dump_t_calc_size (vl_api_pot_profile_show_config_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pot_profile_show_config_details_t_calc_size (vl_api_pot_profile_show_config_details_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(pot.api, 1, 0, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(pot.api, 0xa9d8e55c)

#endif

