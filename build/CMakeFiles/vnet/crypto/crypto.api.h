/*
 * VLIB API definitions 2026-04-04 08:31:58
 * Input file: crypto.api
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
#warning no content included from crypto.api
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
vl_msg_id(VL_API_CRYPTO_SET_ASYNC_DISPATCH, vl_api_crypto_set_async_dispatch_t_handler)
vl_msg_id(VL_API_CRYPTO_SET_ASYNC_DISPATCH_REPLY, vl_api_crypto_set_async_dispatch_reply_t_handler)
vl_msg_id(VL_API_CRYPTO_SET_ASYNC_DISPATCH_V2, vl_api_crypto_set_async_dispatch_v2_t_handler)
vl_msg_id(VL_API_CRYPTO_SET_ASYNC_DISPATCH_V2_REPLY, vl_api_crypto_set_async_dispatch_v2_reply_t_handler)
vl_msg_id(VL_API_CRYPTO_SET_HANDLER, vl_api_crypto_set_handler_t_handler)
vl_msg_id(VL_API_CRYPTO_SET_HANDLER_REPLY, vl_api_crypto_set_handler_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_crypto_set_async_dispatch_t, 1)
vl_msg_name(vl_api_crypto_set_async_dispatch_reply_t, 1)
vl_msg_name(vl_api_crypto_set_async_dispatch_v2_t, 1)
vl_msg_name(vl_api_crypto_set_async_dispatch_v2_reply_t, 1)
vl_msg_name(vl_api_crypto_set_handler_t, 1)
vl_msg_name(vl_api_crypto_set_handler_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_crypto \
_(VL_API_CRYPTO_SET_ASYNC_DISPATCH, crypto_set_async_dispatch, 5ca4adc0) \
_(VL_API_CRYPTO_SET_ASYNC_DISPATCH_REPLY, crypto_set_async_dispatch_reply, e8d4e804) \
_(VL_API_CRYPTO_SET_ASYNC_DISPATCH_V2, crypto_set_async_dispatch_v2, 667d2d54) \
_(VL_API_CRYPTO_SET_ASYNC_DISPATCH_V2_REPLY, crypto_set_async_dispatch_v2_reply, e8d4e804) \
_(VL_API_CRYPTO_SET_HANDLER, crypto_set_handler, ce9ad00d) \
_(VL_API_CRYPTO_SET_HANDLER_REPLY, crypto_set_handler_reply, e8d4e804) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "crypto.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_crypto_printfun_types
#define included_crypto_printfun_types

static inline u8 *format_vl_api_crypto_dispatch_mode_t (u8 *s, va_list * args)
{
    vl_api_crypto_dispatch_mode_t *a = va_arg (*args, vl_api_crypto_dispatch_mode_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "CRYPTO_ASYNC_DISPATCH_POLLING");
    case 1:
        return format(s, "CRYPTO_ASYNC_DISPATCH_INTERRUPT");
    }
    return s;
}

static inline u8 *format_vl_api_crypto_op_class_type_t (u8 *s, va_list * args)
{
    vl_api_crypto_op_class_type_t *a = va_arg (*args, vl_api_crypto_op_class_type_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "CRYPTO_API_OP_SIMPLE");
    case 1:
        return format(s, "CRYPTO_API_OP_CHAINED");
    case 2:
        return format(s, "CRYPTO_API_OP_BOTH");
    }
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_crypto_printfun
#define included_crypto_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "crypto.api_tojson.h"
#include "crypto.api_fromjson.h"

static inline u8 *vl_api_crypto_set_async_dispatch_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_crypto_set_async_dispatch_t *a = va_arg (*args, vl_api_crypto_set_async_dispatch_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_crypto_set_async_dispatch_t: */
    s = format(s, "vl_api_crypto_set_async_dispatch_t:");
    s = format(s, "\n%Umode: %U", format_white_space, indent, format_vl_api_crypto_dispatch_mode_t, &a->mode, indent);
    return s;
}

static inline u8 *vl_api_crypto_set_async_dispatch_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_crypto_set_async_dispatch_reply_t *a = va_arg (*args, vl_api_crypto_set_async_dispatch_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_crypto_set_async_dispatch_reply_t: */
    s = format(s, "vl_api_crypto_set_async_dispatch_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_crypto_set_async_dispatch_v2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_crypto_set_async_dispatch_v2_t *a = va_arg (*args, vl_api_crypto_set_async_dispatch_v2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_crypto_set_async_dispatch_v2_t: */
    s = format(s, "vl_api_crypto_set_async_dispatch_v2_t:");
    s = format(s, "\n%Umode: %U", format_white_space, indent, format_vl_api_crypto_dispatch_mode_t, &a->mode, indent);
    s = format(s, "\n%Uadaptive: %u", format_white_space, indent, a->adaptive);
    return s;
}

static inline u8 *vl_api_crypto_set_async_dispatch_v2_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_crypto_set_async_dispatch_v2_reply_t *a = va_arg (*args, vl_api_crypto_set_async_dispatch_v2_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_crypto_set_async_dispatch_v2_reply_t: */
    s = format(s, "vl_api_crypto_set_async_dispatch_v2_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_crypto_set_handler_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_crypto_set_handler_t *a = va_arg (*args, vl_api_crypto_set_handler_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_crypto_set_handler_t: */
    s = format(s, "vl_api_crypto_set_handler_t:");
    s = format(s, "\n%Ualg_name: %s", format_white_space, indent, a->alg_name);
    s = format(s, "\n%Uengine: %s", format_white_space, indent, a->engine);
    s = format(s, "\n%Uoct: %U", format_white_space, indent, format_vl_api_crypto_op_class_type_t, &a->oct, indent);
    s = format(s, "\n%Uis_async: %u", format_white_space, indent, a->is_async);
    return s;
}

static inline u8 *vl_api_crypto_set_handler_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_crypto_set_handler_reply_t *a = va_arg (*args, vl_api_crypto_set_handler_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_crypto_set_handler_reply_t: */
    s = format(s, "vl_api_crypto_set_handler_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_crypto_endianfun
#define included_crypto_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_crypto_dispatch_mode_t_endian (vl_api_crypto_dispatch_mode_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->crypto_dispatch_mode = a->crypto_dispatch_mode (no-op) */
}

static inline void vl_api_crypto_op_class_type_t_endian (vl_api_crypto_op_class_type_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->crypto_op_class_type = a->crypto_op_class_type (no-op) */
}

static inline void vl_api_crypto_set_async_dispatch_t_endian (vl_api_crypto_set_async_dispatch_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_crypto_dispatch_mode_t_endian(&a->mode, to_net);
}

static inline void vl_api_crypto_set_async_dispatch_reply_t_endian (vl_api_crypto_set_async_dispatch_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_crypto_set_async_dispatch_v2_t_endian (vl_api_crypto_set_async_dispatch_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_crypto_dispatch_mode_t_endian(&a->mode, to_net);
    /* a->adaptive = a->adaptive (no-op) */
}

static inline void vl_api_crypto_set_async_dispatch_v2_reply_t_endian (vl_api_crypto_set_async_dispatch_v2_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_crypto_set_handler_t_endian (vl_api_crypto_set_handler_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->alg_name = a->alg_name (no-op) */
    /* a->engine = a->engine (no-op) */
    vl_api_crypto_op_class_type_t_endian(&a->oct, to_net);
    /* a->is_async = a->is_async (no-op) */
}

static inline void vl_api_crypto_set_handler_reply_t_endian (vl_api_crypto_set_handler_reply_t *a, bool to_net)
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
#ifndef included_crypto_calcsizefun
#define included_crypto_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_crypto_dispatch_mode_t_calc_size (vl_api_crypto_dispatch_mode_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_crypto_op_class_type_t_calc_size (vl_api_crypto_op_class_type_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_crypto_set_async_dispatch_t_calc_size (vl_api_crypto_set_async_dispatch_t *a)
{
      return sizeof(*a) - sizeof(a->mode) + vl_api_crypto_dispatch_mode_t_calc_size(&a->mode);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_crypto_set_async_dispatch_reply_t_calc_size (vl_api_crypto_set_async_dispatch_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_crypto_set_async_dispatch_v2_t_calc_size (vl_api_crypto_set_async_dispatch_v2_t *a)
{
      return sizeof(*a) - sizeof(a->mode) + vl_api_crypto_dispatch_mode_t_calc_size(&a->mode);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_crypto_set_async_dispatch_v2_reply_t_calc_size (vl_api_crypto_set_async_dispatch_v2_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_crypto_set_handler_t_calc_size (vl_api_crypto_set_handler_t *a)
{
      return sizeof(*a) - sizeof(a->oct) + vl_api_crypto_op_class_type_t_calc_size(&a->oct);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_crypto_set_handler_reply_t_calc_size (vl_api_crypto_set_handler_reply_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(crypto.api, 1, 0, 1)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(crypto.api, 0x2a68080c)

#endif

