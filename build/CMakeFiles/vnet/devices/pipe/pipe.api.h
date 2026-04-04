/*
 * VLIB API definitions 2026-04-04 08:31:58
 * Input file: pipe.api
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
#warning no content included from pipe.api
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
vl_msg_id(VL_API_PIPE_CREATE, vl_api_pipe_create_t_handler)
vl_msg_id(VL_API_PIPE_CREATE_REPLY, vl_api_pipe_create_reply_t_handler)
vl_msg_id(VL_API_PIPE_DELETE, vl_api_pipe_delete_t_handler)
vl_msg_id(VL_API_PIPE_DELETE_REPLY, vl_api_pipe_delete_reply_t_handler)
vl_msg_id(VL_API_PIPE_DUMP, vl_api_pipe_dump_t_handler)
vl_msg_id(VL_API_PIPE_DETAILS, vl_api_pipe_details_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_pipe_create_t, 1)
vl_msg_name(vl_api_pipe_create_reply_t, 1)
vl_msg_name(vl_api_pipe_delete_t, 1)
vl_msg_name(vl_api_pipe_delete_reply_t, 1)
vl_msg_name(vl_api_pipe_dump_t, 1)
vl_msg_name(vl_api_pipe_details_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_pipe \
_(VL_API_PIPE_CREATE, pipe_create, bb263bd3) \
_(VL_API_PIPE_CREATE_REPLY, pipe_create_reply, b7ce310c) \
_(VL_API_PIPE_DELETE, pipe_delete, f9e6675e) \
_(VL_API_PIPE_DELETE_REPLY, pipe_delete_reply, e8d4e804) \
_(VL_API_PIPE_DUMP, pipe_dump, 51077d14) \
_(VL_API_PIPE_DETAILS, pipe_details, c52b799d) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "pipe.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_pipe_printfun_types
#define included_pipe_printfun_types


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_pipe_printfun
#define included_pipe_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "pipe.api_tojson.h"
#include "pipe.api_fromjson.h"

static inline u8 *vl_api_pipe_create_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pipe_create_t *a = va_arg (*args, vl_api_pipe_create_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pipe_create_t: */
    s = format(s, "vl_api_pipe_create_t:");
    s = format(s, "\n%Uis_specified: %u", format_white_space, indent, a->is_specified);
    s = format(s, "\n%Uuser_instance: %u", format_white_space, indent, a->user_instance);
    return s;
}

static inline u8 *vl_api_pipe_create_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pipe_create_reply_t *a = va_arg (*args, vl_api_pipe_create_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pipe_create_reply_t: */
    s = format(s, "vl_api_pipe_create_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    for (i = 0; i < 2; i++) {
        s = format(s, "\n%Upipe_sw_if_index: %U",
                   format_white_space, indent, format_vl_api_interface_index_t, &a->pipe_sw_if_index[i], indent);
    }
    return s;
}

static inline u8 *vl_api_pipe_delete_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pipe_delete_t *a = va_arg (*args, vl_api_pipe_delete_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pipe_delete_t: */
    s = format(s, "vl_api_pipe_delete_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_pipe_delete_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pipe_delete_reply_t *a = va_arg (*args, vl_api_pipe_delete_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pipe_delete_reply_t: */
    s = format(s, "vl_api_pipe_delete_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_pipe_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pipe_dump_t *a = va_arg (*args, vl_api_pipe_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pipe_dump_t: */
    s = format(s, "vl_api_pipe_dump_t:");
    return s;
}

static inline u8 *vl_api_pipe_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pipe_details_t *a = va_arg (*args, vl_api_pipe_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pipe_details_t: */
    s = format(s, "vl_api_pipe_details_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    for (i = 0; i < 2; i++) {
        s = format(s, "\n%Upipe_sw_if_index: %U",
                   format_white_space, indent, format_vl_api_interface_index_t, &a->pipe_sw_if_index[i], indent);
    }
    s = format(s, "\n%Uinstance: %u", format_white_space, indent, a->instance);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_pipe_endianfun
#define included_pipe_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_pipe_create_t_endian (vl_api_pipe_create_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_specified = a->is_specified (no-op) */
    a->user_instance = clib_net_to_host_u32(a->user_instance);
}

static inline void vl_api_pipe_create_reply_t_endian (vl_api_pipe_create_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    for (i = 0; i < 2; i++) {
        vl_api_interface_index_t_endian(&a->pipe_sw_if_index[i], to_net);
    }
}

static inline void vl_api_pipe_delete_t_endian (vl_api_pipe_delete_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_pipe_delete_reply_t_endian (vl_api_pipe_delete_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_pipe_dump_t_endian (vl_api_pipe_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_pipe_details_t_endian (vl_api_pipe_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    for (i = 0; i < 2; i++) {
        vl_api_interface_index_t_endian(&a->pipe_sw_if_index[i], to_net);
    }
    a->instance = clib_net_to_host_u32(a->instance);
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_pipe_calcsizefun
#define included_pipe_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_pipe_create_t_calc_size (vl_api_pipe_create_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pipe_create_reply_t_calc_size (vl_api_pipe_create_reply_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pipe_delete_t_calc_size (vl_api_pipe_delete_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pipe_delete_reply_t_calc_size (vl_api_pipe_delete_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pipe_dump_t_calc_size (vl_api_pipe_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pipe_details_t_calc_size (vl_api_pipe_details_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(pipe.api, 1, 0, 1)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(pipe.api, 0xbf185589)

#endif

