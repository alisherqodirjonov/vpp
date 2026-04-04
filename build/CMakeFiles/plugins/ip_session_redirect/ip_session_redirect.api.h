/*
 * VLIB API definitions 2026-04-04 08:31:59
 * Input file: ip_session_redirect.api
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
#warning no content included from ip_session_redirect.api
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
#include <vnet/fib/fib_types.api.h>
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_IP_SESSION_REDIRECT_ADD, vl_api_ip_session_redirect_add_t_handler)
vl_msg_id(VL_API_IP_SESSION_REDIRECT_ADD_REPLY, vl_api_ip_session_redirect_add_reply_t_handler)
vl_msg_id(VL_API_IP_SESSION_REDIRECT_ADD_V2, vl_api_ip_session_redirect_add_v2_t_handler)
vl_msg_id(VL_API_IP_SESSION_REDIRECT_ADD_V2_REPLY, vl_api_ip_session_redirect_add_v2_reply_t_handler)
vl_msg_id(VL_API_IP_SESSION_REDIRECT_DEL, vl_api_ip_session_redirect_del_t_handler)
vl_msg_id(VL_API_IP_SESSION_REDIRECT_DEL_REPLY, vl_api_ip_session_redirect_del_reply_t_handler)
vl_msg_id(VL_API_IP_SESSION_REDIRECT_DUMP, vl_api_ip_session_redirect_dump_t_handler)
vl_msg_id(VL_API_IP_SESSION_REDIRECT_DETAILS, vl_api_ip_session_redirect_details_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_ip_session_redirect_add_t, 1)
vl_msg_name(vl_api_ip_session_redirect_add_reply_t, 1)
vl_msg_name(vl_api_ip_session_redirect_add_v2_t, 1)
vl_msg_name(vl_api_ip_session_redirect_add_v2_reply_t, 1)
vl_msg_name(vl_api_ip_session_redirect_del_t, 1)
vl_msg_name(vl_api_ip_session_redirect_del_reply_t, 1)
vl_msg_name(vl_api_ip_session_redirect_dump_t, 1)
vl_msg_name(vl_api_ip_session_redirect_details_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_ip_session_redirect \
_(VL_API_IP_SESSION_REDIRECT_ADD, ip_session_redirect_add, 2f78ffda) \
_(VL_API_IP_SESSION_REDIRECT_ADD_REPLY, ip_session_redirect_add_reply, e8d4e804) \
_(VL_API_IP_SESSION_REDIRECT_ADD_V2, ip_session_redirect_add_v2, 0765f51f) \
_(VL_API_IP_SESSION_REDIRECT_ADD_V2_REPLY, ip_session_redirect_add_v2_reply, e8d4e804) \
_(VL_API_IP_SESSION_REDIRECT_DEL, ip_session_redirect_del, fb643388) \
_(VL_API_IP_SESSION_REDIRECT_DEL_REPLY, ip_session_redirect_del_reply, e8d4e804) \
_(VL_API_IP_SESSION_REDIRECT_DUMP, ip_session_redirect_dump, 33554253) \
_(VL_API_IP_SESSION_REDIRECT_DETAILS, ip_session_redirect_details, 4487a233) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "ip_session_redirect.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_ip_session_redirect_printfun_types
#define included_ip_session_redirect_printfun_types


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_ip_session_redirect_printfun
#define included_ip_session_redirect_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "ip_session_redirect.api_tojson.h"
#include "ip_session_redirect.api_fromjson.h"

static inline u8 *vl_api_ip_session_redirect_add_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ip_session_redirect_add_t *a = va_arg (*args, vl_api_ip_session_redirect_add_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ip_session_redirect_add_t: */
    s = format(s, "vl_api_ip_session_redirect_add_t:");
    s = format(s, "\n%Utable_index: %u", format_white_space, indent, a->table_index);
    s = format(s, "\n%Umatch_len: %u", format_white_space, indent, a->match_len);
    s = format(s, "\n%Umatch: %U", format_white_space, indent, format_hex_bytes, a, 80);
    s = format(s, "\n%Uopaque_index: %u", format_white_space, indent, a->opaque_index);
    s = format(s, "\n%Uis_punt: %u", format_white_space, indent, a->is_punt);
    s = format(s, "\n%Un_paths: %u", format_white_space, indent, a->n_paths);
    for (i = 0; i < a->n_paths; i++) {
        s = format(s, "\n%Upaths: %U",
                   format_white_space, indent, format_vl_api_fib_path_t, &a->paths[i], indent);
    }
    return s;
}

static inline u8 *vl_api_ip_session_redirect_add_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ip_session_redirect_add_reply_t *a = va_arg (*args, vl_api_ip_session_redirect_add_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ip_session_redirect_add_reply_t: */
    s = format(s, "vl_api_ip_session_redirect_add_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_ip_session_redirect_add_v2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ip_session_redirect_add_v2_t *a = va_arg (*args, vl_api_ip_session_redirect_add_v2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ip_session_redirect_add_v2_t: */
    s = format(s, "vl_api_ip_session_redirect_add_v2_t:");
    s = format(s, "\n%Utable_index: %u", format_white_space, indent, a->table_index);
    s = format(s, "\n%Uopaque_index: %u", format_white_space, indent, a->opaque_index);
    s = format(s, "\n%Uproto: %U", format_white_space, indent, format_vl_api_fib_path_nh_proto_t, &a->proto, indent);
    s = format(s, "\n%Uis_punt: %u", format_white_space, indent, a->is_punt);
    s = format(s, "\n%Umatch_len: %u", format_white_space, indent, a->match_len);
    s = format(s, "\n%Umatch: %U", format_white_space, indent, format_hex_bytes, a, 80);
    s = format(s, "\n%Un_paths: %u", format_white_space, indent, a->n_paths);
    for (i = 0; i < a->n_paths; i++) {
        s = format(s, "\n%Upaths: %U",
                   format_white_space, indent, format_vl_api_fib_path_t, &a->paths[i], indent);
    }
    return s;
}

static inline u8 *vl_api_ip_session_redirect_add_v2_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ip_session_redirect_add_v2_reply_t *a = va_arg (*args, vl_api_ip_session_redirect_add_v2_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ip_session_redirect_add_v2_reply_t: */
    s = format(s, "vl_api_ip_session_redirect_add_v2_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_ip_session_redirect_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ip_session_redirect_del_t *a = va_arg (*args, vl_api_ip_session_redirect_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ip_session_redirect_del_t: */
    s = format(s, "vl_api_ip_session_redirect_del_t:");
    s = format(s, "\n%Utable_index: %u", format_white_space, indent, a->table_index);
    s = format(s, "\n%Umatch_len: %u", format_white_space, indent, a->match_len);
    s = format(s, "\n%Umatch: %U", format_white_space, indent, format_hex_bytes, a->match, a->match_len);
    return s;
}

static inline u8 *vl_api_ip_session_redirect_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ip_session_redirect_del_reply_t *a = va_arg (*args, vl_api_ip_session_redirect_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ip_session_redirect_del_reply_t: */
    s = format(s, "vl_api_ip_session_redirect_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_ip_session_redirect_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ip_session_redirect_dump_t *a = va_arg (*args, vl_api_ip_session_redirect_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ip_session_redirect_dump_t: */
    s = format(s, "vl_api_ip_session_redirect_dump_t:");
    s = format(s, "\n%Utable_index: %u", format_white_space, indent, a->table_index);
    return s;
}

static inline u8 *vl_api_ip_session_redirect_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ip_session_redirect_details_t *a = va_arg (*args, vl_api_ip_session_redirect_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ip_session_redirect_details_t: */
    s = format(s, "vl_api_ip_session_redirect_details_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Utable_index: %u", format_white_space, indent, a->table_index);
    s = format(s, "\n%Uopaque_index: %u", format_white_space, indent, a->opaque_index);
    s = format(s, "\n%Uis_punt: %u", format_white_space, indent, a->is_punt);
    s = format(s, "\n%Uis_ip6: %u", format_white_space, indent, a->is_ip6);
    s = format(s, "\n%Umatch_length: %u", format_white_space, indent, a->match_length);
    s = format(s, "\n%Umatch: %U", format_white_space, indent, format_hex_bytes, a, 80);
    s = format(s, "\n%Un_paths: %u", format_white_space, indent, a->n_paths);
    for (i = 0; i < a->n_paths; i++) {
        s = format(s, "\n%Upaths: %U",
                   format_white_space, indent, format_vl_api_fib_path_t, &a->paths[i], indent);
    }
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_ip_session_redirect_endianfun
#define included_ip_session_redirect_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_ip_session_redirect_add_t_endian (vl_api_ip_session_redirect_add_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->table_index = clib_net_to_host_u32(a->table_index);
    /* a->match_len = a->match_len (no-op) */
    /* a->match = a->match (no-op) */
    a->opaque_index = clib_net_to_host_u32(a->opaque_index);
    /* a->is_punt = a->is_punt (no-op) */
    /* a->n_paths = a->n_paths (no-op) */
    u32 count = a->n_paths;
    for (i = 0; i < count; i++) {
        vl_api_fib_path_t_endian(&a->paths[i], to_net);
    }
}

static inline void vl_api_ip_session_redirect_add_reply_t_endian (vl_api_ip_session_redirect_add_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_ip_session_redirect_add_v2_t_endian (vl_api_ip_session_redirect_add_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->table_index = clib_net_to_host_u32(a->table_index);
    a->opaque_index = clib_net_to_host_u32(a->opaque_index);
    vl_api_fib_path_nh_proto_t_endian(&a->proto, to_net);
    /* a->is_punt = a->is_punt (no-op) */
    /* a->match_len = a->match_len (no-op) */
    /* a->match = a->match (no-op) */
    /* a->n_paths = a->n_paths (no-op) */
    u32 count = a->n_paths;
    for (i = 0; i < count; i++) {
        vl_api_fib_path_t_endian(&a->paths[i], to_net);
    }
}

static inline void vl_api_ip_session_redirect_add_v2_reply_t_endian (vl_api_ip_session_redirect_add_v2_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_ip_session_redirect_del_t_endian (vl_api_ip_session_redirect_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->table_index = clib_net_to_host_u32(a->table_index);
    /* a->match_len = a->match_len (no-op) */
    /* a->match = a->match (no-op) */
}

static inline void vl_api_ip_session_redirect_del_reply_t_endian (vl_api_ip_session_redirect_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_ip_session_redirect_dump_t_endian (vl_api_ip_session_redirect_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->table_index = clib_net_to_host_u32(a->table_index);
}

static inline void vl_api_ip_session_redirect_details_t_endian (vl_api_ip_session_redirect_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->table_index = clib_net_to_host_u32(a->table_index);
    a->opaque_index = clib_net_to_host_u32(a->opaque_index);
    /* a->is_punt = a->is_punt (no-op) */
    /* a->is_ip6 = a->is_ip6 (no-op) */
    a->match_length = clib_net_to_host_u32(a->match_length);
    /* a->match = a->match (no-op) */
    /* a->n_paths = a->n_paths (no-op) */
    u32 count = a->n_paths;
    for (i = 0; i < count; i++) {
        vl_api_fib_path_t_endian(&a->paths[i], to_net);
    }
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_ip_session_redirect_calcsizefun
#define included_ip_session_redirect_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_ip_session_redirect_add_t_calc_size (vl_api_ip_session_redirect_add_t *a)
{
      return sizeof(*a) + a->n_paths * sizeof(a->paths[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip_session_redirect_add_reply_t_calc_size (vl_api_ip_session_redirect_add_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip_session_redirect_add_v2_t_calc_size (vl_api_ip_session_redirect_add_v2_t *a)
{
      return sizeof(*a) - sizeof(a->proto) + vl_api_fib_path_nh_proto_t_calc_size(&a->proto) + a->n_paths * sizeof(a->paths[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip_session_redirect_add_v2_reply_t_calc_size (vl_api_ip_session_redirect_add_v2_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip_session_redirect_del_t_calc_size (vl_api_ip_session_redirect_del_t *a)
{
      return sizeof(*a) + a->match_len * sizeof(a->match[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip_session_redirect_del_reply_t_calc_size (vl_api_ip_session_redirect_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip_session_redirect_dump_t_calc_size (vl_api_ip_session_redirect_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip_session_redirect_details_t_calc_size (vl_api_ip_session_redirect_details_t *a)
{
      return sizeof(*a) + a->n_paths * sizeof(a->paths[0]);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(ip_session_redirect.api, 0, 3, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(ip_session_redirect.api, 0x53620f15)

#endif

