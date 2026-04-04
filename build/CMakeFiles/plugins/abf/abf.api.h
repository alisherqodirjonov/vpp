/*
 * VLIB API definitions 2026-04-04 08:31:59
 * Input file: abf.api
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
#warning no content included from abf.api
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
vl_msg_id(VL_API_ABF_PLUGIN_GET_VERSION, vl_api_abf_plugin_get_version_t_handler)
vl_msg_id(VL_API_ABF_PLUGIN_GET_VERSION_REPLY, vl_api_abf_plugin_get_version_reply_t_handler)
vl_msg_id(VL_API_ABF_POLICY_ADD_DEL, vl_api_abf_policy_add_del_t_handler)
vl_msg_id(VL_API_ABF_POLICY_ADD_DEL_REPLY, vl_api_abf_policy_add_del_reply_t_handler)
vl_msg_id(VL_API_ABF_POLICY_DETAILS, vl_api_abf_policy_details_t_handler)
vl_msg_id(VL_API_ABF_POLICY_DUMP, vl_api_abf_policy_dump_t_handler)
vl_msg_id(VL_API_ABF_ITF_ATTACH_ADD_DEL, vl_api_abf_itf_attach_add_del_t_handler)
vl_msg_id(VL_API_ABF_ITF_ATTACH_ADD_DEL_REPLY, vl_api_abf_itf_attach_add_del_reply_t_handler)
vl_msg_id(VL_API_ABF_ITF_ATTACH_DETAILS, vl_api_abf_itf_attach_details_t_handler)
vl_msg_id(VL_API_ABF_ITF_ATTACH_DUMP, vl_api_abf_itf_attach_dump_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_abf_plugin_get_version_t, 1)
vl_msg_name(vl_api_abf_plugin_get_version_reply_t, 1)
vl_msg_name(vl_api_abf_policy_add_del_t, 1)
vl_msg_name(vl_api_abf_policy_add_del_reply_t, 1)
vl_msg_name(vl_api_abf_policy_details_t, 1)
vl_msg_name(vl_api_abf_policy_dump_t, 1)
vl_msg_name(vl_api_abf_itf_attach_add_del_t, 1)
vl_msg_name(vl_api_abf_itf_attach_add_del_reply_t, 1)
vl_msg_name(vl_api_abf_itf_attach_details_t, 1)
vl_msg_name(vl_api_abf_itf_attach_dump_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_abf \
_(VL_API_ABF_PLUGIN_GET_VERSION, abf_plugin_get_version, 51077d14) \
_(VL_API_ABF_PLUGIN_GET_VERSION_REPLY, abf_plugin_get_version_reply, 9b32cf86) \
_(VL_API_ABF_POLICY_ADD_DEL, abf_policy_add_del, c6131197) \
_(VL_API_ABF_POLICY_ADD_DEL_REPLY, abf_policy_add_del_reply, e8d4e804) \
_(VL_API_ABF_POLICY_DETAILS, abf_policy_details, b7487fa4) \
_(VL_API_ABF_POLICY_DUMP, abf_policy_dump, 51077d14) \
_(VL_API_ABF_ITF_ATTACH_ADD_DEL, abf_itf_attach_add_del, 25c8621b) \
_(VL_API_ABF_ITF_ATTACH_ADD_DEL_REPLY, abf_itf_attach_add_del_reply, e8d4e804) \
_(VL_API_ABF_ITF_ATTACH_DETAILS, abf_itf_attach_details, 7819523e) \
_(VL_API_ABF_ITF_ATTACH_DUMP, abf_itf_attach_dump, 51077d14) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "abf.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_abf_printfun_types
#define included_abf_printfun_types

static inline u8 *format_vl_api_abf_policy_t (u8 *s, va_list * args)
{
    vl_api_abf_policy_t *a = va_arg (*args, vl_api_abf_policy_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Upolicy_id: %u", format_white_space, indent, a->policy_id);
    s = format(s, "\n%Uacl_index: %u", format_white_space, indent, a->acl_index);
    s = format(s, "\n%Un_paths: %u", format_white_space, indent, a->n_paths);
    for (i = 0; i < a->n_paths; i++) {
        s = format(s, "\n%Upaths: %U",
                   format_white_space, indent, format_vl_api_fib_path_t, &a->paths[i], indent);
    }
    return s;
}

static inline u8 *format_vl_api_abf_itf_attach_t (u8 *s, va_list * args)
{
    vl_api_abf_itf_attach_t *a = va_arg (*args, vl_api_abf_itf_attach_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Upolicy_id: %u", format_white_space, indent, a->policy_id);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Upriority: %u", format_white_space, indent, a->priority);
    s = format(s, "\n%Uis_ipv6: %u", format_white_space, indent, a->is_ipv6);
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_abf_printfun
#define included_abf_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "abf.api_tojson.h"
#include "abf.api_fromjson.h"

static inline u8 *vl_api_abf_plugin_get_version_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_abf_plugin_get_version_t *a = va_arg (*args, vl_api_abf_plugin_get_version_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_abf_plugin_get_version_t: */
    s = format(s, "vl_api_abf_plugin_get_version_t:");
    return s;
}

static inline u8 *vl_api_abf_plugin_get_version_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_abf_plugin_get_version_reply_t *a = va_arg (*args, vl_api_abf_plugin_get_version_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_abf_plugin_get_version_reply_t: */
    s = format(s, "vl_api_abf_plugin_get_version_reply_t:");
    s = format(s, "\n%Umajor: %u", format_white_space, indent, a->major);
    s = format(s, "\n%Uminor: %u", format_white_space, indent, a->minor);
    return s;
}

static inline u8 *vl_api_abf_policy_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_abf_policy_add_del_t *a = va_arg (*args, vl_api_abf_policy_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_abf_policy_add_del_t: */
    s = format(s, "vl_api_abf_policy_add_del_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Upolicy: %U", format_white_space, indent, format_vl_api_abf_policy_t, &a->policy, indent);
    return s;
}

static inline u8 *vl_api_abf_policy_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_abf_policy_add_del_reply_t *a = va_arg (*args, vl_api_abf_policy_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_abf_policy_add_del_reply_t: */
    s = format(s, "vl_api_abf_policy_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_abf_policy_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_abf_policy_details_t *a = va_arg (*args, vl_api_abf_policy_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_abf_policy_details_t: */
    s = format(s, "vl_api_abf_policy_details_t:");
    s = format(s, "\n%Upolicy: %U", format_white_space, indent, format_vl_api_abf_policy_t, &a->policy, indent);
    return s;
}

static inline u8 *vl_api_abf_policy_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_abf_policy_dump_t *a = va_arg (*args, vl_api_abf_policy_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_abf_policy_dump_t: */
    s = format(s, "vl_api_abf_policy_dump_t:");
    return s;
}

static inline u8 *vl_api_abf_itf_attach_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_abf_itf_attach_add_del_t *a = va_arg (*args, vl_api_abf_itf_attach_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_abf_itf_attach_add_del_t: */
    s = format(s, "vl_api_abf_itf_attach_add_del_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uattach: %U", format_white_space, indent, format_vl_api_abf_itf_attach_t, &a->attach, indent);
    return s;
}

static inline u8 *vl_api_abf_itf_attach_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_abf_itf_attach_add_del_reply_t *a = va_arg (*args, vl_api_abf_itf_attach_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_abf_itf_attach_add_del_reply_t: */
    s = format(s, "vl_api_abf_itf_attach_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_abf_itf_attach_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_abf_itf_attach_details_t *a = va_arg (*args, vl_api_abf_itf_attach_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_abf_itf_attach_details_t: */
    s = format(s, "vl_api_abf_itf_attach_details_t:");
    s = format(s, "\n%Uattach: %U", format_white_space, indent, format_vl_api_abf_itf_attach_t, &a->attach, indent);
    return s;
}

static inline u8 *vl_api_abf_itf_attach_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_abf_itf_attach_dump_t *a = va_arg (*args, vl_api_abf_itf_attach_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_abf_itf_attach_dump_t: */
    s = format(s, "vl_api_abf_itf_attach_dump_t:");
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_abf_endianfun
#define included_abf_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_abf_policy_t_endian (vl_api_abf_policy_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->policy_id = clib_net_to_host_u32(a->policy_id);
    a->acl_index = clib_net_to_host_u32(a->acl_index);
    /* a->n_paths = a->n_paths (no-op) */
    u32 count = a->n_paths;
    for (i = 0; i < count; i++) {
        vl_api_fib_path_t_endian(&a->paths[i], to_net);
    }
}

static inline void vl_api_abf_itf_attach_t_endian (vl_api_abf_itf_attach_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->policy_id = clib_net_to_host_u32(a->policy_id);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    a->priority = clib_net_to_host_u32(a->priority);
    /* a->is_ipv6 = a->is_ipv6 (no-op) */
}

static inline void vl_api_abf_plugin_get_version_t_endian (vl_api_abf_plugin_get_version_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_abf_plugin_get_version_reply_t_endian (vl_api_abf_plugin_get_version_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->major = clib_net_to_host_u32(a->major);
    a->minor = clib_net_to_host_u32(a->minor);
}

static inline void vl_api_abf_policy_add_del_t_endian (vl_api_abf_policy_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_abf_policy_t_endian(&a->policy, to_net);
}

static inline void vl_api_abf_policy_add_del_reply_t_endian (vl_api_abf_policy_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_abf_policy_details_t_endian (vl_api_abf_policy_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_abf_policy_t_endian(&a->policy, to_net);
}

static inline void vl_api_abf_policy_dump_t_endian (vl_api_abf_policy_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_abf_itf_attach_add_del_t_endian (vl_api_abf_itf_attach_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_abf_itf_attach_t_endian(&a->attach, to_net);
}

static inline void vl_api_abf_itf_attach_add_del_reply_t_endian (vl_api_abf_itf_attach_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_abf_itf_attach_details_t_endian (vl_api_abf_itf_attach_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_abf_itf_attach_t_endian(&a->attach, to_net);
}

static inline void vl_api_abf_itf_attach_dump_t_endian (vl_api_abf_itf_attach_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_abf_calcsizefun
#define included_abf_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_abf_policy_t_calc_size (vl_api_abf_policy_t *a)
{
      return sizeof(*a) + a->n_paths * sizeof(a->paths[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_abf_itf_attach_t_calc_size (vl_api_abf_itf_attach_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_abf_plugin_get_version_t_calc_size (vl_api_abf_plugin_get_version_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_abf_plugin_get_version_reply_t_calc_size (vl_api_abf_plugin_get_version_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_abf_policy_add_del_t_calc_size (vl_api_abf_policy_add_del_t *a)
{
      return sizeof(*a) - sizeof(a->policy) + vl_api_abf_policy_t_calc_size(&a->policy);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_abf_policy_add_del_reply_t_calc_size (vl_api_abf_policy_add_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_abf_policy_details_t_calc_size (vl_api_abf_policy_details_t *a)
{
      return sizeof(*a) - sizeof(a->policy) + vl_api_abf_policy_t_calc_size(&a->policy);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_abf_policy_dump_t_calc_size (vl_api_abf_policy_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_abf_itf_attach_add_del_t_calc_size (vl_api_abf_itf_attach_add_del_t *a)
{
      return sizeof(*a) - sizeof(a->attach) + vl_api_abf_itf_attach_t_calc_size(&a->attach);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_abf_itf_attach_add_del_reply_t_calc_size (vl_api_abf_itf_attach_add_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_abf_itf_attach_details_t_calc_size (vl_api_abf_itf_attach_details_t *a)
{
      return sizeof(*a) - sizeof(a->attach) + vl_api_abf_itf_attach_t_calc_size(&a->attach);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_abf_itf_attach_dump_t_calc_size (vl_api_abf_itf_attach_dump_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(abf.api, 1, 0, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(abf.api, 0x70fd229c)

#endif

