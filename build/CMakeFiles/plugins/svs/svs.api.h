/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: svs.api
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
#warning no content included from svs.api
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
vl_msg_id(VL_API_SVS_PLUGIN_GET_VERSION, vl_api_svs_plugin_get_version_t_handler)
vl_msg_id(VL_API_SVS_PLUGIN_GET_VERSION_REPLY, vl_api_svs_plugin_get_version_reply_t_handler)
vl_msg_id(VL_API_SVS_TABLE_ADD_DEL, vl_api_svs_table_add_del_t_handler)
vl_msg_id(VL_API_SVS_TABLE_ADD_DEL_REPLY, vl_api_svs_table_add_del_reply_t_handler)
vl_msg_id(VL_API_SVS_ROUTE_ADD_DEL, vl_api_svs_route_add_del_t_handler)
vl_msg_id(VL_API_SVS_ROUTE_ADD_DEL_REPLY, vl_api_svs_route_add_del_reply_t_handler)
vl_msg_id(VL_API_SVS_ENABLE_DISABLE, vl_api_svs_enable_disable_t_handler)
vl_msg_id(VL_API_SVS_ENABLE_DISABLE_REPLY, vl_api_svs_enable_disable_reply_t_handler)
vl_msg_id(VL_API_SVS_DUMP, vl_api_svs_dump_t_handler)
vl_msg_id(VL_API_SVS_DETAILS, vl_api_svs_details_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_svs_plugin_get_version_t, 1)
vl_msg_name(vl_api_svs_plugin_get_version_reply_t, 1)
vl_msg_name(vl_api_svs_table_add_del_t, 1)
vl_msg_name(vl_api_svs_table_add_del_reply_t, 1)
vl_msg_name(vl_api_svs_route_add_del_t, 1)
vl_msg_name(vl_api_svs_route_add_del_reply_t, 1)
vl_msg_name(vl_api_svs_enable_disable_t, 1)
vl_msg_name(vl_api_svs_enable_disable_reply_t, 1)
vl_msg_name(vl_api_svs_dump_t, 1)
vl_msg_name(vl_api_svs_details_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_svs \
_(VL_API_SVS_PLUGIN_GET_VERSION, svs_plugin_get_version, 51077d14) \
_(VL_API_SVS_PLUGIN_GET_VERSION_REPLY, svs_plugin_get_version_reply, 9b32cf86) \
_(VL_API_SVS_TABLE_ADD_DEL, svs_table_add_del, 7d21cb2a) \
_(VL_API_SVS_TABLE_ADD_DEL_REPLY, svs_table_add_del_reply, e8d4e804) \
_(VL_API_SVS_ROUTE_ADD_DEL, svs_route_add_del, e49bc63c) \
_(VL_API_SVS_ROUTE_ADD_DEL_REPLY, svs_route_add_del_reply, e8d4e804) \
_(VL_API_SVS_ENABLE_DISABLE, svs_enable_disable, 634b89d2) \
_(VL_API_SVS_ENABLE_DISABLE_REPLY, svs_enable_disable_reply, e8d4e804) \
_(VL_API_SVS_DUMP, svs_dump, 51077d14) \
_(VL_API_SVS_DETAILS, svs_details, 6282cd55) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "svs.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_svs_printfun_types
#define included_svs_printfun_types


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_svs_printfun
#define included_svs_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "svs.api_tojson.h"
#include "svs.api_fromjson.h"

static inline u8 *vl_api_svs_plugin_get_version_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_svs_plugin_get_version_t *a = va_arg (*args, vl_api_svs_plugin_get_version_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_svs_plugin_get_version_t: */
    s = format(s, "vl_api_svs_plugin_get_version_t:");
    return s;
}

static inline u8 *vl_api_svs_plugin_get_version_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_svs_plugin_get_version_reply_t *a = va_arg (*args, vl_api_svs_plugin_get_version_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_svs_plugin_get_version_reply_t: */
    s = format(s, "vl_api_svs_plugin_get_version_reply_t:");
    s = format(s, "\n%Umajor: %u", format_white_space, indent, a->major);
    s = format(s, "\n%Uminor: %u", format_white_space, indent, a->minor);
    return s;
}

static inline u8 *vl_api_svs_table_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_svs_table_add_del_t *a = va_arg (*args, vl_api_svs_table_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_svs_table_add_del_t: */
    s = format(s, "vl_api_svs_table_add_del_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uaf: %U", format_white_space, indent, format_vl_api_address_family_t, &a->af, indent);
    s = format(s, "\n%Utable_id: %u", format_white_space, indent, a->table_id);
    return s;
}

static inline u8 *vl_api_svs_table_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_svs_table_add_del_reply_t *a = va_arg (*args, vl_api_svs_table_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_svs_table_add_del_reply_t: */
    s = format(s, "vl_api_svs_table_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_svs_route_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_svs_route_add_del_t *a = va_arg (*args, vl_api_svs_route_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_svs_route_add_del_t: */
    s = format(s, "vl_api_svs_route_add_del_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uprefix: %U", format_white_space, indent, format_vl_api_prefix_t, &a->prefix, indent);
    s = format(s, "\n%Utable_id: %u", format_white_space, indent, a->table_id);
    s = format(s, "\n%Usource_table_id: %u", format_white_space, indent, a->source_table_id);
    return s;
}

static inline u8 *vl_api_svs_route_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_svs_route_add_del_reply_t *a = va_arg (*args, vl_api_svs_route_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_svs_route_add_del_reply_t: */
    s = format(s, "vl_api_svs_route_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_svs_enable_disable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_svs_enable_disable_t *a = va_arg (*args, vl_api_svs_enable_disable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_svs_enable_disable_t: */
    s = format(s, "vl_api_svs_enable_disable_t:");
    s = format(s, "\n%Uis_enable: %u", format_white_space, indent, a->is_enable);
    s = format(s, "\n%Uaf: %U", format_white_space, indent, format_vl_api_address_family_t, &a->af, indent);
    s = format(s, "\n%Utable_id: %u", format_white_space, indent, a->table_id);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_svs_enable_disable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_svs_enable_disable_reply_t *a = va_arg (*args, vl_api_svs_enable_disable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_svs_enable_disable_reply_t: */
    s = format(s, "vl_api_svs_enable_disable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_svs_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_svs_dump_t *a = va_arg (*args, vl_api_svs_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_svs_dump_t: */
    s = format(s, "vl_api_svs_dump_t:");
    return s;
}

static inline u8 *vl_api_svs_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_svs_details_t *a = va_arg (*args, vl_api_svs_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_svs_details_t: */
    s = format(s, "vl_api_svs_details_t:");
    s = format(s, "\n%Utable_id: %u", format_white_space, indent, a->table_id);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uaf: %U", format_white_space, indent, format_vl_api_address_family_t, &a->af, indent);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_svs_endianfun
#define included_svs_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_svs_plugin_get_version_t_endian (vl_api_svs_plugin_get_version_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_svs_plugin_get_version_reply_t_endian (vl_api_svs_plugin_get_version_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->major = clib_net_to_host_u32(a->major);
    a->minor = clib_net_to_host_u32(a->minor);
}

static inline void vl_api_svs_table_add_del_t_endian (vl_api_svs_table_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_address_family_t_endian(&a->af, to_net);
    a->table_id = clib_net_to_host_u32(a->table_id);
}

static inline void vl_api_svs_table_add_del_reply_t_endian (vl_api_svs_table_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_svs_route_add_del_t_endian (vl_api_svs_route_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_prefix_t_endian(&a->prefix, to_net);
    a->table_id = clib_net_to_host_u32(a->table_id);
    a->source_table_id = clib_net_to_host_u32(a->source_table_id);
}

static inline void vl_api_svs_route_add_del_reply_t_endian (vl_api_svs_route_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_svs_enable_disable_t_endian (vl_api_svs_enable_disable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_enable = a->is_enable (no-op) */
    vl_api_address_family_t_endian(&a->af, to_net);
    a->table_id = clib_net_to_host_u32(a->table_id);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_svs_enable_disable_reply_t_endian (vl_api_svs_enable_disable_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_svs_dump_t_endian (vl_api_svs_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_svs_details_t_endian (vl_api_svs_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->table_id = clib_net_to_host_u32(a->table_id);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    vl_api_address_family_t_endian(&a->af, to_net);
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_svs_calcsizefun
#define included_svs_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_svs_plugin_get_version_t_calc_size (vl_api_svs_plugin_get_version_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_svs_plugin_get_version_reply_t_calc_size (vl_api_svs_plugin_get_version_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_svs_table_add_del_t_calc_size (vl_api_svs_table_add_del_t *a)
{
      return sizeof(*a) - sizeof(a->af) + vl_api_address_family_t_calc_size(&a->af);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_svs_table_add_del_reply_t_calc_size (vl_api_svs_table_add_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_svs_route_add_del_t_calc_size (vl_api_svs_route_add_del_t *a)
{
      return sizeof(*a) - sizeof(a->prefix) + vl_api_prefix_t_calc_size(&a->prefix);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_svs_route_add_del_reply_t_calc_size (vl_api_svs_route_add_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_svs_enable_disable_t_calc_size (vl_api_svs_enable_disable_t *a)
{
      return sizeof(*a) - sizeof(a->af) + vl_api_address_family_t_calc_size(&a->af) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_svs_enable_disable_reply_t_calc_size (vl_api_svs_enable_disable_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_svs_dump_t_calc_size (vl_api_svs_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_svs_details_t_calc_size (vl_api_svs_details_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->af) + vl_api_address_family_t_calc_size(&a->af);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(svs.api, 1, 0, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(svs.api, 0x6238424)

#endif

