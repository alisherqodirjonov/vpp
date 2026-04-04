/*
 * VLIB API definitions 2026-04-04 08:31:58
 * Input file: pg.api
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
#warning no content included from pg.api
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
vl_msg_id(VL_API_PG_CREATE_INTERFACE, vl_api_pg_create_interface_t_handler)
vl_msg_id(VL_API_PG_CREATE_INTERFACE_V2, vl_api_pg_create_interface_v2_t_handler)
vl_msg_id(VL_API_PG_CREATE_INTERFACE_V3, vl_api_pg_create_interface_v3_t_handler)
vl_msg_id(VL_API_PG_CREATE_INTERFACE_REPLY, vl_api_pg_create_interface_reply_t_handler)
vl_msg_id(VL_API_PG_CREATE_INTERFACE_V2_REPLY, vl_api_pg_create_interface_v2_reply_t_handler)
vl_msg_id(VL_API_PG_CREATE_INTERFACE_V3_REPLY, vl_api_pg_create_interface_v3_reply_t_handler)
vl_msg_id(VL_API_PG_DELETE_INTERFACE, vl_api_pg_delete_interface_t_handler)
vl_msg_id(VL_API_PG_DELETE_INTERFACE_REPLY, vl_api_pg_delete_interface_reply_t_handler)
vl_msg_id(VL_API_PG_INTERFACE_ENABLE_DISABLE_COALESCE, vl_api_pg_interface_enable_disable_coalesce_t_handler)
vl_msg_id(VL_API_PG_INTERFACE_ENABLE_DISABLE_COALESCE_REPLY, vl_api_pg_interface_enable_disable_coalesce_reply_t_handler)
vl_msg_id(VL_API_PG_CAPTURE, vl_api_pg_capture_t_handler)
vl_msg_id(VL_API_PG_CAPTURE_REPLY, vl_api_pg_capture_reply_t_handler)
vl_msg_id(VL_API_PG_ENABLE_DISABLE, vl_api_pg_enable_disable_t_handler)
vl_msg_id(VL_API_PG_ENABLE_DISABLE_REPLY, vl_api_pg_enable_disable_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_pg_create_interface_t, 1)
vl_msg_name(vl_api_pg_create_interface_v2_t, 1)
vl_msg_name(vl_api_pg_create_interface_v3_t, 1)
vl_msg_name(vl_api_pg_create_interface_reply_t, 1)
vl_msg_name(vl_api_pg_create_interface_v2_reply_t, 1)
vl_msg_name(vl_api_pg_create_interface_v3_reply_t, 1)
vl_msg_name(vl_api_pg_delete_interface_t, 1)
vl_msg_name(vl_api_pg_delete_interface_reply_t, 1)
vl_msg_name(vl_api_pg_interface_enable_disable_coalesce_t, 1)
vl_msg_name(vl_api_pg_interface_enable_disable_coalesce_reply_t, 1)
vl_msg_name(vl_api_pg_capture_t, 1)
vl_msg_name(vl_api_pg_capture_reply_t, 1)
vl_msg_name(vl_api_pg_enable_disable_t, 1)
vl_msg_name(vl_api_pg_enable_disable_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_pg \
_(VL_API_PG_CREATE_INTERFACE, pg_create_interface, b7c893d7) \
_(VL_API_PG_CREATE_INTERFACE_V2, pg_create_interface_v2, 8657466a) \
_(VL_API_PG_CREATE_INTERFACE_V3, pg_create_interface_v3, b2aac653) \
_(VL_API_PG_CREATE_INTERFACE_REPLY, pg_create_interface_reply, 5383d31f) \
_(VL_API_PG_CREATE_INTERFACE_V2_REPLY, pg_create_interface_v2_reply, 5383d31f) \
_(VL_API_PG_CREATE_INTERFACE_V3_REPLY, pg_create_interface_v3_reply, 5383d31f) \
_(VL_API_PG_DELETE_INTERFACE, pg_delete_interface, f9e6675e) \
_(VL_API_PG_DELETE_INTERFACE_REPLY, pg_delete_interface_reply, e8d4e804) \
_(VL_API_PG_INTERFACE_ENABLE_DISABLE_COALESCE, pg_interface_enable_disable_coalesce, a2ef99e7) \
_(VL_API_PG_INTERFACE_ENABLE_DISABLE_COALESCE_REPLY, pg_interface_enable_disable_coalesce_reply, e8d4e804) \
_(VL_API_PG_CAPTURE, pg_capture, 3712fb6c) \
_(VL_API_PG_CAPTURE_REPLY, pg_capture_reply, e8d4e804) \
_(VL_API_PG_ENABLE_DISABLE, pg_enable_disable, 01f94f3a) \
_(VL_API_PG_ENABLE_DISABLE_REPLY, pg_enable_disable_reply, e8d4e804) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "pg.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_pg_printfun_types
#define included_pg_printfun_types

static inline u8 *format_vl_api_pg_interface_mode_t (u8 *s, va_list * args)
{
    vl_api_pg_interface_mode_t *a = va_arg (*args, vl_api_pg_interface_mode_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "PG_API_MODE_ETHERNET");
    case 1:
        return format(s, "PG_API_MODE_IP4");
    case 2:
        return format(s, "PG_API_MODE_IP6");
    }
    return s;
}

static inline u8 *format_vl_api_pg_interface_flags_t (u8 *s, va_list * args)
{
    vl_api_pg_interface_flags_t *a = va_arg (*args, vl_api_pg_interface_flags_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "PG_API_FLAG_NONE");
    case 1:
        return format(s, "PG_API_FLAG_CSUM_OFFLOAD");
    case 2:
        return format(s, "PG_API_FLAG_GSO");
    case 4:
        return format(s, "PG_API_FLAG_GRO_COALESCE");
    }
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_pg_printfun
#define included_pg_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "pg.api_tojson.h"
#include "pg.api_fromjson.h"

static inline u8 *vl_api_pg_create_interface_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pg_create_interface_t *a = va_arg (*args, vl_api_pg_create_interface_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pg_create_interface_t: */
    s = format(s, "vl_api_pg_create_interface_t:");
    s = format(s, "\n%Uinterface_id: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->interface_id, indent);
    s = format(s, "\n%Ugso_enabled: %u", format_white_space, indent, a->gso_enabled);
    s = format(s, "\n%Ugso_size: %u", format_white_space, indent, a->gso_size);
    return s;
}

static inline u8 *vl_api_pg_create_interface_v2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pg_create_interface_v2_t *a = va_arg (*args, vl_api_pg_create_interface_v2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pg_create_interface_v2_t: */
    s = format(s, "vl_api_pg_create_interface_v2_t:");
    s = format(s, "\n%Uinterface_id: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->interface_id, indent);
    s = format(s, "\n%Ugso_enabled: %u", format_white_space, indent, a->gso_enabled);
    s = format(s, "\n%Ugso_size: %u", format_white_space, indent, a->gso_size);
    s = format(s, "\n%Umode: %U", format_white_space, indent, format_vl_api_pg_interface_mode_t, &a->mode, indent);
    return s;
}

static inline u8 *vl_api_pg_create_interface_v3_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pg_create_interface_v3_t *a = va_arg (*args, vl_api_pg_create_interface_v3_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pg_create_interface_v3_t: */
    s = format(s, "vl_api_pg_create_interface_v3_t:");
    s = format(s, "\n%Uinterface_id: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->interface_id, indent);
    s = format(s, "\n%Upg_flags: %U", format_white_space, indent, format_vl_api_pg_interface_flags_t, &a->pg_flags, indent);
    s = format(s, "\n%Ugso_size: %u", format_white_space, indent, a->gso_size);
    s = format(s, "\n%Umode: %U", format_white_space, indent, format_vl_api_pg_interface_mode_t, &a->mode, indent);
    return s;
}

static inline u8 *vl_api_pg_create_interface_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pg_create_interface_reply_t *a = va_arg (*args, vl_api_pg_create_interface_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pg_create_interface_reply_t: */
    s = format(s, "vl_api_pg_create_interface_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_pg_create_interface_v2_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pg_create_interface_v2_reply_t *a = va_arg (*args, vl_api_pg_create_interface_v2_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pg_create_interface_v2_reply_t: */
    s = format(s, "vl_api_pg_create_interface_v2_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_pg_create_interface_v3_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pg_create_interface_v3_reply_t *a = va_arg (*args, vl_api_pg_create_interface_v3_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pg_create_interface_v3_reply_t: */
    s = format(s, "vl_api_pg_create_interface_v3_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_pg_delete_interface_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pg_delete_interface_t *a = va_arg (*args, vl_api_pg_delete_interface_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pg_delete_interface_t: */
    s = format(s, "vl_api_pg_delete_interface_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_pg_delete_interface_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pg_delete_interface_reply_t *a = va_arg (*args, vl_api_pg_delete_interface_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pg_delete_interface_reply_t: */
    s = format(s, "vl_api_pg_delete_interface_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_pg_interface_enable_disable_coalesce_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pg_interface_enable_disable_coalesce_t *a = va_arg (*args, vl_api_pg_interface_enable_disable_coalesce_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pg_interface_enable_disable_coalesce_t: */
    s = format(s, "vl_api_pg_interface_enable_disable_coalesce_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Ucoalesce_enabled: %u", format_white_space, indent, a->coalesce_enabled);
    return s;
}

static inline u8 *vl_api_pg_interface_enable_disable_coalesce_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pg_interface_enable_disable_coalesce_reply_t *a = va_arg (*args, vl_api_pg_interface_enable_disable_coalesce_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pg_interface_enable_disable_coalesce_reply_t: */
    s = format(s, "vl_api_pg_interface_enable_disable_coalesce_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_pg_capture_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pg_capture_t *a = va_arg (*args, vl_api_pg_capture_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pg_capture_t: */
    s = format(s, "vl_api_pg_capture_t:");
    s = format(s, "\n%Uinterface_id: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->interface_id, indent);
    s = format(s, "\n%Uis_enabled: %u", format_white_space, indent, a->is_enabled);
    s = format(s, "\n%Ucount: %u", format_white_space, indent, a->count);
    if (vl_api_string_len(&a->pcap_file_name) > 0) {
        s = format(s, "\n%Upcap_file_name: %U", format_white_space, indent, vl_api_format_string, (&a->pcap_file_name));
    } else {
        s = format(s, "\n%Upcap_file_name:", format_white_space, indent);
    }
    return s;
}

static inline u8 *vl_api_pg_capture_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pg_capture_reply_t *a = va_arg (*args, vl_api_pg_capture_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pg_capture_reply_t: */
    s = format(s, "vl_api_pg_capture_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_pg_enable_disable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pg_enable_disable_t *a = va_arg (*args, vl_api_pg_enable_disable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pg_enable_disable_t: */
    s = format(s, "vl_api_pg_enable_disable_t:");
    s = format(s, "\n%Uis_enabled: %u", format_white_space, indent, a->is_enabled);
    if (vl_api_string_len(&a->stream_name) > 0) {
        s = format(s, "\n%Ustream_name: %U", format_white_space, indent, vl_api_format_string, (&a->stream_name));
    } else {
        s = format(s, "\n%Ustream_name:", format_white_space, indent);
    }
    return s;
}

static inline u8 *vl_api_pg_enable_disable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pg_enable_disable_reply_t *a = va_arg (*args, vl_api_pg_enable_disable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pg_enable_disable_reply_t: */
    s = format(s, "vl_api_pg_enable_disable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_pg_endianfun
#define included_pg_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_pg_interface_mode_t_endian (vl_api_pg_interface_mode_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->pg_interface_mode = a->pg_interface_mode (no-op) */
}

static inline void vl_api_pg_interface_flags_t_endian (vl_api_pg_interface_flags_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_pg_create_interface_t_endian (vl_api_pg_create_interface_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->interface_id, to_net);
    /* a->gso_enabled = a->gso_enabled (no-op) */
    a->gso_size = clib_net_to_host_u32(a->gso_size);
}

static inline void vl_api_pg_create_interface_v2_t_endian (vl_api_pg_create_interface_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->interface_id, to_net);
    /* a->gso_enabled = a->gso_enabled (no-op) */
    a->gso_size = clib_net_to_host_u32(a->gso_size);
    vl_api_pg_interface_mode_t_endian(&a->mode, to_net);
}

static inline void vl_api_pg_create_interface_v3_t_endian (vl_api_pg_create_interface_v3_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->interface_id, to_net);
    vl_api_pg_interface_flags_t_endian(&a->pg_flags, to_net);
    a->gso_size = clib_net_to_host_u32(a->gso_size);
    vl_api_pg_interface_mode_t_endian(&a->mode, to_net);
}

static inline void vl_api_pg_create_interface_reply_t_endian (vl_api_pg_create_interface_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_pg_create_interface_v2_reply_t_endian (vl_api_pg_create_interface_v2_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_pg_create_interface_v3_reply_t_endian (vl_api_pg_create_interface_v3_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_pg_delete_interface_t_endian (vl_api_pg_delete_interface_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_pg_delete_interface_reply_t_endian (vl_api_pg_delete_interface_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_pg_interface_enable_disable_coalesce_t_endian (vl_api_pg_interface_enable_disable_coalesce_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->coalesce_enabled = a->coalesce_enabled (no-op) */
}

static inline void vl_api_pg_interface_enable_disable_coalesce_reply_t_endian (vl_api_pg_interface_enable_disable_coalesce_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_pg_capture_t_endian (vl_api_pg_capture_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->interface_id, to_net);
    /* a->is_enabled = a->is_enabled (no-op) */
    a->count = clib_net_to_host_u32(a->count);
    /* a->pcap_file_name = a->pcap_file_name (no-op) */
}

static inline void vl_api_pg_capture_reply_t_endian (vl_api_pg_capture_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_pg_enable_disable_t_endian (vl_api_pg_enable_disable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_enabled = a->is_enabled (no-op) */
    /* a->stream_name = a->stream_name (no-op) */
}

static inline void vl_api_pg_enable_disable_reply_t_endian (vl_api_pg_enable_disable_reply_t *a, bool to_net)
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
#ifndef included_pg_calcsizefun
#define included_pg_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_pg_interface_mode_t_calc_size (vl_api_pg_interface_mode_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pg_interface_flags_t_calc_size (vl_api_pg_interface_flags_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pg_create_interface_t_calc_size (vl_api_pg_create_interface_t *a)
{
      return sizeof(*a) - sizeof(a->interface_id) + vl_api_interface_index_t_calc_size(&a->interface_id);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pg_create_interface_v2_t_calc_size (vl_api_pg_create_interface_v2_t *a)
{
      return sizeof(*a) - sizeof(a->interface_id) + vl_api_interface_index_t_calc_size(&a->interface_id) - sizeof(a->mode) + vl_api_pg_interface_mode_t_calc_size(&a->mode);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pg_create_interface_v3_t_calc_size (vl_api_pg_create_interface_v3_t *a)
{
      return sizeof(*a) - sizeof(a->interface_id) + vl_api_interface_index_t_calc_size(&a->interface_id) - sizeof(a->pg_flags) + vl_api_pg_interface_flags_t_calc_size(&a->pg_flags) - sizeof(a->mode) + vl_api_pg_interface_mode_t_calc_size(&a->mode);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pg_create_interface_reply_t_calc_size (vl_api_pg_create_interface_reply_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pg_create_interface_v2_reply_t_calc_size (vl_api_pg_create_interface_v2_reply_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pg_create_interface_v3_reply_t_calc_size (vl_api_pg_create_interface_v3_reply_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pg_delete_interface_t_calc_size (vl_api_pg_delete_interface_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pg_delete_interface_reply_t_calc_size (vl_api_pg_delete_interface_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pg_interface_enable_disable_coalesce_t_calc_size (vl_api_pg_interface_enable_disable_coalesce_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pg_interface_enable_disable_coalesce_reply_t_calc_size (vl_api_pg_interface_enable_disable_coalesce_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pg_capture_t_calc_size (vl_api_pg_capture_t *a)
{
      return sizeof(*a) - sizeof(a->interface_id) + vl_api_interface_index_t_calc_size(&a->interface_id) + vl_api_string_len(&a->pcap_file_name);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pg_capture_reply_t_calc_size (vl_api_pg_capture_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pg_enable_disable_t_calc_size (vl_api_pg_enable_disable_t *a)
{
      return sizeof(*a) + vl_api_string_len(&a->stream_name);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pg_enable_disable_reply_t_calc_size (vl_api_pg_enable_disable_reply_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(pg.api, 2, 1, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(pg.api, 0xb62765bc)

#endif

