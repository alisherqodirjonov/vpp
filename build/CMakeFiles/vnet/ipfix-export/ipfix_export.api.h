/*
 * VLIB API definitions 2026-04-04 08:31:58
 * Input file: ipfix_export.api
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
#warning no content included from ipfix_export.api
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
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_SET_IPFIX_EXPORTER, vl_api_set_ipfix_exporter_t_handler)
vl_msg_id(VL_API_SET_IPFIX_EXPORTER_REPLY, vl_api_set_ipfix_exporter_reply_t_handler)
vl_msg_id(VL_API_IPFIX_EXPORTER_DUMP, vl_api_ipfix_exporter_dump_t_handler)
vl_msg_id(VL_API_IPFIX_EXPORTER_DETAILS, vl_api_ipfix_exporter_details_t_handler)
vl_msg_id(VL_API_IPFIX_EXPORTER_CREATE_DELETE, vl_api_ipfix_exporter_create_delete_t_handler)
vl_msg_id(VL_API_IPFIX_EXPORTER_CREATE_DELETE_REPLY, vl_api_ipfix_exporter_create_delete_reply_t_handler)
vl_msg_id(VL_API_IPFIX_ALL_EXPORTER_GET, vl_api_ipfix_all_exporter_get_t_handler)
vl_msg_id(VL_API_IPFIX_ALL_EXPORTER_GET_REPLY, vl_api_ipfix_all_exporter_get_reply_t_handler)
vl_msg_id(VL_API_IPFIX_ALL_EXPORTER_DETAILS, vl_api_ipfix_all_exporter_details_t_handler)
vl_msg_id(VL_API_SET_IPFIX_CLASSIFY_STREAM, vl_api_set_ipfix_classify_stream_t_handler)
vl_msg_id(VL_API_SET_IPFIX_CLASSIFY_STREAM_REPLY, vl_api_set_ipfix_classify_stream_reply_t_handler)
vl_msg_id(VL_API_IPFIX_CLASSIFY_STREAM_DUMP, vl_api_ipfix_classify_stream_dump_t_handler)
vl_msg_id(VL_API_IPFIX_CLASSIFY_STREAM_DETAILS, vl_api_ipfix_classify_stream_details_t_handler)
vl_msg_id(VL_API_IPFIX_CLASSIFY_TABLE_ADD_DEL, vl_api_ipfix_classify_table_add_del_t_handler)
vl_msg_id(VL_API_IPFIX_CLASSIFY_TABLE_ADD_DEL_REPLY, vl_api_ipfix_classify_table_add_del_reply_t_handler)
vl_msg_id(VL_API_IPFIX_CLASSIFY_TABLE_DUMP, vl_api_ipfix_classify_table_dump_t_handler)
vl_msg_id(VL_API_IPFIX_CLASSIFY_TABLE_DETAILS, vl_api_ipfix_classify_table_details_t_handler)
vl_msg_id(VL_API_IPFIX_FLUSH, vl_api_ipfix_flush_t_handler)
vl_msg_id(VL_API_IPFIX_FLUSH_REPLY, vl_api_ipfix_flush_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_set_ipfix_exporter_t, 1)
vl_msg_name(vl_api_set_ipfix_exporter_reply_t, 1)
vl_msg_name(vl_api_ipfix_exporter_dump_t, 1)
vl_msg_name(vl_api_ipfix_exporter_details_t, 1)
vl_msg_name(vl_api_ipfix_exporter_create_delete_t, 1)
vl_msg_name(vl_api_ipfix_exporter_create_delete_reply_t, 1)
vl_msg_name(vl_api_ipfix_all_exporter_get_t, 1)
vl_msg_name(vl_api_ipfix_all_exporter_get_reply_t, 1)
vl_msg_name(vl_api_ipfix_all_exporter_details_t, 1)
vl_msg_name(vl_api_set_ipfix_classify_stream_t, 1)
vl_msg_name(vl_api_set_ipfix_classify_stream_reply_t, 1)
vl_msg_name(vl_api_ipfix_classify_stream_dump_t, 1)
vl_msg_name(vl_api_ipfix_classify_stream_details_t, 1)
vl_msg_name(vl_api_ipfix_classify_table_add_del_t, 1)
vl_msg_name(vl_api_ipfix_classify_table_add_del_reply_t, 1)
vl_msg_name(vl_api_ipfix_classify_table_dump_t, 1)
vl_msg_name(vl_api_ipfix_classify_table_details_t, 1)
vl_msg_name(vl_api_ipfix_flush_t, 1)
vl_msg_name(vl_api_ipfix_flush_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_ipfix_export \
_(VL_API_SET_IPFIX_EXPORTER, set_ipfix_exporter, 5530c8a0) \
_(VL_API_SET_IPFIX_EXPORTER_REPLY, set_ipfix_exporter_reply, e8d4e804) \
_(VL_API_IPFIX_EXPORTER_DUMP, ipfix_exporter_dump, 51077d14) \
_(VL_API_IPFIX_EXPORTER_DETAILS, ipfix_exporter_details, 0dedbfe4) \
_(VL_API_IPFIX_EXPORTER_CREATE_DELETE, ipfix_exporter_create_delete, 0753a768) \
_(VL_API_IPFIX_EXPORTER_CREATE_DELETE_REPLY, ipfix_exporter_create_delete_reply, 9ffac24b) \
_(VL_API_IPFIX_ALL_EXPORTER_GET, ipfix_all_exporter_get, f75ba505) \
_(VL_API_IPFIX_ALL_EXPORTER_GET_REPLY, ipfix_all_exporter_get_reply, 53b48f5d) \
_(VL_API_IPFIX_ALL_EXPORTER_DETAILS, ipfix_all_exporter_details, 0dedbfe4) \
_(VL_API_SET_IPFIX_CLASSIFY_STREAM, set_ipfix_classify_stream, c9cbe053) \
_(VL_API_SET_IPFIX_CLASSIFY_STREAM_REPLY, set_ipfix_classify_stream_reply, e8d4e804) \
_(VL_API_IPFIX_CLASSIFY_STREAM_DUMP, ipfix_classify_stream_dump, 51077d14) \
_(VL_API_IPFIX_CLASSIFY_STREAM_DETAILS, ipfix_classify_stream_details, 2903539d) \
_(VL_API_IPFIX_CLASSIFY_TABLE_ADD_DEL, ipfix_classify_table_add_del, 3e449bb9) \
_(VL_API_IPFIX_CLASSIFY_TABLE_ADD_DEL_REPLY, ipfix_classify_table_add_del_reply, e8d4e804) \
_(VL_API_IPFIX_CLASSIFY_TABLE_DUMP, ipfix_classify_table_dump, 51077d14) \
_(VL_API_IPFIX_CLASSIFY_TABLE_DETAILS, ipfix_classify_table_details, 1af8c28c) \
_(VL_API_IPFIX_FLUSH, ipfix_flush, 51077d14) \
_(VL_API_IPFIX_FLUSH_REPLY, ipfix_flush_reply, e8d4e804) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "ipfix_export.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_ipfix_export_printfun_types
#define included_ipfix_export_printfun_types


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_ipfix_export_printfun
#define included_ipfix_export_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "ipfix_export.api_tojson.h"
#include "ipfix_export.api_fromjson.h"

static inline u8 *vl_api_set_ipfix_exporter_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_set_ipfix_exporter_t *a = va_arg (*args, vl_api_set_ipfix_exporter_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_set_ipfix_exporter_t: */
    s = format(s, "vl_api_set_ipfix_exporter_t:");
    s = format(s, "\n%Ucollector_address: %U", format_white_space, indent, format_vl_api_address_t, &a->collector_address, indent);
    s = format(s, "\n%Ucollector_port: %u", format_white_space, indent, a->collector_port);
    s = format(s, "\n%Usrc_address: %U", format_white_space, indent, format_vl_api_address_t, &a->src_address, indent);
    s = format(s, "\n%Uvrf_id: %u", format_white_space, indent, a->vrf_id);
    s = format(s, "\n%Upath_mtu: %u", format_white_space, indent, a->path_mtu);
    s = format(s, "\n%Utemplate_interval: %u", format_white_space, indent, a->template_interval);
    s = format(s, "\n%Uudp_checksum: %u", format_white_space, indent, a->udp_checksum);
    return s;
}

static inline u8 *vl_api_set_ipfix_exporter_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_set_ipfix_exporter_reply_t *a = va_arg (*args, vl_api_set_ipfix_exporter_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_set_ipfix_exporter_reply_t: */
    s = format(s, "vl_api_set_ipfix_exporter_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_ipfix_exporter_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipfix_exporter_dump_t *a = va_arg (*args, vl_api_ipfix_exporter_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipfix_exporter_dump_t: */
    s = format(s, "vl_api_ipfix_exporter_dump_t:");
    return s;
}

static inline u8 *vl_api_ipfix_exporter_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipfix_exporter_details_t *a = va_arg (*args, vl_api_ipfix_exporter_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipfix_exporter_details_t: */
    s = format(s, "vl_api_ipfix_exporter_details_t:");
    s = format(s, "\n%Ucollector_address: %U", format_white_space, indent, format_vl_api_address_t, &a->collector_address, indent);
    s = format(s, "\n%Ucollector_port: %u", format_white_space, indent, a->collector_port);
    s = format(s, "\n%Usrc_address: %U", format_white_space, indent, format_vl_api_address_t, &a->src_address, indent);
    s = format(s, "\n%Uvrf_id: %u", format_white_space, indent, a->vrf_id);
    s = format(s, "\n%Upath_mtu: %u", format_white_space, indent, a->path_mtu);
    s = format(s, "\n%Utemplate_interval: %u", format_white_space, indent, a->template_interval);
    s = format(s, "\n%Uudp_checksum: %u", format_white_space, indent, a->udp_checksum);
    return s;
}

static inline u8 *vl_api_ipfix_exporter_create_delete_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipfix_exporter_create_delete_t *a = va_arg (*args, vl_api_ipfix_exporter_create_delete_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipfix_exporter_create_delete_t: */
    s = format(s, "vl_api_ipfix_exporter_create_delete_t:");
    s = format(s, "\n%Uis_create: %u", format_white_space, indent, a->is_create);
    s = format(s, "\n%Ucollector_address: %U", format_white_space, indent, format_vl_api_address_t, &a->collector_address, indent);
    s = format(s, "\n%Ucollector_port: %u", format_white_space, indent, a->collector_port);
    s = format(s, "\n%Usrc_address: %U", format_white_space, indent, format_vl_api_address_t, &a->src_address, indent);
    s = format(s, "\n%Uvrf_id: %u", format_white_space, indent, a->vrf_id);
    s = format(s, "\n%Upath_mtu: %u", format_white_space, indent, a->path_mtu);
    s = format(s, "\n%Utemplate_interval: %u", format_white_space, indent, a->template_interval);
    s = format(s, "\n%Uudp_checksum: %u", format_white_space, indent, a->udp_checksum);
    return s;
}

static inline u8 *vl_api_ipfix_exporter_create_delete_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipfix_exporter_create_delete_reply_t *a = va_arg (*args, vl_api_ipfix_exporter_create_delete_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipfix_exporter_create_delete_reply_t: */
    s = format(s, "vl_api_ipfix_exporter_create_delete_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ustat_index: %u", format_white_space, indent, a->stat_index);
    return s;
}

static inline u8 *vl_api_ipfix_all_exporter_get_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipfix_all_exporter_get_t *a = va_arg (*args, vl_api_ipfix_all_exporter_get_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipfix_all_exporter_get_t: */
    s = format(s, "vl_api_ipfix_all_exporter_get_t:");
    s = format(s, "\n%Ucursor: %u", format_white_space, indent, a->cursor);
    return s;
}

static inline u8 *vl_api_ipfix_all_exporter_get_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipfix_all_exporter_get_reply_t *a = va_arg (*args, vl_api_ipfix_all_exporter_get_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipfix_all_exporter_get_reply_t: */
    s = format(s, "vl_api_ipfix_all_exporter_get_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ucursor: %u", format_white_space, indent, a->cursor);
    return s;
}

static inline u8 *vl_api_ipfix_all_exporter_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipfix_all_exporter_details_t *a = va_arg (*args, vl_api_ipfix_all_exporter_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipfix_all_exporter_details_t: */
    s = format(s, "vl_api_ipfix_all_exporter_details_t:");
    s = format(s, "\n%Ucollector_address: %U", format_white_space, indent, format_vl_api_address_t, &a->collector_address, indent);
    s = format(s, "\n%Ucollector_port: %u", format_white_space, indent, a->collector_port);
    s = format(s, "\n%Usrc_address: %U", format_white_space, indent, format_vl_api_address_t, &a->src_address, indent);
    s = format(s, "\n%Uvrf_id: %u", format_white_space, indent, a->vrf_id);
    s = format(s, "\n%Upath_mtu: %u", format_white_space, indent, a->path_mtu);
    s = format(s, "\n%Utemplate_interval: %u", format_white_space, indent, a->template_interval);
    s = format(s, "\n%Uudp_checksum: %u", format_white_space, indent, a->udp_checksum);
    return s;
}

static inline u8 *vl_api_set_ipfix_classify_stream_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_set_ipfix_classify_stream_t *a = va_arg (*args, vl_api_set_ipfix_classify_stream_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_set_ipfix_classify_stream_t: */
    s = format(s, "vl_api_set_ipfix_classify_stream_t:");
    s = format(s, "\n%Udomain_id: %u", format_white_space, indent, a->domain_id);
    s = format(s, "\n%Usrc_port: %u", format_white_space, indent, a->src_port);
    return s;
}

static inline u8 *vl_api_set_ipfix_classify_stream_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_set_ipfix_classify_stream_reply_t *a = va_arg (*args, vl_api_set_ipfix_classify_stream_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_set_ipfix_classify_stream_reply_t: */
    s = format(s, "vl_api_set_ipfix_classify_stream_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_ipfix_classify_stream_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipfix_classify_stream_dump_t *a = va_arg (*args, vl_api_ipfix_classify_stream_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipfix_classify_stream_dump_t: */
    s = format(s, "vl_api_ipfix_classify_stream_dump_t:");
    return s;
}

static inline u8 *vl_api_ipfix_classify_stream_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipfix_classify_stream_details_t *a = va_arg (*args, vl_api_ipfix_classify_stream_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipfix_classify_stream_details_t: */
    s = format(s, "vl_api_ipfix_classify_stream_details_t:");
    s = format(s, "\n%Udomain_id: %u", format_white_space, indent, a->domain_id);
    s = format(s, "\n%Usrc_port: %u", format_white_space, indent, a->src_port);
    return s;
}

static inline u8 *vl_api_ipfix_classify_table_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipfix_classify_table_add_del_t *a = va_arg (*args, vl_api_ipfix_classify_table_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipfix_classify_table_add_del_t: */
    s = format(s, "vl_api_ipfix_classify_table_add_del_t:");
    s = format(s, "\n%Utable_id: %u", format_white_space, indent, a->table_id);
    s = format(s, "\n%Uip_version: %U", format_white_space, indent, format_vl_api_address_family_t, &a->ip_version, indent);
    s = format(s, "\n%Utransport_protocol: %U", format_white_space, indent, format_vl_api_ip_proto_t, &a->transport_protocol, indent);
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    return s;
}

static inline u8 *vl_api_ipfix_classify_table_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipfix_classify_table_add_del_reply_t *a = va_arg (*args, vl_api_ipfix_classify_table_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipfix_classify_table_add_del_reply_t: */
    s = format(s, "vl_api_ipfix_classify_table_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_ipfix_classify_table_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipfix_classify_table_dump_t *a = va_arg (*args, vl_api_ipfix_classify_table_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipfix_classify_table_dump_t: */
    s = format(s, "vl_api_ipfix_classify_table_dump_t:");
    return s;
}

static inline u8 *vl_api_ipfix_classify_table_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipfix_classify_table_details_t *a = va_arg (*args, vl_api_ipfix_classify_table_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipfix_classify_table_details_t: */
    s = format(s, "vl_api_ipfix_classify_table_details_t:");
    s = format(s, "\n%Utable_id: %u", format_white_space, indent, a->table_id);
    s = format(s, "\n%Uip_version: %U", format_white_space, indent, format_vl_api_address_family_t, &a->ip_version, indent);
    s = format(s, "\n%Utransport_protocol: %U", format_white_space, indent, format_vl_api_ip_proto_t, &a->transport_protocol, indent);
    return s;
}

static inline u8 *vl_api_ipfix_flush_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipfix_flush_t *a = va_arg (*args, vl_api_ipfix_flush_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipfix_flush_t: */
    s = format(s, "vl_api_ipfix_flush_t:");
    return s;
}

static inline u8 *vl_api_ipfix_flush_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipfix_flush_reply_t *a = va_arg (*args, vl_api_ipfix_flush_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipfix_flush_reply_t: */
    s = format(s, "vl_api_ipfix_flush_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_ipfix_export_endianfun
#define included_ipfix_export_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_set_ipfix_exporter_t_endian (vl_api_set_ipfix_exporter_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_address_t_endian(&a->collector_address, to_net);
    a->collector_port = clib_net_to_host_u16(a->collector_port);
    vl_api_address_t_endian(&a->src_address, to_net);
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
    a->path_mtu = clib_net_to_host_u32(a->path_mtu);
    a->template_interval = clib_net_to_host_u32(a->template_interval);
    /* a->udp_checksum = a->udp_checksum (no-op) */
}

static inline void vl_api_set_ipfix_exporter_reply_t_endian (vl_api_set_ipfix_exporter_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_ipfix_exporter_dump_t_endian (vl_api_ipfix_exporter_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_ipfix_exporter_details_t_endian (vl_api_ipfix_exporter_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_address_t_endian(&a->collector_address, to_net);
    a->collector_port = clib_net_to_host_u16(a->collector_port);
    vl_api_address_t_endian(&a->src_address, to_net);
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
    a->path_mtu = clib_net_to_host_u32(a->path_mtu);
    a->template_interval = clib_net_to_host_u32(a->template_interval);
    /* a->udp_checksum = a->udp_checksum (no-op) */
}

static inline void vl_api_ipfix_exporter_create_delete_t_endian (vl_api_ipfix_exporter_create_delete_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_create = a->is_create (no-op) */
    vl_api_address_t_endian(&a->collector_address, to_net);
    a->collector_port = clib_net_to_host_u16(a->collector_port);
    vl_api_address_t_endian(&a->src_address, to_net);
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
    a->path_mtu = clib_net_to_host_u32(a->path_mtu);
    a->template_interval = clib_net_to_host_u32(a->template_interval);
    /* a->udp_checksum = a->udp_checksum (no-op) */
}

static inline void vl_api_ipfix_exporter_create_delete_reply_t_endian (vl_api_ipfix_exporter_create_delete_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->stat_index = clib_net_to_host_u32(a->stat_index);
}

static inline void vl_api_ipfix_all_exporter_get_t_endian (vl_api_ipfix_all_exporter_get_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->cursor = clib_net_to_host_u32(a->cursor);
}

static inline void vl_api_ipfix_all_exporter_get_reply_t_endian (vl_api_ipfix_all_exporter_get_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->cursor = clib_net_to_host_u32(a->cursor);
}

static inline void vl_api_ipfix_all_exporter_details_t_endian (vl_api_ipfix_all_exporter_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_address_t_endian(&a->collector_address, to_net);
    a->collector_port = clib_net_to_host_u16(a->collector_port);
    vl_api_address_t_endian(&a->src_address, to_net);
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
    a->path_mtu = clib_net_to_host_u32(a->path_mtu);
    a->template_interval = clib_net_to_host_u32(a->template_interval);
    /* a->udp_checksum = a->udp_checksum (no-op) */
}

static inline void vl_api_set_ipfix_classify_stream_t_endian (vl_api_set_ipfix_classify_stream_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->domain_id = clib_net_to_host_u32(a->domain_id);
    a->src_port = clib_net_to_host_u16(a->src_port);
}

static inline void vl_api_set_ipfix_classify_stream_reply_t_endian (vl_api_set_ipfix_classify_stream_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_ipfix_classify_stream_dump_t_endian (vl_api_ipfix_classify_stream_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_ipfix_classify_stream_details_t_endian (vl_api_ipfix_classify_stream_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->domain_id = clib_net_to_host_u32(a->domain_id);
    a->src_port = clib_net_to_host_u16(a->src_port);
}

static inline void vl_api_ipfix_classify_table_add_del_t_endian (vl_api_ipfix_classify_table_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->table_id = clib_net_to_host_u32(a->table_id);
    vl_api_address_family_t_endian(&a->ip_version, to_net);
    vl_api_ip_proto_t_endian(&a->transport_protocol, to_net);
    /* a->is_add = a->is_add (no-op) */
}

static inline void vl_api_ipfix_classify_table_add_del_reply_t_endian (vl_api_ipfix_classify_table_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_ipfix_classify_table_dump_t_endian (vl_api_ipfix_classify_table_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_ipfix_classify_table_details_t_endian (vl_api_ipfix_classify_table_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->table_id = clib_net_to_host_u32(a->table_id);
    vl_api_address_family_t_endian(&a->ip_version, to_net);
    vl_api_ip_proto_t_endian(&a->transport_protocol, to_net);
}

static inline void vl_api_ipfix_flush_t_endian (vl_api_ipfix_flush_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_ipfix_flush_reply_t_endian (vl_api_ipfix_flush_reply_t *a, bool to_net)
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
#ifndef included_ipfix_export_calcsizefun
#define included_ipfix_export_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_set_ipfix_exporter_t_calc_size (vl_api_set_ipfix_exporter_t *a)
{
      return sizeof(*a) - sizeof(a->collector_address) + vl_api_address_t_calc_size(&a->collector_address) - sizeof(a->src_address) + vl_api_address_t_calc_size(&a->src_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_set_ipfix_exporter_reply_t_calc_size (vl_api_set_ipfix_exporter_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipfix_exporter_dump_t_calc_size (vl_api_ipfix_exporter_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipfix_exporter_details_t_calc_size (vl_api_ipfix_exporter_details_t *a)
{
      return sizeof(*a) - sizeof(a->collector_address) + vl_api_address_t_calc_size(&a->collector_address) - sizeof(a->src_address) + vl_api_address_t_calc_size(&a->src_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipfix_exporter_create_delete_t_calc_size (vl_api_ipfix_exporter_create_delete_t *a)
{
      return sizeof(*a) - sizeof(a->collector_address) + vl_api_address_t_calc_size(&a->collector_address) - sizeof(a->src_address) + vl_api_address_t_calc_size(&a->src_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipfix_exporter_create_delete_reply_t_calc_size (vl_api_ipfix_exporter_create_delete_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipfix_all_exporter_get_t_calc_size (vl_api_ipfix_all_exporter_get_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipfix_all_exporter_get_reply_t_calc_size (vl_api_ipfix_all_exporter_get_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipfix_all_exporter_details_t_calc_size (vl_api_ipfix_all_exporter_details_t *a)
{
      return sizeof(*a) - sizeof(a->collector_address) + vl_api_address_t_calc_size(&a->collector_address) - sizeof(a->src_address) + vl_api_address_t_calc_size(&a->src_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_set_ipfix_classify_stream_t_calc_size (vl_api_set_ipfix_classify_stream_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_set_ipfix_classify_stream_reply_t_calc_size (vl_api_set_ipfix_classify_stream_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipfix_classify_stream_dump_t_calc_size (vl_api_ipfix_classify_stream_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipfix_classify_stream_details_t_calc_size (vl_api_ipfix_classify_stream_details_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipfix_classify_table_add_del_t_calc_size (vl_api_ipfix_classify_table_add_del_t *a)
{
      return sizeof(*a) - sizeof(a->ip_version) + vl_api_address_family_t_calc_size(&a->ip_version) - sizeof(a->transport_protocol) + vl_api_ip_proto_t_calc_size(&a->transport_protocol);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipfix_classify_table_add_del_reply_t_calc_size (vl_api_ipfix_classify_table_add_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipfix_classify_table_dump_t_calc_size (vl_api_ipfix_classify_table_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipfix_classify_table_details_t_calc_size (vl_api_ipfix_classify_table_details_t *a)
{
      return sizeof(*a) - sizeof(a->ip_version) + vl_api_address_family_t_calc_size(&a->ip_version) - sizeof(a->transport_protocol) + vl_api_ip_proto_t_calc_size(&a->transport_protocol);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipfix_flush_t_calc_size (vl_api_ipfix_flush_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipfix_flush_reply_t_calc_size (vl_api_ipfix_flush_reply_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(ipfix_export.api, 2, 0, 3)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(ipfix_export.api, 0xe118ab1c)

#endif

