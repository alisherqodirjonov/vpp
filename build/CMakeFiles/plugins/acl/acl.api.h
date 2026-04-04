/*
 * VLIB API definitions 2026-04-04 08:31:59
 * Input file: acl.api
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
#warning no content included from acl.api
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
#include <acl/acl_types.api.h>
#include <vnet/interface_types.api.h>
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_ACL_PLUGIN_GET_VERSION, vl_api_acl_plugin_get_version_t_handler)
vl_msg_id(VL_API_ACL_PLUGIN_GET_VERSION_REPLY, vl_api_acl_plugin_get_version_reply_t_handler)
vl_msg_id(VL_API_ACL_PLUGIN_CONTROL_PING, vl_api_acl_plugin_control_ping_t_handler)
vl_msg_id(VL_API_ACL_PLUGIN_CONTROL_PING_REPLY, vl_api_acl_plugin_control_ping_reply_t_handler)
vl_msg_id(VL_API_ACL_PLUGIN_GET_CONN_TABLE_MAX_ENTRIES, vl_api_acl_plugin_get_conn_table_max_entries_t_handler)
vl_msg_id(VL_API_ACL_PLUGIN_GET_CONN_TABLE_MAX_ENTRIES_REPLY, vl_api_acl_plugin_get_conn_table_max_entries_reply_t_handler)
vl_msg_id(VL_API_ACL_ADD_REPLACE, vl_api_acl_add_replace_t_handler)
vl_msg_id(VL_API_ACL_ADD_REPLACE_REPLY, vl_api_acl_add_replace_reply_t_handler)
vl_msg_id(VL_API_ACL_DEL, vl_api_acl_del_t_handler)
vl_msg_id(VL_API_ACL_DEL_REPLY, vl_api_acl_del_reply_t_handler)
vl_msg_id(VL_API_ACL_INTERFACE_ADD_DEL, vl_api_acl_interface_add_del_t_handler)
vl_msg_id(VL_API_ACL_INTERFACE_ADD_DEL_REPLY, vl_api_acl_interface_add_del_reply_t_handler)
vl_msg_id(VL_API_ACL_INTERFACE_SET_ACL_LIST, vl_api_acl_interface_set_acl_list_t_handler)
vl_msg_id(VL_API_ACL_INTERFACE_SET_ACL_LIST_REPLY, vl_api_acl_interface_set_acl_list_reply_t_handler)
vl_msg_id(VL_API_ACL_DUMP, vl_api_acl_dump_t_handler)
vl_msg_id(VL_API_ACL_DETAILS, vl_api_acl_details_t_handler)
vl_msg_id(VL_API_ACL_INTERFACE_LIST_DUMP, vl_api_acl_interface_list_dump_t_handler)
vl_msg_id(VL_API_ACL_INTERFACE_LIST_DETAILS, vl_api_acl_interface_list_details_t_handler)
vl_msg_id(VL_API_MACIP_ACL_ADD, vl_api_macip_acl_add_t_handler)
vl_msg_id(VL_API_MACIP_ACL_ADD_REPLY, vl_api_macip_acl_add_reply_t_handler)
vl_msg_id(VL_API_MACIP_ACL_ADD_REPLACE, vl_api_macip_acl_add_replace_t_handler)
vl_msg_id(VL_API_MACIP_ACL_ADD_REPLACE_REPLY, vl_api_macip_acl_add_replace_reply_t_handler)
vl_msg_id(VL_API_MACIP_ACL_DEL, vl_api_macip_acl_del_t_handler)
vl_msg_id(VL_API_MACIP_ACL_DEL_REPLY, vl_api_macip_acl_del_reply_t_handler)
vl_msg_id(VL_API_MACIP_ACL_INTERFACE_ADD_DEL, vl_api_macip_acl_interface_add_del_t_handler)
vl_msg_id(VL_API_MACIP_ACL_INTERFACE_ADD_DEL_REPLY, vl_api_macip_acl_interface_add_del_reply_t_handler)
vl_msg_id(VL_API_MACIP_ACL_DUMP, vl_api_macip_acl_dump_t_handler)
vl_msg_id(VL_API_MACIP_ACL_DETAILS, vl_api_macip_acl_details_t_handler)
vl_msg_id(VL_API_MACIP_ACL_INTERFACE_GET, vl_api_macip_acl_interface_get_t_handler)
vl_msg_id(VL_API_MACIP_ACL_INTERFACE_GET_REPLY, vl_api_macip_acl_interface_get_reply_t_handler)
vl_msg_id(VL_API_MACIP_ACL_INTERFACE_LIST_DUMP, vl_api_macip_acl_interface_list_dump_t_handler)
vl_msg_id(VL_API_MACIP_ACL_INTERFACE_LIST_DETAILS, vl_api_macip_acl_interface_list_details_t_handler)
vl_msg_id(VL_API_ACL_INTERFACE_SET_ETYPE_WHITELIST, vl_api_acl_interface_set_etype_whitelist_t_handler)
vl_msg_id(VL_API_ACL_INTERFACE_SET_ETYPE_WHITELIST_REPLY, vl_api_acl_interface_set_etype_whitelist_reply_t_handler)
vl_msg_id(VL_API_ACL_INTERFACE_ETYPE_WHITELIST_DUMP, vl_api_acl_interface_etype_whitelist_dump_t_handler)
vl_msg_id(VL_API_ACL_INTERFACE_ETYPE_WHITELIST_DETAILS, vl_api_acl_interface_etype_whitelist_details_t_handler)
vl_msg_id(VL_API_ACL_STATS_INTF_COUNTERS_ENABLE, vl_api_acl_stats_intf_counters_enable_t_handler)
vl_msg_id(VL_API_ACL_STATS_INTF_COUNTERS_ENABLE_REPLY, vl_api_acl_stats_intf_counters_enable_reply_t_handler)
vl_msg_id(VL_API_ACL_PLUGIN_USE_HASH_LOOKUP_SET, vl_api_acl_plugin_use_hash_lookup_set_t_handler)
vl_msg_id(VL_API_ACL_PLUGIN_USE_HASH_LOOKUP_SET_REPLY, vl_api_acl_plugin_use_hash_lookup_set_reply_t_handler)
vl_msg_id(VL_API_ACL_PLUGIN_USE_HASH_LOOKUP_GET, vl_api_acl_plugin_use_hash_lookup_get_t_handler)
vl_msg_id(VL_API_ACL_PLUGIN_USE_HASH_LOOKUP_GET_REPLY, vl_api_acl_plugin_use_hash_lookup_get_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_acl_plugin_get_version_t, 1)
vl_msg_name(vl_api_acl_plugin_get_version_reply_t, 1)
vl_msg_name(vl_api_acl_plugin_control_ping_t, 1)
vl_msg_name(vl_api_acl_plugin_control_ping_reply_t, 1)
vl_msg_name(vl_api_acl_plugin_get_conn_table_max_entries_t, 1)
vl_msg_name(vl_api_acl_plugin_get_conn_table_max_entries_reply_t, 1)
vl_msg_name(vl_api_acl_add_replace_t, 1)
vl_msg_name(vl_api_acl_add_replace_reply_t, 1)
vl_msg_name(vl_api_acl_del_t, 1)
vl_msg_name(vl_api_acl_del_reply_t, 1)
vl_msg_name(vl_api_acl_interface_add_del_t, 1)
vl_msg_name(vl_api_acl_interface_add_del_reply_t, 1)
vl_msg_name(vl_api_acl_interface_set_acl_list_t, 1)
vl_msg_name(vl_api_acl_interface_set_acl_list_reply_t, 1)
vl_msg_name(vl_api_acl_dump_t, 1)
vl_msg_name(vl_api_acl_details_t, 1)
vl_msg_name(vl_api_acl_interface_list_dump_t, 1)
vl_msg_name(vl_api_acl_interface_list_details_t, 1)
vl_msg_name(vl_api_macip_acl_add_t, 1)
vl_msg_name(vl_api_macip_acl_add_reply_t, 1)
vl_msg_name(vl_api_macip_acl_add_replace_t, 1)
vl_msg_name(vl_api_macip_acl_add_replace_reply_t, 1)
vl_msg_name(vl_api_macip_acl_del_t, 1)
vl_msg_name(vl_api_macip_acl_del_reply_t, 1)
vl_msg_name(vl_api_macip_acl_interface_add_del_t, 1)
vl_msg_name(vl_api_macip_acl_interface_add_del_reply_t, 1)
vl_msg_name(vl_api_macip_acl_dump_t, 1)
vl_msg_name(vl_api_macip_acl_details_t, 1)
vl_msg_name(vl_api_macip_acl_interface_get_t, 1)
vl_msg_name(vl_api_macip_acl_interface_get_reply_t, 1)
vl_msg_name(vl_api_macip_acl_interface_list_dump_t, 1)
vl_msg_name(vl_api_macip_acl_interface_list_details_t, 1)
vl_msg_name(vl_api_acl_interface_set_etype_whitelist_t, 1)
vl_msg_name(vl_api_acl_interface_set_etype_whitelist_reply_t, 1)
vl_msg_name(vl_api_acl_interface_etype_whitelist_dump_t, 1)
vl_msg_name(vl_api_acl_interface_etype_whitelist_details_t, 1)
vl_msg_name(vl_api_acl_stats_intf_counters_enable_t, 1)
vl_msg_name(vl_api_acl_stats_intf_counters_enable_reply_t, 1)
vl_msg_name(vl_api_acl_plugin_use_hash_lookup_set_t, 1)
vl_msg_name(vl_api_acl_plugin_use_hash_lookup_set_reply_t, 1)
vl_msg_name(vl_api_acl_plugin_use_hash_lookup_get_t, 1)
vl_msg_name(vl_api_acl_plugin_use_hash_lookup_get_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_acl \
_(VL_API_ACL_PLUGIN_GET_VERSION, acl_plugin_get_version, 51077d14) \
_(VL_API_ACL_PLUGIN_GET_VERSION_REPLY, acl_plugin_get_version_reply, 9b32cf86) \
_(VL_API_ACL_PLUGIN_CONTROL_PING, acl_plugin_control_ping, 51077d14) \
_(VL_API_ACL_PLUGIN_CONTROL_PING_REPLY, acl_plugin_control_ping_reply, f6b0b8ca) \
_(VL_API_ACL_PLUGIN_GET_CONN_TABLE_MAX_ENTRIES, acl_plugin_get_conn_table_max_entries, 51077d14) \
_(VL_API_ACL_PLUGIN_GET_CONN_TABLE_MAX_ENTRIES_REPLY, acl_plugin_get_conn_table_max_entries_reply, 7a096d3d) \
_(VL_API_ACL_ADD_REPLACE, acl_add_replace, ee5c2f18) \
_(VL_API_ACL_ADD_REPLACE_REPLY, acl_add_replace_reply, ac407b0c) \
_(VL_API_ACL_DEL, acl_del, ef34fea4) \
_(VL_API_ACL_DEL_REPLY, acl_del_reply, e8d4e804) \
_(VL_API_ACL_INTERFACE_ADD_DEL, acl_interface_add_del, 4b54bebd) \
_(VL_API_ACL_INTERFACE_ADD_DEL_REPLY, acl_interface_add_del_reply, e8d4e804) \
_(VL_API_ACL_INTERFACE_SET_ACL_LIST, acl_interface_set_acl_list, 473982bd) \
_(VL_API_ACL_INTERFACE_SET_ACL_LIST_REPLY, acl_interface_set_acl_list_reply, e8d4e804) \
_(VL_API_ACL_DUMP, acl_dump, ef34fea4) \
_(VL_API_ACL_DETAILS, acl_details, 95babae0) \
_(VL_API_ACL_INTERFACE_LIST_DUMP, acl_interface_list_dump, f9e6675e) \
_(VL_API_ACL_INTERFACE_LIST_DETAILS, acl_interface_list_details, e695d256) \
_(VL_API_MACIP_ACL_ADD, macip_acl_add, ce6fbad0) \
_(VL_API_MACIP_ACL_ADD_REPLY, macip_acl_add_reply, ac407b0c) \
_(VL_API_MACIP_ACL_ADD_REPLACE, macip_acl_add_replace, 2a461dd4) \
_(VL_API_MACIP_ACL_ADD_REPLACE_REPLY, macip_acl_add_replace_reply, ac407b0c) \
_(VL_API_MACIP_ACL_DEL, macip_acl_del, ef34fea4) \
_(VL_API_MACIP_ACL_DEL_REPLY, macip_acl_del_reply, e8d4e804) \
_(VL_API_MACIP_ACL_INTERFACE_ADD_DEL, macip_acl_interface_add_del, 4b8690b1) \
_(VL_API_MACIP_ACL_INTERFACE_ADD_DEL_REPLY, macip_acl_interface_add_del_reply, e8d4e804) \
_(VL_API_MACIP_ACL_DUMP, macip_acl_dump, ef34fea4) \
_(VL_API_MACIP_ACL_DETAILS, macip_acl_details, 27135b59) \
_(VL_API_MACIP_ACL_INTERFACE_GET, macip_acl_interface_get, 51077d14) \
_(VL_API_MACIP_ACL_INTERFACE_GET_REPLY, macip_acl_interface_get_reply, accf9b05) \
_(VL_API_MACIP_ACL_INTERFACE_LIST_DUMP, macip_acl_interface_list_dump, f9e6675e) \
_(VL_API_MACIP_ACL_INTERFACE_LIST_DETAILS, macip_acl_interface_list_details, a0c5d56d) \
_(VL_API_ACL_INTERFACE_SET_ETYPE_WHITELIST, acl_interface_set_etype_whitelist, 3f5c2d2d) \
_(VL_API_ACL_INTERFACE_SET_ETYPE_WHITELIST_REPLY, acl_interface_set_etype_whitelist_reply, e8d4e804) \
_(VL_API_ACL_INTERFACE_ETYPE_WHITELIST_DUMP, acl_interface_etype_whitelist_dump, f9e6675e) \
_(VL_API_ACL_INTERFACE_ETYPE_WHITELIST_DETAILS, acl_interface_etype_whitelist_details, cc2bfded) \
_(VL_API_ACL_STATS_INTF_COUNTERS_ENABLE, acl_stats_intf_counters_enable, b3e225d2) \
_(VL_API_ACL_STATS_INTF_COUNTERS_ENABLE_REPLY, acl_stats_intf_counters_enable_reply, e8d4e804) \
_(VL_API_ACL_PLUGIN_USE_HASH_LOOKUP_SET, acl_plugin_use_hash_lookup_set, b3e225d2) \
_(VL_API_ACL_PLUGIN_USE_HASH_LOOKUP_SET_REPLY, acl_plugin_use_hash_lookup_set_reply, e8d4e804) \
_(VL_API_ACL_PLUGIN_USE_HASH_LOOKUP_GET, acl_plugin_use_hash_lookup_get, 51077d14) \
_(VL_API_ACL_PLUGIN_USE_HASH_LOOKUP_GET_REPLY, acl_plugin_use_hash_lookup_get_reply, 5392ad31) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "acl.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_acl_printfun_types
#define included_acl_printfun_types


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_acl_printfun
#define included_acl_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "acl.api_tojson.h"
#include "acl.api_fromjson.h"

static inline u8 *vl_api_acl_plugin_get_version_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_acl_plugin_get_version_t *a = va_arg (*args, vl_api_acl_plugin_get_version_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_acl_plugin_get_version_t: */
    s = format(s, "vl_api_acl_plugin_get_version_t:");
    return s;
}

static inline u8 *vl_api_acl_plugin_get_version_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_acl_plugin_get_version_reply_t *a = va_arg (*args, vl_api_acl_plugin_get_version_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_acl_plugin_get_version_reply_t: */
    s = format(s, "vl_api_acl_plugin_get_version_reply_t:");
    s = format(s, "\n%Umajor: %u", format_white_space, indent, a->major);
    s = format(s, "\n%Uminor: %u", format_white_space, indent, a->minor);
    return s;
}

static inline u8 *vl_api_acl_plugin_control_ping_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_acl_plugin_control_ping_t *a = va_arg (*args, vl_api_acl_plugin_control_ping_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_acl_plugin_control_ping_t: */
    s = format(s, "vl_api_acl_plugin_control_ping_t:");
    return s;
}

static inline u8 *vl_api_acl_plugin_control_ping_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_acl_plugin_control_ping_reply_t *a = va_arg (*args, vl_api_acl_plugin_control_ping_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_acl_plugin_control_ping_reply_t: */
    s = format(s, "vl_api_acl_plugin_control_ping_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uvpe_pid: %u", format_white_space, indent, a->vpe_pid);
    return s;
}

static inline u8 *vl_api_acl_plugin_get_conn_table_max_entries_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_acl_plugin_get_conn_table_max_entries_t *a = va_arg (*args, vl_api_acl_plugin_get_conn_table_max_entries_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_acl_plugin_get_conn_table_max_entries_t: */
    s = format(s, "vl_api_acl_plugin_get_conn_table_max_entries_t:");
    return s;
}

static inline u8 *vl_api_acl_plugin_get_conn_table_max_entries_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_acl_plugin_get_conn_table_max_entries_reply_t *a = va_arg (*args, vl_api_acl_plugin_get_conn_table_max_entries_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_acl_plugin_get_conn_table_max_entries_reply_t: */
    s = format(s, "vl_api_acl_plugin_get_conn_table_max_entries_reply_t:");
    s = format(s, "\n%Uconn_table_max_entries: %llu", format_white_space, indent, a->conn_table_max_entries);
    return s;
}

static inline u8 *vl_api_acl_add_replace_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_acl_add_replace_t *a = va_arg (*args, vl_api_acl_add_replace_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_acl_add_replace_t: */
    s = format(s, "vl_api_acl_add_replace_t:");
    s = format(s, "\n%Uacl_index: %u", format_white_space, indent, a->acl_index);
    s = format(s, "\n%Utag: %s", format_white_space, indent, a->tag);
    s = format(s, "\n%Ucount: %u", format_white_space, indent, a->count);
    for (i = 0; i < a->count; i++) {
        s = format(s, "\n%Ur: %U",
                   format_white_space, indent, format_vl_api_acl_rule_t, &a->r[i], indent);
    }
    return s;
}

static inline u8 *vl_api_acl_add_replace_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_acl_add_replace_reply_t *a = va_arg (*args, vl_api_acl_add_replace_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_acl_add_replace_reply_t: */
    s = format(s, "vl_api_acl_add_replace_reply_t:");
    s = format(s, "\n%Uacl_index: %u", format_white_space, indent, a->acl_index);
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_acl_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_acl_del_t *a = va_arg (*args, vl_api_acl_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_acl_del_t: */
    s = format(s, "vl_api_acl_del_t:");
    s = format(s, "\n%Uacl_index: %u", format_white_space, indent, a->acl_index);
    return s;
}

static inline u8 *vl_api_acl_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_acl_del_reply_t *a = va_arg (*args, vl_api_acl_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_acl_del_reply_t: */
    s = format(s, "vl_api_acl_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_acl_interface_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_acl_interface_add_del_t *a = va_arg (*args, vl_api_acl_interface_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_acl_interface_add_del_t: */
    s = format(s, "vl_api_acl_interface_add_del_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uis_input: %u", format_white_space, indent, a->is_input);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uacl_index: %u", format_white_space, indent, a->acl_index);
    return s;
}

static inline u8 *vl_api_acl_interface_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_acl_interface_add_del_reply_t *a = va_arg (*args, vl_api_acl_interface_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_acl_interface_add_del_reply_t: */
    s = format(s, "vl_api_acl_interface_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_acl_interface_set_acl_list_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_acl_interface_set_acl_list_t *a = va_arg (*args, vl_api_acl_interface_set_acl_list_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_acl_interface_set_acl_list_t: */
    s = format(s, "vl_api_acl_interface_set_acl_list_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Ucount: %u", format_white_space, indent, a->count);
    s = format(s, "\n%Un_input: %u", format_white_space, indent, a->n_input);
    for (i = 0; i < a->count; i++) {
        s = format(s, "\n%Uacls: %u",
                   format_white_space, indent, a->acls[i]);
    }
    return s;
}

static inline u8 *vl_api_acl_interface_set_acl_list_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_acl_interface_set_acl_list_reply_t *a = va_arg (*args, vl_api_acl_interface_set_acl_list_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_acl_interface_set_acl_list_reply_t: */
    s = format(s, "vl_api_acl_interface_set_acl_list_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_acl_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_acl_dump_t *a = va_arg (*args, vl_api_acl_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_acl_dump_t: */
    s = format(s, "vl_api_acl_dump_t:");
    s = format(s, "\n%Uacl_index: %u", format_white_space, indent, a->acl_index);
    return s;
}

static inline u8 *vl_api_acl_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_acl_details_t *a = va_arg (*args, vl_api_acl_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_acl_details_t: */
    s = format(s, "vl_api_acl_details_t:");
    s = format(s, "\n%Uacl_index: %u", format_white_space, indent, a->acl_index);
    s = format(s, "\n%Utag: %s", format_white_space, indent, a->tag);
    s = format(s, "\n%Ucount: %u", format_white_space, indent, a->count);
    for (i = 0; i < a->count; i++) {
        s = format(s, "\n%Ur: %U",
                   format_white_space, indent, format_vl_api_acl_rule_t, &a->r[i], indent);
    }
    return s;
}

static inline u8 *vl_api_acl_interface_list_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_acl_interface_list_dump_t *a = va_arg (*args, vl_api_acl_interface_list_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_acl_interface_list_dump_t: */
    s = format(s, "vl_api_acl_interface_list_dump_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_acl_interface_list_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_acl_interface_list_details_t *a = va_arg (*args, vl_api_acl_interface_list_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_acl_interface_list_details_t: */
    s = format(s, "vl_api_acl_interface_list_details_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Ucount: %u", format_white_space, indent, a->count);
    s = format(s, "\n%Un_input: %u", format_white_space, indent, a->n_input);
    for (i = 0; i < a->count; i++) {
        s = format(s, "\n%Uacls: %u",
                   format_white_space, indent, a->acls[i]);
    }
    return s;
}

static inline u8 *vl_api_macip_acl_add_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_macip_acl_add_t *a = va_arg (*args, vl_api_macip_acl_add_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_macip_acl_add_t: */
    s = format(s, "vl_api_macip_acl_add_t:");
    s = format(s, "\n%Utag: %s", format_white_space, indent, a->tag);
    s = format(s, "\n%Ucount: %u", format_white_space, indent, a->count);
    for (i = 0; i < a->count; i++) {
        s = format(s, "\n%Ur: %U",
                   format_white_space, indent, format_vl_api_macip_acl_rule_t, &a->r[i], indent);
    }
    return s;
}

static inline u8 *vl_api_macip_acl_add_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_macip_acl_add_reply_t *a = va_arg (*args, vl_api_macip_acl_add_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_macip_acl_add_reply_t: */
    s = format(s, "vl_api_macip_acl_add_reply_t:");
    s = format(s, "\n%Uacl_index: %u", format_white_space, indent, a->acl_index);
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_macip_acl_add_replace_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_macip_acl_add_replace_t *a = va_arg (*args, vl_api_macip_acl_add_replace_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_macip_acl_add_replace_t: */
    s = format(s, "vl_api_macip_acl_add_replace_t:");
    s = format(s, "\n%Uacl_index: %u", format_white_space, indent, a->acl_index);
    s = format(s, "\n%Utag: %s", format_white_space, indent, a->tag);
    s = format(s, "\n%Ucount: %u", format_white_space, indent, a->count);
    for (i = 0; i < a->count; i++) {
        s = format(s, "\n%Ur: %U",
                   format_white_space, indent, format_vl_api_macip_acl_rule_t, &a->r[i], indent);
    }
    return s;
}

static inline u8 *vl_api_macip_acl_add_replace_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_macip_acl_add_replace_reply_t *a = va_arg (*args, vl_api_macip_acl_add_replace_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_macip_acl_add_replace_reply_t: */
    s = format(s, "vl_api_macip_acl_add_replace_reply_t:");
    s = format(s, "\n%Uacl_index: %u", format_white_space, indent, a->acl_index);
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_macip_acl_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_macip_acl_del_t *a = va_arg (*args, vl_api_macip_acl_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_macip_acl_del_t: */
    s = format(s, "vl_api_macip_acl_del_t:");
    s = format(s, "\n%Uacl_index: %u", format_white_space, indent, a->acl_index);
    return s;
}

static inline u8 *vl_api_macip_acl_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_macip_acl_del_reply_t *a = va_arg (*args, vl_api_macip_acl_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_macip_acl_del_reply_t: */
    s = format(s, "vl_api_macip_acl_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_macip_acl_interface_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_macip_acl_interface_add_del_t *a = va_arg (*args, vl_api_macip_acl_interface_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_macip_acl_interface_add_del_t: */
    s = format(s, "vl_api_macip_acl_interface_add_del_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uacl_index: %u", format_white_space, indent, a->acl_index);
    return s;
}

static inline u8 *vl_api_macip_acl_interface_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_macip_acl_interface_add_del_reply_t *a = va_arg (*args, vl_api_macip_acl_interface_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_macip_acl_interface_add_del_reply_t: */
    s = format(s, "vl_api_macip_acl_interface_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_macip_acl_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_macip_acl_dump_t *a = va_arg (*args, vl_api_macip_acl_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_macip_acl_dump_t: */
    s = format(s, "vl_api_macip_acl_dump_t:");
    s = format(s, "\n%Uacl_index: %u", format_white_space, indent, a->acl_index);
    return s;
}

static inline u8 *vl_api_macip_acl_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_macip_acl_details_t *a = va_arg (*args, vl_api_macip_acl_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_macip_acl_details_t: */
    s = format(s, "vl_api_macip_acl_details_t:");
    s = format(s, "\n%Uacl_index: %u", format_white_space, indent, a->acl_index);
    s = format(s, "\n%Utag: %s", format_white_space, indent, a->tag);
    s = format(s, "\n%Ucount: %u", format_white_space, indent, a->count);
    for (i = 0; i < a->count; i++) {
        s = format(s, "\n%Ur: %U",
                   format_white_space, indent, format_vl_api_macip_acl_rule_t, &a->r[i], indent);
    }
    return s;
}

static inline u8 *vl_api_macip_acl_interface_get_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_macip_acl_interface_get_t *a = va_arg (*args, vl_api_macip_acl_interface_get_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_macip_acl_interface_get_t: */
    s = format(s, "vl_api_macip_acl_interface_get_t:");
    return s;
}

static inline u8 *vl_api_macip_acl_interface_get_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_macip_acl_interface_get_reply_t *a = va_arg (*args, vl_api_macip_acl_interface_get_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_macip_acl_interface_get_reply_t: */
    s = format(s, "vl_api_macip_acl_interface_get_reply_t:");
    s = format(s, "\n%Ucount: %u", format_white_space, indent, a->count);
    for (i = 0; i < a->count; i++) {
        s = format(s, "\n%Uacls: %u",
                   format_white_space, indent, a->acls[i]);
    }
    return s;
}

static inline u8 *vl_api_macip_acl_interface_list_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_macip_acl_interface_list_dump_t *a = va_arg (*args, vl_api_macip_acl_interface_list_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_macip_acl_interface_list_dump_t: */
    s = format(s, "vl_api_macip_acl_interface_list_dump_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_macip_acl_interface_list_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_macip_acl_interface_list_details_t *a = va_arg (*args, vl_api_macip_acl_interface_list_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_macip_acl_interface_list_details_t: */
    s = format(s, "vl_api_macip_acl_interface_list_details_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Ucount: %u", format_white_space, indent, a->count);
    for (i = 0; i < a->count; i++) {
        s = format(s, "\n%Uacls: %u",
                   format_white_space, indent, a->acls[i]);
    }
    return s;
}

static inline u8 *vl_api_acl_interface_set_etype_whitelist_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_acl_interface_set_etype_whitelist_t *a = va_arg (*args, vl_api_acl_interface_set_etype_whitelist_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_acl_interface_set_etype_whitelist_t: */
    s = format(s, "vl_api_acl_interface_set_etype_whitelist_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Ucount: %u", format_white_space, indent, a->count);
    s = format(s, "\n%Un_input: %u", format_white_space, indent, a->n_input);
    for (i = 0; i < a->count; i++) {
        s = format(s, "\n%Uwhitelist: %u",
                   format_white_space, indent, a->whitelist[i]);
    }
    return s;
}

static inline u8 *vl_api_acl_interface_set_etype_whitelist_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_acl_interface_set_etype_whitelist_reply_t *a = va_arg (*args, vl_api_acl_interface_set_etype_whitelist_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_acl_interface_set_etype_whitelist_reply_t: */
    s = format(s, "vl_api_acl_interface_set_etype_whitelist_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_acl_interface_etype_whitelist_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_acl_interface_etype_whitelist_dump_t *a = va_arg (*args, vl_api_acl_interface_etype_whitelist_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_acl_interface_etype_whitelist_dump_t: */
    s = format(s, "vl_api_acl_interface_etype_whitelist_dump_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_acl_interface_etype_whitelist_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_acl_interface_etype_whitelist_details_t *a = va_arg (*args, vl_api_acl_interface_etype_whitelist_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_acl_interface_etype_whitelist_details_t: */
    s = format(s, "vl_api_acl_interface_etype_whitelist_details_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Ucount: %u", format_white_space, indent, a->count);
    s = format(s, "\n%Un_input: %u", format_white_space, indent, a->n_input);
    for (i = 0; i < a->count; i++) {
        s = format(s, "\n%Uwhitelist: %u",
                   format_white_space, indent, a->whitelist[i]);
    }
    return s;
}

static inline u8 *vl_api_acl_stats_intf_counters_enable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_acl_stats_intf_counters_enable_t *a = va_arg (*args, vl_api_acl_stats_intf_counters_enable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_acl_stats_intf_counters_enable_t: */
    s = format(s, "vl_api_acl_stats_intf_counters_enable_t:");
    s = format(s, "\n%Uenable: %u", format_white_space, indent, a->enable);
    return s;
}

static inline u8 *vl_api_acl_stats_intf_counters_enable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_acl_stats_intf_counters_enable_reply_t *a = va_arg (*args, vl_api_acl_stats_intf_counters_enable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_acl_stats_intf_counters_enable_reply_t: */
    s = format(s, "vl_api_acl_stats_intf_counters_enable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_acl_plugin_use_hash_lookup_set_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_acl_plugin_use_hash_lookup_set_t *a = va_arg (*args, vl_api_acl_plugin_use_hash_lookup_set_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_acl_plugin_use_hash_lookup_set_t: */
    s = format(s, "vl_api_acl_plugin_use_hash_lookup_set_t:");
    s = format(s, "\n%Uenable: %u", format_white_space, indent, a->enable);
    return s;
}

static inline u8 *vl_api_acl_plugin_use_hash_lookup_set_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_acl_plugin_use_hash_lookup_set_reply_t *a = va_arg (*args, vl_api_acl_plugin_use_hash_lookup_set_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_acl_plugin_use_hash_lookup_set_reply_t: */
    s = format(s, "vl_api_acl_plugin_use_hash_lookup_set_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_acl_plugin_use_hash_lookup_get_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_acl_plugin_use_hash_lookup_get_t *a = va_arg (*args, vl_api_acl_plugin_use_hash_lookup_get_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_acl_plugin_use_hash_lookup_get_t: */
    s = format(s, "vl_api_acl_plugin_use_hash_lookup_get_t:");
    return s;
}

static inline u8 *vl_api_acl_plugin_use_hash_lookup_get_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_acl_plugin_use_hash_lookup_get_reply_t *a = va_arg (*args, vl_api_acl_plugin_use_hash_lookup_get_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_acl_plugin_use_hash_lookup_get_reply_t: */
    s = format(s, "vl_api_acl_plugin_use_hash_lookup_get_reply_t:");
    s = format(s, "\n%Uenable: %u", format_white_space, indent, a->enable);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_acl_endianfun
#define included_acl_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_acl_plugin_get_version_t_endian (vl_api_acl_plugin_get_version_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_acl_plugin_get_version_reply_t_endian (vl_api_acl_plugin_get_version_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->major = clib_net_to_host_u32(a->major);
    a->minor = clib_net_to_host_u32(a->minor);
}

static inline void vl_api_acl_plugin_control_ping_t_endian (vl_api_acl_plugin_control_ping_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_acl_plugin_control_ping_reply_t_endian (vl_api_acl_plugin_control_ping_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    /* a->client_index = a->client_index (no-op) */
    a->vpe_pid = clib_net_to_host_u32(a->vpe_pid);
}

static inline void vl_api_acl_plugin_get_conn_table_max_entries_t_endian (vl_api_acl_plugin_get_conn_table_max_entries_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_acl_plugin_get_conn_table_max_entries_reply_t_endian (vl_api_acl_plugin_get_conn_table_max_entries_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->conn_table_max_entries = clib_net_to_host_u64(a->conn_table_max_entries);
}

static inline void vl_api_acl_add_replace_t_endian (vl_api_acl_add_replace_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->acl_index = clib_net_to_host_u32(a->acl_index);
    /* a->tag = a->tag (no-op) */
    a->count = clib_net_to_host_u32(a->count);
    u32 count = to_net ? clib_net_to_host_u32(a->count) : a->count;
    for (i = 0; i < count; i++) {
        vl_api_acl_rule_t_endian(&a->r[i], to_net);
    }
}

static inline void vl_api_acl_add_replace_reply_t_endian (vl_api_acl_add_replace_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->acl_index = clib_net_to_host_u32(a->acl_index);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_acl_del_t_endian (vl_api_acl_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->acl_index = clib_net_to_host_u32(a->acl_index);
}

static inline void vl_api_acl_del_reply_t_endian (vl_api_acl_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_acl_interface_add_del_t_endian (vl_api_acl_interface_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    /* a->is_input = a->is_input (no-op) */
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    a->acl_index = clib_net_to_host_u32(a->acl_index);
}

static inline void vl_api_acl_interface_add_del_reply_t_endian (vl_api_acl_interface_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_acl_interface_set_acl_list_t_endian (vl_api_acl_interface_set_acl_list_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->count = a->count (no-op) */
    /* a->n_input = a->n_input (no-op) */
    u32 count = a->count;
    ASSERT((u32)count <= (u32)VL_API_MAX_ARRAY_SIZE);
    for (i = 0; i < count; i++) {
        a->acls[i] = clib_net_to_host_u32(a->acls[i]);
    }
}

static inline void vl_api_acl_interface_set_acl_list_reply_t_endian (vl_api_acl_interface_set_acl_list_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_acl_dump_t_endian (vl_api_acl_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->acl_index = clib_net_to_host_u32(a->acl_index);
}

static inline void vl_api_acl_details_t_endian (vl_api_acl_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->acl_index = clib_net_to_host_u32(a->acl_index);
    /* a->tag = a->tag (no-op) */
    a->count = clib_net_to_host_u32(a->count);
    u32 count = to_net ? clib_net_to_host_u32(a->count) : a->count;
    for (i = 0; i < count; i++) {
        vl_api_acl_rule_t_endian(&a->r[i], to_net);
    }
}

static inline void vl_api_acl_interface_list_dump_t_endian (vl_api_acl_interface_list_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_acl_interface_list_details_t_endian (vl_api_acl_interface_list_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->count = a->count (no-op) */
    /* a->n_input = a->n_input (no-op) */
    u32 count = a->count;
    ASSERT((u32)count <= (u32)VL_API_MAX_ARRAY_SIZE);
    for (i = 0; i < count; i++) {
        a->acls[i] = clib_net_to_host_u32(a->acls[i]);
    }
}

static inline void vl_api_macip_acl_add_t_endian (vl_api_macip_acl_add_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->tag = a->tag (no-op) */
    a->count = clib_net_to_host_u32(a->count);
    u32 count = to_net ? clib_net_to_host_u32(a->count) : a->count;
    for (i = 0; i < count; i++) {
        vl_api_macip_acl_rule_t_endian(&a->r[i], to_net);
    }
}

static inline void vl_api_macip_acl_add_reply_t_endian (vl_api_macip_acl_add_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->acl_index = clib_net_to_host_u32(a->acl_index);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_macip_acl_add_replace_t_endian (vl_api_macip_acl_add_replace_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->acl_index = clib_net_to_host_u32(a->acl_index);
    /* a->tag = a->tag (no-op) */
    a->count = clib_net_to_host_u32(a->count);
    u32 count = to_net ? clib_net_to_host_u32(a->count) : a->count;
    for (i = 0; i < count; i++) {
        vl_api_macip_acl_rule_t_endian(&a->r[i], to_net);
    }
}

static inline void vl_api_macip_acl_add_replace_reply_t_endian (vl_api_macip_acl_add_replace_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->acl_index = clib_net_to_host_u32(a->acl_index);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_macip_acl_del_t_endian (vl_api_macip_acl_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->acl_index = clib_net_to_host_u32(a->acl_index);
}

static inline void vl_api_macip_acl_del_reply_t_endian (vl_api_macip_acl_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_macip_acl_interface_add_del_t_endian (vl_api_macip_acl_interface_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    a->acl_index = clib_net_to_host_u32(a->acl_index);
}

static inline void vl_api_macip_acl_interface_add_del_reply_t_endian (vl_api_macip_acl_interface_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_macip_acl_dump_t_endian (vl_api_macip_acl_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->acl_index = clib_net_to_host_u32(a->acl_index);
}

static inline void vl_api_macip_acl_details_t_endian (vl_api_macip_acl_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->acl_index = clib_net_to_host_u32(a->acl_index);
    /* a->tag = a->tag (no-op) */
    a->count = clib_net_to_host_u32(a->count);
    u32 count = to_net ? clib_net_to_host_u32(a->count) : a->count;
    for (i = 0; i < count; i++) {
        vl_api_macip_acl_rule_t_endian(&a->r[i], to_net);
    }
}

static inline void vl_api_macip_acl_interface_get_t_endian (vl_api_macip_acl_interface_get_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_macip_acl_interface_get_reply_t_endian (vl_api_macip_acl_interface_get_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->count = clib_net_to_host_u32(a->count);
    u32 count = to_net ? clib_net_to_host_u32(a->count) : a->count;
    ASSERT((u32)count <= (u32)VL_API_MAX_ARRAY_SIZE);
    for (i = 0; i < count; i++) {
        a->acls[i] = clib_net_to_host_u32(a->acls[i]);
    }
}

static inline void vl_api_macip_acl_interface_list_dump_t_endian (vl_api_macip_acl_interface_list_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_macip_acl_interface_list_details_t_endian (vl_api_macip_acl_interface_list_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->count = a->count (no-op) */
    u32 count = a->count;
    ASSERT((u32)count <= (u32)VL_API_MAX_ARRAY_SIZE);
    for (i = 0; i < count; i++) {
        a->acls[i] = clib_net_to_host_u32(a->acls[i]);
    }
}

static inline void vl_api_acl_interface_set_etype_whitelist_t_endian (vl_api_acl_interface_set_etype_whitelist_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->count = a->count (no-op) */
    /* a->n_input = a->n_input (no-op) */
    u32 count = a->count;
    ASSERT((u32)count <= (u32)VL_API_MAX_ARRAY_SIZE);
    for (i = 0; i < count; i++) {
        a->whitelist[i] = clib_net_to_host_u16(a->whitelist[i]);
    }
}

static inline void vl_api_acl_interface_set_etype_whitelist_reply_t_endian (vl_api_acl_interface_set_etype_whitelist_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_acl_interface_etype_whitelist_dump_t_endian (vl_api_acl_interface_etype_whitelist_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_acl_interface_etype_whitelist_details_t_endian (vl_api_acl_interface_etype_whitelist_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->count = a->count (no-op) */
    /* a->n_input = a->n_input (no-op) */
    u32 count = a->count;
    ASSERT((u32)count <= (u32)VL_API_MAX_ARRAY_SIZE);
    for (i = 0; i < count; i++) {
        a->whitelist[i] = clib_net_to_host_u16(a->whitelist[i]);
    }
}

static inline void vl_api_acl_stats_intf_counters_enable_t_endian (vl_api_acl_stats_intf_counters_enable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->enable = a->enable (no-op) */
}

static inline void vl_api_acl_stats_intf_counters_enable_reply_t_endian (vl_api_acl_stats_intf_counters_enable_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_acl_plugin_use_hash_lookup_set_t_endian (vl_api_acl_plugin_use_hash_lookup_set_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->enable = a->enable (no-op) */
}

static inline void vl_api_acl_plugin_use_hash_lookup_set_reply_t_endian (vl_api_acl_plugin_use_hash_lookup_set_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_acl_plugin_use_hash_lookup_get_t_endian (vl_api_acl_plugin_use_hash_lookup_get_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_acl_plugin_use_hash_lookup_get_reply_t_endian (vl_api_acl_plugin_use_hash_lookup_get_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    /* a->enable = a->enable (no-op) */
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_acl_calcsizefun
#define included_acl_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_acl_plugin_get_version_t_calc_size (vl_api_acl_plugin_get_version_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_acl_plugin_get_version_reply_t_calc_size (vl_api_acl_plugin_get_version_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_acl_plugin_control_ping_t_calc_size (vl_api_acl_plugin_control_ping_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_acl_plugin_control_ping_reply_t_calc_size (vl_api_acl_plugin_control_ping_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_acl_plugin_get_conn_table_max_entries_t_calc_size (vl_api_acl_plugin_get_conn_table_max_entries_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_acl_plugin_get_conn_table_max_entries_reply_t_calc_size (vl_api_acl_plugin_get_conn_table_max_entries_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_acl_add_replace_t_calc_size (vl_api_acl_add_replace_t *a)
{
      return sizeof(*a) + clib_net_to_host_u32(a->count) * sizeof(a->r[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_acl_add_replace_reply_t_calc_size (vl_api_acl_add_replace_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_acl_del_t_calc_size (vl_api_acl_del_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_acl_del_reply_t_calc_size (vl_api_acl_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_acl_interface_add_del_t_calc_size (vl_api_acl_interface_add_del_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_acl_interface_add_del_reply_t_calc_size (vl_api_acl_interface_add_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_acl_interface_set_acl_list_t_calc_size (vl_api_acl_interface_set_acl_list_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) + a->count * sizeof(a->acls[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_acl_interface_set_acl_list_reply_t_calc_size (vl_api_acl_interface_set_acl_list_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_acl_dump_t_calc_size (vl_api_acl_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_acl_details_t_calc_size (vl_api_acl_details_t *a)
{
      return sizeof(*a) + clib_net_to_host_u32(a->count) * sizeof(a->r[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_acl_interface_list_dump_t_calc_size (vl_api_acl_interface_list_dump_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_acl_interface_list_details_t_calc_size (vl_api_acl_interface_list_details_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) + a->count * sizeof(a->acls[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_macip_acl_add_t_calc_size (vl_api_macip_acl_add_t *a)
{
      return sizeof(*a) + clib_net_to_host_u32(a->count) * sizeof(a->r[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_macip_acl_add_reply_t_calc_size (vl_api_macip_acl_add_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_macip_acl_add_replace_t_calc_size (vl_api_macip_acl_add_replace_t *a)
{
      return sizeof(*a) + clib_net_to_host_u32(a->count) * sizeof(a->r[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_macip_acl_add_replace_reply_t_calc_size (vl_api_macip_acl_add_replace_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_macip_acl_del_t_calc_size (vl_api_macip_acl_del_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_macip_acl_del_reply_t_calc_size (vl_api_macip_acl_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_macip_acl_interface_add_del_t_calc_size (vl_api_macip_acl_interface_add_del_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_macip_acl_interface_add_del_reply_t_calc_size (vl_api_macip_acl_interface_add_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_macip_acl_dump_t_calc_size (vl_api_macip_acl_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_macip_acl_details_t_calc_size (vl_api_macip_acl_details_t *a)
{
      return sizeof(*a) + clib_net_to_host_u32(a->count) * sizeof(a->r[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_macip_acl_interface_get_t_calc_size (vl_api_macip_acl_interface_get_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_macip_acl_interface_get_reply_t_calc_size (vl_api_macip_acl_interface_get_reply_t *a)
{
      return sizeof(*a) + clib_net_to_host_u32(a->count) * sizeof(a->acls[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_macip_acl_interface_list_dump_t_calc_size (vl_api_macip_acl_interface_list_dump_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_macip_acl_interface_list_details_t_calc_size (vl_api_macip_acl_interface_list_details_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) + a->count * sizeof(a->acls[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_acl_interface_set_etype_whitelist_t_calc_size (vl_api_acl_interface_set_etype_whitelist_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) + a->count * sizeof(a->whitelist[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_acl_interface_set_etype_whitelist_reply_t_calc_size (vl_api_acl_interface_set_etype_whitelist_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_acl_interface_etype_whitelist_dump_t_calc_size (vl_api_acl_interface_etype_whitelist_dump_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_acl_interface_etype_whitelist_details_t_calc_size (vl_api_acl_interface_etype_whitelist_details_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) + a->count * sizeof(a->whitelist[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_acl_stats_intf_counters_enable_t_calc_size (vl_api_acl_stats_intf_counters_enable_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_acl_stats_intf_counters_enable_reply_t_calc_size (vl_api_acl_stats_intf_counters_enable_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_acl_plugin_use_hash_lookup_set_t_calc_size (vl_api_acl_plugin_use_hash_lookup_set_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_acl_plugin_use_hash_lookup_set_reply_t_calc_size (vl_api_acl_plugin_use_hash_lookup_set_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_acl_plugin_use_hash_lookup_get_t_calc_size (vl_api_acl_plugin_use_hash_lookup_get_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_acl_plugin_use_hash_lookup_get_reply_t_calc_size (vl_api_acl_plugin_use_hash_lookup_get_reply_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(acl.api, 2, 0, 1)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(acl.api, 0x9cde599d)

#endif

