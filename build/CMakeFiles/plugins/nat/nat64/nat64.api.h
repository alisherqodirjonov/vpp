/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: nat64.api
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
#warning no content included from nat64.api
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
#include <nat/lib/nat_types.api.h>
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_NAT64_PLUGIN_ENABLE_DISABLE, vl_api_nat64_plugin_enable_disable_t_handler)
vl_msg_id(VL_API_NAT64_PLUGIN_ENABLE_DISABLE_REPLY, vl_api_nat64_plugin_enable_disable_reply_t_handler)
vl_msg_id(VL_API_NAT64_SET_TIMEOUTS, vl_api_nat64_set_timeouts_t_handler)
vl_msg_id(VL_API_NAT64_SET_TIMEOUTS_REPLY, vl_api_nat64_set_timeouts_reply_t_handler)
vl_msg_id(VL_API_NAT64_GET_TIMEOUTS, vl_api_nat64_get_timeouts_t_handler)
vl_msg_id(VL_API_NAT64_GET_TIMEOUTS_REPLY, vl_api_nat64_get_timeouts_reply_t_handler)
vl_msg_id(VL_API_NAT64_ADD_DEL_POOL_ADDR_RANGE, vl_api_nat64_add_del_pool_addr_range_t_handler)
vl_msg_id(VL_API_NAT64_ADD_DEL_POOL_ADDR_RANGE_REPLY, vl_api_nat64_add_del_pool_addr_range_reply_t_handler)
vl_msg_id(VL_API_NAT64_POOL_ADDR_DUMP, vl_api_nat64_pool_addr_dump_t_handler)
vl_msg_id(VL_API_NAT64_POOL_ADDR_DETAILS, vl_api_nat64_pool_addr_details_t_handler)
vl_msg_id(VL_API_NAT64_ADD_DEL_INTERFACE, vl_api_nat64_add_del_interface_t_handler)
vl_msg_id(VL_API_NAT64_ADD_DEL_INTERFACE_REPLY, vl_api_nat64_add_del_interface_reply_t_handler)
vl_msg_id(VL_API_NAT64_INTERFACE_DUMP, vl_api_nat64_interface_dump_t_handler)
vl_msg_id(VL_API_NAT64_INTERFACE_DETAILS, vl_api_nat64_interface_details_t_handler)
vl_msg_id(VL_API_NAT64_ADD_DEL_STATIC_BIB, vl_api_nat64_add_del_static_bib_t_handler)
vl_msg_id(VL_API_NAT64_ADD_DEL_STATIC_BIB_REPLY, vl_api_nat64_add_del_static_bib_reply_t_handler)
vl_msg_id(VL_API_NAT64_BIB_DUMP, vl_api_nat64_bib_dump_t_handler)
vl_msg_id(VL_API_NAT64_BIB_DETAILS, vl_api_nat64_bib_details_t_handler)
vl_msg_id(VL_API_NAT64_ST_DUMP, vl_api_nat64_st_dump_t_handler)
vl_msg_id(VL_API_NAT64_ST_DETAILS, vl_api_nat64_st_details_t_handler)
vl_msg_id(VL_API_NAT64_ADD_DEL_PREFIX, vl_api_nat64_add_del_prefix_t_handler)
vl_msg_id(VL_API_NAT64_ADD_DEL_PREFIX_REPLY, vl_api_nat64_add_del_prefix_reply_t_handler)
vl_msg_id(VL_API_NAT64_PREFIX_DUMP, vl_api_nat64_prefix_dump_t_handler)
vl_msg_id(VL_API_NAT64_PREFIX_DETAILS, vl_api_nat64_prefix_details_t_handler)
vl_msg_id(VL_API_NAT64_ADD_DEL_INTERFACE_ADDR, vl_api_nat64_add_del_interface_addr_t_handler)
vl_msg_id(VL_API_NAT64_ADD_DEL_INTERFACE_ADDR_REPLY, vl_api_nat64_add_del_interface_addr_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_nat64_plugin_enable_disable_t, 1)
vl_msg_name(vl_api_nat64_plugin_enable_disable_reply_t, 1)
vl_msg_name(vl_api_nat64_set_timeouts_t, 1)
vl_msg_name(vl_api_nat64_set_timeouts_reply_t, 1)
vl_msg_name(vl_api_nat64_get_timeouts_t, 1)
vl_msg_name(vl_api_nat64_get_timeouts_reply_t, 1)
vl_msg_name(vl_api_nat64_add_del_pool_addr_range_t, 1)
vl_msg_name(vl_api_nat64_add_del_pool_addr_range_reply_t, 1)
vl_msg_name(vl_api_nat64_pool_addr_dump_t, 1)
vl_msg_name(vl_api_nat64_pool_addr_details_t, 1)
vl_msg_name(vl_api_nat64_add_del_interface_t, 1)
vl_msg_name(vl_api_nat64_add_del_interface_reply_t, 1)
vl_msg_name(vl_api_nat64_interface_dump_t, 1)
vl_msg_name(vl_api_nat64_interface_details_t, 1)
vl_msg_name(vl_api_nat64_add_del_static_bib_t, 1)
vl_msg_name(vl_api_nat64_add_del_static_bib_reply_t, 1)
vl_msg_name(vl_api_nat64_bib_dump_t, 1)
vl_msg_name(vl_api_nat64_bib_details_t, 1)
vl_msg_name(vl_api_nat64_st_dump_t, 1)
vl_msg_name(vl_api_nat64_st_details_t, 1)
vl_msg_name(vl_api_nat64_add_del_prefix_t, 1)
vl_msg_name(vl_api_nat64_add_del_prefix_reply_t, 1)
vl_msg_name(vl_api_nat64_prefix_dump_t, 1)
vl_msg_name(vl_api_nat64_prefix_details_t, 1)
vl_msg_name(vl_api_nat64_add_del_interface_addr_t, 1)
vl_msg_name(vl_api_nat64_add_del_interface_addr_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_nat64 \
_(VL_API_NAT64_PLUGIN_ENABLE_DISABLE, nat64_plugin_enable_disable, 45948b90) \
_(VL_API_NAT64_PLUGIN_ENABLE_DISABLE_REPLY, nat64_plugin_enable_disable_reply, e8d4e804) \
_(VL_API_NAT64_SET_TIMEOUTS, nat64_set_timeouts, d4746b16) \
_(VL_API_NAT64_SET_TIMEOUTS_REPLY, nat64_set_timeouts_reply, e8d4e804) \
_(VL_API_NAT64_GET_TIMEOUTS, nat64_get_timeouts, 51077d14) \
_(VL_API_NAT64_GET_TIMEOUTS_REPLY, nat64_get_timeouts_reply, 3c4df4e1) \
_(VL_API_NAT64_ADD_DEL_POOL_ADDR_RANGE, nat64_add_del_pool_addr_range, a3b944e3) \
_(VL_API_NAT64_ADD_DEL_POOL_ADDR_RANGE_REPLY, nat64_add_del_pool_addr_range_reply, e8d4e804) \
_(VL_API_NAT64_POOL_ADDR_DUMP, nat64_pool_addr_dump, 51077d14) \
_(VL_API_NAT64_POOL_ADDR_DETAILS, nat64_pool_addr_details, 9bb99cdb) \
_(VL_API_NAT64_ADD_DEL_INTERFACE, nat64_add_del_interface, f3699b83) \
_(VL_API_NAT64_ADD_DEL_INTERFACE_REPLY, nat64_add_del_interface_reply, e8d4e804) \
_(VL_API_NAT64_INTERFACE_DUMP, nat64_interface_dump, 51077d14) \
_(VL_API_NAT64_INTERFACE_DETAILS, nat64_interface_details, 5d286289) \
_(VL_API_NAT64_ADD_DEL_STATIC_BIB, nat64_add_del_static_bib, 1c404de5) \
_(VL_API_NAT64_ADD_DEL_STATIC_BIB_REPLY, nat64_add_del_static_bib_reply, e8d4e804) \
_(VL_API_NAT64_BIB_DUMP, nat64_bib_dump, cfcb6b75) \
_(VL_API_NAT64_BIB_DETAILS, nat64_bib_details, 43bc3ddf) \
_(VL_API_NAT64_ST_DUMP, nat64_st_dump, cfcb6b75) \
_(VL_API_NAT64_ST_DETAILS, nat64_st_details, dd3361ed) \
_(VL_API_NAT64_ADD_DEL_PREFIX, nat64_add_del_prefix, 727b2f4c) \
_(VL_API_NAT64_ADD_DEL_PREFIX_REPLY, nat64_add_del_prefix_reply, e8d4e804) \
_(VL_API_NAT64_PREFIX_DUMP, nat64_prefix_dump, 51077d14) \
_(VL_API_NAT64_PREFIX_DETAILS, nat64_prefix_details, 20568de3) \
_(VL_API_NAT64_ADD_DEL_INTERFACE_ADDR, nat64_add_del_interface_addr, 47d6e753) \
_(VL_API_NAT64_ADD_DEL_INTERFACE_ADDR_REPLY, nat64_add_del_interface_addr_reply, e8d4e804) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "nat64.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_nat64_printfun_types
#define included_nat64_printfun_types


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_nat64_printfun
#define included_nat64_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "nat64.api_tojson.h"
#include "nat64.api_fromjson.h"

static inline u8 *vl_api_nat64_plugin_enable_disable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat64_plugin_enable_disable_t *a = va_arg (*args, vl_api_nat64_plugin_enable_disable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat64_plugin_enable_disable_t: */
    s = format(s, "vl_api_nat64_plugin_enable_disable_t:");
    s = format(s, "\n%Ubib_buckets: %u", format_white_space, indent, a->bib_buckets);
    s = format(s, "\n%Ubib_memory_size: %u", format_white_space, indent, a->bib_memory_size);
    s = format(s, "\n%Ust_buckets: %u", format_white_space, indent, a->st_buckets);
    s = format(s, "\n%Ust_memory_size: %u", format_white_space, indent, a->st_memory_size);
    s = format(s, "\n%Uenable: %u", format_white_space, indent, a->enable);
    return s;
}

static inline u8 *vl_api_nat64_plugin_enable_disable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat64_plugin_enable_disable_reply_t *a = va_arg (*args, vl_api_nat64_plugin_enable_disable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat64_plugin_enable_disable_reply_t: */
    s = format(s, "vl_api_nat64_plugin_enable_disable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat64_set_timeouts_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat64_set_timeouts_t *a = va_arg (*args, vl_api_nat64_set_timeouts_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat64_set_timeouts_t: */
    s = format(s, "vl_api_nat64_set_timeouts_t:");
    s = format(s, "\n%Uudp: %u", format_white_space, indent, a->udp);
    s = format(s, "\n%Utcp_established: %u", format_white_space, indent, a->tcp_established);
    s = format(s, "\n%Utcp_transitory: %u", format_white_space, indent, a->tcp_transitory);
    s = format(s, "\n%Uicmp: %u", format_white_space, indent, a->icmp);
    return s;
}

static inline u8 *vl_api_nat64_set_timeouts_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat64_set_timeouts_reply_t *a = va_arg (*args, vl_api_nat64_set_timeouts_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat64_set_timeouts_reply_t: */
    s = format(s, "vl_api_nat64_set_timeouts_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat64_get_timeouts_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat64_get_timeouts_t *a = va_arg (*args, vl_api_nat64_get_timeouts_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat64_get_timeouts_t: */
    s = format(s, "vl_api_nat64_get_timeouts_t:");
    return s;
}

static inline u8 *vl_api_nat64_get_timeouts_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat64_get_timeouts_reply_t *a = va_arg (*args, vl_api_nat64_get_timeouts_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat64_get_timeouts_reply_t: */
    s = format(s, "vl_api_nat64_get_timeouts_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uudp: %u", format_white_space, indent, a->udp);
    s = format(s, "\n%Utcp_established: %u", format_white_space, indent, a->tcp_established);
    s = format(s, "\n%Utcp_transitory: %u", format_white_space, indent, a->tcp_transitory);
    s = format(s, "\n%Uicmp: %u", format_white_space, indent, a->icmp);
    return s;
}

static inline u8 *vl_api_nat64_add_del_pool_addr_range_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat64_add_del_pool_addr_range_t *a = va_arg (*args, vl_api_nat64_add_del_pool_addr_range_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat64_add_del_pool_addr_range_t: */
    s = format(s, "vl_api_nat64_add_del_pool_addr_range_t:");
    s = format(s, "\n%Ustart_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->start_addr, indent);
    s = format(s, "\n%Uend_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->end_addr, indent);
    s = format(s, "\n%Uvrf_id: %u", format_white_space, indent, a->vrf_id);
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    return s;
}

static inline u8 *vl_api_nat64_add_del_pool_addr_range_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat64_add_del_pool_addr_range_reply_t *a = va_arg (*args, vl_api_nat64_add_del_pool_addr_range_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat64_add_del_pool_addr_range_reply_t: */
    s = format(s, "vl_api_nat64_add_del_pool_addr_range_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat64_pool_addr_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat64_pool_addr_dump_t *a = va_arg (*args, vl_api_nat64_pool_addr_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat64_pool_addr_dump_t: */
    s = format(s, "vl_api_nat64_pool_addr_dump_t:");
    return s;
}

static inline u8 *vl_api_nat64_pool_addr_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat64_pool_addr_details_t *a = va_arg (*args, vl_api_nat64_pool_addr_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat64_pool_addr_details_t: */
    s = format(s, "vl_api_nat64_pool_addr_details_t:");
    s = format(s, "\n%Uaddress: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->address, indent);
    s = format(s, "\n%Uvrf_id: %u", format_white_space, indent, a->vrf_id);
    return s;
}

static inline u8 *vl_api_nat64_add_del_interface_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat64_add_del_interface_t *a = va_arg (*args, vl_api_nat64_add_del_interface_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat64_add_del_interface_t: */
    s = format(s, "vl_api_nat64_add_del_interface_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_nat_config_flags_t, &a->flags, indent);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_nat64_add_del_interface_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat64_add_del_interface_reply_t *a = va_arg (*args, vl_api_nat64_add_del_interface_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat64_add_del_interface_reply_t: */
    s = format(s, "vl_api_nat64_add_del_interface_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat64_interface_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat64_interface_dump_t *a = va_arg (*args, vl_api_nat64_interface_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat64_interface_dump_t: */
    s = format(s, "vl_api_nat64_interface_dump_t:");
    return s;
}

static inline u8 *vl_api_nat64_interface_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat64_interface_details_t *a = va_arg (*args, vl_api_nat64_interface_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat64_interface_details_t: */
    s = format(s, "vl_api_nat64_interface_details_t:");
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_nat_config_flags_t, &a->flags, indent);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_nat64_add_del_static_bib_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat64_add_del_static_bib_t *a = va_arg (*args, vl_api_nat64_add_del_static_bib_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat64_add_del_static_bib_t: */
    s = format(s, "vl_api_nat64_add_del_static_bib_t:");
    s = format(s, "\n%Ui_addr: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->i_addr, indent);
    s = format(s, "\n%Uo_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->o_addr, indent);
    s = format(s, "\n%Ui_port: %u", format_white_space, indent, a->i_port);
    s = format(s, "\n%Uo_port: %u", format_white_space, indent, a->o_port);
    s = format(s, "\n%Uvrf_id: %u", format_white_space, indent, a->vrf_id);
    s = format(s, "\n%Uproto: %u", format_white_space, indent, a->proto);
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    return s;
}

static inline u8 *vl_api_nat64_add_del_static_bib_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat64_add_del_static_bib_reply_t *a = va_arg (*args, vl_api_nat64_add_del_static_bib_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat64_add_del_static_bib_reply_t: */
    s = format(s, "vl_api_nat64_add_del_static_bib_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat64_bib_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat64_bib_dump_t *a = va_arg (*args, vl_api_nat64_bib_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat64_bib_dump_t: */
    s = format(s, "vl_api_nat64_bib_dump_t:");
    s = format(s, "\n%Uproto: %u", format_white_space, indent, a->proto);
    return s;
}

static inline u8 *vl_api_nat64_bib_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat64_bib_details_t *a = va_arg (*args, vl_api_nat64_bib_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat64_bib_details_t: */
    s = format(s, "vl_api_nat64_bib_details_t:");
    s = format(s, "\n%Ui_addr: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->i_addr, indent);
    s = format(s, "\n%Uo_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->o_addr, indent);
    s = format(s, "\n%Ui_port: %u", format_white_space, indent, a->i_port);
    s = format(s, "\n%Uo_port: %u", format_white_space, indent, a->o_port);
    s = format(s, "\n%Uvrf_id: %u", format_white_space, indent, a->vrf_id);
    s = format(s, "\n%Uproto: %u", format_white_space, indent, a->proto);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_nat_config_flags_t, &a->flags, indent);
    s = format(s, "\n%Uses_num: %u", format_white_space, indent, a->ses_num);
    return s;
}

static inline u8 *vl_api_nat64_st_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat64_st_dump_t *a = va_arg (*args, vl_api_nat64_st_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat64_st_dump_t: */
    s = format(s, "vl_api_nat64_st_dump_t:");
    s = format(s, "\n%Uproto: %u", format_white_space, indent, a->proto);
    return s;
}

static inline u8 *vl_api_nat64_st_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat64_st_details_t *a = va_arg (*args, vl_api_nat64_st_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat64_st_details_t: */
    s = format(s, "vl_api_nat64_st_details_t:");
    s = format(s, "\n%Uil_addr: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->il_addr, indent);
    s = format(s, "\n%Uol_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ol_addr, indent);
    s = format(s, "\n%Uil_port: %u", format_white_space, indent, a->il_port);
    s = format(s, "\n%Uol_port: %u", format_white_space, indent, a->ol_port);
    s = format(s, "\n%Uir_addr: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->ir_addr, indent);
    s = format(s, "\n%Uor_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->or_addr, indent);
    s = format(s, "\n%Ur_port: %u", format_white_space, indent, a->r_port);
    s = format(s, "\n%Uvrf_id: %u", format_white_space, indent, a->vrf_id);
    s = format(s, "\n%Uproto: %u", format_white_space, indent, a->proto);
    return s;
}

static inline u8 *vl_api_nat64_add_del_prefix_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat64_add_del_prefix_t *a = va_arg (*args, vl_api_nat64_add_del_prefix_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat64_add_del_prefix_t: */
    s = format(s, "vl_api_nat64_add_del_prefix_t:");
    s = format(s, "\n%Uprefix: %U", format_white_space, indent, format_vl_api_ip6_prefix_t, &a->prefix, indent);
    s = format(s, "\n%Uvrf_id: %u", format_white_space, indent, a->vrf_id);
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    return s;
}

static inline u8 *vl_api_nat64_add_del_prefix_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat64_add_del_prefix_reply_t *a = va_arg (*args, vl_api_nat64_add_del_prefix_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat64_add_del_prefix_reply_t: */
    s = format(s, "vl_api_nat64_add_del_prefix_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat64_prefix_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat64_prefix_dump_t *a = va_arg (*args, vl_api_nat64_prefix_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat64_prefix_dump_t: */
    s = format(s, "vl_api_nat64_prefix_dump_t:");
    return s;
}

static inline u8 *vl_api_nat64_prefix_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat64_prefix_details_t *a = va_arg (*args, vl_api_nat64_prefix_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat64_prefix_details_t: */
    s = format(s, "vl_api_nat64_prefix_details_t:");
    s = format(s, "\n%Uprefix: %U", format_white_space, indent, format_vl_api_ip6_prefix_t, &a->prefix, indent);
    s = format(s, "\n%Uvrf_id: %u", format_white_space, indent, a->vrf_id);
    return s;
}

static inline u8 *vl_api_nat64_add_del_interface_addr_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat64_add_del_interface_addr_t *a = va_arg (*args, vl_api_nat64_add_del_interface_addr_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat64_add_del_interface_addr_t: */
    s = format(s, "vl_api_nat64_add_del_interface_addr_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_nat64_add_del_interface_addr_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat64_add_del_interface_addr_reply_t *a = va_arg (*args, vl_api_nat64_add_del_interface_addr_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat64_add_del_interface_addr_reply_t: */
    s = format(s, "vl_api_nat64_add_del_interface_addr_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_nat64_endianfun
#define included_nat64_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_nat64_plugin_enable_disable_t_endian (vl_api_nat64_plugin_enable_disable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->bib_buckets = clib_net_to_host_u32(a->bib_buckets);
    a->bib_memory_size = clib_net_to_host_u32(a->bib_memory_size);
    a->st_buckets = clib_net_to_host_u32(a->st_buckets);
    a->st_memory_size = clib_net_to_host_u32(a->st_memory_size);
    /* a->enable = a->enable (no-op) */
}

static inline void vl_api_nat64_plugin_enable_disable_reply_t_endian (vl_api_nat64_plugin_enable_disable_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat64_set_timeouts_t_endian (vl_api_nat64_set_timeouts_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->udp = clib_net_to_host_u32(a->udp);
    a->tcp_established = clib_net_to_host_u32(a->tcp_established);
    a->tcp_transitory = clib_net_to_host_u32(a->tcp_transitory);
    a->icmp = clib_net_to_host_u32(a->icmp);
}

static inline void vl_api_nat64_set_timeouts_reply_t_endian (vl_api_nat64_set_timeouts_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat64_get_timeouts_t_endian (vl_api_nat64_get_timeouts_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_nat64_get_timeouts_reply_t_endian (vl_api_nat64_get_timeouts_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->udp = clib_net_to_host_u32(a->udp);
    a->tcp_established = clib_net_to_host_u32(a->tcp_established);
    a->tcp_transitory = clib_net_to_host_u32(a->tcp_transitory);
    a->icmp = clib_net_to_host_u32(a->icmp);
}

static inline void vl_api_nat64_add_del_pool_addr_range_t_endian (vl_api_nat64_add_del_pool_addr_range_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->start_addr, to_net);
    vl_api_ip4_address_t_endian(&a->end_addr, to_net);
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
    /* a->is_add = a->is_add (no-op) */
}

static inline void vl_api_nat64_add_del_pool_addr_range_reply_t_endian (vl_api_nat64_add_del_pool_addr_range_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat64_pool_addr_dump_t_endian (vl_api_nat64_pool_addr_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_nat64_pool_addr_details_t_endian (vl_api_nat64_pool_addr_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->address, to_net);
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
}

static inline void vl_api_nat64_add_del_interface_t_endian (vl_api_nat64_add_del_interface_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_nat_config_flags_t_endian(&a->flags, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_nat64_add_del_interface_reply_t_endian (vl_api_nat64_add_del_interface_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat64_interface_dump_t_endian (vl_api_nat64_interface_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_nat64_interface_details_t_endian (vl_api_nat64_interface_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_nat_config_flags_t_endian(&a->flags, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_nat64_add_del_static_bib_t_endian (vl_api_nat64_add_del_static_bib_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip6_address_t_endian(&a->i_addr, to_net);
    vl_api_ip4_address_t_endian(&a->o_addr, to_net);
    a->i_port = clib_net_to_host_u16(a->i_port);
    a->o_port = clib_net_to_host_u16(a->o_port);
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
    /* a->proto = a->proto (no-op) */
    /* a->is_add = a->is_add (no-op) */
}

static inline void vl_api_nat64_add_del_static_bib_reply_t_endian (vl_api_nat64_add_del_static_bib_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat64_bib_dump_t_endian (vl_api_nat64_bib_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->proto = a->proto (no-op) */
}

static inline void vl_api_nat64_bib_details_t_endian (vl_api_nat64_bib_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip6_address_t_endian(&a->i_addr, to_net);
    vl_api_ip4_address_t_endian(&a->o_addr, to_net);
    a->i_port = clib_net_to_host_u16(a->i_port);
    a->o_port = clib_net_to_host_u16(a->o_port);
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
    /* a->proto = a->proto (no-op) */
    vl_api_nat_config_flags_t_endian(&a->flags, to_net);
    a->ses_num = clib_net_to_host_u32(a->ses_num);
}

static inline void vl_api_nat64_st_dump_t_endian (vl_api_nat64_st_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->proto = a->proto (no-op) */
}

static inline void vl_api_nat64_st_details_t_endian (vl_api_nat64_st_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip6_address_t_endian(&a->il_addr, to_net);
    vl_api_ip4_address_t_endian(&a->ol_addr, to_net);
    a->il_port = clib_net_to_host_u16(a->il_port);
    a->ol_port = clib_net_to_host_u16(a->ol_port);
    vl_api_ip6_address_t_endian(&a->ir_addr, to_net);
    vl_api_ip4_address_t_endian(&a->or_addr, to_net);
    a->r_port = clib_net_to_host_u16(a->r_port);
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
    /* a->proto = a->proto (no-op) */
}

static inline void vl_api_nat64_add_del_prefix_t_endian (vl_api_nat64_add_del_prefix_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip6_prefix_t_endian(&a->prefix, to_net);
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
    /* a->is_add = a->is_add (no-op) */
}

static inline void vl_api_nat64_add_del_prefix_reply_t_endian (vl_api_nat64_add_del_prefix_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat64_prefix_dump_t_endian (vl_api_nat64_prefix_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_nat64_prefix_details_t_endian (vl_api_nat64_prefix_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip6_prefix_t_endian(&a->prefix, to_net);
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
}

static inline void vl_api_nat64_add_del_interface_addr_t_endian (vl_api_nat64_add_del_interface_addr_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_nat64_add_del_interface_addr_reply_t_endian (vl_api_nat64_add_del_interface_addr_reply_t *a, bool to_net)
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
#ifndef included_nat64_calcsizefun
#define included_nat64_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_nat64_plugin_enable_disable_t_calc_size (vl_api_nat64_plugin_enable_disable_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat64_plugin_enable_disable_reply_t_calc_size (vl_api_nat64_plugin_enable_disable_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat64_set_timeouts_t_calc_size (vl_api_nat64_set_timeouts_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat64_set_timeouts_reply_t_calc_size (vl_api_nat64_set_timeouts_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat64_get_timeouts_t_calc_size (vl_api_nat64_get_timeouts_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat64_get_timeouts_reply_t_calc_size (vl_api_nat64_get_timeouts_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat64_add_del_pool_addr_range_t_calc_size (vl_api_nat64_add_del_pool_addr_range_t *a)
{
      return sizeof(*a) - sizeof(a->start_addr) + vl_api_ip4_address_t_calc_size(&a->start_addr) - sizeof(a->end_addr) + vl_api_ip4_address_t_calc_size(&a->end_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat64_add_del_pool_addr_range_reply_t_calc_size (vl_api_nat64_add_del_pool_addr_range_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat64_pool_addr_dump_t_calc_size (vl_api_nat64_pool_addr_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat64_pool_addr_details_t_calc_size (vl_api_nat64_pool_addr_details_t *a)
{
      return sizeof(*a) - sizeof(a->address) + vl_api_ip4_address_t_calc_size(&a->address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat64_add_del_interface_t_calc_size (vl_api_nat64_add_del_interface_t *a)
{
      return sizeof(*a) - sizeof(a->flags) + vl_api_nat_config_flags_t_calc_size(&a->flags) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat64_add_del_interface_reply_t_calc_size (vl_api_nat64_add_del_interface_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat64_interface_dump_t_calc_size (vl_api_nat64_interface_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat64_interface_details_t_calc_size (vl_api_nat64_interface_details_t *a)
{
      return sizeof(*a) - sizeof(a->flags) + vl_api_nat_config_flags_t_calc_size(&a->flags) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat64_add_del_static_bib_t_calc_size (vl_api_nat64_add_del_static_bib_t *a)
{
      return sizeof(*a) - sizeof(a->i_addr) + vl_api_ip6_address_t_calc_size(&a->i_addr) - sizeof(a->o_addr) + vl_api_ip4_address_t_calc_size(&a->o_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat64_add_del_static_bib_reply_t_calc_size (vl_api_nat64_add_del_static_bib_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat64_bib_dump_t_calc_size (vl_api_nat64_bib_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat64_bib_details_t_calc_size (vl_api_nat64_bib_details_t *a)
{
      return sizeof(*a) - sizeof(a->i_addr) + vl_api_ip6_address_t_calc_size(&a->i_addr) - sizeof(a->o_addr) + vl_api_ip4_address_t_calc_size(&a->o_addr) - sizeof(a->flags) + vl_api_nat_config_flags_t_calc_size(&a->flags);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat64_st_dump_t_calc_size (vl_api_nat64_st_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat64_st_details_t_calc_size (vl_api_nat64_st_details_t *a)
{
      return sizeof(*a) - sizeof(a->il_addr) + vl_api_ip6_address_t_calc_size(&a->il_addr) - sizeof(a->ol_addr) + vl_api_ip4_address_t_calc_size(&a->ol_addr) - sizeof(a->ir_addr) + vl_api_ip6_address_t_calc_size(&a->ir_addr) - sizeof(a->or_addr) + vl_api_ip4_address_t_calc_size(&a->or_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat64_add_del_prefix_t_calc_size (vl_api_nat64_add_del_prefix_t *a)
{
      return sizeof(*a) - sizeof(a->prefix) + vl_api_ip6_prefix_t_calc_size(&a->prefix);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat64_add_del_prefix_reply_t_calc_size (vl_api_nat64_add_del_prefix_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat64_prefix_dump_t_calc_size (vl_api_nat64_prefix_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat64_prefix_details_t_calc_size (vl_api_nat64_prefix_details_t *a)
{
      return sizeof(*a) - sizeof(a->prefix) + vl_api_ip6_prefix_t_calc_size(&a->prefix);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat64_add_del_interface_addr_t_calc_size (vl_api_nat64_add_del_interface_addr_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat64_add_del_interface_addr_reply_t_calc_size (vl_api_nat64_add_del_interface_addr_reply_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(nat64.api, 1, 0, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(nat64.api, 0xb1b82fcf)

#endif

