/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: lisp.api
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
#warning no content included from lisp.api
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
#include <lisp/lisp-cp/lisp_types.api.h>
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_LISP_ADD_DEL_LOCATOR_SET, vl_api_lisp_add_del_locator_set_t_handler)
vl_msg_id(VL_API_LISP_ADD_DEL_LOCATOR_SET_REPLY, vl_api_lisp_add_del_locator_set_reply_t_handler)
vl_msg_id(VL_API_LISP_ADD_DEL_LOCATOR, vl_api_lisp_add_del_locator_t_handler)
vl_msg_id(VL_API_LISP_ADD_DEL_LOCATOR_REPLY, vl_api_lisp_add_del_locator_reply_t_handler)
vl_msg_id(VL_API_LISP_ADD_DEL_LOCAL_EID, vl_api_lisp_add_del_local_eid_t_handler)
vl_msg_id(VL_API_LISP_ADD_DEL_LOCAL_EID_REPLY, vl_api_lisp_add_del_local_eid_reply_t_handler)
vl_msg_id(VL_API_LISP_ADD_DEL_MAP_SERVER, vl_api_lisp_add_del_map_server_t_handler)
vl_msg_id(VL_API_LISP_ADD_DEL_MAP_SERVER_REPLY, vl_api_lisp_add_del_map_server_reply_t_handler)
vl_msg_id(VL_API_LISP_ADD_DEL_MAP_RESOLVER, vl_api_lisp_add_del_map_resolver_t_handler)
vl_msg_id(VL_API_LISP_ADD_DEL_MAP_RESOLVER_REPLY, vl_api_lisp_add_del_map_resolver_reply_t_handler)
vl_msg_id(VL_API_LISP_ENABLE_DISABLE, vl_api_lisp_enable_disable_t_handler)
vl_msg_id(VL_API_LISP_ENABLE_DISABLE_REPLY, vl_api_lisp_enable_disable_reply_t_handler)
vl_msg_id(VL_API_LISP_PITR_SET_LOCATOR_SET, vl_api_lisp_pitr_set_locator_set_t_handler)
vl_msg_id(VL_API_LISP_PITR_SET_LOCATOR_SET_REPLY, vl_api_lisp_pitr_set_locator_set_reply_t_handler)
vl_msg_id(VL_API_LISP_USE_PETR, vl_api_lisp_use_petr_t_handler)
vl_msg_id(VL_API_LISP_USE_PETR_REPLY, vl_api_lisp_use_petr_reply_t_handler)
vl_msg_id(VL_API_SHOW_LISP_USE_PETR, vl_api_show_lisp_use_petr_t_handler)
vl_msg_id(VL_API_SHOW_LISP_USE_PETR_REPLY, vl_api_show_lisp_use_petr_reply_t_handler)
vl_msg_id(VL_API_SHOW_LISP_RLOC_PROBE_STATE, vl_api_show_lisp_rloc_probe_state_t_handler)
vl_msg_id(VL_API_SHOW_LISP_RLOC_PROBE_STATE_REPLY, vl_api_show_lisp_rloc_probe_state_reply_t_handler)
vl_msg_id(VL_API_LISP_RLOC_PROBE_ENABLE_DISABLE, vl_api_lisp_rloc_probe_enable_disable_t_handler)
vl_msg_id(VL_API_LISP_RLOC_PROBE_ENABLE_DISABLE_REPLY, vl_api_lisp_rloc_probe_enable_disable_reply_t_handler)
vl_msg_id(VL_API_LISP_MAP_REGISTER_ENABLE_DISABLE, vl_api_lisp_map_register_enable_disable_t_handler)
vl_msg_id(VL_API_LISP_MAP_REGISTER_ENABLE_DISABLE_REPLY, vl_api_lisp_map_register_enable_disable_reply_t_handler)
vl_msg_id(VL_API_SHOW_LISP_MAP_REGISTER_STATE, vl_api_show_lisp_map_register_state_t_handler)
vl_msg_id(VL_API_SHOW_LISP_MAP_REGISTER_STATE_REPLY, vl_api_show_lisp_map_register_state_reply_t_handler)
vl_msg_id(VL_API_LISP_MAP_REQUEST_MODE, vl_api_lisp_map_request_mode_t_handler)
vl_msg_id(VL_API_LISP_MAP_REQUEST_MODE_REPLY, vl_api_lisp_map_request_mode_reply_t_handler)
vl_msg_id(VL_API_SHOW_LISP_MAP_REQUEST_MODE, vl_api_show_lisp_map_request_mode_t_handler)
vl_msg_id(VL_API_SHOW_LISP_MAP_REQUEST_MODE_REPLY, vl_api_show_lisp_map_request_mode_reply_t_handler)
vl_msg_id(VL_API_LISP_ADD_DEL_REMOTE_MAPPING, vl_api_lisp_add_del_remote_mapping_t_handler)
vl_msg_id(VL_API_LISP_ADD_DEL_REMOTE_MAPPING_REPLY, vl_api_lisp_add_del_remote_mapping_reply_t_handler)
vl_msg_id(VL_API_LISP_ADD_DEL_ADJACENCY, vl_api_lisp_add_del_adjacency_t_handler)
vl_msg_id(VL_API_LISP_ADD_DEL_ADJACENCY_REPLY, vl_api_lisp_add_del_adjacency_reply_t_handler)
vl_msg_id(VL_API_LISP_ADD_DEL_MAP_REQUEST_ITR_RLOCS, vl_api_lisp_add_del_map_request_itr_rlocs_t_handler)
vl_msg_id(VL_API_LISP_ADD_DEL_MAP_REQUEST_ITR_RLOCS_REPLY, vl_api_lisp_add_del_map_request_itr_rlocs_reply_t_handler)
vl_msg_id(VL_API_LISP_EID_TABLE_ADD_DEL_MAP, vl_api_lisp_eid_table_add_del_map_t_handler)
vl_msg_id(VL_API_LISP_EID_TABLE_ADD_DEL_MAP_REPLY, vl_api_lisp_eid_table_add_del_map_reply_t_handler)
vl_msg_id(VL_API_LISP_LOCATOR_DUMP, vl_api_lisp_locator_dump_t_handler)
vl_msg_id(VL_API_LISP_LOCATOR_DETAILS, vl_api_lisp_locator_details_t_handler)
vl_msg_id(VL_API_LISP_LOCATOR_SET_DETAILS, vl_api_lisp_locator_set_details_t_handler)
vl_msg_id(VL_API_LISP_LOCATOR_SET_DUMP, vl_api_lisp_locator_set_dump_t_handler)
vl_msg_id(VL_API_LISP_EID_TABLE_DETAILS, vl_api_lisp_eid_table_details_t_handler)
vl_msg_id(VL_API_LISP_EID_TABLE_DUMP, vl_api_lisp_eid_table_dump_t_handler)
vl_msg_id(VL_API_LISP_ADJACENCIES_GET_REPLY, vl_api_lisp_adjacencies_get_reply_t_handler)
vl_msg_id(VL_API_LISP_ADJACENCIES_GET, vl_api_lisp_adjacencies_get_t_handler)
vl_msg_id(VL_API_LISP_EID_TABLE_MAP_DETAILS, vl_api_lisp_eid_table_map_details_t_handler)
vl_msg_id(VL_API_LISP_EID_TABLE_MAP_DUMP, vl_api_lisp_eid_table_map_dump_t_handler)
vl_msg_id(VL_API_LISP_EID_TABLE_VNI_DUMP, vl_api_lisp_eid_table_vni_dump_t_handler)
vl_msg_id(VL_API_LISP_EID_TABLE_VNI_DETAILS, vl_api_lisp_eid_table_vni_details_t_handler)
vl_msg_id(VL_API_LISP_MAP_RESOLVER_DETAILS, vl_api_lisp_map_resolver_details_t_handler)
vl_msg_id(VL_API_LISP_MAP_RESOLVER_DUMP, vl_api_lisp_map_resolver_dump_t_handler)
vl_msg_id(VL_API_LISP_MAP_SERVER_DETAILS, vl_api_lisp_map_server_details_t_handler)
vl_msg_id(VL_API_LISP_MAP_SERVER_DUMP, vl_api_lisp_map_server_dump_t_handler)
vl_msg_id(VL_API_SHOW_LISP_STATUS, vl_api_show_lisp_status_t_handler)
vl_msg_id(VL_API_SHOW_LISP_STATUS_REPLY, vl_api_show_lisp_status_reply_t_handler)
vl_msg_id(VL_API_LISP_GET_MAP_REQUEST_ITR_RLOCS, vl_api_lisp_get_map_request_itr_rlocs_t_handler)
vl_msg_id(VL_API_LISP_GET_MAP_REQUEST_ITR_RLOCS_REPLY, vl_api_lisp_get_map_request_itr_rlocs_reply_t_handler)
vl_msg_id(VL_API_SHOW_LISP_PITR, vl_api_show_lisp_pitr_t_handler)
vl_msg_id(VL_API_SHOW_LISP_PITR_REPLY, vl_api_show_lisp_pitr_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_lisp_add_del_locator_set_t, 1)
vl_msg_name(vl_api_lisp_add_del_locator_set_reply_t, 1)
vl_msg_name(vl_api_lisp_add_del_locator_t, 1)
vl_msg_name(vl_api_lisp_add_del_locator_reply_t, 1)
vl_msg_name(vl_api_lisp_add_del_local_eid_t, 1)
vl_msg_name(vl_api_lisp_add_del_local_eid_reply_t, 1)
vl_msg_name(vl_api_lisp_add_del_map_server_t, 1)
vl_msg_name(vl_api_lisp_add_del_map_server_reply_t, 1)
vl_msg_name(vl_api_lisp_add_del_map_resolver_t, 1)
vl_msg_name(vl_api_lisp_add_del_map_resolver_reply_t, 1)
vl_msg_name(vl_api_lisp_enable_disable_t, 1)
vl_msg_name(vl_api_lisp_enable_disable_reply_t, 1)
vl_msg_name(vl_api_lisp_pitr_set_locator_set_t, 1)
vl_msg_name(vl_api_lisp_pitr_set_locator_set_reply_t, 1)
vl_msg_name(vl_api_lisp_use_petr_t, 1)
vl_msg_name(vl_api_lisp_use_petr_reply_t, 1)
vl_msg_name(vl_api_show_lisp_use_petr_t, 1)
vl_msg_name(vl_api_show_lisp_use_petr_reply_t, 1)
vl_msg_name(vl_api_show_lisp_rloc_probe_state_t, 1)
vl_msg_name(vl_api_show_lisp_rloc_probe_state_reply_t, 1)
vl_msg_name(vl_api_lisp_rloc_probe_enable_disable_t, 1)
vl_msg_name(vl_api_lisp_rloc_probe_enable_disable_reply_t, 1)
vl_msg_name(vl_api_lisp_map_register_enable_disable_t, 1)
vl_msg_name(vl_api_lisp_map_register_enable_disable_reply_t, 1)
vl_msg_name(vl_api_show_lisp_map_register_state_t, 1)
vl_msg_name(vl_api_show_lisp_map_register_state_reply_t, 1)
vl_msg_name(vl_api_lisp_map_request_mode_t, 1)
vl_msg_name(vl_api_lisp_map_request_mode_reply_t, 1)
vl_msg_name(vl_api_show_lisp_map_request_mode_t, 1)
vl_msg_name(vl_api_show_lisp_map_request_mode_reply_t, 1)
vl_msg_name(vl_api_lisp_add_del_remote_mapping_t, 1)
vl_msg_name(vl_api_lisp_add_del_remote_mapping_reply_t, 1)
vl_msg_name(vl_api_lisp_add_del_adjacency_t, 1)
vl_msg_name(vl_api_lisp_add_del_adjacency_reply_t, 1)
vl_msg_name(vl_api_lisp_add_del_map_request_itr_rlocs_t, 1)
vl_msg_name(vl_api_lisp_add_del_map_request_itr_rlocs_reply_t, 1)
vl_msg_name(vl_api_lisp_eid_table_add_del_map_t, 1)
vl_msg_name(vl_api_lisp_eid_table_add_del_map_reply_t, 1)
vl_msg_name(vl_api_lisp_locator_dump_t, 1)
vl_msg_name(vl_api_lisp_locator_details_t, 1)
vl_msg_name(vl_api_lisp_locator_set_details_t, 1)
vl_msg_name(vl_api_lisp_locator_set_dump_t, 1)
vl_msg_name(vl_api_lisp_eid_table_details_t, 1)
vl_msg_name(vl_api_lisp_eid_table_dump_t, 1)
vl_msg_name(vl_api_lisp_adjacencies_get_reply_t, 1)
vl_msg_name(vl_api_lisp_adjacencies_get_t, 1)
vl_msg_name(vl_api_lisp_eid_table_map_details_t, 1)
vl_msg_name(vl_api_lisp_eid_table_map_dump_t, 1)
vl_msg_name(vl_api_lisp_eid_table_vni_dump_t, 1)
vl_msg_name(vl_api_lisp_eid_table_vni_details_t, 1)
vl_msg_name(vl_api_lisp_map_resolver_details_t, 1)
vl_msg_name(vl_api_lisp_map_resolver_dump_t, 1)
vl_msg_name(vl_api_lisp_map_server_details_t, 1)
vl_msg_name(vl_api_lisp_map_server_dump_t, 1)
vl_msg_name(vl_api_show_lisp_status_t, 1)
vl_msg_name(vl_api_show_lisp_status_reply_t, 1)
vl_msg_name(vl_api_lisp_get_map_request_itr_rlocs_t, 1)
vl_msg_name(vl_api_lisp_get_map_request_itr_rlocs_reply_t, 1)
vl_msg_name(vl_api_show_lisp_pitr_t, 1)
vl_msg_name(vl_api_show_lisp_pitr_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_lisp \
_(VL_API_LISP_ADD_DEL_LOCATOR_SET, lisp_add_del_locator_set, 6fcd6471) \
_(VL_API_LISP_ADD_DEL_LOCATOR_SET_REPLY, lisp_add_del_locator_set_reply, b6666db4) \
_(VL_API_LISP_ADD_DEL_LOCATOR, lisp_add_del_locator, af4d8f13) \
_(VL_API_LISP_ADD_DEL_LOCATOR_REPLY, lisp_add_del_locator_reply, e8d4e804) \
_(VL_API_LISP_ADD_DEL_LOCAL_EID, lisp_add_del_local_eid, 4e5a83a2) \
_(VL_API_LISP_ADD_DEL_LOCAL_EID_REPLY, lisp_add_del_local_eid_reply, e8d4e804) \
_(VL_API_LISP_ADD_DEL_MAP_SERVER, lisp_add_del_map_server, ce19e32d) \
_(VL_API_LISP_ADD_DEL_MAP_SERVER_REPLY, lisp_add_del_map_server_reply, e8d4e804) \
_(VL_API_LISP_ADD_DEL_MAP_RESOLVER, lisp_add_del_map_resolver, ce19e32d) \
_(VL_API_LISP_ADD_DEL_MAP_RESOLVER_REPLY, lisp_add_del_map_resolver_reply, e8d4e804) \
_(VL_API_LISP_ENABLE_DISABLE, lisp_enable_disable, c264d7bf) \
_(VL_API_LISP_ENABLE_DISABLE_REPLY, lisp_enable_disable_reply, e8d4e804) \
_(VL_API_LISP_PITR_SET_LOCATOR_SET, lisp_pitr_set_locator_set, 486e2b76) \
_(VL_API_LISP_PITR_SET_LOCATOR_SET_REPLY, lisp_pitr_set_locator_set_reply, e8d4e804) \
_(VL_API_LISP_USE_PETR, lisp_use_petr, d87dbad9) \
_(VL_API_LISP_USE_PETR_REPLY, lisp_use_petr_reply, e8d4e804) \
_(VL_API_SHOW_LISP_USE_PETR, show_lisp_use_petr, 51077d14) \
_(VL_API_SHOW_LISP_USE_PETR_REPLY, show_lisp_use_petr_reply, 22b9a4b0) \
_(VL_API_SHOW_LISP_RLOC_PROBE_STATE, show_lisp_rloc_probe_state, 51077d14) \
_(VL_API_SHOW_LISP_RLOC_PROBE_STATE_REPLY, show_lisp_rloc_probe_state_reply, e33a377b) \
_(VL_API_LISP_RLOC_PROBE_ENABLE_DISABLE, lisp_rloc_probe_enable_disable, c264d7bf) \
_(VL_API_LISP_RLOC_PROBE_ENABLE_DISABLE_REPLY, lisp_rloc_probe_enable_disable_reply, e8d4e804) \
_(VL_API_LISP_MAP_REGISTER_ENABLE_DISABLE, lisp_map_register_enable_disable, c264d7bf) \
_(VL_API_LISP_MAP_REGISTER_ENABLE_DISABLE_REPLY, lisp_map_register_enable_disable_reply, e8d4e804) \
_(VL_API_SHOW_LISP_MAP_REGISTER_STATE, show_lisp_map_register_state, 51077d14) \
_(VL_API_SHOW_LISP_MAP_REGISTER_STATE_REPLY, show_lisp_map_register_state_reply, e33a377b) \
_(VL_API_LISP_MAP_REQUEST_MODE, lisp_map_request_mode, f43c26ae) \
_(VL_API_LISP_MAP_REQUEST_MODE_REPLY, lisp_map_request_mode_reply, e8d4e804) \
_(VL_API_SHOW_LISP_MAP_REQUEST_MODE, show_lisp_map_request_mode, 51077d14) \
_(VL_API_SHOW_LISP_MAP_REQUEST_MODE_REPLY, show_lisp_map_request_mode_reply, 5b05038e) \
_(VL_API_LISP_ADD_DEL_REMOTE_MAPPING, lisp_add_del_remote_mapping, 6d5c789e) \
_(VL_API_LISP_ADD_DEL_REMOTE_MAPPING_REPLY, lisp_add_del_remote_mapping_reply, e8d4e804) \
_(VL_API_LISP_ADD_DEL_ADJACENCY, lisp_add_del_adjacency, 2ce0e6f6) \
_(VL_API_LISP_ADD_DEL_ADJACENCY_REPLY, lisp_add_del_adjacency_reply, e8d4e804) \
_(VL_API_LISP_ADD_DEL_MAP_REQUEST_ITR_RLOCS, lisp_add_del_map_request_itr_rlocs, 6be88e45) \
_(VL_API_LISP_ADD_DEL_MAP_REQUEST_ITR_RLOCS_REPLY, lisp_add_del_map_request_itr_rlocs_reply, e8d4e804) \
_(VL_API_LISP_EID_TABLE_ADD_DEL_MAP, lisp_eid_table_add_del_map, 9481416b) \
_(VL_API_LISP_EID_TABLE_ADD_DEL_MAP_REPLY, lisp_eid_table_add_del_map_reply, e8d4e804) \
_(VL_API_LISP_LOCATOR_DUMP, lisp_locator_dump, b954fad7) \
_(VL_API_LISP_LOCATOR_DETAILS, lisp_locator_details, 2c620ffe) \
_(VL_API_LISP_LOCATOR_SET_DETAILS, lisp_locator_set_details, 5b33a105) \
_(VL_API_LISP_LOCATOR_SET_DUMP, lisp_locator_set_dump, c2cb5922) \
_(VL_API_LISP_EID_TABLE_DETAILS, lisp_eid_table_details, 1c29f792) \
_(VL_API_LISP_EID_TABLE_DUMP, lisp_eid_table_dump, 629468b5) \
_(VL_API_LISP_ADJACENCIES_GET_REPLY, lisp_adjacencies_get_reply, 807257bf) \
_(VL_API_LISP_ADJACENCIES_GET, lisp_adjacencies_get, 8d1f2fe9) \
_(VL_API_LISP_EID_TABLE_MAP_DETAILS, lisp_eid_table_map_details, 0b6859e2) \
_(VL_API_LISP_EID_TABLE_MAP_DUMP, lisp_eid_table_map_dump, d6cf0c3d) \
_(VL_API_LISP_EID_TABLE_VNI_DUMP, lisp_eid_table_vni_dump, 51077d14) \
_(VL_API_LISP_EID_TABLE_VNI_DETAILS, lisp_eid_table_vni_details, 64abc01e) \
_(VL_API_LISP_MAP_RESOLVER_DETAILS, lisp_map_resolver_details, 3e78fc57) \
_(VL_API_LISP_MAP_RESOLVER_DUMP, lisp_map_resolver_dump, 51077d14) \
_(VL_API_LISP_MAP_SERVER_DETAILS, lisp_map_server_details, 3e78fc57) \
_(VL_API_LISP_MAP_SERVER_DUMP, lisp_map_server_dump, 51077d14) \
_(VL_API_SHOW_LISP_STATUS, show_lisp_status, 51077d14) \
_(VL_API_SHOW_LISP_STATUS_REPLY, show_lisp_status_reply, 9e8f10c0) \
_(VL_API_LISP_GET_MAP_REQUEST_ITR_RLOCS, lisp_get_map_request_itr_rlocs, 51077d14) \
_(VL_API_LISP_GET_MAP_REQUEST_ITR_RLOCS_REPLY, lisp_get_map_request_itr_rlocs_reply, 76580f3a) \
_(VL_API_SHOW_LISP_PITR, show_lisp_pitr, 51077d14) \
_(VL_API_SHOW_LISP_PITR_REPLY, show_lisp_pitr_reply, 27aa69b1) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "lisp.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_lisp_printfun_types
#define included_lisp_printfun_types

static inline u8 *format_vl_api_lisp_locator_set_filter_t (u8 *s, va_list * args)
{
    vl_api_lisp_locator_set_filter_t *a = va_arg (*args, vl_api_lisp_locator_set_filter_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "LISP_LOCATOR_SET_FILTER_API_ALL");
    case 1:
        return format(s, "LISP_LOCATOR_SET_FILTER_API_LOCAL");
    case 2:
        return format(s, "LISP_LOCATOR_SET_FILTER_API_REMOTE");
    }
    return s;
}

static inline u8 *format_vl_api_lisp_adjacency_t (u8 *s, va_list * args)
{
    vl_api_lisp_adjacency_t *a = va_arg (*args, vl_api_lisp_adjacency_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Ureid: %U", format_white_space, indent, format_vl_api_eid_t, &a->reid, indent);
    s = format(s, "\n%Uleid: %U", format_white_space, indent, format_vl_api_eid_t, &a->leid, indent);
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_lisp_printfun
#define included_lisp_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "lisp.api_tojson.h"
#include "lisp.api_fromjson.h"

static inline u8 *vl_api_lisp_add_del_locator_set_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_add_del_locator_set_t *a = va_arg (*args, vl_api_lisp_add_del_locator_set_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_add_del_locator_set_t: */
    s = format(s, "vl_api_lisp_add_del_locator_set_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Ulocator_set_name: %s", format_white_space, indent, a->locator_set_name);
    s = format(s, "\n%Ulocator_num: %u", format_white_space, indent, a->locator_num);
    for (i = 0; i < a->locator_num; i++) {
        s = format(s, "\n%Ulocators: %U",
                   format_white_space, indent, format_vl_api_local_locator_t, &a->locators[i], indent);
    }
    return s;
}

static inline u8 *vl_api_lisp_add_del_locator_set_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_add_del_locator_set_reply_t *a = va_arg (*args, vl_api_lisp_add_del_locator_set_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_add_del_locator_set_reply_t: */
    s = format(s, "vl_api_lisp_add_del_locator_set_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uls_index: %u", format_white_space, indent, a->ls_index);
    return s;
}

static inline u8 *vl_api_lisp_add_del_locator_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_add_del_locator_t *a = va_arg (*args, vl_api_lisp_add_del_locator_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_add_del_locator_t: */
    s = format(s, "vl_api_lisp_add_del_locator_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Ulocator_set_name: %s", format_white_space, indent, a->locator_set_name);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Upriority: %u", format_white_space, indent, a->priority);
    s = format(s, "\n%Uweight: %u", format_white_space, indent, a->weight);
    return s;
}

static inline u8 *vl_api_lisp_add_del_locator_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_add_del_locator_reply_t *a = va_arg (*args, vl_api_lisp_add_del_locator_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_add_del_locator_reply_t: */
    s = format(s, "vl_api_lisp_add_del_locator_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_lisp_add_del_local_eid_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_add_del_local_eid_t *a = va_arg (*args, vl_api_lisp_add_del_local_eid_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_add_del_local_eid_t: */
    s = format(s, "vl_api_lisp_add_del_local_eid_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Ueid: %U", format_white_space, indent, format_vl_api_eid_t, &a->eid, indent);
    s = format(s, "\n%Ulocator_set_name: %s", format_white_space, indent, a->locator_set_name);
    s = format(s, "\n%Uvni: %u", format_white_space, indent, a->vni);
    s = format(s, "\n%Ukey: %U", format_white_space, indent, format_vl_api_hmac_key_t, &a->key, indent);
    return s;
}

static inline u8 *vl_api_lisp_add_del_local_eid_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_add_del_local_eid_reply_t *a = va_arg (*args, vl_api_lisp_add_del_local_eid_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_add_del_local_eid_reply_t: */
    s = format(s, "vl_api_lisp_add_del_local_eid_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_lisp_add_del_map_server_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_add_del_map_server_t *a = va_arg (*args, vl_api_lisp_add_del_map_server_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_add_del_map_server_t: */
    s = format(s, "vl_api_lisp_add_del_map_server_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uip_address: %U", format_white_space, indent, format_vl_api_address_t, &a->ip_address, indent);
    return s;
}

static inline u8 *vl_api_lisp_add_del_map_server_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_add_del_map_server_reply_t *a = va_arg (*args, vl_api_lisp_add_del_map_server_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_add_del_map_server_reply_t: */
    s = format(s, "vl_api_lisp_add_del_map_server_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_lisp_add_del_map_resolver_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_add_del_map_resolver_t *a = va_arg (*args, vl_api_lisp_add_del_map_resolver_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_add_del_map_resolver_t: */
    s = format(s, "vl_api_lisp_add_del_map_resolver_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uip_address: %U", format_white_space, indent, format_vl_api_address_t, &a->ip_address, indent);
    return s;
}

static inline u8 *vl_api_lisp_add_del_map_resolver_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_add_del_map_resolver_reply_t *a = va_arg (*args, vl_api_lisp_add_del_map_resolver_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_add_del_map_resolver_reply_t: */
    s = format(s, "vl_api_lisp_add_del_map_resolver_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_lisp_enable_disable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_enable_disable_t *a = va_arg (*args, vl_api_lisp_enable_disable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_enable_disable_t: */
    s = format(s, "vl_api_lisp_enable_disable_t:");
    s = format(s, "\n%Uis_enable: %u", format_white_space, indent, a->is_enable);
    return s;
}

static inline u8 *vl_api_lisp_enable_disable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_enable_disable_reply_t *a = va_arg (*args, vl_api_lisp_enable_disable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_enable_disable_reply_t: */
    s = format(s, "vl_api_lisp_enable_disable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_lisp_pitr_set_locator_set_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_pitr_set_locator_set_t *a = va_arg (*args, vl_api_lisp_pitr_set_locator_set_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_pitr_set_locator_set_t: */
    s = format(s, "vl_api_lisp_pitr_set_locator_set_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uls_name: %s", format_white_space, indent, a->ls_name);
    return s;
}

static inline u8 *vl_api_lisp_pitr_set_locator_set_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_pitr_set_locator_set_reply_t *a = va_arg (*args, vl_api_lisp_pitr_set_locator_set_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_pitr_set_locator_set_reply_t: */
    s = format(s, "vl_api_lisp_pitr_set_locator_set_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_lisp_use_petr_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_use_petr_t *a = va_arg (*args, vl_api_lisp_use_petr_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_use_petr_t: */
    s = format(s, "vl_api_lisp_use_petr_t:");
    s = format(s, "\n%Uip_address: %U", format_white_space, indent, format_vl_api_address_t, &a->ip_address, indent);
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    return s;
}

static inline u8 *vl_api_lisp_use_petr_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_use_petr_reply_t *a = va_arg (*args, vl_api_lisp_use_petr_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_use_petr_reply_t: */
    s = format(s, "vl_api_lisp_use_petr_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_show_lisp_use_petr_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_show_lisp_use_petr_t *a = va_arg (*args, vl_api_show_lisp_use_petr_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_show_lisp_use_petr_t: */
    s = format(s, "vl_api_show_lisp_use_petr_t:");
    return s;
}

static inline u8 *vl_api_show_lisp_use_petr_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_show_lisp_use_petr_reply_t *a = va_arg (*args, vl_api_show_lisp_use_petr_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_show_lisp_use_petr_reply_t: */
    s = format(s, "vl_api_show_lisp_use_petr_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uis_petr_enable: %u", format_white_space, indent, a->is_petr_enable);
    s = format(s, "\n%Uip_address: %U", format_white_space, indent, format_vl_api_address_t, &a->ip_address, indent);
    return s;
}

static inline u8 *vl_api_show_lisp_rloc_probe_state_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_show_lisp_rloc_probe_state_t *a = va_arg (*args, vl_api_show_lisp_rloc_probe_state_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_show_lisp_rloc_probe_state_t: */
    s = format(s, "vl_api_show_lisp_rloc_probe_state_t:");
    return s;
}

static inline u8 *vl_api_show_lisp_rloc_probe_state_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_show_lisp_rloc_probe_state_reply_t *a = va_arg (*args, vl_api_show_lisp_rloc_probe_state_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_show_lisp_rloc_probe_state_reply_t: */
    s = format(s, "vl_api_show_lisp_rloc_probe_state_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uis_enabled: %u", format_white_space, indent, a->is_enabled);
    return s;
}

static inline u8 *vl_api_lisp_rloc_probe_enable_disable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_rloc_probe_enable_disable_t *a = va_arg (*args, vl_api_lisp_rloc_probe_enable_disable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_rloc_probe_enable_disable_t: */
    s = format(s, "vl_api_lisp_rloc_probe_enable_disable_t:");
    s = format(s, "\n%Uis_enable: %u", format_white_space, indent, a->is_enable);
    return s;
}

static inline u8 *vl_api_lisp_rloc_probe_enable_disable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_rloc_probe_enable_disable_reply_t *a = va_arg (*args, vl_api_lisp_rloc_probe_enable_disable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_rloc_probe_enable_disable_reply_t: */
    s = format(s, "vl_api_lisp_rloc_probe_enable_disable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_lisp_map_register_enable_disable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_map_register_enable_disable_t *a = va_arg (*args, vl_api_lisp_map_register_enable_disable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_map_register_enable_disable_t: */
    s = format(s, "vl_api_lisp_map_register_enable_disable_t:");
    s = format(s, "\n%Uis_enable: %u", format_white_space, indent, a->is_enable);
    return s;
}

static inline u8 *vl_api_lisp_map_register_enable_disable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_map_register_enable_disable_reply_t *a = va_arg (*args, vl_api_lisp_map_register_enable_disable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_map_register_enable_disable_reply_t: */
    s = format(s, "vl_api_lisp_map_register_enable_disable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_show_lisp_map_register_state_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_show_lisp_map_register_state_t *a = va_arg (*args, vl_api_show_lisp_map_register_state_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_show_lisp_map_register_state_t: */
    s = format(s, "vl_api_show_lisp_map_register_state_t:");
    return s;
}

static inline u8 *vl_api_show_lisp_map_register_state_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_show_lisp_map_register_state_reply_t *a = va_arg (*args, vl_api_show_lisp_map_register_state_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_show_lisp_map_register_state_reply_t: */
    s = format(s, "vl_api_show_lisp_map_register_state_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uis_enabled: %u", format_white_space, indent, a->is_enabled);
    return s;
}

static inline u8 *vl_api_lisp_map_request_mode_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_map_request_mode_t *a = va_arg (*args, vl_api_lisp_map_request_mode_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_map_request_mode_t: */
    s = format(s, "vl_api_lisp_map_request_mode_t:");
    s = format(s, "\n%Uis_src_dst: %u", format_white_space, indent, a->is_src_dst);
    return s;
}

static inline u8 *vl_api_lisp_map_request_mode_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_map_request_mode_reply_t *a = va_arg (*args, vl_api_lisp_map_request_mode_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_map_request_mode_reply_t: */
    s = format(s, "vl_api_lisp_map_request_mode_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_show_lisp_map_request_mode_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_show_lisp_map_request_mode_t *a = va_arg (*args, vl_api_show_lisp_map_request_mode_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_show_lisp_map_request_mode_t: */
    s = format(s, "vl_api_show_lisp_map_request_mode_t:");
    return s;
}

static inline u8 *vl_api_show_lisp_map_request_mode_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_show_lisp_map_request_mode_reply_t *a = va_arg (*args, vl_api_show_lisp_map_request_mode_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_show_lisp_map_request_mode_reply_t: */
    s = format(s, "vl_api_show_lisp_map_request_mode_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uis_src_dst: %u", format_white_space, indent, a->is_src_dst);
    return s;
}

static inline u8 *vl_api_lisp_add_del_remote_mapping_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_add_del_remote_mapping_t *a = va_arg (*args, vl_api_lisp_add_del_remote_mapping_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_add_del_remote_mapping_t: */
    s = format(s, "vl_api_lisp_add_del_remote_mapping_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uis_src_dst: %u", format_white_space, indent, a->is_src_dst);
    s = format(s, "\n%Udel_all: %u", format_white_space, indent, a->del_all);
    s = format(s, "\n%Uvni: %u", format_white_space, indent, a->vni);
    s = format(s, "\n%Uaction: %u", format_white_space, indent, a->action);
    s = format(s, "\n%Udeid: %U", format_white_space, indent, format_vl_api_eid_t, &a->deid, indent);
    s = format(s, "\n%Useid: %U", format_white_space, indent, format_vl_api_eid_t, &a->seid, indent);
    s = format(s, "\n%Urloc_num: %u", format_white_space, indent, a->rloc_num);
    for (i = 0; i < a->rloc_num; i++) {
        s = format(s, "\n%Urlocs: %U",
                   format_white_space, indent, format_vl_api_remote_locator_t, &a->rlocs[i], indent);
    }
    return s;
}

static inline u8 *vl_api_lisp_add_del_remote_mapping_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_add_del_remote_mapping_reply_t *a = va_arg (*args, vl_api_lisp_add_del_remote_mapping_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_add_del_remote_mapping_reply_t: */
    s = format(s, "vl_api_lisp_add_del_remote_mapping_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_lisp_add_del_adjacency_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_add_del_adjacency_t *a = va_arg (*args, vl_api_lisp_add_del_adjacency_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_add_del_adjacency_t: */
    s = format(s, "vl_api_lisp_add_del_adjacency_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uvni: %u", format_white_space, indent, a->vni);
    s = format(s, "\n%Ureid: %U", format_white_space, indent, format_vl_api_eid_t, &a->reid, indent);
    s = format(s, "\n%Uleid: %U", format_white_space, indent, format_vl_api_eid_t, &a->leid, indent);
    return s;
}

static inline u8 *vl_api_lisp_add_del_adjacency_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_add_del_adjacency_reply_t *a = va_arg (*args, vl_api_lisp_add_del_adjacency_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_add_del_adjacency_reply_t: */
    s = format(s, "vl_api_lisp_add_del_adjacency_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_lisp_add_del_map_request_itr_rlocs_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_add_del_map_request_itr_rlocs_t *a = va_arg (*args, vl_api_lisp_add_del_map_request_itr_rlocs_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_add_del_map_request_itr_rlocs_t: */
    s = format(s, "vl_api_lisp_add_del_map_request_itr_rlocs_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Ulocator_set_name: %s", format_white_space, indent, a->locator_set_name);
    return s;
}

static inline u8 *vl_api_lisp_add_del_map_request_itr_rlocs_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_add_del_map_request_itr_rlocs_reply_t *a = va_arg (*args, vl_api_lisp_add_del_map_request_itr_rlocs_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_add_del_map_request_itr_rlocs_reply_t: */
    s = format(s, "vl_api_lisp_add_del_map_request_itr_rlocs_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_lisp_eid_table_add_del_map_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_eid_table_add_del_map_t *a = va_arg (*args, vl_api_lisp_eid_table_add_del_map_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_eid_table_add_del_map_t: */
    s = format(s, "vl_api_lisp_eid_table_add_del_map_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uvni: %u", format_white_space, indent, a->vni);
    s = format(s, "\n%Udp_table: %u", format_white_space, indent, a->dp_table);
    s = format(s, "\n%Uis_l2: %u", format_white_space, indent, a->is_l2);
    return s;
}

static inline u8 *vl_api_lisp_eid_table_add_del_map_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_eid_table_add_del_map_reply_t *a = va_arg (*args, vl_api_lisp_eid_table_add_del_map_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_eid_table_add_del_map_reply_t: */
    s = format(s, "vl_api_lisp_eid_table_add_del_map_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_lisp_locator_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_locator_dump_t *a = va_arg (*args, vl_api_lisp_locator_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_locator_dump_t: */
    s = format(s, "vl_api_lisp_locator_dump_t:");
    s = format(s, "\n%Uls_index: %u", format_white_space, indent, a->ls_index);
    s = format(s, "\n%Uls_name: %s", format_white_space, indent, a->ls_name);
    s = format(s, "\n%Uis_index_set: %u", format_white_space, indent, a->is_index_set);
    return s;
}

static inline u8 *vl_api_lisp_locator_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_locator_details_t *a = va_arg (*args, vl_api_lisp_locator_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_locator_details_t: */
    s = format(s, "vl_api_lisp_locator_details_t:");
    s = format(s, "\n%Ulocal: %u", format_white_space, indent, a->local);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uip_address: %U", format_white_space, indent, format_vl_api_address_t, &a->ip_address, indent);
    s = format(s, "\n%Upriority: %u", format_white_space, indent, a->priority);
    s = format(s, "\n%Uweight: %u", format_white_space, indent, a->weight);
    return s;
}

static inline u8 *vl_api_lisp_locator_set_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_locator_set_details_t *a = va_arg (*args, vl_api_lisp_locator_set_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_locator_set_details_t: */
    s = format(s, "vl_api_lisp_locator_set_details_t:");
    s = format(s, "\n%Uls_index: %u", format_white_space, indent, a->ls_index);
    s = format(s, "\n%Uls_name: %s", format_white_space, indent, a->ls_name);
    return s;
}

static inline u8 *vl_api_lisp_locator_set_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_locator_set_dump_t *a = va_arg (*args, vl_api_lisp_locator_set_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_locator_set_dump_t: */
    s = format(s, "vl_api_lisp_locator_set_dump_t:");
    s = format(s, "\n%Ufilter: %U", format_white_space, indent, format_vl_api_lisp_locator_set_filter_t, &a->filter, indent);
    return s;
}

static inline u8 *vl_api_lisp_eid_table_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_eid_table_details_t *a = va_arg (*args, vl_api_lisp_eid_table_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_eid_table_details_t: */
    s = format(s, "vl_api_lisp_eid_table_details_t:");
    s = format(s, "\n%Ulocator_set_index: %u", format_white_space, indent, a->locator_set_index);
    s = format(s, "\n%Uaction: %u", format_white_space, indent, a->action);
    s = format(s, "\n%Uis_local: %u", format_white_space, indent, a->is_local);
    s = format(s, "\n%Uis_src_dst: %u", format_white_space, indent, a->is_src_dst);
    s = format(s, "\n%Uvni: %u", format_white_space, indent, a->vni);
    s = format(s, "\n%Udeid: %U", format_white_space, indent, format_vl_api_eid_t, &a->deid, indent);
    s = format(s, "\n%Useid: %U", format_white_space, indent, format_vl_api_eid_t, &a->seid, indent);
    s = format(s, "\n%Uttl: %u", format_white_space, indent, a->ttl);
    s = format(s, "\n%Uauthoritative: %u", format_white_space, indent, a->authoritative);
    s = format(s, "\n%Ukey: %U", format_white_space, indent, format_vl_api_hmac_key_t, &a->key, indent);
    return s;
}

static inline u8 *vl_api_lisp_eid_table_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_eid_table_dump_t *a = va_arg (*args, vl_api_lisp_eid_table_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_eid_table_dump_t: */
    s = format(s, "vl_api_lisp_eid_table_dump_t:");
    s = format(s, "\n%Ueid_set: %u", format_white_space, indent, a->eid_set);
    s = format(s, "\n%Uprefix_length: %u", format_white_space, indent, a->prefix_length);
    s = format(s, "\n%Uvni: %u", format_white_space, indent, a->vni);
    s = format(s, "\n%Ueid: %U", format_white_space, indent, format_vl_api_eid_t, &a->eid, indent);
    s = format(s, "\n%Ufilter: %U", format_white_space, indent, format_vl_api_lisp_locator_set_filter_t, &a->filter, indent);
    return s;
}

static inline u8 *vl_api_lisp_adjacencies_get_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_adjacencies_get_reply_t *a = va_arg (*args, vl_api_lisp_adjacencies_get_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_adjacencies_get_reply_t: */
    s = format(s, "vl_api_lisp_adjacencies_get_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ucount: %u", format_white_space, indent, a->count);
    for (i = 0; i < a->count; i++) {
        s = format(s, "\n%Uadjacencies: %U",
                   format_white_space, indent, format_vl_api_lisp_adjacency_t, &a->adjacencies[i], indent);
    }
    return s;
}

static inline u8 *vl_api_lisp_adjacencies_get_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_adjacencies_get_t *a = va_arg (*args, vl_api_lisp_adjacencies_get_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_adjacencies_get_t: */
    s = format(s, "vl_api_lisp_adjacencies_get_t:");
    s = format(s, "\n%Uvni: %u", format_white_space, indent, a->vni);
    return s;
}

static inline u8 *vl_api_lisp_eid_table_map_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_eid_table_map_details_t *a = va_arg (*args, vl_api_lisp_eid_table_map_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_eid_table_map_details_t: */
    s = format(s, "vl_api_lisp_eid_table_map_details_t:");
    s = format(s, "\n%Uvni: %u", format_white_space, indent, a->vni);
    s = format(s, "\n%Udp_table: %u", format_white_space, indent, a->dp_table);
    return s;
}

static inline u8 *vl_api_lisp_eid_table_map_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_eid_table_map_dump_t *a = va_arg (*args, vl_api_lisp_eid_table_map_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_eid_table_map_dump_t: */
    s = format(s, "vl_api_lisp_eid_table_map_dump_t:");
    s = format(s, "\n%Uis_l2: %u", format_white_space, indent, a->is_l2);
    return s;
}

static inline u8 *vl_api_lisp_eid_table_vni_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_eid_table_vni_dump_t *a = va_arg (*args, vl_api_lisp_eid_table_vni_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_eid_table_vni_dump_t: */
    s = format(s, "vl_api_lisp_eid_table_vni_dump_t:");
    return s;
}

static inline u8 *vl_api_lisp_eid_table_vni_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_eid_table_vni_details_t *a = va_arg (*args, vl_api_lisp_eid_table_vni_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_eid_table_vni_details_t: */
    s = format(s, "vl_api_lisp_eid_table_vni_details_t:");
    s = format(s, "\n%Uvni: %u", format_white_space, indent, a->vni);
    return s;
}

static inline u8 *vl_api_lisp_map_resolver_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_map_resolver_details_t *a = va_arg (*args, vl_api_lisp_map_resolver_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_map_resolver_details_t: */
    s = format(s, "vl_api_lisp_map_resolver_details_t:");
    s = format(s, "\n%Uip_address: %U", format_white_space, indent, format_vl_api_address_t, &a->ip_address, indent);
    return s;
}

static inline u8 *vl_api_lisp_map_resolver_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_map_resolver_dump_t *a = va_arg (*args, vl_api_lisp_map_resolver_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_map_resolver_dump_t: */
    s = format(s, "vl_api_lisp_map_resolver_dump_t:");
    return s;
}

static inline u8 *vl_api_lisp_map_server_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_map_server_details_t *a = va_arg (*args, vl_api_lisp_map_server_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_map_server_details_t: */
    s = format(s, "vl_api_lisp_map_server_details_t:");
    s = format(s, "\n%Uip_address: %U", format_white_space, indent, format_vl_api_address_t, &a->ip_address, indent);
    return s;
}

static inline u8 *vl_api_lisp_map_server_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_map_server_dump_t *a = va_arg (*args, vl_api_lisp_map_server_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_map_server_dump_t: */
    s = format(s, "vl_api_lisp_map_server_dump_t:");
    return s;
}

static inline u8 *vl_api_show_lisp_status_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_show_lisp_status_t *a = va_arg (*args, vl_api_show_lisp_status_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_show_lisp_status_t: */
    s = format(s, "vl_api_show_lisp_status_t:");
    return s;
}

static inline u8 *vl_api_show_lisp_status_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_show_lisp_status_reply_t *a = va_arg (*args, vl_api_show_lisp_status_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_show_lisp_status_reply_t: */
    s = format(s, "vl_api_show_lisp_status_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uis_lisp_enabled: %u", format_white_space, indent, a->is_lisp_enabled);
    s = format(s, "\n%Uis_gpe_enabled: %u", format_white_space, indent, a->is_gpe_enabled);
    return s;
}

static inline u8 *vl_api_lisp_get_map_request_itr_rlocs_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_get_map_request_itr_rlocs_t *a = va_arg (*args, vl_api_lisp_get_map_request_itr_rlocs_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_get_map_request_itr_rlocs_t: */
    s = format(s, "vl_api_lisp_get_map_request_itr_rlocs_t:");
    return s;
}

static inline u8 *vl_api_lisp_get_map_request_itr_rlocs_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lisp_get_map_request_itr_rlocs_reply_t *a = va_arg (*args, vl_api_lisp_get_map_request_itr_rlocs_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lisp_get_map_request_itr_rlocs_reply_t: */
    s = format(s, "vl_api_lisp_get_map_request_itr_rlocs_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ulocator_set_name: %s", format_white_space, indent, a->locator_set_name);
    return s;
}

static inline u8 *vl_api_show_lisp_pitr_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_show_lisp_pitr_t *a = va_arg (*args, vl_api_show_lisp_pitr_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_show_lisp_pitr_t: */
    s = format(s, "vl_api_show_lisp_pitr_t:");
    return s;
}

static inline u8 *vl_api_show_lisp_pitr_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_show_lisp_pitr_reply_t *a = va_arg (*args, vl_api_show_lisp_pitr_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_show_lisp_pitr_reply_t: */
    s = format(s, "vl_api_show_lisp_pitr_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uis_enabled: %u", format_white_space, indent, a->is_enabled);
    s = format(s, "\n%Ulocator_set_name: %s", format_white_space, indent, a->locator_set_name);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_lisp_endianfun
#define included_lisp_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_lisp_locator_set_filter_t_endian (vl_api_lisp_locator_set_filter_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->lisp_locator_set_filter = a->lisp_locator_set_filter (no-op) */
}

static inline void vl_api_lisp_adjacency_t_endian (vl_api_lisp_adjacency_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_eid_t_endian(&a->reid, to_net);
    vl_api_eid_t_endian(&a->leid, to_net);
}

static inline void vl_api_lisp_add_del_locator_set_t_endian (vl_api_lisp_add_del_locator_set_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    /* a->locator_set_name = a->locator_set_name (no-op) */
    a->locator_num = clib_net_to_host_u32(a->locator_num);
    u32 count = to_net ? clib_net_to_host_u32(a->locator_num) : a->locator_num;
    for (i = 0; i < count; i++) {
        vl_api_local_locator_t_endian(&a->locators[i], to_net);
    }
}

static inline void vl_api_lisp_add_del_locator_set_reply_t_endian (vl_api_lisp_add_del_locator_set_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->ls_index = clib_net_to_host_u32(a->ls_index);
}

static inline void vl_api_lisp_add_del_locator_t_endian (vl_api_lisp_add_del_locator_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    /* a->locator_set_name = a->locator_set_name (no-op) */
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->priority = a->priority (no-op) */
    /* a->weight = a->weight (no-op) */
}

static inline void vl_api_lisp_add_del_locator_reply_t_endian (vl_api_lisp_add_del_locator_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_lisp_add_del_local_eid_t_endian (vl_api_lisp_add_del_local_eid_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_eid_t_endian(&a->eid, to_net);
    /* a->locator_set_name = a->locator_set_name (no-op) */
    a->vni = clib_net_to_host_u32(a->vni);
    vl_api_hmac_key_t_endian(&a->key, to_net);
}

static inline void vl_api_lisp_add_del_local_eid_reply_t_endian (vl_api_lisp_add_del_local_eid_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_lisp_add_del_map_server_t_endian (vl_api_lisp_add_del_map_server_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_address_t_endian(&a->ip_address, to_net);
}

static inline void vl_api_lisp_add_del_map_server_reply_t_endian (vl_api_lisp_add_del_map_server_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_lisp_add_del_map_resolver_t_endian (vl_api_lisp_add_del_map_resolver_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_address_t_endian(&a->ip_address, to_net);
}

static inline void vl_api_lisp_add_del_map_resolver_reply_t_endian (vl_api_lisp_add_del_map_resolver_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_lisp_enable_disable_t_endian (vl_api_lisp_enable_disable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_enable = a->is_enable (no-op) */
}

static inline void vl_api_lisp_enable_disable_reply_t_endian (vl_api_lisp_enable_disable_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_lisp_pitr_set_locator_set_t_endian (vl_api_lisp_pitr_set_locator_set_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    /* a->ls_name = a->ls_name (no-op) */
}

static inline void vl_api_lisp_pitr_set_locator_set_reply_t_endian (vl_api_lisp_pitr_set_locator_set_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_lisp_use_petr_t_endian (vl_api_lisp_use_petr_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_address_t_endian(&a->ip_address, to_net);
    /* a->is_add = a->is_add (no-op) */
}

static inline void vl_api_lisp_use_petr_reply_t_endian (vl_api_lisp_use_petr_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_show_lisp_use_petr_t_endian (vl_api_show_lisp_use_petr_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_show_lisp_use_petr_reply_t_endian (vl_api_show_lisp_use_petr_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    /* a->is_petr_enable = a->is_petr_enable (no-op) */
    vl_api_address_t_endian(&a->ip_address, to_net);
}

static inline void vl_api_show_lisp_rloc_probe_state_t_endian (vl_api_show_lisp_rloc_probe_state_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_show_lisp_rloc_probe_state_reply_t_endian (vl_api_show_lisp_rloc_probe_state_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    /* a->is_enabled = a->is_enabled (no-op) */
}

static inline void vl_api_lisp_rloc_probe_enable_disable_t_endian (vl_api_lisp_rloc_probe_enable_disable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_enable = a->is_enable (no-op) */
}

static inline void vl_api_lisp_rloc_probe_enable_disable_reply_t_endian (vl_api_lisp_rloc_probe_enable_disable_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_lisp_map_register_enable_disable_t_endian (vl_api_lisp_map_register_enable_disable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_enable = a->is_enable (no-op) */
}

static inline void vl_api_lisp_map_register_enable_disable_reply_t_endian (vl_api_lisp_map_register_enable_disable_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_show_lisp_map_register_state_t_endian (vl_api_show_lisp_map_register_state_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_show_lisp_map_register_state_reply_t_endian (vl_api_show_lisp_map_register_state_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    /* a->is_enabled = a->is_enabled (no-op) */
}

static inline void vl_api_lisp_map_request_mode_t_endian (vl_api_lisp_map_request_mode_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_src_dst = a->is_src_dst (no-op) */
}

static inline void vl_api_lisp_map_request_mode_reply_t_endian (vl_api_lisp_map_request_mode_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_show_lisp_map_request_mode_t_endian (vl_api_show_lisp_map_request_mode_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_show_lisp_map_request_mode_reply_t_endian (vl_api_show_lisp_map_request_mode_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    /* a->is_src_dst = a->is_src_dst (no-op) */
}

static inline void vl_api_lisp_add_del_remote_mapping_t_endian (vl_api_lisp_add_del_remote_mapping_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    /* a->is_src_dst = a->is_src_dst (no-op) */
    /* a->del_all = a->del_all (no-op) */
    a->vni = clib_net_to_host_u32(a->vni);
    /* a->action = a->action (no-op) */
    vl_api_eid_t_endian(&a->deid, to_net);
    vl_api_eid_t_endian(&a->seid, to_net);
    a->rloc_num = clib_net_to_host_u32(a->rloc_num);
    u32 count = to_net ? clib_net_to_host_u32(a->rloc_num) : a->rloc_num;
    for (i = 0; i < count; i++) {
        vl_api_remote_locator_t_endian(&a->rlocs[i], to_net);
    }
}

static inline void vl_api_lisp_add_del_remote_mapping_reply_t_endian (vl_api_lisp_add_del_remote_mapping_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_lisp_add_del_adjacency_t_endian (vl_api_lisp_add_del_adjacency_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    a->vni = clib_net_to_host_u32(a->vni);
    vl_api_eid_t_endian(&a->reid, to_net);
    vl_api_eid_t_endian(&a->leid, to_net);
}

static inline void vl_api_lisp_add_del_adjacency_reply_t_endian (vl_api_lisp_add_del_adjacency_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_lisp_add_del_map_request_itr_rlocs_t_endian (vl_api_lisp_add_del_map_request_itr_rlocs_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    /* a->locator_set_name = a->locator_set_name (no-op) */
}

static inline void vl_api_lisp_add_del_map_request_itr_rlocs_reply_t_endian (vl_api_lisp_add_del_map_request_itr_rlocs_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_lisp_eid_table_add_del_map_t_endian (vl_api_lisp_eid_table_add_del_map_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    a->vni = clib_net_to_host_u32(a->vni);
    a->dp_table = clib_net_to_host_u32(a->dp_table);
    /* a->is_l2 = a->is_l2 (no-op) */
}

static inline void vl_api_lisp_eid_table_add_del_map_reply_t_endian (vl_api_lisp_eid_table_add_del_map_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_lisp_locator_dump_t_endian (vl_api_lisp_locator_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->ls_index = clib_net_to_host_u32(a->ls_index);
    /* a->ls_name = a->ls_name (no-op) */
    /* a->is_index_set = a->is_index_set (no-op) */
}

static inline void vl_api_lisp_locator_details_t_endian (vl_api_lisp_locator_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    /* a->local = a->local (no-op) */
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    vl_api_address_t_endian(&a->ip_address, to_net);
    /* a->priority = a->priority (no-op) */
    /* a->weight = a->weight (no-op) */
}

static inline void vl_api_lisp_locator_set_details_t_endian (vl_api_lisp_locator_set_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->ls_index = clib_net_to_host_u32(a->ls_index);
    /* a->ls_name = a->ls_name (no-op) */
}

static inline void vl_api_lisp_locator_set_dump_t_endian (vl_api_lisp_locator_set_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_lisp_locator_set_filter_t_endian(&a->filter, to_net);
}

static inline void vl_api_lisp_eid_table_details_t_endian (vl_api_lisp_eid_table_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->locator_set_index = clib_net_to_host_u32(a->locator_set_index);
    /* a->action = a->action (no-op) */
    /* a->is_local = a->is_local (no-op) */
    /* a->is_src_dst = a->is_src_dst (no-op) */
    a->vni = clib_net_to_host_u32(a->vni);
    vl_api_eid_t_endian(&a->deid, to_net);
    vl_api_eid_t_endian(&a->seid, to_net);
    a->ttl = clib_net_to_host_u32(a->ttl);
    /* a->authoritative = a->authoritative (no-op) */
    vl_api_hmac_key_t_endian(&a->key, to_net);
}

static inline void vl_api_lisp_eid_table_dump_t_endian (vl_api_lisp_eid_table_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->eid_set = a->eid_set (no-op) */
    /* a->prefix_length = a->prefix_length (no-op) */
    a->vni = clib_net_to_host_u32(a->vni);
    vl_api_eid_t_endian(&a->eid, to_net);
    vl_api_lisp_locator_set_filter_t_endian(&a->filter, to_net);
}

static inline void vl_api_lisp_adjacencies_get_reply_t_endian (vl_api_lisp_adjacencies_get_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->count = clib_net_to_host_u32(a->count);
    u32 count = to_net ? clib_net_to_host_u32(a->count) : a->count;
    for (i = 0; i < count; i++) {
        vl_api_lisp_adjacency_t_endian(&a->adjacencies[i], to_net);
    }
}

static inline void vl_api_lisp_adjacencies_get_t_endian (vl_api_lisp_adjacencies_get_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->vni = clib_net_to_host_u32(a->vni);
}

static inline void vl_api_lisp_eid_table_map_details_t_endian (vl_api_lisp_eid_table_map_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->vni = clib_net_to_host_u32(a->vni);
    a->dp_table = clib_net_to_host_u32(a->dp_table);
}

static inline void vl_api_lisp_eid_table_map_dump_t_endian (vl_api_lisp_eid_table_map_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_l2 = a->is_l2 (no-op) */
}

static inline void vl_api_lisp_eid_table_vni_dump_t_endian (vl_api_lisp_eid_table_vni_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_lisp_eid_table_vni_details_t_endian (vl_api_lisp_eid_table_vni_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->vni = clib_net_to_host_u32(a->vni);
}

static inline void vl_api_lisp_map_resolver_details_t_endian (vl_api_lisp_map_resolver_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_address_t_endian(&a->ip_address, to_net);
}

static inline void vl_api_lisp_map_resolver_dump_t_endian (vl_api_lisp_map_resolver_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_lisp_map_server_details_t_endian (vl_api_lisp_map_server_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_address_t_endian(&a->ip_address, to_net);
}

static inline void vl_api_lisp_map_server_dump_t_endian (vl_api_lisp_map_server_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_show_lisp_status_t_endian (vl_api_show_lisp_status_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_show_lisp_status_reply_t_endian (vl_api_show_lisp_status_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    /* a->is_lisp_enabled = a->is_lisp_enabled (no-op) */
    /* a->is_gpe_enabled = a->is_gpe_enabled (no-op) */
}

static inline void vl_api_lisp_get_map_request_itr_rlocs_t_endian (vl_api_lisp_get_map_request_itr_rlocs_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_lisp_get_map_request_itr_rlocs_reply_t_endian (vl_api_lisp_get_map_request_itr_rlocs_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    /* a->locator_set_name = a->locator_set_name (no-op) */
}

static inline void vl_api_show_lisp_pitr_t_endian (vl_api_show_lisp_pitr_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_show_lisp_pitr_reply_t_endian (vl_api_show_lisp_pitr_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    /* a->is_enabled = a->is_enabled (no-op) */
    /* a->locator_set_name = a->locator_set_name (no-op) */
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_lisp_calcsizefun
#define included_lisp_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_locator_set_filter_t_calc_size (vl_api_lisp_locator_set_filter_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_adjacency_t_calc_size (vl_api_lisp_adjacency_t *a)
{
      return sizeof(*a) - sizeof(a->reid) + vl_api_eid_t_calc_size(&a->reid) - sizeof(a->leid) + vl_api_eid_t_calc_size(&a->leid);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_add_del_locator_set_t_calc_size (vl_api_lisp_add_del_locator_set_t *a)
{
      return sizeof(*a) + clib_net_to_host_u32(a->locator_num) * sizeof(a->locators[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_add_del_locator_set_reply_t_calc_size (vl_api_lisp_add_del_locator_set_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_add_del_locator_t_calc_size (vl_api_lisp_add_del_locator_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_add_del_locator_reply_t_calc_size (vl_api_lisp_add_del_locator_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_add_del_local_eid_t_calc_size (vl_api_lisp_add_del_local_eid_t *a)
{
      return sizeof(*a) - sizeof(a->eid) + vl_api_eid_t_calc_size(&a->eid) - sizeof(a->key) + vl_api_hmac_key_t_calc_size(&a->key);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_add_del_local_eid_reply_t_calc_size (vl_api_lisp_add_del_local_eid_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_add_del_map_server_t_calc_size (vl_api_lisp_add_del_map_server_t *a)
{
      return sizeof(*a) - sizeof(a->ip_address) + vl_api_address_t_calc_size(&a->ip_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_add_del_map_server_reply_t_calc_size (vl_api_lisp_add_del_map_server_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_add_del_map_resolver_t_calc_size (vl_api_lisp_add_del_map_resolver_t *a)
{
      return sizeof(*a) - sizeof(a->ip_address) + vl_api_address_t_calc_size(&a->ip_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_add_del_map_resolver_reply_t_calc_size (vl_api_lisp_add_del_map_resolver_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_enable_disable_t_calc_size (vl_api_lisp_enable_disable_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_enable_disable_reply_t_calc_size (vl_api_lisp_enable_disable_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_pitr_set_locator_set_t_calc_size (vl_api_lisp_pitr_set_locator_set_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_pitr_set_locator_set_reply_t_calc_size (vl_api_lisp_pitr_set_locator_set_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_use_petr_t_calc_size (vl_api_lisp_use_petr_t *a)
{
      return sizeof(*a) - sizeof(a->ip_address) + vl_api_address_t_calc_size(&a->ip_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_use_petr_reply_t_calc_size (vl_api_lisp_use_petr_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_show_lisp_use_petr_t_calc_size (vl_api_show_lisp_use_petr_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_show_lisp_use_petr_reply_t_calc_size (vl_api_show_lisp_use_petr_reply_t *a)
{
      return sizeof(*a) - sizeof(a->ip_address) + vl_api_address_t_calc_size(&a->ip_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_show_lisp_rloc_probe_state_t_calc_size (vl_api_show_lisp_rloc_probe_state_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_show_lisp_rloc_probe_state_reply_t_calc_size (vl_api_show_lisp_rloc_probe_state_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_rloc_probe_enable_disable_t_calc_size (vl_api_lisp_rloc_probe_enable_disable_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_rloc_probe_enable_disable_reply_t_calc_size (vl_api_lisp_rloc_probe_enable_disable_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_map_register_enable_disable_t_calc_size (vl_api_lisp_map_register_enable_disable_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_map_register_enable_disable_reply_t_calc_size (vl_api_lisp_map_register_enable_disable_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_show_lisp_map_register_state_t_calc_size (vl_api_show_lisp_map_register_state_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_show_lisp_map_register_state_reply_t_calc_size (vl_api_show_lisp_map_register_state_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_map_request_mode_t_calc_size (vl_api_lisp_map_request_mode_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_map_request_mode_reply_t_calc_size (vl_api_lisp_map_request_mode_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_show_lisp_map_request_mode_t_calc_size (vl_api_show_lisp_map_request_mode_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_show_lisp_map_request_mode_reply_t_calc_size (vl_api_show_lisp_map_request_mode_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_add_del_remote_mapping_t_calc_size (vl_api_lisp_add_del_remote_mapping_t *a)
{
      return sizeof(*a) - sizeof(a->deid) + vl_api_eid_t_calc_size(&a->deid) - sizeof(a->seid) + vl_api_eid_t_calc_size(&a->seid) + clib_net_to_host_u32(a->rloc_num) * sizeof(a->rlocs[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_add_del_remote_mapping_reply_t_calc_size (vl_api_lisp_add_del_remote_mapping_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_add_del_adjacency_t_calc_size (vl_api_lisp_add_del_adjacency_t *a)
{
      return sizeof(*a) - sizeof(a->reid) + vl_api_eid_t_calc_size(&a->reid) - sizeof(a->leid) + vl_api_eid_t_calc_size(&a->leid);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_add_del_adjacency_reply_t_calc_size (vl_api_lisp_add_del_adjacency_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_add_del_map_request_itr_rlocs_t_calc_size (vl_api_lisp_add_del_map_request_itr_rlocs_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_add_del_map_request_itr_rlocs_reply_t_calc_size (vl_api_lisp_add_del_map_request_itr_rlocs_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_eid_table_add_del_map_t_calc_size (vl_api_lisp_eid_table_add_del_map_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_eid_table_add_del_map_reply_t_calc_size (vl_api_lisp_eid_table_add_del_map_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_locator_dump_t_calc_size (vl_api_lisp_locator_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_locator_details_t_calc_size (vl_api_lisp_locator_details_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->ip_address) + vl_api_address_t_calc_size(&a->ip_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_locator_set_details_t_calc_size (vl_api_lisp_locator_set_details_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_locator_set_dump_t_calc_size (vl_api_lisp_locator_set_dump_t *a)
{
      return sizeof(*a) - sizeof(a->filter) + vl_api_lisp_locator_set_filter_t_calc_size(&a->filter);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_eid_table_details_t_calc_size (vl_api_lisp_eid_table_details_t *a)
{
      return sizeof(*a) - sizeof(a->deid) + vl_api_eid_t_calc_size(&a->deid) - sizeof(a->seid) + vl_api_eid_t_calc_size(&a->seid) - sizeof(a->key) + vl_api_hmac_key_t_calc_size(&a->key);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_eid_table_dump_t_calc_size (vl_api_lisp_eid_table_dump_t *a)
{
      return sizeof(*a) - sizeof(a->eid) + vl_api_eid_t_calc_size(&a->eid) - sizeof(a->filter) + vl_api_lisp_locator_set_filter_t_calc_size(&a->filter);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_adjacencies_get_reply_t_calc_size (vl_api_lisp_adjacencies_get_reply_t *a)
{
      return sizeof(*a) + clib_net_to_host_u32(a->count) * sizeof(a->adjacencies[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_adjacencies_get_t_calc_size (vl_api_lisp_adjacencies_get_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_eid_table_map_details_t_calc_size (vl_api_lisp_eid_table_map_details_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_eid_table_map_dump_t_calc_size (vl_api_lisp_eid_table_map_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_eid_table_vni_dump_t_calc_size (vl_api_lisp_eid_table_vni_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_eid_table_vni_details_t_calc_size (vl_api_lisp_eid_table_vni_details_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_map_resolver_details_t_calc_size (vl_api_lisp_map_resolver_details_t *a)
{
      return sizeof(*a) - sizeof(a->ip_address) + vl_api_address_t_calc_size(&a->ip_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_map_resolver_dump_t_calc_size (vl_api_lisp_map_resolver_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_map_server_details_t_calc_size (vl_api_lisp_map_server_details_t *a)
{
      return sizeof(*a) - sizeof(a->ip_address) + vl_api_address_t_calc_size(&a->ip_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_map_server_dump_t_calc_size (vl_api_lisp_map_server_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_show_lisp_status_t_calc_size (vl_api_show_lisp_status_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_show_lisp_status_reply_t_calc_size (vl_api_show_lisp_status_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_get_map_request_itr_rlocs_t_calc_size (vl_api_lisp_get_map_request_itr_rlocs_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lisp_get_map_request_itr_rlocs_reply_t_calc_size (vl_api_lisp_get_map_request_itr_rlocs_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_show_lisp_pitr_t_calc_size (vl_api_show_lisp_pitr_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_show_lisp_pitr_reply_t_calc_size (vl_api_show_lisp_pitr_reply_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(lisp.api, 2, 0, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(lisp.api, 0x2ec1dfcd)

#endif

