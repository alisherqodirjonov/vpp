#define vl_endianfun            /* define message structures */
#include "ip.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "ip.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "ip.api.h"
#undef vl_printfun

/* Generation not supported (vl_api_ip_path_mtu_get_reply_t_handler()) */
#ifndef VL_API_IP_TABLE_ADD_DEL_REPLY_T_HANDLER
static void
vl_api_ip_table_add_del_reply_t_handler (vl_api_ip_table_add_del_reply_t * mp) {
   vat_main_t * vam = ip_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IP_TABLE_ADD_DEL_V2_REPLY_T_HANDLER
static void
vl_api_ip_table_add_del_v2_reply_t_handler (vl_api_ip_table_add_del_v2_reply_t * mp) {
   vat_main_t * vam = ip_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_ip_table_allocate_reply_t_handler()) */
/* Generation not supported (vl_api_ip_table_details_t_handler()) */
#ifndef VL_API_IP_TABLE_REPLACE_BEGIN_REPLY_T_HANDLER
static void
vl_api_ip_table_replace_begin_reply_t_handler (vl_api_ip_table_replace_begin_reply_t * mp) {
   vat_main_t * vam = ip_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IP_TABLE_REPLACE_END_REPLY_T_HANDLER
static void
vl_api_ip_table_replace_end_reply_t_handler (vl_api_ip_table_replace_end_reply_t * mp) {
   vat_main_t * vam = ip_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IP_TABLE_FLUSH_REPLY_T_HANDLER
static void
vl_api_ip_table_flush_reply_t_handler (vl_api_ip_table_flush_reply_t * mp) {
   vat_main_t * vam = ip_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_ip_route_add_del_reply_t_handler()) */
/* Generation not supported (vl_api_ip_route_add_del_v2_reply_t_handler()) */
/* Generation not supported (vl_api_ip_route_details_t_handler()) */
/* Generation not supported (vl_api_ip_route_v2_details_t_handler()) */
/* Generation not supported (vl_api_ip_route_lookup_reply_t_handler()) */
/* Generation not supported (vl_api_ip_route_lookup_v2_reply_t_handler()) */
#ifndef VL_API_SET_IP_FLOW_HASH_REPLY_T_HANDLER
static void
vl_api_set_ip_flow_hash_reply_t_handler (vl_api_set_ip_flow_hash_reply_t * mp) {
   vat_main_t * vam = ip_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_SET_IP_FLOW_HASH_V2_REPLY_T_HANDLER
static void
vl_api_set_ip_flow_hash_v2_reply_t_handler (vl_api_set_ip_flow_hash_v2_reply_t * mp) {
   vat_main_t * vam = ip_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_SET_IP_FLOW_HASH_V3_REPLY_T_HANDLER
static void
vl_api_set_ip_flow_hash_v3_reply_t_handler (vl_api_set_ip_flow_hash_v3_reply_t * mp) {
   vat_main_t * vam = ip_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_SET_IP_FLOW_HASH_ROUTER_ID_REPLY_T_HANDLER
static void
vl_api_set_ip_flow_hash_router_id_reply_t_handler (vl_api_set_ip_flow_hash_router_id_reply_t * mp) {
   vat_main_t * vam = ip_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_SW_INTERFACE_IP6_ENABLE_DISABLE_REPLY_T_HANDLER
static void
vl_api_sw_interface_ip6_enable_disable_reply_t_handler (vl_api_sw_interface_ip6_enable_disable_reply_t * mp) {
   vat_main_t * vam = ip_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_SW_INTERFACE_IP4_ENABLE_DISABLE_REPLY_T_HANDLER
static void
vl_api_sw_interface_ip4_enable_disable_reply_t_handler (vl_api_sw_interface_ip4_enable_disable_reply_t * mp) {
   vat_main_t * vam = ip_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_ip_mtable_details_t_handler()) */
/* Generation not supported (vl_api_ip_mroute_add_del_reply_t_handler()) */
/* Generation not supported (vl_api_ip_mroute_details_t_handler()) */
/* Generation not supported (vl_api_ip_address_details_t_handler()) */
/* Generation not supported (vl_api_ip_unnumbered_details_t_handler()) */
/* Generation not supported (vl_api_ip_details_t_handler()) */
/* Generation not supported (vl_api_mfib_signal_details_t_handler()) */
#ifndef VL_API_IP_PUNT_POLICE_REPLY_T_HANDLER
static void
vl_api_ip_punt_police_reply_t_handler (vl_api_ip_punt_police_reply_t * mp) {
   vat_main_t * vam = ip_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IP_PUNT_REDIRECT_REPLY_T_HANDLER
static void
vl_api_ip_punt_redirect_reply_t_handler (vl_api_ip_punt_redirect_reply_t * mp) {
   vat_main_t * vam = ip_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_ip_punt_redirect_details_t_handler()) */
#ifndef VL_API_ADD_DEL_IP_PUNT_REDIRECT_V2_REPLY_T_HANDLER
static void
vl_api_add_del_ip_punt_redirect_v2_reply_t_handler (vl_api_add_del_ip_punt_redirect_v2_reply_t * mp) {
   vat_main_t * vam = ip_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_ip_punt_redirect_v2_details_t_handler()) */
#ifndef VL_API_IP_CONTAINER_PROXY_ADD_DEL_REPLY_T_HANDLER
static void
vl_api_ip_container_proxy_add_del_reply_t_handler (vl_api_ip_container_proxy_add_del_reply_t * mp) {
   vat_main_t * vam = ip_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_ip_container_proxy_details_t_handler()) */
#ifndef VL_API_IP_SOURCE_AND_PORT_RANGE_CHECK_ADD_DEL_REPLY_T_HANDLER
static void
vl_api_ip_source_and_port_range_check_add_del_reply_t_handler (vl_api_ip_source_and_port_range_check_add_del_reply_t * mp) {
   vat_main_t * vam = ip_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IP_SOURCE_AND_PORT_RANGE_CHECK_INTERFACE_ADD_DEL_REPLY_T_HANDLER
static void
vl_api_ip_source_and_port_range_check_interface_add_del_reply_t_handler (vl_api_ip_source_and_port_range_check_interface_add_del_reply_t * mp) {
   vat_main_t * vam = ip_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_SW_INTERFACE_IP6_SET_LINK_LOCAL_ADDRESS_REPLY_T_HANDLER
static void
vl_api_sw_interface_ip6_set_link_local_address_reply_t_handler (vl_api_sw_interface_ip6_set_link_local_address_reply_t * mp) {
   vat_main_t * vam = ip_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_sw_interface_ip6_get_link_local_address_reply_t_handler()) */
#ifndef VL_API_IOAM_ENABLE_REPLY_T_HANDLER
static void
vl_api_ioam_enable_reply_t_handler (vl_api_ioam_enable_reply_t * mp) {
   vat_main_t * vam = ip_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IOAM_DISABLE_REPLY_T_HANDLER
static void
vl_api_ioam_disable_reply_t_handler (vl_api_ioam_disable_reply_t * mp) {
   vat_main_t * vam = ip_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IP_REASSEMBLY_SET_REPLY_T_HANDLER
static void
vl_api_ip_reassembly_set_reply_t_handler (vl_api_ip_reassembly_set_reply_t * mp) {
   vat_main_t * vam = ip_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_ip_reassembly_get_reply_t_handler()) */
#ifndef VL_API_IP_REASSEMBLY_ENABLE_DISABLE_REPLY_T_HANDLER
static void
vl_api_ip_reassembly_enable_disable_reply_t_handler (vl_api_ip_reassembly_enable_disable_reply_t * mp) {
   vat_main_t * vam = ip_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IP_LOCAL_REASS_ENABLE_DISABLE_REPLY_T_HANDLER
static void
vl_api_ip_local_reass_enable_disable_reply_t_handler (vl_api_ip_local_reass_enable_disable_reply_t * mp) {
   vat_main_t * vam = ip_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_ip_local_reass_get_reply_t_handler()) */
#ifndef VL_API_IP_PATH_MTU_UPDATE_REPLY_T_HANDLER
static void
vl_api_ip_path_mtu_update_reply_t_handler (vl_api_ip_path_mtu_update_reply_t * mp) {
   vat_main_t * vam = ip_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IP_PATH_MTU_REPLACE_BEGIN_REPLY_T_HANDLER
static void
vl_api_ip_path_mtu_replace_begin_reply_t_handler (vl_api_ip_path_mtu_replace_begin_reply_t * mp) {
   vat_main_t * vam = ip_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IP_PATH_MTU_REPLACE_END_REPLY_T_HANDLER
static void
vl_api_ip_path_mtu_replace_end_reply_t_handler (vl_api_ip_path_mtu_replace_end_reply_t * mp) {
   vat_main_t * vam = ip_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_PATH_MTU_GET_REPLY + msg_id_base,
    .name = "ip_path_mtu_get_reply",
    .handler = vl_api_ip_path_mtu_get_reply_t_handler,
    .endian = vl_api_ip_path_mtu_get_reply_t_endian,
    .format_fn = vl_api_ip_path_mtu_get_reply_t_format,
    .size = sizeof(vl_api_ip_path_mtu_get_reply_t),
    .traced = 1,
    .tojson = vl_api_ip_path_mtu_get_reply_t_tojson,
    .fromjson = vl_api_ip_path_mtu_get_reply_t_fromjson,
    .calc_size = vl_api_ip_path_mtu_get_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_path_mtu_get", api_ip_path_mtu_get);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_TABLE_ADD_DEL_REPLY + msg_id_base,
    .name = "ip_table_add_del_reply",
    .handler = vl_api_ip_table_add_del_reply_t_handler,
    .endian = vl_api_ip_table_add_del_reply_t_endian,
    .format_fn = vl_api_ip_table_add_del_reply_t_format,
    .size = sizeof(vl_api_ip_table_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_ip_table_add_del_reply_t_tojson,
    .fromjson = vl_api_ip_table_add_del_reply_t_fromjson,
    .calc_size = vl_api_ip_table_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_table_add_del", api_ip_table_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_TABLE_ADD_DEL_V2_REPLY + msg_id_base,
    .name = "ip_table_add_del_v2_reply",
    .handler = vl_api_ip_table_add_del_v2_reply_t_handler,
    .endian = vl_api_ip_table_add_del_v2_reply_t_endian,
    .format_fn = vl_api_ip_table_add_del_v2_reply_t_format,
    .size = sizeof(vl_api_ip_table_add_del_v2_reply_t),
    .traced = 1,
    .tojson = vl_api_ip_table_add_del_v2_reply_t_tojson,
    .fromjson = vl_api_ip_table_add_del_v2_reply_t_fromjson,
    .calc_size = vl_api_ip_table_add_del_v2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_table_add_del_v2", api_ip_table_add_del_v2);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_TABLE_ALLOCATE_REPLY + msg_id_base,
    .name = "ip_table_allocate_reply",
    .handler = vl_api_ip_table_allocate_reply_t_handler,
    .endian = vl_api_ip_table_allocate_reply_t_endian,
    .format_fn = vl_api_ip_table_allocate_reply_t_format,
    .size = sizeof(vl_api_ip_table_allocate_reply_t),
    .traced = 1,
    .tojson = vl_api_ip_table_allocate_reply_t_tojson,
    .fromjson = vl_api_ip_table_allocate_reply_t_fromjson,
    .calc_size = vl_api_ip_table_allocate_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_table_allocate", api_ip_table_allocate);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_TABLE_DETAILS + msg_id_base,
    .name = "ip_table_details",
    .handler = vl_api_ip_table_details_t_handler,
    .endian = vl_api_ip_table_details_t_endian,
    .format_fn = vl_api_ip_table_details_t_format,
    .size = sizeof(vl_api_ip_table_details_t),
    .traced = 1,
    .tojson = vl_api_ip_table_details_t_tojson,
    .fromjson = vl_api_ip_table_details_t_fromjson,
    .calc_size = vl_api_ip_table_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_table_dump", api_ip_table_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_TABLE_REPLACE_BEGIN_REPLY + msg_id_base,
    .name = "ip_table_replace_begin_reply",
    .handler = vl_api_ip_table_replace_begin_reply_t_handler,
    .endian = vl_api_ip_table_replace_begin_reply_t_endian,
    .format_fn = vl_api_ip_table_replace_begin_reply_t_format,
    .size = sizeof(vl_api_ip_table_replace_begin_reply_t),
    .traced = 1,
    .tojson = vl_api_ip_table_replace_begin_reply_t_tojson,
    .fromjson = vl_api_ip_table_replace_begin_reply_t_fromjson,
    .calc_size = vl_api_ip_table_replace_begin_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_table_replace_begin", api_ip_table_replace_begin);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_TABLE_REPLACE_END_REPLY + msg_id_base,
    .name = "ip_table_replace_end_reply",
    .handler = vl_api_ip_table_replace_end_reply_t_handler,
    .endian = vl_api_ip_table_replace_end_reply_t_endian,
    .format_fn = vl_api_ip_table_replace_end_reply_t_format,
    .size = sizeof(vl_api_ip_table_replace_end_reply_t),
    .traced = 1,
    .tojson = vl_api_ip_table_replace_end_reply_t_tojson,
    .fromjson = vl_api_ip_table_replace_end_reply_t_fromjson,
    .calc_size = vl_api_ip_table_replace_end_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_table_replace_end", api_ip_table_replace_end);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_TABLE_FLUSH_REPLY + msg_id_base,
    .name = "ip_table_flush_reply",
    .handler = vl_api_ip_table_flush_reply_t_handler,
    .endian = vl_api_ip_table_flush_reply_t_endian,
    .format_fn = vl_api_ip_table_flush_reply_t_format,
    .size = sizeof(vl_api_ip_table_flush_reply_t),
    .traced = 1,
    .tojson = vl_api_ip_table_flush_reply_t_tojson,
    .fromjson = vl_api_ip_table_flush_reply_t_fromjson,
    .calc_size = vl_api_ip_table_flush_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_table_flush", api_ip_table_flush);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_ROUTE_ADD_DEL_REPLY + msg_id_base,
    .name = "ip_route_add_del_reply",
    .handler = vl_api_ip_route_add_del_reply_t_handler,
    .endian = vl_api_ip_route_add_del_reply_t_endian,
    .format_fn = vl_api_ip_route_add_del_reply_t_format,
    .size = sizeof(vl_api_ip_route_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_ip_route_add_del_reply_t_tojson,
    .fromjson = vl_api_ip_route_add_del_reply_t_fromjson,
    .calc_size = vl_api_ip_route_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_route_add_del", api_ip_route_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_ROUTE_ADD_DEL_V2_REPLY + msg_id_base,
    .name = "ip_route_add_del_v2_reply",
    .handler = vl_api_ip_route_add_del_v2_reply_t_handler,
    .endian = vl_api_ip_route_add_del_v2_reply_t_endian,
    .format_fn = vl_api_ip_route_add_del_v2_reply_t_format,
    .size = sizeof(vl_api_ip_route_add_del_v2_reply_t),
    .traced = 1,
    .tojson = vl_api_ip_route_add_del_v2_reply_t_tojson,
    .fromjson = vl_api_ip_route_add_del_v2_reply_t_fromjson,
    .calc_size = vl_api_ip_route_add_del_v2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_route_add_del_v2", api_ip_route_add_del_v2);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_ROUTE_DETAILS + msg_id_base,
    .name = "ip_route_details",
    .handler = vl_api_ip_route_details_t_handler,
    .endian = vl_api_ip_route_details_t_endian,
    .format_fn = vl_api_ip_route_details_t_format,
    .size = sizeof(vl_api_ip_route_details_t),
    .traced = 1,
    .tojson = vl_api_ip_route_details_t_tojson,
    .fromjson = vl_api_ip_route_details_t_fromjson,
    .calc_size = vl_api_ip_route_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_route_dump", api_ip_route_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_ROUTE_V2_DETAILS + msg_id_base,
    .name = "ip_route_v2_details",
    .handler = vl_api_ip_route_v2_details_t_handler,
    .endian = vl_api_ip_route_v2_details_t_endian,
    .format_fn = vl_api_ip_route_v2_details_t_format,
    .size = sizeof(vl_api_ip_route_v2_details_t),
    .traced = 1,
    .tojson = vl_api_ip_route_v2_details_t_tojson,
    .fromjson = vl_api_ip_route_v2_details_t_fromjson,
    .calc_size = vl_api_ip_route_v2_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_route_v2_dump", api_ip_route_v2_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_ROUTE_LOOKUP_REPLY + msg_id_base,
    .name = "ip_route_lookup_reply",
    .handler = vl_api_ip_route_lookup_reply_t_handler,
    .endian = vl_api_ip_route_lookup_reply_t_endian,
    .format_fn = vl_api_ip_route_lookup_reply_t_format,
    .size = sizeof(vl_api_ip_route_lookup_reply_t),
    .traced = 1,
    .tojson = vl_api_ip_route_lookup_reply_t_tojson,
    .fromjson = vl_api_ip_route_lookup_reply_t_fromjson,
    .calc_size = vl_api_ip_route_lookup_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_route_lookup", api_ip_route_lookup);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_ROUTE_LOOKUP_V2_REPLY + msg_id_base,
    .name = "ip_route_lookup_v2_reply",
    .handler = vl_api_ip_route_lookup_v2_reply_t_handler,
    .endian = vl_api_ip_route_lookup_v2_reply_t_endian,
    .format_fn = vl_api_ip_route_lookup_v2_reply_t_format,
    .size = sizeof(vl_api_ip_route_lookup_v2_reply_t),
    .traced = 1,
    .tojson = vl_api_ip_route_lookup_v2_reply_t_tojson,
    .fromjson = vl_api_ip_route_lookup_v2_reply_t_fromjson,
    .calc_size = vl_api_ip_route_lookup_v2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_route_lookup_v2", api_ip_route_lookup_v2);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SET_IP_FLOW_HASH_REPLY + msg_id_base,
    .name = "set_ip_flow_hash_reply",
    .handler = vl_api_set_ip_flow_hash_reply_t_handler,
    .endian = vl_api_set_ip_flow_hash_reply_t_endian,
    .format_fn = vl_api_set_ip_flow_hash_reply_t_format,
    .size = sizeof(vl_api_set_ip_flow_hash_reply_t),
    .traced = 1,
    .tojson = vl_api_set_ip_flow_hash_reply_t_tojson,
    .fromjson = vl_api_set_ip_flow_hash_reply_t_fromjson,
    .calc_size = vl_api_set_ip_flow_hash_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "set_ip_flow_hash", api_set_ip_flow_hash);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SET_IP_FLOW_HASH_V2_REPLY + msg_id_base,
    .name = "set_ip_flow_hash_v2_reply",
    .handler = vl_api_set_ip_flow_hash_v2_reply_t_handler,
    .endian = vl_api_set_ip_flow_hash_v2_reply_t_endian,
    .format_fn = vl_api_set_ip_flow_hash_v2_reply_t_format,
    .size = sizeof(vl_api_set_ip_flow_hash_v2_reply_t),
    .traced = 1,
    .tojson = vl_api_set_ip_flow_hash_v2_reply_t_tojson,
    .fromjson = vl_api_set_ip_flow_hash_v2_reply_t_fromjson,
    .calc_size = vl_api_set_ip_flow_hash_v2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "set_ip_flow_hash_v2", api_set_ip_flow_hash_v2);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SET_IP_FLOW_HASH_V3_REPLY + msg_id_base,
    .name = "set_ip_flow_hash_v3_reply",
    .handler = vl_api_set_ip_flow_hash_v3_reply_t_handler,
    .endian = vl_api_set_ip_flow_hash_v3_reply_t_endian,
    .format_fn = vl_api_set_ip_flow_hash_v3_reply_t_format,
    .size = sizeof(vl_api_set_ip_flow_hash_v3_reply_t),
    .traced = 1,
    .tojson = vl_api_set_ip_flow_hash_v3_reply_t_tojson,
    .fromjson = vl_api_set_ip_flow_hash_v3_reply_t_fromjson,
    .calc_size = vl_api_set_ip_flow_hash_v3_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "set_ip_flow_hash_v3", api_set_ip_flow_hash_v3);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SET_IP_FLOW_HASH_ROUTER_ID_REPLY + msg_id_base,
    .name = "set_ip_flow_hash_router_id_reply",
    .handler = vl_api_set_ip_flow_hash_router_id_reply_t_handler,
    .endian = vl_api_set_ip_flow_hash_router_id_reply_t_endian,
    .format_fn = vl_api_set_ip_flow_hash_router_id_reply_t_format,
    .size = sizeof(vl_api_set_ip_flow_hash_router_id_reply_t),
    .traced = 1,
    .tojson = vl_api_set_ip_flow_hash_router_id_reply_t_tojson,
    .fromjson = vl_api_set_ip_flow_hash_router_id_reply_t_fromjson,
    .calc_size = vl_api_set_ip_flow_hash_router_id_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "set_ip_flow_hash_router_id", api_set_ip_flow_hash_router_id);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_IP6_ENABLE_DISABLE_REPLY + msg_id_base,
    .name = "sw_interface_ip6_enable_disable_reply",
    .handler = vl_api_sw_interface_ip6_enable_disable_reply_t_handler,
    .endian = vl_api_sw_interface_ip6_enable_disable_reply_t_endian,
    .format_fn = vl_api_sw_interface_ip6_enable_disable_reply_t_format,
    .size = sizeof(vl_api_sw_interface_ip6_enable_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_ip6_enable_disable_reply_t_tojson,
    .fromjson = vl_api_sw_interface_ip6_enable_disable_reply_t_fromjson,
    .calc_size = vl_api_sw_interface_ip6_enable_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_ip6_enable_disable", api_sw_interface_ip6_enable_disable);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_IP4_ENABLE_DISABLE_REPLY + msg_id_base,
    .name = "sw_interface_ip4_enable_disable_reply",
    .handler = vl_api_sw_interface_ip4_enable_disable_reply_t_handler,
    .endian = vl_api_sw_interface_ip4_enable_disable_reply_t_endian,
    .format_fn = vl_api_sw_interface_ip4_enable_disable_reply_t_format,
    .size = sizeof(vl_api_sw_interface_ip4_enable_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_ip4_enable_disable_reply_t_tojson,
    .fromjson = vl_api_sw_interface_ip4_enable_disable_reply_t_fromjson,
    .calc_size = vl_api_sw_interface_ip4_enable_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_ip4_enable_disable", api_sw_interface_ip4_enable_disable);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_MTABLE_DETAILS + msg_id_base,
    .name = "ip_mtable_details",
    .handler = vl_api_ip_mtable_details_t_handler,
    .endian = vl_api_ip_mtable_details_t_endian,
    .format_fn = vl_api_ip_mtable_details_t_format,
    .size = sizeof(vl_api_ip_mtable_details_t),
    .traced = 1,
    .tojson = vl_api_ip_mtable_details_t_tojson,
    .fromjson = vl_api_ip_mtable_details_t_fromjson,
    .calc_size = vl_api_ip_mtable_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_mtable_dump", api_ip_mtable_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_MROUTE_ADD_DEL_REPLY + msg_id_base,
    .name = "ip_mroute_add_del_reply",
    .handler = vl_api_ip_mroute_add_del_reply_t_handler,
    .endian = vl_api_ip_mroute_add_del_reply_t_endian,
    .format_fn = vl_api_ip_mroute_add_del_reply_t_format,
    .size = sizeof(vl_api_ip_mroute_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_ip_mroute_add_del_reply_t_tojson,
    .fromjson = vl_api_ip_mroute_add_del_reply_t_fromjson,
    .calc_size = vl_api_ip_mroute_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_mroute_add_del", api_ip_mroute_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_MROUTE_DETAILS + msg_id_base,
    .name = "ip_mroute_details",
    .handler = vl_api_ip_mroute_details_t_handler,
    .endian = vl_api_ip_mroute_details_t_endian,
    .format_fn = vl_api_ip_mroute_details_t_format,
    .size = sizeof(vl_api_ip_mroute_details_t),
    .traced = 1,
    .tojson = vl_api_ip_mroute_details_t_tojson,
    .fromjson = vl_api_ip_mroute_details_t_fromjson,
    .calc_size = vl_api_ip_mroute_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_mroute_dump", api_ip_mroute_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_ADDRESS_DETAILS + msg_id_base,
    .name = "ip_address_details",
    .handler = vl_api_ip_address_details_t_handler,
    .endian = vl_api_ip_address_details_t_endian,
    .format_fn = vl_api_ip_address_details_t_format,
    .size = sizeof(vl_api_ip_address_details_t),
    .traced = 1,
    .tojson = vl_api_ip_address_details_t_tojson,
    .fromjson = vl_api_ip_address_details_t_fromjson,
    .calc_size = vl_api_ip_address_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_address_dump", api_ip_address_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_UNNUMBERED_DETAILS + msg_id_base,
    .name = "ip_unnumbered_details",
    .handler = vl_api_ip_unnumbered_details_t_handler,
    .endian = vl_api_ip_unnumbered_details_t_endian,
    .format_fn = vl_api_ip_unnumbered_details_t_format,
    .size = sizeof(vl_api_ip_unnumbered_details_t),
    .traced = 1,
    .tojson = vl_api_ip_unnumbered_details_t_tojson,
    .fromjson = vl_api_ip_unnumbered_details_t_fromjson,
    .calc_size = vl_api_ip_unnumbered_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_unnumbered_dump", api_ip_unnumbered_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_DETAILS + msg_id_base,
    .name = "ip_details",
    .handler = vl_api_ip_details_t_handler,
    .endian = vl_api_ip_details_t_endian,
    .format_fn = vl_api_ip_details_t_format,
    .size = sizeof(vl_api_ip_details_t),
    .traced = 1,
    .tojson = vl_api_ip_details_t_tojson,
    .fromjson = vl_api_ip_details_t_fromjson,
    .calc_size = vl_api_ip_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_dump", api_ip_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MFIB_SIGNAL_DETAILS + msg_id_base,
    .name = "mfib_signal_details",
    .handler = vl_api_mfib_signal_details_t_handler,
    .endian = vl_api_mfib_signal_details_t_endian,
    .format_fn = vl_api_mfib_signal_details_t_format,
    .size = sizeof(vl_api_mfib_signal_details_t),
    .traced = 1,
    .tojson = vl_api_mfib_signal_details_t_tojson,
    .fromjson = vl_api_mfib_signal_details_t_fromjson,
    .calc_size = vl_api_mfib_signal_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "mfib_signal_dump", api_mfib_signal_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_PUNT_POLICE_REPLY + msg_id_base,
    .name = "ip_punt_police_reply",
    .handler = vl_api_ip_punt_police_reply_t_handler,
    .endian = vl_api_ip_punt_police_reply_t_endian,
    .format_fn = vl_api_ip_punt_police_reply_t_format,
    .size = sizeof(vl_api_ip_punt_police_reply_t),
    .traced = 1,
    .tojson = vl_api_ip_punt_police_reply_t_tojson,
    .fromjson = vl_api_ip_punt_police_reply_t_fromjson,
    .calc_size = vl_api_ip_punt_police_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_punt_police", api_ip_punt_police);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_PUNT_REDIRECT_REPLY + msg_id_base,
    .name = "ip_punt_redirect_reply",
    .handler = vl_api_ip_punt_redirect_reply_t_handler,
    .endian = vl_api_ip_punt_redirect_reply_t_endian,
    .format_fn = vl_api_ip_punt_redirect_reply_t_format,
    .size = sizeof(vl_api_ip_punt_redirect_reply_t),
    .traced = 1,
    .tojson = vl_api_ip_punt_redirect_reply_t_tojson,
    .fromjson = vl_api_ip_punt_redirect_reply_t_fromjson,
    .calc_size = vl_api_ip_punt_redirect_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_punt_redirect", api_ip_punt_redirect);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_PUNT_REDIRECT_DETAILS + msg_id_base,
    .name = "ip_punt_redirect_details",
    .handler = vl_api_ip_punt_redirect_details_t_handler,
    .endian = vl_api_ip_punt_redirect_details_t_endian,
    .format_fn = vl_api_ip_punt_redirect_details_t_format,
    .size = sizeof(vl_api_ip_punt_redirect_details_t),
    .traced = 1,
    .tojson = vl_api_ip_punt_redirect_details_t_tojson,
    .fromjson = vl_api_ip_punt_redirect_details_t_fromjson,
    .calc_size = vl_api_ip_punt_redirect_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_punt_redirect_dump", api_ip_punt_redirect_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ADD_DEL_IP_PUNT_REDIRECT_V2_REPLY + msg_id_base,
    .name = "add_del_ip_punt_redirect_v2_reply",
    .handler = vl_api_add_del_ip_punt_redirect_v2_reply_t_handler,
    .endian = vl_api_add_del_ip_punt_redirect_v2_reply_t_endian,
    .format_fn = vl_api_add_del_ip_punt_redirect_v2_reply_t_format,
    .size = sizeof(vl_api_add_del_ip_punt_redirect_v2_reply_t),
    .traced = 1,
    .tojson = vl_api_add_del_ip_punt_redirect_v2_reply_t_tojson,
    .fromjson = vl_api_add_del_ip_punt_redirect_v2_reply_t_fromjson,
    .calc_size = vl_api_add_del_ip_punt_redirect_v2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "add_del_ip_punt_redirect_v2", api_add_del_ip_punt_redirect_v2);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_PUNT_REDIRECT_V2_DETAILS + msg_id_base,
    .name = "ip_punt_redirect_v2_details",
    .handler = vl_api_ip_punt_redirect_v2_details_t_handler,
    .endian = vl_api_ip_punt_redirect_v2_details_t_endian,
    .format_fn = vl_api_ip_punt_redirect_v2_details_t_format,
    .size = sizeof(vl_api_ip_punt_redirect_v2_details_t),
    .traced = 1,
    .tojson = vl_api_ip_punt_redirect_v2_details_t_tojson,
    .fromjson = vl_api_ip_punt_redirect_v2_details_t_fromjson,
    .calc_size = vl_api_ip_punt_redirect_v2_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_punt_redirect_v2_dump", api_ip_punt_redirect_v2_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_CONTAINER_PROXY_ADD_DEL_REPLY + msg_id_base,
    .name = "ip_container_proxy_add_del_reply",
    .handler = vl_api_ip_container_proxy_add_del_reply_t_handler,
    .endian = vl_api_ip_container_proxy_add_del_reply_t_endian,
    .format_fn = vl_api_ip_container_proxy_add_del_reply_t_format,
    .size = sizeof(vl_api_ip_container_proxy_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_ip_container_proxy_add_del_reply_t_tojson,
    .fromjson = vl_api_ip_container_proxy_add_del_reply_t_fromjson,
    .calc_size = vl_api_ip_container_proxy_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_container_proxy_add_del", api_ip_container_proxy_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_CONTAINER_PROXY_DETAILS + msg_id_base,
    .name = "ip_container_proxy_details",
    .handler = vl_api_ip_container_proxy_details_t_handler,
    .endian = vl_api_ip_container_proxy_details_t_endian,
    .format_fn = vl_api_ip_container_proxy_details_t_format,
    .size = sizeof(vl_api_ip_container_proxy_details_t),
    .traced = 1,
    .tojson = vl_api_ip_container_proxy_details_t_tojson,
    .fromjson = vl_api_ip_container_proxy_details_t_fromjson,
    .calc_size = vl_api_ip_container_proxy_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_container_proxy_dump", api_ip_container_proxy_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_SOURCE_AND_PORT_RANGE_CHECK_ADD_DEL_REPLY + msg_id_base,
    .name = "ip_source_and_port_range_check_add_del_reply",
    .handler = vl_api_ip_source_and_port_range_check_add_del_reply_t_handler,
    .endian = vl_api_ip_source_and_port_range_check_add_del_reply_t_endian,
    .format_fn = vl_api_ip_source_and_port_range_check_add_del_reply_t_format,
    .size = sizeof(vl_api_ip_source_and_port_range_check_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_ip_source_and_port_range_check_add_del_reply_t_tojson,
    .fromjson = vl_api_ip_source_and_port_range_check_add_del_reply_t_fromjson,
    .calc_size = vl_api_ip_source_and_port_range_check_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_source_and_port_range_check_add_del", api_ip_source_and_port_range_check_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_SOURCE_AND_PORT_RANGE_CHECK_INTERFACE_ADD_DEL_REPLY + msg_id_base,
    .name = "ip_source_and_port_range_check_interface_add_del_reply",
    .handler = vl_api_ip_source_and_port_range_check_interface_add_del_reply_t_handler,
    .endian = vl_api_ip_source_and_port_range_check_interface_add_del_reply_t_endian,
    .format_fn = vl_api_ip_source_and_port_range_check_interface_add_del_reply_t_format,
    .size = sizeof(vl_api_ip_source_and_port_range_check_interface_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_ip_source_and_port_range_check_interface_add_del_reply_t_tojson,
    .fromjson = vl_api_ip_source_and_port_range_check_interface_add_del_reply_t_fromjson,
    .calc_size = vl_api_ip_source_and_port_range_check_interface_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_source_and_port_range_check_interface_add_del", api_ip_source_and_port_range_check_interface_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_IP6_SET_LINK_LOCAL_ADDRESS_REPLY + msg_id_base,
    .name = "sw_interface_ip6_set_link_local_address_reply",
    .handler = vl_api_sw_interface_ip6_set_link_local_address_reply_t_handler,
    .endian = vl_api_sw_interface_ip6_set_link_local_address_reply_t_endian,
    .format_fn = vl_api_sw_interface_ip6_set_link_local_address_reply_t_format,
    .size = sizeof(vl_api_sw_interface_ip6_set_link_local_address_reply_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_ip6_set_link_local_address_reply_t_tojson,
    .fromjson = vl_api_sw_interface_ip6_set_link_local_address_reply_t_fromjson,
    .calc_size = vl_api_sw_interface_ip6_set_link_local_address_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_ip6_set_link_local_address", api_sw_interface_ip6_set_link_local_address);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_IP6_GET_LINK_LOCAL_ADDRESS_REPLY + msg_id_base,
    .name = "sw_interface_ip6_get_link_local_address_reply",
    .handler = vl_api_sw_interface_ip6_get_link_local_address_reply_t_handler,
    .endian = vl_api_sw_interface_ip6_get_link_local_address_reply_t_endian,
    .format_fn = vl_api_sw_interface_ip6_get_link_local_address_reply_t_format,
    .size = sizeof(vl_api_sw_interface_ip6_get_link_local_address_reply_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_ip6_get_link_local_address_reply_t_tojson,
    .fromjson = vl_api_sw_interface_ip6_get_link_local_address_reply_t_fromjson,
    .calc_size = vl_api_sw_interface_ip6_get_link_local_address_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_ip6_get_link_local_address", api_sw_interface_ip6_get_link_local_address);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IOAM_ENABLE_REPLY + msg_id_base,
    .name = "ioam_enable_reply",
    .handler = vl_api_ioam_enable_reply_t_handler,
    .endian = vl_api_ioam_enable_reply_t_endian,
    .format_fn = vl_api_ioam_enable_reply_t_format,
    .size = sizeof(vl_api_ioam_enable_reply_t),
    .traced = 1,
    .tojson = vl_api_ioam_enable_reply_t_tojson,
    .fromjson = vl_api_ioam_enable_reply_t_fromjson,
    .calc_size = vl_api_ioam_enable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ioam_enable", api_ioam_enable);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IOAM_DISABLE_REPLY + msg_id_base,
    .name = "ioam_disable_reply",
    .handler = vl_api_ioam_disable_reply_t_handler,
    .endian = vl_api_ioam_disable_reply_t_endian,
    .format_fn = vl_api_ioam_disable_reply_t_format,
    .size = sizeof(vl_api_ioam_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_ioam_disable_reply_t_tojson,
    .fromjson = vl_api_ioam_disable_reply_t_fromjson,
    .calc_size = vl_api_ioam_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ioam_disable", api_ioam_disable);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_REASSEMBLY_SET_REPLY + msg_id_base,
    .name = "ip_reassembly_set_reply",
    .handler = vl_api_ip_reassembly_set_reply_t_handler,
    .endian = vl_api_ip_reassembly_set_reply_t_endian,
    .format_fn = vl_api_ip_reassembly_set_reply_t_format,
    .size = sizeof(vl_api_ip_reassembly_set_reply_t),
    .traced = 1,
    .tojson = vl_api_ip_reassembly_set_reply_t_tojson,
    .fromjson = vl_api_ip_reassembly_set_reply_t_fromjson,
    .calc_size = vl_api_ip_reassembly_set_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_reassembly_set", api_ip_reassembly_set);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_REASSEMBLY_GET_REPLY + msg_id_base,
    .name = "ip_reassembly_get_reply",
    .handler = vl_api_ip_reassembly_get_reply_t_handler,
    .endian = vl_api_ip_reassembly_get_reply_t_endian,
    .format_fn = vl_api_ip_reassembly_get_reply_t_format,
    .size = sizeof(vl_api_ip_reassembly_get_reply_t),
    .traced = 1,
    .tojson = vl_api_ip_reassembly_get_reply_t_tojson,
    .fromjson = vl_api_ip_reassembly_get_reply_t_fromjson,
    .calc_size = vl_api_ip_reassembly_get_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_reassembly_get", api_ip_reassembly_get);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_REASSEMBLY_ENABLE_DISABLE_REPLY + msg_id_base,
    .name = "ip_reassembly_enable_disable_reply",
    .handler = vl_api_ip_reassembly_enable_disable_reply_t_handler,
    .endian = vl_api_ip_reassembly_enable_disable_reply_t_endian,
    .format_fn = vl_api_ip_reassembly_enable_disable_reply_t_format,
    .size = sizeof(vl_api_ip_reassembly_enable_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_ip_reassembly_enable_disable_reply_t_tojson,
    .fromjson = vl_api_ip_reassembly_enable_disable_reply_t_fromjson,
    .calc_size = vl_api_ip_reassembly_enable_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_reassembly_enable_disable", api_ip_reassembly_enable_disable);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_LOCAL_REASS_ENABLE_DISABLE_REPLY + msg_id_base,
    .name = "ip_local_reass_enable_disable_reply",
    .handler = vl_api_ip_local_reass_enable_disable_reply_t_handler,
    .endian = vl_api_ip_local_reass_enable_disable_reply_t_endian,
    .format_fn = vl_api_ip_local_reass_enable_disable_reply_t_format,
    .size = sizeof(vl_api_ip_local_reass_enable_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_ip_local_reass_enable_disable_reply_t_tojson,
    .fromjson = vl_api_ip_local_reass_enable_disable_reply_t_fromjson,
    .calc_size = vl_api_ip_local_reass_enable_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_local_reass_enable_disable", api_ip_local_reass_enable_disable);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_LOCAL_REASS_GET_REPLY + msg_id_base,
    .name = "ip_local_reass_get_reply",
    .handler = vl_api_ip_local_reass_get_reply_t_handler,
    .endian = vl_api_ip_local_reass_get_reply_t_endian,
    .format_fn = vl_api_ip_local_reass_get_reply_t_format,
    .size = sizeof(vl_api_ip_local_reass_get_reply_t),
    .traced = 1,
    .tojson = vl_api_ip_local_reass_get_reply_t_tojson,
    .fromjson = vl_api_ip_local_reass_get_reply_t_fromjson,
    .calc_size = vl_api_ip_local_reass_get_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_local_reass_get", api_ip_local_reass_get);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_PATH_MTU_UPDATE_REPLY + msg_id_base,
    .name = "ip_path_mtu_update_reply",
    .handler = vl_api_ip_path_mtu_update_reply_t_handler,
    .endian = vl_api_ip_path_mtu_update_reply_t_endian,
    .format_fn = vl_api_ip_path_mtu_update_reply_t_format,
    .size = sizeof(vl_api_ip_path_mtu_update_reply_t),
    .traced = 1,
    .tojson = vl_api_ip_path_mtu_update_reply_t_tojson,
    .fromjson = vl_api_ip_path_mtu_update_reply_t_fromjson,
    .calc_size = vl_api_ip_path_mtu_update_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_path_mtu_update", api_ip_path_mtu_update);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_PATH_MTU_REPLACE_BEGIN_REPLY + msg_id_base,
    .name = "ip_path_mtu_replace_begin_reply",
    .handler = vl_api_ip_path_mtu_replace_begin_reply_t_handler,
    .endian = vl_api_ip_path_mtu_replace_begin_reply_t_endian,
    .format_fn = vl_api_ip_path_mtu_replace_begin_reply_t_format,
    .size = sizeof(vl_api_ip_path_mtu_replace_begin_reply_t),
    .traced = 1,
    .tojson = vl_api_ip_path_mtu_replace_begin_reply_t_tojson,
    .fromjson = vl_api_ip_path_mtu_replace_begin_reply_t_fromjson,
    .calc_size = vl_api_ip_path_mtu_replace_begin_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_path_mtu_replace_begin", api_ip_path_mtu_replace_begin);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_PATH_MTU_REPLACE_END_REPLY + msg_id_base,
    .name = "ip_path_mtu_replace_end_reply",
    .handler = vl_api_ip_path_mtu_replace_end_reply_t_handler,
    .endian = vl_api_ip_path_mtu_replace_end_reply_t_endian,
    .format_fn = vl_api_ip_path_mtu_replace_end_reply_t_format,
    .size = sizeof(vl_api_ip_path_mtu_replace_end_reply_t),
    .traced = 1,
    .tojson = vl_api_ip_path_mtu_replace_end_reply_t_tojson,
    .fromjson = vl_api_ip_path_mtu_replace_end_reply_t_fromjson,
    .calc_size = vl_api_ip_path_mtu_replace_end_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_path_mtu_replace_end", api_ip_path_mtu_replace_end);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   ip_test_main_t * mainp = &ip_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("ip_4a15ce55");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "ip plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
