#define vl_endianfun            /* define message structures */
#include "one.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "one.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "one.api.h"
#undef vl_printfun

/* Generation not supported (vl_api_one_add_del_locator_set_reply_t_handler()) */
#ifndef VL_API_ONE_ADD_DEL_LOCATOR_REPLY_T_HANDLER
static void
vl_api_one_add_del_locator_reply_t_handler (vl_api_one_add_del_locator_reply_t * mp) {
   vat_main_t * vam = one_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_ONE_ADD_DEL_LOCAL_EID_REPLY_T_HANDLER
static void
vl_api_one_add_del_local_eid_reply_t_handler (vl_api_one_add_del_local_eid_reply_t * mp) {
   vat_main_t * vam = one_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_ONE_MAP_REGISTER_SET_TTL_REPLY_T_HANDLER
static void
vl_api_one_map_register_set_ttl_reply_t_handler (vl_api_one_map_register_set_ttl_reply_t * mp) {
   vat_main_t * vam = one_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_show_one_map_register_ttl_reply_t_handler()) */
#ifndef VL_API_ONE_ADD_DEL_MAP_SERVER_REPLY_T_HANDLER
static void
vl_api_one_add_del_map_server_reply_t_handler (vl_api_one_add_del_map_server_reply_t * mp) {
   vat_main_t * vam = one_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_ONE_ADD_DEL_MAP_RESOLVER_REPLY_T_HANDLER
static void
vl_api_one_add_del_map_resolver_reply_t_handler (vl_api_one_add_del_map_resolver_reply_t * mp) {
   vat_main_t * vam = one_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_ONE_ENABLE_DISABLE_REPLY_T_HANDLER
static void
vl_api_one_enable_disable_reply_t_handler (vl_api_one_enable_disable_reply_t * mp) {
   vat_main_t * vam = one_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_ONE_NSH_SET_LOCATOR_SET_REPLY_T_HANDLER
static void
vl_api_one_nsh_set_locator_set_reply_t_handler (vl_api_one_nsh_set_locator_set_reply_t * mp) {
   vat_main_t * vam = one_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_ONE_PITR_SET_LOCATOR_SET_REPLY_T_HANDLER
static void
vl_api_one_pitr_set_locator_set_reply_t_handler (vl_api_one_pitr_set_locator_set_reply_t * mp) {
   vat_main_t * vam = one_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_ONE_USE_PETR_REPLY_T_HANDLER
static void
vl_api_one_use_petr_reply_t_handler (vl_api_one_use_petr_reply_t * mp) {
   vat_main_t * vam = one_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_show_one_use_petr_reply_t_handler()) */
/* Generation not supported (vl_api_show_one_rloc_probe_state_reply_t_handler()) */
#ifndef VL_API_ONE_RLOC_PROBE_ENABLE_DISABLE_REPLY_T_HANDLER
static void
vl_api_one_rloc_probe_enable_disable_reply_t_handler (vl_api_one_rloc_probe_enable_disable_reply_t * mp) {
   vat_main_t * vam = one_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_ONE_MAP_REGISTER_ENABLE_DISABLE_REPLY_T_HANDLER
static void
vl_api_one_map_register_enable_disable_reply_t_handler (vl_api_one_map_register_enable_disable_reply_t * mp) {
   vat_main_t * vam = one_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_show_one_map_register_state_reply_t_handler()) */
#ifndef VL_API_ONE_MAP_REQUEST_MODE_REPLY_T_HANDLER
static void
vl_api_one_map_request_mode_reply_t_handler (vl_api_one_map_request_mode_reply_t * mp) {
   vat_main_t * vam = one_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_show_one_map_request_mode_reply_t_handler()) */
#ifndef VL_API_ONE_ADD_DEL_REMOTE_MAPPING_REPLY_T_HANDLER
static void
vl_api_one_add_del_remote_mapping_reply_t_handler (vl_api_one_add_del_remote_mapping_reply_t * mp) {
   vat_main_t * vam = one_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_ONE_ADD_DEL_L2_ARP_ENTRY_REPLY_T_HANDLER
static void
vl_api_one_add_del_l2_arp_entry_reply_t_handler (vl_api_one_add_del_l2_arp_entry_reply_t * mp) {
   vat_main_t * vam = one_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_one_l2_arp_entries_get_reply_t_handler()) */
#ifndef VL_API_ONE_ADD_DEL_NDP_ENTRY_REPLY_T_HANDLER
static void
vl_api_one_add_del_ndp_entry_reply_t_handler (vl_api_one_add_del_ndp_entry_reply_t * mp) {
   vat_main_t * vam = one_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_one_ndp_entries_get_reply_t_handler()) */
#ifndef VL_API_ONE_SET_TRANSPORT_PROTOCOL_REPLY_T_HANDLER
static void
vl_api_one_set_transport_protocol_reply_t_handler (vl_api_one_set_transport_protocol_reply_t * mp) {
   vat_main_t * vam = one_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_one_get_transport_protocol_reply_t_handler()) */
/* Generation not supported (vl_api_one_ndp_bd_get_reply_t_handler()) */
/* Generation not supported (vl_api_one_l2_arp_bd_get_reply_t_handler()) */
#ifndef VL_API_ONE_ADD_DEL_ADJACENCY_REPLY_T_HANDLER
static void
vl_api_one_add_del_adjacency_reply_t_handler (vl_api_one_add_del_adjacency_reply_t * mp) {
   vat_main_t * vam = one_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_ONE_ADD_DEL_MAP_REQUEST_ITR_RLOCS_REPLY_T_HANDLER
static void
vl_api_one_add_del_map_request_itr_rlocs_reply_t_handler (vl_api_one_add_del_map_request_itr_rlocs_reply_t * mp) {
   vat_main_t * vam = one_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_ONE_EID_TABLE_ADD_DEL_MAP_REPLY_T_HANDLER
static void
vl_api_one_eid_table_add_del_map_reply_t_handler (vl_api_one_eid_table_add_del_map_reply_t * mp) {
   vat_main_t * vam = one_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_one_locator_details_t_handler()) */
/* Generation not supported (vl_api_one_locator_set_details_t_handler()) */
/* Generation not supported (vl_api_one_eid_table_details_t_handler()) */
/* Generation not supported (vl_api_one_adjacencies_get_reply_t_handler()) */
/* Generation not supported (vl_api_one_eid_table_map_details_t_handler()) */
/* Generation not supported (vl_api_one_eid_table_vni_details_t_handler()) */
/* Generation not supported (vl_api_one_map_resolver_details_t_handler()) */
/* Generation not supported (vl_api_one_map_server_details_t_handler()) */
/* Generation not supported (vl_api_show_one_status_reply_t_handler()) */
/* Generation not supported (vl_api_one_get_map_request_itr_rlocs_reply_t_handler()) */
/* Generation not supported (vl_api_show_one_nsh_mapping_reply_t_handler()) */
/* Generation not supported (vl_api_show_one_pitr_reply_t_handler()) */
/* Generation not supported (vl_api_one_stats_details_t_handler()) */
#ifndef VL_API_ONE_STATS_FLUSH_REPLY_T_HANDLER
static void
vl_api_one_stats_flush_reply_t_handler (vl_api_one_stats_flush_reply_t * mp) {
   vat_main_t * vam = one_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_ONE_STATS_ENABLE_DISABLE_REPLY_T_HANDLER
static void
vl_api_one_stats_enable_disable_reply_t_handler (vl_api_one_stats_enable_disable_reply_t * mp) {
   vat_main_t * vam = one_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_show_one_stats_enable_disable_reply_t_handler()) */
#ifndef VL_API_ONE_MAP_REGISTER_FALLBACK_THRESHOLD_REPLY_T_HANDLER
static void
vl_api_one_map_register_fallback_threshold_reply_t_handler (vl_api_one_map_register_fallback_threshold_reply_t * mp) {
   vat_main_t * vam = one_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_show_one_map_register_fallback_threshold_reply_t_handler()) */
#ifndef VL_API_ONE_ENABLE_DISABLE_XTR_MODE_REPLY_T_HANDLER
static void
vl_api_one_enable_disable_xtr_mode_reply_t_handler (vl_api_one_enable_disable_xtr_mode_reply_t * mp) {
   vat_main_t * vam = one_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_one_show_xtr_mode_reply_t_handler()) */
#ifndef VL_API_ONE_ENABLE_DISABLE_PETR_MODE_REPLY_T_HANDLER
static void
vl_api_one_enable_disable_petr_mode_reply_t_handler (vl_api_one_enable_disable_petr_mode_reply_t * mp) {
   vat_main_t * vam = one_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_one_show_petr_mode_reply_t_handler()) */
#ifndef VL_API_ONE_ENABLE_DISABLE_PITR_MODE_REPLY_T_HANDLER
static void
vl_api_one_enable_disable_pitr_mode_reply_t_handler (vl_api_one_enable_disable_pitr_mode_reply_t * mp) {
   vat_main_t * vam = one_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_one_show_pitr_mode_reply_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_ADD_DEL_LOCATOR_SET_REPLY + msg_id_base,
    .name = "one_add_del_locator_set_reply",
    .handler = vl_api_one_add_del_locator_set_reply_t_handler,
    .endian = vl_api_one_add_del_locator_set_reply_t_endian,
    .format_fn = vl_api_one_add_del_locator_set_reply_t_format,
    .size = sizeof(vl_api_one_add_del_locator_set_reply_t),
    .traced = 1,
    .tojson = vl_api_one_add_del_locator_set_reply_t_tojson,
    .fromjson = vl_api_one_add_del_locator_set_reply_t_fromjson,
    .calc_size = vl_api_one_add_del_locator_set_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_add_del_locator_set", api_one_add_del_locator_set);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_ADD_DEL_LOCATOR_REPLY + msg_id_base,
    .name = "one_add_del_locator_reply",
    .handler = vl_api_one_add_del_locator_reply_t_handler,
    .endian = vl_api_one_add_del_locator_reply_t_endian,
    .format_fn = vl_api_one_add_del_locator_reply_t_format,
    .size = sizeof(vl_api_one_add_del_locator_reply_t),
    .traced = 1,
    .tojson = vl_api_one_add_del_locator_reply_t_tojson,
    .fromjson = vl_api_one_add_del_locator_reply_t_fromjson,
    .calc_size = vl_api_one_add_del_locator_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_add_del_locator", api_one_add_del_locator);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_ADD_DEL_LOCAL_EID_REPLY + msg_id_base,
    .name = "one_add_del_local_eid_reply",
    .handler = vl_api_one_add_del_local_eid_reply_t_handler,
    .endian = vl_api_one_add_del_local_eid_reply_t_endian,
    .format_fn = vl_api_one_add_del_local_eid_reply_t_format,
    .size = sizeof(vl_api_one_add_del_local_eid_reply_t),
    .traced = 1,
    .tojson = vl_api_one_add_del_local_eid_reply_t_tojson,
    .fromjson = vl_api_one_add_del_local_eid_reply_t_fromjson,
    .calc_size = vl_api_one_add_del_local_eid_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_add_del_local_eid", api_one_add_del_local_eid);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_MAP_REGISTER_SET_TTL_REPLY + msg_id_base,
    .name = "one_map_register_set_ttl_reply",
    .handler = vl_api_one_map_register_set_ttl_reply_t_handler,
    .endian = vl_api_one_map_register_set_ttl_reply_t_endian,
    .format_fn = vl_api_one_map_register_set_ttl_reply_t_format,
    .size = sizeof(vl_api_one_map_register_set_ttl_reply_t),
    .traced = 1,
    .tojson = vl_api_one_map_register_set_ttl_reply_t_tojson,
    .fromjson = vl_api_one_map_register_set_ttl_reply_t_fromjson,
    .calc_size = vl_api_one_map_register_set_ttl_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_map_register_set_ttl", api_one_map_register_set_ttl);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SHOW_ONE_MAP_REGISTER_TTL_REPLY + msg_id_base,
    .name = "show_one_map_register_ttl_reply",
    .handler = vl_api_show_one_map_register_ttl_reply_t_handler,
    .endian = vl_api_show_one_map_register_ttl_reply_t_endian,
    .format_fn = vl_api_show_one_map_register_ttl_reply_t_format,
    .size = sizeof(vl_api_show_one_map_register_ttl_reply_t),
    .traced = 1,
    .tojson = vl_api_show_one_map_register_ttl_reply_t_tojson,
    .fromjson = vl_api_show_one_map_register_ttl_reply_t_fromjson,
    .calc_size = vl_api_show_one_map_register_ttl_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "show_one_map_register_ttl", api_show_one_map_register_ttl);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_ADD_DEL_MAP_SERVER_REPLY + msg_id_base,
    .name = "one_add_del_map_server_reply",
    .handler = vl_api_one_add_del_map_server_reply_t_handler,
    .endian = vl_api_one_add_del_map_server_reply_t_endian,
    .format_fn = vl_api_one_add_del_map_server_reply_t_format,
    .size = sizeof(vl_api_one_add_del_map_server_reply_t),
    .traced = 1,
    .tojson = vl_api_one_add_del_map_server_reply_t_tojson,
    .fromjson = vl_api_one_add_del_map_server_reply_t_fromjson,
    .calc_size = vl_api_one_add_del_map_server_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_add_del_map_server", api_one_add_del_map_server);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_ADD_DEL_MAP_RESOLVER_REPLY + msg_id_base,
    .name = "one_add_del_map_resolver_reply",
    .handler = vl_api_one_add_del_map_resolver_reply_t_handler,
    .endian = vl_api_one_add_del_map_resolver_reply_t_endian,
    .format_fn = vl_api_one_add_del_map_resolver_reply_t_format,
    .size = sizeof(vl_api_one_add_del_map_resolver_reply_t),
    .traced = 1,
    .tojson = vl_api_one_add_del_map_resolver_reply_t_tojson,
    .fromjson = vl_api_one_add_del_map_resolver_reply_t_fromjson,
    .calc_size = vl_api_one_add_del_map_resolver_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_add_del_map_resolver", api_one_add_del_map_resolver);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_ENABLE_DISABLE_REPLY + msg_id_base,
    .name = "one_enable_disable_reply",
    .handler = vl_api_one_enable_disable_reply_t_handler,
    .endian = vl_api_one_enable_disable_reply_t_endian,
    .format_fn = vl_api_one_enable_disable_reply_t_format,
    .size = sizeof(vl_api_one_enable_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_one_enable_disable_reply_t_tojson,
    .fromjson = vl_api_one_enable_disable_reply_t_fromjson,
    .calc_size = vl_api_one_enable_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_enable_disable", api_one_enable_disable);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_NSH_SET_LOCATOR_SET_REPLY + msg_id_base,
    .name = "one_nsh_set_locator_set_reply",
    .handler = vl_api_one_nsh_set_locator_set_reply_t_handler,
    .endian = vl_api_one_nsh_set_locator_set_reply_t_endian,
    .format_fn = vl_api_one_nsh_set_locator_set_reply_t_format,
    .size = sizeof(vl_api_one_nsh_set_locator_set_reply_t),
    .traced = 1,
    .tojson = vl_api_one_nsh_set_locator_set_reply_t_tojson,
    .fromjson = vl_api_one_nsh_set_locator_set_reply_t_fromjson,
    .calc_size = vl_api_one_nsh_set_locator_set_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_nsh_set_locator_set", api_one_nsh_set_locator_set);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_PITR_SET_LOCATOR_SET_REPLY + msg_id_base,
    .name = "one_pitr_set_locator_set_reply",
    .handler = vl_api_one_pitr_set_locator_set_reply_t_handler,
    .endian = vl_api_one_pitr_set_locator_set_reply_t_endian,
    .format_fn = vl_api_one_pitr_set_locator_set_reply_t_format,
    .size = sizeof(vl_api_one_pitr_set_locator_set_reply_t),
    .traced = 1,
    .tojson = vl_api_one_pitr_set_locator_set_reply_t_tojson,
    .fromjson = vl_api_one_pitr_set_locator_set_reply_t_fromjson,
    .calc_size = vl_api_one_pitr_set_locator_set_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_pitr_set_locator_set", api_one_pitr_set_locator_set);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_USE_PETR_REPLY + msg_id_base,
    .name = "one_use_petr_reply",
    .handler = vl_api_one_use_petr_reply_t_handler,
    .endian = vl_api_one_use_petr_reply_t_endian,
    .format_fn = vl_api_one_use_petr_reply_t_format,
    .size = sizeof(vl_api_one_use_petr_reply_t),
    .traced = 1,
    .tojson = vl_api_one_use_petr_reply_t_tojson,
    .fromjson = vl_api_one_use_petr_reply_t_fromjson,
    .calc_size = vl_api_one_use_petr_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_use_petr", api_one_use_petr);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SHOW_ONE_USE_PETR_REPLY + msg_id_base,
    .name = "show_one_use_petr_reply",
    .handler = vl_api_show_one_use_petr_reply_t_handler,
    .endian = vl_api_show_one_use_petr_reply_t_endian,
    .format_fn = vl_api_show_one_use_petr_reply_t_format,
    .size = sizeof(vl_api_show_one_use_petr_reply_t),
    .traced = 1,
    .tojson = vl_api_show_one_use_petr_reply_t_tojson,
    .fromjson = vl_api_show_one_use_petr_reply_t_fromjson,
    .calc_size = vl_api_show_one_use_petr_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "show_one_use_petr", api_show_one_use_petr);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SHOW_ONE_RLOC_PROBE_STATE_REPLY + msg_id_base,
    .name = "show_one_rloc_probe_state_reply",
    .handler = vl_api_show_one_rloc_probe_state_reply_t_handler,
    .endian = vl_api_show_one_rloc_probe_state_reply_t_endian,
    .format_fn = vl_api_show_one_rloc_probe_state_reply_t_format,
    .size = sizeof(vl_api_show_one_rloc_probe_state_reply_t),
    .traced = 1,
    .tojson = vl_api_show_one_rloc_probe_state_reply_t_tojson,
    .fromjson = vl_api_show_one_rloc_probe_state_reply_t_fromjson,
    .calc_size = vl_api_show_one_rloc_probe_state_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "show_one_rloc_probe_state", api_show_one_rloc_probe_state);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_RLOC_PROBE_ENABLE_DISABLE_REPLY + msg_id_base,
    .name = "one_rloc_probe_enable_disable_reply",
    .handler = vl_api_one_rloc_probe_enable_disable_reply_t_handler,
    .endian = vl_api_one_rloc_probe_enable_disable_reply_t_endian,
    .format_fn = vl_api_one_rloc_probe_enable_disable_reply_t_format,
    .size = sizeof(vl_api_one_rloc_probe_enable_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_one_rloc_probe_enable_disable_reply_t_tojson,
    .fromjson = vl_api_one_rloc_probe_enable_disable_reply_t_fromjson,
    .calc_size = vl_api_one_rloc_probe_enable_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_rloc_probe_enable_disable", api_one_rloc_probe_enable_disable);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_MAP_REGISTER_ENABLE_DISABLE_REPLY + msg_id_base,
    .name = "one_map_register_enable_disable_reply",
    .handler = vl_api_one_map_register_enable_disable_reply_t_handler,
    .endian = vl_api_one_map_register_enable_disable_reply_t_endian,
    .format_fn = vl_api_one_map_register_enable_disable_reply_t_format,
    .size = sizeof(vl_api_one_map_register_enable_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_one_map_register_enable_disable_reply_t_tojson,
    .fromjson = vl_api_one_map_register_enable_disable_reply_t_fromjson,
    .calc_size = vl_api_one_map_register_enable_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_map_register_enable_disable", api_one_map_register_enable_disable);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SHOW_ONE_MAP_REGISTER_STATE_REPLY + msg_id_base,
    .name = "show_one_map_register_state_reply",
    .handler = vl_api_show_one_map_register_state_reply_t_handler,
    .endian = vl_api_show_one_map_register_state_reply_t_endian,
    .format_fn = vl_api_show_one_map_register_state_reply_t_format,
    .size = sizeof(vl_api_show_one_map_register_state_reply_t),
    .traced = 1,
    .tojson = vl_api_show_one_map_register_state_reply_t_tojson,
    .fromjson = vl_api_show_one_map_register_state_reply_t_fromjson,
    .calc_size = vl_api_show_one_map_register_state_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "show_one_map_register_state", api_show_one_map_register_state);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_MAP_REQUEST_MODE_REPLY + msg_id_base,
    .name = "one_map_request_mode_reply",
    .handler = vl_api_one_map_request_mode_reply_t_handler,
    .endian = vl_api_one_map_request_mode_reply_t_endian,
    .format_fn = vl_api_one_map_request_mode_reply_t_format,
    .size = sizeof(vl_api_one_map_request_mode_reply_t),
    .traced = 1,
    .tojson = vl_api_one_map_request_mode_reply_t_tojson,
    .fromjson = vl_api_one_map_request_mode_reply_t_fromjson,
    .calc_size = vl_api_one_map_request_mode_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_map_request_mode", api_one_map_request_mode);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SHOW_ONE_MAP_REQUEST_MODE_REPLY + msg_id_base,
    .name = "show_one_map_request_mode_reply",
    .handler = vl_api_show_one_map_request_mode_reply_t_handler,
    .endian = vl_api_show_one_map_request_mode_reply_t_endian,
    .format_fn = vl_api_show_one_map_request_mode_reply_t_format,
    .size = sizeof(vl_api_show_one_map_request_mode_reply_t),
    .traced = 1,
    .tojson = vl_api_show_one_map_request_mode_reply_t_tojson,
    .fromjson = vl_api_show_one_map_request_mode_reply_t_fromjson,
    .calc_size = vl_api_show_one_map_request_mode_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "show_one_map_request_mode", api_show_one_map_request_mode);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_ADD_DEL_REMOTE_MAPPING_REPLY + msg_id_base,
    .name = "one_add_del_remote_mapping_reply",
    .handler = vl_api_one_add_del_remote_mapping_reply_t_handler,
    .endian = vl_api_one_add_del_remote_mapping_reply_t_endian,
    .format_fn = vl_api_one_add_del_remote_mapping_reply_t_format,
    .size = sizeof(vl_api_one_add_del_remote_mapping_reply_t),
    .traced = 1,
    .tojson = vl_api_one_add_del_remote_mapping_reply_t_tojson,
    .fromjson = vl_api_one_add_del_remote_mapping_reply_t_fromjson,
    .calc_size = vl_api_one_add_del_remote_mapping_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_add_del_remote_mapping", api_one_add_del_remote_mapping);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_ADD_DEL_L2_ARP_ENTRY_REPLY + msg_id_base,
    .name = "one_add_del_l2_arp_entry_reply",
    .handler = vl_api_one_add_del_l2_arp_entry_reply_t_handler,
    .endian = vl_api_one_add_del_l2_arp_entry_reply_t_endian,
    .format_fn = vl_api_one_add_del_l2_arp_entry_reply_t_format,
    .size = sizeof(vl_api_one_add_del_l2_arp_entry_reply_t),
    .traced = 1,
    .tojson = vl_api_one_add_del_l2_arp_entry_reply_t_tojson,
    .fromjson = vl_api_one_add_del_l2_arp_entry_reply_t_fromjson,
    .calc_size = vl_api_one_add_del_l2_arp_entry_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_add_del_l2_arp_entry", api_one_add_del_l2_arp_entry);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_L2_ARP_ENTRIES_GET_REPLY + msg_id_base,
    .name = "one_l2_arp_entries_get_reply",
    .handler = vl_api_one_l2_arp_entries_get_reply_t_handler,
    .endian = vl_api_one_l2_arp_entries_get_reply_t_endian,
    .format_fn = vl_api_one_l2_arp_entries_get_reply_t_format,
    .size = sizeof(vl_api_one_l2_arp_entries_get_reply_t),
    .traced = 1,
    .tojson = vl_api_one_l2_arp_entries_get_reply_t_tojson,
    .fromjson = vl_api_one_l2_arp_entries_get_reply_t_fromjson,
    .calc_size = vl_api_one_l2_arp_entries_get_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_l2_arp_entries_get", api_one_l2_arp_entries_get);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_ADD_DEL_NDP_ENTRY_REPLY + msg_id_base,
    .name = "one_add_del_ndp_entry_reply",
    .handler = vl_api_one_add_del_ndp_entry_reply_t_handler,
    .endian = vl_api_one_add_del_ndp_entry_reply_t_endian,
    .format_fn = vl_api_one_add_del_ndp_entry_reply_t_format,
    .size = sizeof(vl_api_one_add_del_ndp_entry_reply_t),
    .traced = 1,
    .tojson = vl_api_one_add_del_ndp_entry_reply_t_tojson,
    .fromjson = vl_api_one_add_del_ndp_entry_reply_t_fromjson,
    .calc_size = vl_api_one_add_del_ndp_entry_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_add_del_ndp_entry", api_one_add_del_ndp_entry);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_NDP_ENTRIES_GET_REPLY + msg_id_base,
    .name = "one_ndp_entries_get_reply",
    .handler = vl_api_one_ndp_entries_get_reply_t_handler,
    .endian = vl_api_one_ndp_entries_get_reply_t_endian,
    .format_fn = vl_api_one_ndp_entries_get_reply_t_format,
    .size = sizeof(vl_api_one_ndp_entries_get_reply_t),
    .traced = 1,
    .tojson = vl_api_one_ndp_entries_get_reply_t_tojson,
    .fromjson = vl_api_one_ndp_entries_get_reply_t_fromjson,
    .calc_size = vl_api_one_ndp_entries_get_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_ndp_entries_get", api_one_ndp_entries_get);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_SET_TRANSPORT_PROTOCOL_REPLY + msg_id_base,
    .name = "one_set_transport_protocol_reply",
    .handler = vl_api_one_set_transport_protocol_reply_t_handler,
    .endian = vl_api_one_set_transport_protocol_reply_t_endian,
    .format_fn = vl_api_one_set_transport_protocol_reply_t_format,
    .size = sizeof(vl_api_one_set_transport_protocol_reply_t),
    .traced = 1,
    .tojson = vl_api_one_set_transport_protocol_reply_t_tojson,
    .fromjson = vl_api_one_set_transport_protocol_reply_t_fromjson,
    .calc_size = vl_api_one_set_transport_protocol_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_set_transport_protocol", api_one_set_transport_protocol);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_GET_TRANSPORT_PROTOCOL_REPLY + msg_id_base,
    .name = "one_get_transport_protocol_reply",
    .handler = vl_api_one_get_transport_protocol_reply_t_handler,
    .endian = vl_api_one_get_transport_protocol_reply_t_endian,
    .format_fn = vl_api_one_get_transport_protocol_reply_t_format,
    .size = sizeof(vl_api_one_get_transport_protocol_reply_t),
    .traced = 1,
    .tojson = vl_api_one_get_transport_protocol_reply_t_tojson,
    .fromjson = vl_api_one_get_transport_protocol_reply_t_fromjson,
    .calc_size = vl_api_one_get_transport_protocol_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_get_transport_protocol", api_one_get_transport_protocol);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_NDP_BD_GET_REPLY + msg_id_base,
    .name = "one_ndp_bd_get_reply",
    .handler = vl_api_one_ndp_bd_get_reply_t_handler,
    .endian = vl_api_one_ndp_bd_get_reply_t_endian,
    .format_fn = vl_api_one_ndp_bd_get_reply_t_format,
    .size = sizeof(vl_api_one_ndp_bd_get_reply_t),
    .traced = 1,
    .tojson = vl_api_one_ndp_bd_get_reply_t_tojson,
    .fromjson = vl_api_one_ndp_bd_get_reply_t_fromjson,
    .calc_size = vl_api_one_ndp_bd_get_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_ndp_bd_get", api_one_ndp_bd_get);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_L2_ARP_BD_GET_REPLY + msg_id_base,
    .name = "one_l2_arp_bd_get_reply",
    .handler = vl_api_one_l2_arp_bd_get_reply_t_handler,
    .endian = vl_api_one_l2_arp_bd_get_reply_t_endian,
    .format_fn = vl_api_one_l2_arp_bd_get_reply_t_format,
    .size = sizeof(vl_api_one_l2_arp_bd_get_reply_t),
    .traced = 1,
    .tojson = vl_api_one_l2_arp_bd_get_reply_t_tojson,
    .fromjson = vl_api_one_l2_arp_bd_get_reply_t_fromjson,
    .calc_size = vl_api_one_l2_arp_bd_get_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_l2_arp_bd_get", api_one_l2_arp_bd_get);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_ADD_DEL_ADJACENCY_REPLY + msg_id_base,
    .name = "one_add_del_adjacency_reply",
    .handler = vl_api_one_add_del_adjacency_reply_t_handler,
    .endian = vl_api_one_add_del_adjacency_reply_t_endian,
    .format_fn = vl_api_one_add_del_adjacency_reply_t_format,
    .size = sizeof(vl_api_one_add_del_adjacency_reply_t),
    .traced = 1,
    .tojson = vl_api_one_add_del_adjacency_reply_t_tojson,
    .fromjson = vl_api_one_add_del_adjacency_reply_t_fromjson,
    .calc_size = vl_api_one_add_del_adjacency_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_add_del_adjacency", api_one_add_del_adjacency);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_ADD_DEL_MAP_REQUEST_ITR_RLOCS_REPLY + msg_id_base,
    .name = "one_add_del_map_request_itr_rlocs_reply",
    .handler = vl_api_one_add_del_map_request_itr_rlocs_reply_t_handler,
    .endian = vl_api_one_add_del_map_request_itr_rlocs_reply_t_endian,
    .format_fn = vl_api_one_add_del_map_request_itr_rlocs_reply_t_format,
    .size = sizeof(vl_api_one_add_del_map_request_itr_rlocs_reply_t),
    .traced = 1,
    .tojson = vl_api_one_add_del_map_request_itr_rlocs_reply_t_tojson,
    .fromjson = vl_api_one_add_del_map_request_itr_rlocs_reply_t_fromjson,
    .calc_size = vl_api_one_add_del_map_request_itr_rlocs_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_add_del_map_request_itr_rlocs", api_one_add_del_map_request_itr_rlocs);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_EID_TABLE_ADD_DEL_MAP_REPLY + msg_id_base,
    .name = "one_eid_table_add_del_map_reply",
    .handler = vl_api_one_eid_table_add_del_map_reply_t_handler,
    .endian = vl_api_one_eid_table_add_del_map_reply_t_endian,
    .format_fn = vl_api_one_eid_table_add_del_map_reply_t_format,
    .size = sizeof(vl_api_one_eid_table_add_del_map_reply_t),
    .traced = 1,
    .tojson = vl_api_one_eid_table_add_del_map_reply_t_tojson,
    .fromjson = vl_api_one_eid_table_add_del_map_reply_t_fromjson,
    .calc_size = vl_api_one_eid_table_add_del_map_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_eid_table_add_del_map", api_one_eid_table_add_del_map);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_LOCATOR_DETAILS + msg_id_base,
    .name = "one_locator_details",
    .handler = vl_api_one_locator_details_t_handler,
    .endian = vl_api_one_locator_details_t_endian,
    .format_fn = vl_api_one_locator_details_t_format,
    .size = sizeof(vl_api_one_locator_details_t),
    .traced = 1,
    .tojson = vl_api_one_locator_details_t_tojson,
    .fromjson = vl_api_one_locator_details_t_fromjson,
    .calc_size = vl_api_one_locator_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_locator_dump", api_one_locator_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_LOCATOR_SET_DETAILS + msg_id_base,
    .name = "one_locator_set_details",
    .handler = vl_api_one_locator_set_details_t_handler,
    .endian = vl_api_one_locator_set_details_t_endian,
    .format_fn = vl_api_one_locator_set_details_t_format,
    .size = sizeof(vl_api_one_locator_set_details_t),
    .traced = 1,
    .tojson = vl_api_one_locator_set_details_t_tojson,
    .fromjson = vl_api_one_locator_set_details_t_fromjson,
    .calc_size = vl_api_one_locator_set_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_locator_set_dump", api_one_locator_set_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_EID_TABLE_DETAILS + msg_id_base,
    .name = "one_eid_table_details",
    .handler = vl_api_one_eid_table_details_t_handler,
    .endian = vl_api_one_eid_table_details_t_endian,
    .format_fn = vl_api_one_eid_table_details_t_format,
    .size = sizeof(vl_api_one_eid_table_details_t),
    .traced = 1,
    .tojson = vl_api_one_eid_table_details_t_tojson,
    .fromjson = vl_api_one_eid_table_details_t_fromjson,
    .calc_size = vl_api_one_eid_table_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_eid_table_dump", api_one_eid_table_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_ADJACENCIES_GET_REPLY + msg_id_base,
    .name = "one_adjacencies_get_reply",
    .handler = vl_api_one_adjacencies_get_reply_t_handler,
    .endian = vl_api_one_adjacencies_get_reply_t_endian,
    .format_fn = vl_api_one_adjacencies_get_reply_t_format,
    .size = sizeof(vl_api_one_adjacencies_get_reply_t),
    .traced = 1,
    .tojson = vl_api_one_adjacencies_get_reply_t_tojson,
    .fromjson = vl_api_one_adjacencies_get_reply_t_fromjson,
    .calc_size = vl_api_one_adjacencies_get_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_adjacencies_get", api_one_adjacencies_get);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_EID_TABLE_MAP_DETAILS + msg_id_base,
    .name = "one_eid_table_map_details",
    .handler = vl_api_one_eid_table_map_details_t_handler,
    .endian = vl_api_one_eid_table_map_details_t_endian,
    .format_fn = vl_api_one_eid_table_map_details_t_format,
    .size = sizeof(vl_api_one_eid_table_map_details_t),
    .traced = 1,
    .tojson = vl_api_one_eid_table_map_details_t_tojson,
    .fromjson = vl_api_one_eid_table_map_details_t_fromjson,
    .calc_size = vl_api_one_eid_table_map_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_eid_table_map_dump", api_one_eid_table_map_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_EID_TABLE_VNI_DETAILS + msg_id_base,
    .name = "one_eid_table_vni_details",
    .handler = vl_api_one_eid_table_vni_details_t_handler,
    .endian = vl_api_one_eid_table_vni_details_t_endian,
    .format_fn = vl_api_one_eid_table_vni_details_t_format,
    .size = sizeof(vl_api_one_eid_table_vni_details_t),
    .traced = 1,
    .tojson = vl_api_one_eid_table_vni_details_t_tojson,
    .fromjson = vl_api_one_eid_table_vni_details_t_fromjson,
    .calc_size = vl_api_one_eid_table_vni_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_eid_table_vni_dump", api_one_eid_table_vni_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_MAP_RESOLVER_DETAILS + msg_id_base,
    .name = "one_map_resolver_details",
    .handler = vl_api_one_map_resolver_details_t_handler,
    .endian = vl_api_one_map_resolver_details_t_endian,
    .format_fn = vl_api_one_map_resolver_details_t_format,
    .size = sizeof(vl_api_one_map_resolver_details_t),
    .traced = 1,
    .tojson = vl_api_one_map_resolver_details_t_tojson,
    .fromjson = vl_api_one_map_resolver_details_t_fromjson,
    .calc_size = vl_api_one_map_resolver_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_map_resolver_dump", api_one_map_resolver_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_MAP_SERVER_DETAILS + msg_id_base,
    .name = "one_map_server_details",
    .handler = vl_api_one_map_server_details_t_handler,
    .endian = vl_api_one_map_server_details_t_endian,
    .format_fn = vl_api_one_map_server_details_t_format,
    .size = sizeof(vl_api_one_map_server_details_t),
    .traced = 1,
    .tojson = vl_api_one_map_server_details_t_tojson,
    .fromjson = vl_api_one_map_server_details_t_fromjson,
    .calc_size = vl_api_one_map_server_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_map_server_dump", api_one_map_server_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SHOW_ONE_STATUS_REPLY + msg_id_base,
    .name = "show_one_status_reply",
    .handler = vl_api_show_one_status_reply_t_handler,
    .endian = vl_api_show_one_status_reply_t_endian,
    .format_fn = vl_api_show_one_status_reply_t_format,
    .size = sizeof(vl_api_show_one_status_reply_t),
    .traced = 1,
    .tojson = vl_api_show_one_status_reply_t_tojson,
    .fromjson = vl_api_show_one_status_reply_t_fromjson,
    .calc_size = vl_api_show_one_status_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "show_one_status", api_show_one_status);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_GET_MAP_REQUEST_ITR_RLOCS_REPLY + msg_id_base,
    .name = "one_get_map_request_itr_rlocs_reply",
    .handler = vl_api_one_get_map_request_itr_rlocs_reply_t_handler,
    .endian = vl_api_one_get_map_request_itr_rlocs_reply_t_endian,
    .format_fn = vl_api_one_get_map_request_itr_rlocs_reply_t_format,
    .size = sizeof(vl_api_one_get_map_request_itr_rlocs_reply_t),
    .traced = 1,
    .tojson = vl_api_one_get_map_request_itr_rlocs_reply_t_tojson,
    .fromjson = vl_api_one_get_map_request_itr_rlocs_reply_t_fromjson,
    .calc_size = vl_api_one_get_map_request_itr_rlocs_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_get_map_request_itr_rlocs", api_one_get_map_request_itr_rlocs);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SHOW_ONE_NSH_MAPPING_REPLY + msg_id_base,
    .name = "show_one_nsh_mapping_reply",
    .handler = vl_api_show_one_nsh_mapping_reply_t_handler,
    .endian = vl_api_show_one_nsh_mapping_reply_t_endian,
    .format_fn = vl_api_show_one_nsh_mapping_reply_t_format,
    .size = sizeof(vl_api_show_one_nsh_mapping_reply_t),
    .traced = 1,
    .tojson = vl_api_show_one_nsh_mapping_reply_t_tojson,
    .fromjson = vl_api_show_one_nsh_mapping_reply_t_fromjson,
    .calc_size = vl_api_show_one_nsh_mapping_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "show_one_nsh_mapping", api_show_one_nsh_mapping);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SHOW_ONE_PITR_REPLY + msg_id_base,
    .name = "show_one_pitr_reply",
    .handler = vl_api_show_one_pitr_reply_t_handler,
    .endian = vl_api_show_one_pitr_reply_t_endian,
    .format_fn = vl_api_show_one_pitr_reply_t_format,
    .size = sizeof(vl_api_show_one_pitr_reply_t),
    .traced = 1,
    .tojson = vl_api_show_one_pitr_reply_t_tojson,
    .fromjson = vl_api_show_one_pitr_reply_t_fromjson,
    .calc_size = vl_api_show_one_pitr_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "show_one_pitr", api_show_one_pitr);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_STATS_DETAILS + msg_id_base,
    .name = "one_stats_details",
    .handler = vl_api_one_stats_details_t_handler,
    .endian = vl_api_one_stats_details_t_endian,
    .format_fn = vl_api_one_stats_details_t_format,
    .size = sizeof(vl_api_one_stats_details_t),
    .traced = 1,
    .tojson = vl_api_one_stats_details_t_tojson,
    .fromjson = vl_api_one_stats_details_t_fromjson,
    .calc_size = vl_api_one_stats_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_stats_dump", api_one_stats_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_STATS_FLUSH_REPLY + msg_id_base,
    .name = "one_stats_flush_reply",
    .handler = vl_api_one_stats_flush_reply_t_handler,
    .endian = vl_api_one_stats_flush_reply_t_endian,
    .format_fn = vl_api_one_stats_flush_reply_t_format,
    .size = sizeof(vl_api_one_stats_flush_reply_t),
    .traced = 1,
    .tojson = vl_api_one_stats_flush_reply_t_tojson,
    .fromjson = vl_api_one_stats_flush_reply_t_fromjson,
    .calc_size = vl_api_one_stats_flush_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_stats_flush", api_one_stats_flush);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_STATS_ENABLE_DISABLE_REPLY + msg_id_base,
    .name = "one_stats_enable_disable_reply",
    .handler = vl_api_one_stats_enable_disable_reply_t_handler,
    .endian = vl_api_one_stats_enable_disable_reply_t_endian,
    .format_fn = vl_api_one_stats_enable_disable_reply_t_format,
    .size = sizeof(vl_api_one_stats_enable_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_one_stats_enable_disable_reply_t_tojson,
    .fromjson = vl_api_one_stats_enable_disable_reply_t_fromjson,
    .calc_size = vl_api_one_stats_enable_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_stats_enable_disable", api_one_stats_enable_disable);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SHOW_ONE_STATS_ENABLE_DISABLE_REPLY + msg_id_base,
    .name = "show_one_stats_enable_disable_reply",
    .handler = vl_api_show_one_stats_enable_disable_reply_t_handler,
    .endian = vl_api_show_one_stats_enable_disable_reply_t_endian,
    .format_fn = vl_api_show_one_stats_enable_disable_reply_t_format,
    .size = sizeof(vl_api_show_one_stats_enable_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_show_one_stats_enable_disable_reply_t_tojson,
    .fromjson = vl_api_show_one_stats_enable_disable_reply_t_fromjson,
    .calc_size = vl_api_show_one_stats_enable_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "show_one_stats_enable_disable", api_show_one_stats_enable_disable);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_MAP_REGISTER_FALLBACK_THRESHOLD_REPLY + msg_id_base,
    .name = "one_map_register_fallback_threshold_reply",
    .handler = vl_api_one_map_register_fallback_threshold_reply_t_handler,
    .endian = vl_api_one_map_register_fallback_threshold_reply_t_endian,
    .format_fn = vl_api_one_map_register_fallback_threshold_reply_t_format,
    .size = sizeof(vl_api_one_map_register_fallback_threshold_reply_t),
    .traced = 1,
    .tojson = vl_api_one_map_register_fallback_threshold_reply_t_tojson,
    .fromjson = vl_api_one_map_register_fallback_threshold_reply_t_fromjson,
    .calc_size = vl_api_one_map_register_fallback_threshold_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_map_register_fallback_threshold", api_one_map_register_fallback_threshold);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SHOW_ONE_MAP_REGISTER_FALLBACK_THRESHOLD_REPLY + msg_id_base,
    .name = "show_one_map_register_fallback_threshold_reply",
    .handler = vl_api_show_one_map_register_fallback_threshold_reply_t_handler,
    .endian = vl_api_show_one_map_register_fallback_threshold_reply_t_endian,
    .format_fn = vl_api_show_one_map_register_fallback_threshold_reply_t_format,
    .size = sizeof(vl_api_show_one_map_register_fallback_threshold_reply_t),
    .traced = 1,
    .tojson = vl_api_show_one_map_register_fallback_threshold_reply_t_tojson,
    .fromjson = vl_api_show_one_map_register_fallback_threshold_reply_t_fromjson,
    .calc_size = vl_api_show_one_map_register_fallback_threshold_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "show_one_map_register_fallback_threshold", api_show_one_map_register_fallback_threshold);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_ENABLE_DISABLE_XTR_MODE_REPLY + msg_id_base,
    .name = "one_enable_disable_xtr_mode_reply",
    .handler = vl_api_one_enable_disable_xtr_mode_reply_t_handler,
    .endian = vl_api_one_enable_disable_xtr_mode_reply_t_endian,
    .format_fn = vl_api_one_enable_disable_xtr_mode_reply_t_format,
    .size = sizeof(vl_api_one_enable_disable_xtr_mode_reply_t),
    .traced = 1,
    .tojson = vl_api_one_enable_disable_xtr_mode_reply_t_tojson,
    .fromjson = vl_api_one_enable_disable_xtr_mode_reply_t_fromjson,
    .calc_size = vl_api_one_enable_disable_xtr_mode_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_enable_disable_xtr_mode", api_one_enable_disable_xtr_mode);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_SHOW_XTR_MODE_REPLY + msg_id_base,
    .name = "one_show_xtr_mode_reply",
    .handler = vl_api_one_show_xtr_mode_reply_t_handler,
    .endian = vl_api_one_show_xtr_mode_reply_t_endian,
    .format_fn = vl_api_one_show_xtr_mode_reply_t_format,
    .size = sizeof(vl_api_one_show_xtr_mode_reply_t),
    .traced = 1,
    .tojson = vl_api_one_show_xtr_mode_reply_t_tojson,
    .fromjson = vl_api_one_show_xtr_mode_reply_t_fromjson,
    .calc_size = vl_api_one_show_xtr_mode_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_show_xtr_mode", api_one_show_xtr_mode);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_ENABLE_DISABLE_PETR_MODE_REPLY + msg_id_base,
    .name = "one_enable_disable_petr_mode_reply",
    .handler = vl_api_one_enable_disable_petr_mode_reply_t_handler,
    .endian = vl_api_one_enable_disable_petr_mode_reply_t_endian,
    .format_fn = vl_api_one_enable_disable_petr_mode_reply_t_format,
    .size = sizeof(vl_api_one_enable_disable_petr_mode_reply_t),
    .traced = 1,
    .tojson = vl_api_one_enable_disable_petr_mode_reply_t_tojson,
    .fromjson = vl_api_one_enable_disable_petr_mode_reply_t_fromjson,
    .calc_size = vl_api_one_enable_disable_petr_mode_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_enable_disable_petr_mode", api_one_enable_disable_petr_mode);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_SHOW_PETR_MODE_REPLY + msg_id_base,
    .name = "one_show_petr_mode_reply",
    .handler = vl_api_one_show_petr_mode_reply_t_handler,
    .endian = vl_api_one_show_petr_mode_reply_t_endian,
    .format_fn = vl_api_one_show_petr_mode_reply_t_format,
    .size = sizeof(vl_api_one_show_petr_mode_reply_t),
    .traced = 1,
    .tojson = vl_api_one_show_petr_mode_reply_t_tojson,
    .fromjson = vl_api_one_show_petr_mode_reply_t_fromjson,
    .calc_size = vl_api_one_show_petr_mode_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_show_petr_mode", api_one_show_petr_mode);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_ENABLE_DISABLE_PITR_MODE_REPLY + msg_id_base,
    .name = "one_enable_disable_pitr_mode_reply",
    .handler = vl_api_one_enable_disable_pitr_mode_reply_t_handler,
    .endian = vl_api_one_enable_disable_pitr_mode_reply_t_endian,
    .format_fn = vl_api_one_enable_disable_pitr_mode_reply_t_format,
    .size = sizeof(vl_api_one_enable_disable_pitr_mode_reply_t),
    .traced = 1,
    .tojson = vl_api_one_enable_disable_pitr_mode_reply_t_tojson,
    .fromjson = vl_api_one_enable_disable_pitr_mode_reply_t_fromjson,
    .calc_size = vl_api_one_enable_disable_pitr_mode_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_enable_disable_pitr_mode", api_one_enable_disable_pitr_mode);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ONE_SHOW_PITR_MODE_REPLY + msg_id_base,
    .name = "one_show_pitr_mode_reply",
    .handler = vl_api_one_show_pitr_mode_reply_t_handler,
    .endian = vl_api_one_show_pitr_mode_reply_t_endian,
    .format_fn = vl_api_one_show_pitr_mode_reply_t_format,
    .size = sizeof(vl_api_one_show_pitr_mode_reply_t),
    .traced = 1,
    .tojson = vl_api_one_show_pitr_mode_reply_t_tojson,
    .fromjson = vl_api_one_show_pitr_mode_reply_t_fromjson,
    .calc_size = vl_api_one_show_pitr_mode_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "one_show_pitr_mode", api_one_show_pitr_mode);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   one_test_main_t * mainp = &one_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("one_a4bbba2c");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "one plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
