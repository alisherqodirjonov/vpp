#define vl_endianfun            /* define message structures */
#include "map.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "map.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "map.api.h"
#undef vl_printfun

/* Generation not supported (vl_api_map_domains_get_reply_t_handler()) */
/* Generation not supported (vl_api_map_add_domain_reply_t_handler()) */
#ifndef VL_API_MAP_DEL_DOMAIN_REPLY_T_HANDLER
static void
vl_api_map_del_domain_reply_t_handler (vl_api_map_del_domain_reply_t * mp) {
   vat_main_t * vam = map_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_MAP_ADD_DEL_RULE_REPLY_T_HANDLER
static void
vl_api_map_add_del_rule_reply_t_handler (vl_api_map_add_del_rule_reply_t * mp) {
   vat_main_t * vam = map_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_map_domain_details_t_handler()) */
/* Generation not supported (vl_api_map_rule_details_t_handler()) */
#ifndef VL_API_MAP_IF_ENABLE_DISABLE_REPLY_T_HANDLER
static void
vl_api_map_if_enable_disable_reply_t_handler (vl_api_map_if_enable_disable_reply_t * mp) {
   vat_main_t * vam = map_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_map_summary_stats_reply_t_handler()) */
#ifndef VL_API_MAP_PARAM_SET_FRAGMENTATION_REPLY_T_HANDLER
static void
vl_api_map_param_set_fragmentation_reply_t_handler (vl_api_map_param_set_fragmentation_reply_t * mp) {
   vat_main_t * vam = map_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_MAP_PARAM_SET_ICMP_REPLY_T_HANDLER
static void
vl_api_map_param_set_icmp_reply_t_handler (vl_api_map_param_set_icmp_reply_t * mp) {
   vat_main_t * vam = map_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_MAP_PARAM_SET_ICMP6_REPLY_T_HANDLER
static void
vl_api_map_param_set_icmp6_reply_t_handler (vl_api_map_param_set_icmp6_reply_t * mp) {
   vat_main_t * vam = map_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_MAP_PARAM_ADD_DEL_PRE_RESOLVE_REPLY_T_HANDLER
static void
vl_api_map_param_add_del_pre_resolve_reply_t_handler (vl_api_map_param_add_del_pre_resolve_reply_t * mp) {
   vat_main_t * vam = map_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_MAP_PARAM_SET_SECURITY_CHECK_REPLY_T_HANDLER
static void
vl_api_map_param_set_security_check_reply_t_handler (vl_api_map_param_set_security_check_reply_t * mp) {
   vat_main_t * vam = map_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_MAP_PARAM_SET_TRAFFIC_CLASS_REPLY_T_HANDLER
static void
vl_api_map_param_set_traffic_class_reply_t_handler (vl_api_map_param_set_traffic_class_reply_t * mp) {
   vat_main_t * vam = map_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_MAP_PARAM_SET_TCP_REPLY_T_HANDLER
static void
vl_api_map_param_set_tcp_reply_t_handler (vl_api_map_param_set_tcp_reply_t * mp) {
   vat_main_t * vam = map_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_map_param_get_reply_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MAP_DOMAINS_GET_REPLY + msg_id_base,
    .name = "map_domains_get_reply",
    .handler = vl_api_map_domains_get_reply_t_handler,
    .endian = vl_api_map_domains_get_reply_t_endian,
    .format_fn = vl_api_map_domains_get_reply_t_format,
    .size = sizeof(vl_api_map_domains_get_reply_t),
    .traced = 1,
    .tojson = vl_api_map_domains_get_reply_t_tojson,
    .fromjson = vl_api_map_domains_get_reply_t_fromjson,
    .calc_size = vl_api_map_domains_get_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "map_domains_get", api_map_domains_get);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MAP_ADD_DOMAIN_REPLY + msg_id_base,
    .name = "map_add_domain_reply",
    .handler = vl_api_map_add_domain_reply_t_handler,
    .endian = vl_api_map_add_domain_reply_t_endian,
    .format_fn = vl_api_map_add_domain_reply_t_format,
    .size = sizeof(vl_api_map_add_domain_reply_t),
    .traced = 1,
    .tojson = vl_api_map_add_domain_reply_t_tojson,
    .fromjson = vl_api_map_add_domain_reply_t_fromjson,
    .calc_size = vl_api_map_add_domain_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "map_add_domain", api_map_add_domain);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MAP_DEL_DOMAIN_REPLY + msg_id_base,
    .name = "map_del_domain_reply",
    .handler = vl_api_map_del_domain_reply_t_handler,
    .endian = vl_api_map_del_domain_reply_t_endian,
    .format_fn = vl_api_map_del_domain_reply_t_format,
    .size = sizeof(vl_api_map_del_domain_reply_t),
    .traced = 1,
    .tojson = vl_api_map_del_domain_reply_t_tojson,
    .fromjson = vl_api_map_del_domain_reply_t_fromjson,
    .calc_size = vl_api_map_del_domain_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "map_del_domain", api_map_del_domain);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MAP_ADD_DEL_RULE_REPLY + msg_id_base,
    .name = "map_add_del_rule_reply",
    .handler = vl_api_map_add_del_rule_reply_t_handler,
    .endian = vl_api_map_add_del_rule_reply_t_endian,
    .format_fn = vl_api_map_add_del_rule_reply_t_format,
    .size = sizeof(vl_api_map_add_del_rule_reply_t),
    .traced = 1,
    .tojson = vl_api_map_add_del_rule_reply_t_tojson,
    .fromjson = vl_api_map_add_del_rule_reply_t_fromjson,
    .calc_size = vl_api_map_add_del_rule_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "map_add_del_rule", api_map_add_del_rule);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MAP_DOMAIN_DETAILS + msg_id_base,
    .name = "map_domain_details",
    .handler = vl_api_map_domain_details_t_handler,
    .endian = vl_api_map_domain_details_t_endian,
    .format_fn = vl_api_map_domain_details_t_format,
    .size = sizeof(vl_api_map_domain_details_t),
    .traced = 1,
    .tojson = vl_api_map_domain_details_t_tojson,
    .fromjson = vl_api_map_domain_details_t_fromjson,
    .calc_size = vl_api_map_domain_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "map_domain_dump", api_map_domain_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MAP_RULE_DETAILS + msg_id_base,
    .name = "map_rule_details",
    .handler = vl_api_map_rule_details_t_handler,
    .endian = vl_api_map_rule_details_t_endian,
    .format_fn = vl_api_map_rule_details_t_format,
    .size = sizeof(vl_api_map_rule_details_t),
    .traced = 1,
    .tojson = vl_api_map_rule_details_t_tojson,
    .fromjson = vl_api_map_rule_details_t_fromjson,
    .calc_size = vl_api_map_rule_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "map_rule_dump", api_map_rule_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MAP_IF_ENABLE_DISABLE_REPLY + msg_id_base,
    .name = "map_if_enable_disable_reply",
    .handler = vl_api_map_if_enable_disable_reply_t_handler,
    .endian = vl_api_map_if_enable_disable_reply_t_endian,
    .format_fn = vl_api_map_if_enable_disable_reply_t_format,
    .size = sizeof(vl_api_map_if_enable_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_map_if_enable_disable_reply_t_tojson,
    .fromjson = vl_api_map_if_enable_disable_reply_t_fromjson,
    .calc_size = vl_api_map_if_enable_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "map_if_enable_disable", api_map_if_enable_disable);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MAP_SUMMARY_STATS_REPLY + msg_id_base,
    .name = "map_summary_stats_reply",
    .handler = vl_api_map_summary_stats_reply_t_handler,
    .endian = vl_api_map_summary_stats_reply_t_endian,
    .format_fn = vl_api_map_summary_stats_reply_t_format,
    .size = sizeof(vl_api_map_summary_stats_reply_t),
    .traced = 1,
    .tojson = vl_api_map_summary_stats_reply_t_tojson,
    .fromjson = vl_api_map_summary_stats_reply_t_fromjson,
    .calc_size = vl_api_map_summary_stats_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "map_summary_stats", api_map_summary_stats);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MAP_PARAM_SET_FRAGMENTATION_REPLY + msg_id_base,
    .name = "map_param_set_fragmentation_reply",
    .handler = vl_api_map_param_set_fragmentation_reply_t_handler,
    .endian = vl_api_map_param_set_fragmentation_reply_t_endian,
    .format_fn = vl_api_map_param_set_fragmentation_reply_t_format,
    .size = sizeof(vl_api_map_param_set_fragmentation_reply_t),
    .traced = 1,
    .tojson = vl_api_map_param_set_fragmentation_reply_t_tojson,
    .fromjson = vl_api_map_param_set_fragmentation_reply_t_fromjson,
    .calc_size = vl_api_map_param_set_fragmentation_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "map_param_set_fragmentation", api_map_param_set_fragmentation);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MAP_PARAM_SET_ICMP_REPLY + msg_id_base,
    .name = "map_param_set_icmp_reply",
    .handler = vl_api_map_param_set_icmp_reply_t_handler,
    .endian = vl_api_map_param_set_icmp_reply_t_endian,
    .format_fn = vl_api_map_param_set_icmp_reply_t_format,
    .size = sizeof(vl_api_map_param_set_icmp_reply_t),
    .traced = 1,
    .tojson = vl_api_map_param_set_icmp_reply_t_tojson,
    .fromjson = vl_api_map_param_set_icmp_reply_t_fromjson,
    .calc_size = vl_api_map_param_set_icmp_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "map_param_set_icmp", api_map_param_set_icmp);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MAP_PARAM_SET_ICMP6_REPLY + msg_id_base,
    .name = "map_param_set_icmp6_reply",
    .handler = vl_api_map_param_set_icmp6_reply_t_handler,
    .endian = vl_api_map_param_set_icmp6_reply_t_endian,
    .format_fn = vl_api_map_param_set_icmp6_reply_t_format,
    .size = sizeof(vl_api_map_param_set_icmp6_reply_t),
    .traced = 1,
    .tojson = vl_api_map_param_set_icmp6_reply_t_tojson,
    .fromjson = vl_api_map_param_set_icmp6_reply_t_fromjson,
    .calc_size = vl_api_map_param_set_icmp6_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "map_param_set_icmp6", api_map_param_set_icmp6);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MAP_PARAM_ADD_DEL_PRE_RESOLVE_REPLY + msg_id_base,
    .name = "map_param_add_del_pre_resolve_reply",
    .handler = vl_api_map_param_add_del_pre_resolve_reply_t_handler,
    .endian = vl_api_map_param_add_del_pre_resolve_reply_t_endian,
    .format_fn = vl_api_map_param_add_del_pre_resolve_reply_t_format,
    .size = sizeof(vl_api_map_param_add_del_pre_resolve_reply_t),
    .traced = 1,
    .tojson = vl_api_map_param_add_del_pre_resolve_reply_t_tojson,
    .fromjson = vl_api_map_param_add_del_pre_resolve_reply_t_fromjson,
    .calc_size = vl_api_map_param_add_del_pre_resolve_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "map_param_add_del_pre_resolve", api_map_param_add_del_pre_resolve);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MAP_PARAM_SET_SECURITY_CHECK_REPLY + msg_id_base,
    .name = "map_param_set_security_check_reply",
    .handler = vl_api_map_param_set_security_check_reply_t_handler,
    .endian = vl_api_map_param_set_security_check_reply_t_endian,
    .format_fn = vl_api_map_param_set_security_check_reply_t_format,
    .size = sizeof(vl_api_map_param_set_security_check_reply_t),
    .traced = 1,
    .tojson = vl_api_map_param_set_security_check_reply_t_tojson,
    .fromjson = vl_api_map_param_set_security_check_reply_t_fromjson,
    .calc_size = vl_api_map_param_set_security_check_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "map_param_set_security_check", api_map_param_set_security_check);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MAP_PARAM_SET_TRAFFIC_CLASS_REPLY + msg_id_base,
    .name = "map_param_set_traffic_class_reply",
    .handler = vl_api_map_param_set_traffic_class_reply_t_handler,
    .endian = vl_api_map_param_set_traffic_class_reply_t_endian,
    .format_fn = vl_api_map_param_set_traffic_class_reply_t_format,
    .size = sizeof(vl_api_map_param_set_traffic_class_reply_t),
    .traced = 1,
    .tojson = vl_api_map_param_set_traffic_class_reply_t_tojson,
    .fromjson = vl_api_map_param_set_traffic_class_reply_t_fromjson,
    .calc_size = vl_api_map_param_set_traffic_class_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "map_param_set_traffic_class", api_map_param_set_traffic_class);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MAP_PARAM_SET_TCP_REPLY + msg_id_base,
    .name = "map_param_set_tcp_reply",
    .handler = vl_api_map_param_set_tcp_reply_t_handler,
    .endian = vl_api_map_param_set_tcp_reply_t_endian,
    .format_fn = vl_api_map_param_set_tcp_reply_t_format,
    .size = sizeof(vl_api_map_param_set_tcp_reply_t),
    .traced = 1,
    .tojson = vl_api_map_param_set_tcp_reply_t_tojson,
    .fromjson = vl_api_map_param_set_tcp_reply_t_fromjson,
    .calc_size = vl_api_map_param_set_tcp_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "map_param_set_tcp", api_map_param_set_tcp);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MAP_PARAM_GET_REPLY + msg_id_base,
    .name = "map_param_get_reply",
    .handler = vl_api_map_param_get_reply_t_handler,
    .endian = vl_api_map_param_get_reply_t_endian,
    .format_fn = vl_api_map_param_get_reply_t_format,
    .size = sizeof(vl_api_map_param_get_reply_t),
    .traced = 1,
    .tojson = vl_api_map_param_get_reply_t_tojson,
    .fromjson = vl_api_map_param_get_reply_t_fromjson,
    .calc_size = vl_api_map_param_get_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "map_param_get", api_map_param_get);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   map_test_main_t * mainp = &map_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("map_8bf7a18a");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "map plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
