#define vl_endianfun            /* define message structures */
#include "lb.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "lb.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "lb.api.h"
#undef vl_printfun

#ifndef VL_API_LB_CONF_REPLY_T_HANDLER
static void
vl_api_lb_conf_reply_t_handler (vl_api_lb_conf_reply_t * mp) {
   vat_main_t * vam = lb_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_LB_ADD_DEL_VIP_REPLY_T_HANDLER
static void
vl_api_lb_add_del_vip_reply_t_handler (vl_api_lb_add_del_vip_reply_t * mp) {
   vat_main_t * vam = lb_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_LB_ADD_DEL_VIP_V2_REPLY_T_HANDLER
static void
vl_api_lb_add_del_vip_v2_reply_t_handler (vl_api_lb_add_del_vip_v2_reply_t * mp) {
   vat_main_t * vam = lb_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_LB_ADD_DEL_AS_REPLY_T_HANDLER
static void
vl_api_lb_add_del_as_reply_t_handler (vl_api_lb_add_del_as_reply_t * mp) {
   vat_main_t * vam = lb_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_LB_FLUSH_VIP_REPLY_T_HANDLER
static void
vl_api_lb_flush_vip_reply_t_handler (vl_api_lb_flush_vip_reply_t * mp) {
   vat_main_t * vam = lb_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_lb_vip_details_t_handler()) */
/* Generation not supported (vl_api_lb_as_details_t_handler()) */
#ifndef VL_API_LB_ADD_DEL_INTF_NAT4_REPLY_T_HANDLER
static void
vl_api_lb_add_del_intf_nat4_reply_t_handler (vl_api_lb_add_del_intf_nat4_reply_t * mp) {
   vat_main_t * vam = lb_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_LB_ADD_DEL_INTF_NAT6_REPLY_T_HANDLER
static void
vl_api_lb_add_del_intf_nat6_reply_t_handler (vl_api_lb_add_del_intf_nat6_reply_t * mp) {
   vat_main_t * vam = lb_test_main.vat_main;
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
    .id = VL_API_LB_CONF_REPLY + msg_id_base,
    .name = "lb_conf_reply",
    .handler = vl_api_lb_conf_reply_t_handler,
    .endian = vl_api_lb_conf_reply_t_endian,
    .format_fn = vl_api_lb_conf_reply_t_format,
    .size = sizeof(vl_api_lb_conf_reply_t),
    .traced = 1,
    .tojson = vl_api_lb_conf_reply_t_tojson,
    .fromjson = vl_api_lb_conf_reply_t_fromjson,
    .calc_size = vl_api_lb_conf_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "lb_conf", api_lb_conf);
   hash_set_mem (vam->help_by_name, "lb_conf", "[ip4-src-address <addr>] [ip6-src-address <addr>] [buckets <n>] [timeout <s>]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_LB_ADD_DEL_VIP_REPLY + msg_id_base,
    .name = "lb_add_del_vip_reply",
    .handler = vl_api_lb_add_del_vip_reply_t_handler,
    .endian = vl_api_lb_add_del_vip_reply_t_endian,
    .format_fn = vl_api_lb_add_del_vip_reply_t_format,
    .size = sizeof(vl_api_lb_add_del_vip_reply_t),
    .traced = 1,
    .tojson = vl_api_lb_add_del_vip_reply_t_tojson,
    .fromjson = vl_api_lb_add_del_vip_reply_t_fromjson,
    .calc_size = vl_api_lb_add_del_vip_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "lb_add_del_vip", api_lb_add_del_vip);
   hash_set_mem (vam->help_by_name, "lb_add_del_vip", "<prefix> [protocol (tcp|udp) port <n>] [encap (gre6|gre4|l3dsr|nat4|nat6)] [dscp <n>] [type (nodeport|clusterip) target_port <n>] [new_len <n>] [del]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_LB_ADD_DEL_VIP_V2_REPLY + msg_id_base,
    .name = "lb_add_del_vip_v2_reply",
    .handler = vl_api_lb_add_del_vip_v2_reply_t_handler,
    .endian = vl_api_lb_add_del_vip_v2_reply_t_endian,
    .format_fn = vl_api_lb_add_del_vip_v2_reply_t_format,
    .size = sizeof(vl_api_lb_add_del_vip_v2_reply_t),
    .traced = 1,
    .tojson = vl_api_lb_add_del_vip_v2_reply_t_tojson,
    .fromjson = vl_api_lb_add_del_vip_v2_reply_t_fromjson,
    .calc_size = vl_api_lb_add_del_vip_v2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "lb_add_del_vip_v2", api_lb_add_del_vip_v2);
   hash_set_mem (vam->help_by_name, "lb_add_del_vip_v2", "<prefix> [protocol (tcp|udp) port <n>] [encap (gre6|gre4|l3dsr|nat4|nat6)] [dscp <n>] [type (nodeport|clusterip) target_port <n>] [new_len <n>] [src_ip_sticky] [del]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_LB_ADD_DEL_AS_REPLY + msg_id_base,
    .name = "lb_add_del_as_reply",
    .handler = vl_api_lb_add_del_as_reply_t_handler,
    .endian = vl_api_lb_add_del_as_reply_t_endian,
    .format_fn = vl_api_lb_add_del_as_reply_t_format,
    .size = sizeof(vl_api_lb_add_del_as_reply_t),
    .traced = 1,
    .tojson = vl_api_lb_add_del_as_reply_t_tojson,
    .fromjson = vl_api_lb_add_del_as_reply_t_fromjson,
    .calc_size = vl_api_lb_add_del_as_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "lb_add_del_as", api_lb_add_del_as);
   hash_set_mem (vam->help_by_name, "lb_add_del_as", "<vip-prefix> [protocol (tcp|udp) port <n>] [<address>] [del] [flush]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_LB_FLUSH_VIP_REPLY + msg_id_base,
    .name = "lb_flush_vip_reply",
    .handler = vl_api_lb_flush_vip_reply_t_handler,
    .endian = vl_api_lb_flush_vip_reply_t_endian,
    .format_fn = vl_api_lb_flush_vip_reply_t_format,
    .size = sizeof(vl_api_lb_flush_vip_reply_t),
    .traced = 1,
    .tojson = vl_api_lb_flush_vip_reply_t_tojson,
    .fromjson = vl_api_lb_flush_vip_reply_t_fromjson,
    .calc_size = vl_api_lb_flush_vip_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "lb_flush_vip", api_lb_flush_vip);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_LB_VIP_DETAILS + msg_id_base,
    .name = "lb_vip_details",
    .handler = vl_api_lb_vip_details_t_handler,
    .endian = vl_api_lb_vip_details_t_endian,
    .format_fn = vl_api_lb_vip_details_t_format,
    .size = sizeof(vl_api_lb_vip_details_t),
    .traced = 1,
    .tojson = vl_api_lb_vip_details_t_tojson,
    .fromjson = vl_api_lb_vip_details_t_fromjson,
    .calc_size = vl_api_lb_vip_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "lb_vip_dump", api_lb_vip_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_LB_AS_DETAILS + msg_id_base,
    .name = "lb_as_details",
    .handler = vl_api_lb_as_details_t_handler,
    .endian = vl_api_lb_as_details_t_endian,
    .format_fn = vl_api_lb_as_details_t_format,
    .size = sizeof(vl_api_lb_as_details_t),
    .traced = 1,
    .tojson = vl_api_lb_as_details_t_tojson,
    .fromjson = vl_api_lb_as_details_t_fromjson,
    .calc_size = vl_api_lb_as_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "lb_as_dump", api_lb_as_dump);
   hash_set_mem (vam->help_by_name, "lb_as_dump", "<vip-prefix> [protocol (tcp|udp) port <n>]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_LB_ADD_DEL_INTF_NAT4_REPLY + msg_id_base,
    .name = "lb_add_del_intf_nat4_reply",
    .handler = vl_api_lb_add_del_intf_nat4_reply_t_handler,
    .endian = vl_api_lb_add_del_intf_nat4_reply_t_endian,
    .format_fn = vl_api_lb_add_del_intf_nat4_reply_t_format,
    .size = sizeof(vl_api_lb_add_del_intf_nat4_reply_t),
    .traced = 1,
    .tojson = vl_api_lb_add_del_intf_nat4_reply_t_tojson,
    .fromjson = vl_api_lb_add_del_intf_nat4_reply_t_fromjson,
    .calc_size = vl_api_lb_add_del_intf_nat4_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "lb_add_del_intf_nat4", api_lb_add_del_intf_nat4);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_LB_ADD_DEL_INTF_NAT6_REPLY + msg_id_base,
    .name = "lb_add_del_intf_nat6_reply",
    .handler = vl_api_lb_add_del_intf_nat6_reply_t_handler,
    .endian = vl_api_lb_add_del_intf_nat6_reply_t_endian,
    .format_fn = vl_api_lb_add_del_intf_nat6_reply_t_format,
    .size = sizeof(vl_api_lb_add_del_intf_nat6_reply_t),
    .traced = 1,
    .tojson = vl_api_lb_add_del_intf_nat6_reply_t_tojson,
    .fromjson = vl_api_lb_add_del_intf_nat6_reply_t_fromjson,
    .calc_size = vl_api_lb_add_del_intf_nat6_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "lb_add_del_intf_nat6", api_lb_add_del_intf_nat6);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   lb_test_main_t * mainp = &lb_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("lb_31818767");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "lb plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
