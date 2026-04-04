#define vl_endianfun            /* define message structures */
#include "sr.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "sr.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "sr.api.h"
#undef vl_printfun

#ifndef VL_API_SR_LOCALSID_ADD_DEL_REPLY_T_HANDLER
static void
vl_api_sr_localsid_add_del_reply_t_handler (vl_api_sr_localsid_add_del_reply_t * mp) {
   vat_main_t * vam = sr_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_SR_POLICY_ADD_REPLY_T_HANDLER
static void
vl_api_sr_policy_add_reply_t_handler (vl_api_sr_policy_add_reply_t * mp) {
   vat_main_t * vam = sr_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_SR_POLICY_MOD_REPLY_T_HANDLER
static void
vl_api_sr_policy_mod_reply_t_handler (vl_api_sr_policy_mod_reply_t * mp) {
   vat_main_t * vam = sr_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_SR_POLICY_ADD_V2_REPLY_T_HANDLER
static void
vl_api_sr_policy_add_v2_reply_t_handler (vl_api_sr_policy_add_v2_reply_t * mp) {
   vat_main_t * vam = sr_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_SR_POLICY_MOD_V2_REPLY_T_HANDLER
static void
vl_api_sr_policy_mod_v2_reply_t_handler (vl_api_sr_policy_mod_v2_reply_t * mp) {
   vat_main_t * vam = sr_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_SR_POLICY_DEL_REPLY_T_HANDLER
static void
vl_api_sr_policy_del_reply_t_handler (vl_api_sr_policy_del_reply_t * mp) {
   vat_main_t * vam = sr_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_SR_SET_ENCAP_SOURCE_REPLY_T_HANDLER
static void
vl_api_sr_set_encap_source_reply_t_handler (vl_api_sr_set_encap_source_reply_t * mp) {
   vat_main_t * vam = sr_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_SR_SET_ENCAP_HOP_LIMIT_REPLY_T_HANDLER
static void
vl_api_sr_set_encap_hop_limit_reply_t_handler (vl_api_sr_set_encap_hop_limit_reply_t * mp) {
   vat_main_t * vam = sr_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_SR_STEERING_ADD_DEL_REPLY_T_HANDLER
static void
vl_api_sr_steering_add_del_reply_t_handler (vl_api_sr_steering_add_del_reply_t * mp) {
   vat_main_t * vam = sr_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_sr_localsids_details_t_handler()) */
/* Generation not supported (vl_api_sr_localsids_with_packet_stats_details_t_handler()) */
/* Generation not supported (vl_api_sr_policies_details_t_handler()) */
/* Generation not supported (vl_api_sr_policies_v2_details_t_handler()) */
/* Generation not supported (vl_api_sr_policies_with_sl_index_details_t_handler()) */
/* Generation not supported (vl_api_sr_steering_pol_details_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SR_LOCALSID_ADD_DEL_REPLY + msg_id_base,
    .name = "sr_localsid_add_del_reply",
    .handler = vl_api_sr_localsid_add_del_reply_t_handler,
    .endian = vl_api_sr_localsid_add_del_reply_t_endian,
    .format_fn = vl_api_sr_localsid_add_del_reply_t_format,
    .size = sizeof(vl_api_sr_localsid_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_sr_localsid_add_del_reply_t_tojson,
    .fromjson = vl_api_sr_localsid_add_del_reply_t_fromjson,
    .calc_size = vl_api_sr_localsid_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sr_localsid_add_del", api_sr_localsid_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SR_POLICY_ADD_REPLY + msg_id_base,
    .name = "sr_policy_add_reply",
    .handler = vl_api_sr_policy_add_reply_t_handler,
    .endian = vl_api_sr_policy_add_reply_t_endian,
    .format_fn = vl_api_sr_policy_add_reply_t_format,
    .size = sizeof(vl_api_sr_policy_add_reply_t),
    .traced = 1,
    .tojson = vl_api_sr_policy_add_reply_t_tojson,
    .fromjson = vl_api_sr_policy_add_reply_t_fromjson,
    .calc_size = vl_api_sr_policy_add_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sr_policy_add", api_sr_policy_add);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SR_POLICY_MOD_REPLY + msg_id_base,
    .name = "sr_policy_mod_reply",
    .handler = vl_api_sr_policy_mod_reply_t_handler,
    .endian = vl_api_sr_policy_mod_reply_t_endian,
    .format_fn = vl_api_sr_policy_mod_reply_t_format,
    .size = sizeof(vl_api_sr_policy_mod_reply_t),
    .traced = 1,
    .tojson = vl_api_sr_policy_mod_reply_t_tojson,
    .fromjson = vl_api_sr_policy_mod_reply_t_fromjson,
    .calc_size = vl_api_sr_policy_mod_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sr_policy_mod", api_sr_policy_mod);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SR_POLICY_ADD_V2_REPLY + msg_id_base,
    .name = "sr_policy_add_v2_reply",
    .handler = vl_api_sr_policy_add_v2_reply_t_handler,
    .endian = vl_api_sr_policy_add_v2_reply_t_endian,
    .format_fn = vl_api_sr_policy_add_v2_reply_t_format,
    .size = sizeof(vl_api_sr_policy_add_v2_reply_t),
    .traced = 1,
    .tojson = vl_api_sr_policy_add_v2_reply_t_tojson,
    .fromjson = vl_api_sr_policy_add_v2_reply_t_fromjson,
    .calc_size = vl_api_sr_policy_add_v2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sr_policy_add_v2", api_sr_policy_add_v2);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SR_POLICY_MOD_V2_REPLY + msg_id_base,
    .name = "sr_policy_mod_v2_reply",
    .handler = vl_api_sr_policy_mod_v2_reply_t_handler,
    .endian = vl_api_sr_policy_mod_v2_reply_t_endian,
    .format_fn = vl_api_sr_policy_mod_v2_reply_t_format,
    .size = sizeof(vl_api_sr_policy_mod_v2_reply_t),
    .traced = 1,
    .tojson = vl_api_sr_policy_mod_v2_reply_t_tojson,
    .fromjson = vl_api_sr_policy_mod_v2_reply_t_fromjson,
    .calc_size = vl_api_sr_policy_mod_v2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sr_policy_mod_v2", api_sr_policy_mod_v2);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SR_POLICY_DEL_REPLY + msg_id_base,
    .name = "sr_policy_del_reply",
    .handler = vl_api_sr_policy_del_reply_t_handler,
    .endian = vl_api_sr_policy_del_reply_t_endian,
    .format_fn = vl_api_sr_policy_del_reply_t_format,
    .size = sizeof(vl_api_sr_policy_del_reply_t),
    .traced = 1,
    .tojson = vl_api_sr_policy_del_reply_t_tojson,
    .fromjson = vl_api_sr_policy_del_reply_t_fromjson,
    .calc_size = vl_api_sr_policy_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sr_policy_del", api_sr_policy_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SR_SET_ENCAP_SOURCE_REPLY + msg_id_base,
    .name = "sr_set_encap_source_reply",
    .handler = vl_api_sr_set_encap_source_reply_t_handler,
    .endian = vl_api_sr_set_encap_source_reply_t_endian,
    .format_fn = vl_api_sr_set_encap_source_reply_t_format,
    .size = sizeof(vl_api_sr_set_encap_source_reply_t),
    .traced = 1,
    .tojson = vl_api_sr_set_encap_source_reply_t_tojson,
    .fromjson = vl_api_sr_set_encap_source_reply_t_fromjson,
    .calc_size = vl_api_sr_set_encap_source_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sr_set_encap_source", api_sr_set_encap_source);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SR_SET_ENCAP_HOP_LIMIT_REPLY + msg_id_base,
    .name = "sr_set_encap_hop_limit_reply",
    .handler = vl_api_sr_set_encap_hop_limit_reply_t_handler,
    .endian = vl_api_sr_set_encap_hop_limit_reply_t_endian,
    .format_fn = vl_api_sr_set_encap_hop_limit_reply_t_format,
    .size = sizeof(vl_api_sr_set_encap_hop_limit_reply_t),
    .traced = 1,
    .tojson = vl_api_sr_set_encap_hop_limit_reply_t_tojson,
    .fromjson = vl_api_sr_set_encap_hop_limit_reply_t_fromjson,
    .calc_size = vl_api_sr_set_encap_hop_limit_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sr_set_encap_hop_limit", api_sr_set_encap_hop_limit);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SR_STEERING_ADD_DEL_REPLY + msg_id_base,
    .name = "sr_steering_add_del_reply",
    .handler = vl_api_sr_steering_add_del_reply_t_handler,
    .endian = vl_api_sr_steering_add_del_reply_t_endian,
    .format_fn = vl_api_sr_steering_add_del_reply_t_format,
    .size = sizeof(vl_api_sr_steering_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_sr_steering_add_del_reply_t_tojson,
    .fromjson = vl_api_sr_steering_add_del_reply_t_fromjson,
    .calc_size = vl_api_sr_steering_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sr_steering_add_del", api_sr_steering_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SR_LOCALSIDS_DETAILS + msg_id_base,
    .name = "sr_localsids_details",
    .handler = vl_api_sr_localsids_details_t_handler,
    .endian = vl_api_sr_localsids_details_t_endian,
    .format_fn = vl_api_sr_localsids_details_t_format,
    .size = sizeof(vl_api_sr_localsids_details_t),
    .traced = 1,
    .tojson = vl_api_sr_localsids_details_t_tojson,
    .fromjson = vl_api_sr_localsids_details_t_fromjson,
    .calc_size = vl_api_sr_localsids_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sr_localsids_dump", api_sr_localsids_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SR_LOCALSIDS_WITH_PACKET_STATS_DETAILS + msg_id_base,
    .name = "sr_localsids_with_packet_stats_details",
    .handler = vl_api_sr_localsids_with_packet_stats_details_t_handler,
    .endian = vl_api_sr_localsids_with_packet_stats_details_t_endian,
    .format_fn = vl_api_sr_localsids_with_packet_stats_details_t_format,
    .size = sizeof(vl_api_sr_localsids_with_packet_stats_details_t),
    .traced = 1,
    .tojson = vl_api_sr_localsids_with_packet_stats_details_t_tojson,
    .fromjson = vl_api_sr_localsids_with_packet_stats_details_t_fromjson,
    .calc_size = vl_api_sr_localsids_with_packet_stats_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sr_localsids_with_packet_stats_dump", api_sr_localsids_with_packet_stats_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SR_POLICIES_DETAILS + msg_id_base,
    .name = "sr_policies_details",
    .handler = vl_api_sr_policies_details_t_handler,
    .endian = vl_api_sr_policies_details_t_endian,
    .format_fn = vl_api_sr_policies_details_t_format,
    .size = sizeof(vl_api_sr_policies_details_t),
    .traced = 1,
    .tojson = vl_api_sr_policies_details_t_tojson,
    .fromjson = vl_api_sr_policies_details_t_fromjson,
    .calc_size = vl_api_sr_policies_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sr_policies_dump", api_sr_policies_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SR_POLICIES_V2_DETAILS + msg_id_base,
    .name = "sr_policies_v2_details",
    .handler = vl_api_sr_policies_v2_details_t_handler,
    .endian = vl_api_sr_policies_v2_details_t_endian,
    .format_fn = vl_api_sr_policies_v2_details_t_format,
    .size = sizeof(vl_api_sr_policies_v2_details_t),
    .traced = 1,
    .tojson = vl_api_sr_policies_v2_details_t_tojson,
    .fromjson = vl_api_sr_policies_v2_details_t_fromjson,
    .calc_size = vl_api_sr_policies_v2_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sr_policies_v2_dump", api_sr_policies_v2_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SR_POLICIES_WITH_SL_INDEX_DETAILS + msg_id_base,
    .name = "sr_policies_with_sl_index_details",
    .handler = vl_api_sr_policies_with_sl_index_details_t_handler,
    .endian = vl_api_sr_policies_with_sl_index_details_t_endian,
    .format_fn = vl_api_sr_policies_with_sl_index_details_t_format,
    .size = sizeof(vl_api_sr_policies_with_sl_index_details_t),
    .traced = 1,
    .tojson = vl_api_sr_policies_with_sl_index_details_t_tojson,
    .fromjson = vl_api_sr_policies_with_sl_index_details_t_fromjson,
    .calc_size = vl_api_sr_policies_with_sl_index_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sr_policies_with_sl_index_dump", api_sr_policies_with_sl_index_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SR_STEERING_POL_DETAILS + msg_id_base,
    .name = "sr_steering_pol_details",
    .handler = vl_api_sr_steering_pol_details_t_handler,
    .endian = vl_api_sr_steering_pol_details_t_endian,
    .format_fn = vl_api_sr_steering_pol_details_t_format,
    .size = sizeof(vl_api_sr_steering_pol_details_t),
    .traced = 1,
    .tojson = vl_api_sr_steering_pol_details_t_tojson,
    .fromjson = vl_api_sr_steering_pol_details_t_fromjson,
    .calc_size = vl_api_sr_steering_pol_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sr_steering_pol_dump", api_sr_steering_pol_dump);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   sr_test_main_t * mainp = &sr_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("sr_f0cc4ec6");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "sr plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
