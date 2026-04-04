#define vl_endianfun            /* define message structures */
#include "lcp.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "lcp.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "lcp.api.h"
#undef vl_printfun

/* Generation not supported (vl_api_lcp_itf_pair_get_reply_t_handler()) */
/* Generation not supported (vl_api_lcp_itf_pair_get_v2_reply_t_handler()) */
#ifndef VL_API_LCP_DEFAULT_NS_SET_REPLY_T_HANDLER
static void
vl_api_lcp_default_ns_set_reply_t_handler (vl_api_lcp_default_ns_set_reply_t * mp) {
   vat_main_t * vam = lcp_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_lcp_default_ns_get_reply_t_handler()) */
#ifndef VL_API_LCP_ITF_PAIR_ADD_DEL_REPLY_T_HANDLER
static void
vl_api_lcp_itf_pair_add_del_reply_t_handler (vl_api_lcp_itf_pair_add_del_reply_t * mp) {
   vat_main_t * vam = lcp_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_lcp_itf_pair_add_del_v2_reply_t_handler()) */
/* Generation not supported (vl_api_lcp_itf_pair_add_del_v3_reply_t_handler()) */
#ifndef VL_API_LCP_ETHERTYPE_ENABLE_REPLY_T_HANDLER
static void
vl_api_lcp_ethertype_enable_reply_t_handler (vl_api_lcp_ethertype_enable_reply_t * mp) {
   vat_main_t * vam = lcp_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_lcp_ethertype_get_reply_t_handler()) */
#ifndef VL_API_LCP_ITF_PAIR_REPLACE_BEGIN_REPLY_T_HANDLER
static void
vl_api_lcp_itf_pair_replace_begin_reply_t_handler (vl_api_lcp_itf_pair_replace_begin_reply_t * mp) {
   vat_main_t * vam = lcp_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_LCP_ITF_PAIR_REPLACE_END_REPLY_T_HANDLER
static void
vl_api_lcp_itf_pair_replace_end_reply_t_handler (vl_api_lcp_itf_pair_replace_end_reply_t * mp) {
   vat_main_t * vam = lcp_test_main.vat_main;
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
    .id = VL_API_LCP_ITF_PAIR_GET_REPLY + msg_id_base,
    .name = "lcp_itf_pair_get_reply",
    .handler = vl_api_lcp_itf_pair_get_reply_t_handler,
    .endian = vl_api_lcp_itf_pair_get_reply_t_endian,
    .format_fn = vl_api_lcp_itf_pair_get_reply_t_format,
    .size = sizeof(vl_api_lcp_itf_pair_get_reply_t),
    .traced = 1,
    .tojson = vl_api_lcp_itf_pair_get_reply_t_tojson,
    .fromjson = vl_api_lcp_itf_pair_get_reply_t_fromjson,
    .calc_size = vl_api_lcp_itf_pair_get_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "lcp_itf_pair_get", api_lcp_itf_pair_get);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_LCP_ITF_PAIR_GET_V2_REPLY + msg_id_base,
    .name = "lcp_itf_pair_get_v2_reply",
    .handler = vl_api_lcp_itf_pair_get_v2_reply_t_handler,
    .endian = vl_api_lcp_itf_pair_get_v2_reply_t_endian,
    .format_fn = vl_api_lcp_itf_pair_get_v2_reply_t_format,
    .size = sizeof(vl_api_lcp_itf_pair_get_v2_reply_t),
    .traced = 1,
    .tojson = vl_api_lcp_itf_pair_get_v2_reply_t_tojson,
    .fromjson = vl_api_lcp_itf_pair_get_v2_reply_t_fromjson,
    .calc_size = vl_api_lcp_itf_pair_get_v2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "lcp_itf_pair_get_v2", api_lcp_itf_pair_get_v2);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_LCP_DEFAULT_NS_SET_REPLY + msg_id_base,
    .name = "lcp_default_ns_set_reply",
    .handler = vl_api_lcp_default_ns_set_reply_t_handler,
    .endian = vl_api_lcp_default_ns_set_reply_t_endian,
    .format_fn = vl_api_lcp_default_ns_set_reply_t_format,
    .size = sizeof(vl_api_lcp_default_ns_set_reply_t),
    .traced = 1,
    .tojson = vl_api_lcp_default_ns_set_reply_t_tojson,
    .fromjson = vl_api_lcp_default_ns_set_reply_t_fromjson,
    .calc_size = vl_api_lcp_default_ns_set_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "lcp_default_ns_set", api_lcp_default_ns_set);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_LCP_DEFAULT_NS_GET_REPLY + msg_id_base,
    .name = "lcp_default_ns_get_reply",
    .handler = vl_api_lcp_default_ns_get_reply_t_handler,
    .endian = vl_api_lcp_default_ns_get_reply_t_endian,
    .format_fn = vl_api_lcp_default_ns_get_reply_t_format,
    .size = sizeof(vl_api_lcp_default_ns_get_reply_t),
    .traced = 1,
    .tojson = vl_api_lcp_default_ns_get_reply_t_tojson,
    .fromjson = vl_api_lcp_default_ns_get_reply_t_fromjson,
    .calc_size = vl_api_lcp_default_ns_get_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "lcp_default_ns_get", api_lcp_default_ns_get);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_LCP_ITF_PAIR_ADD_DEL_REPLY + msg_id_base,
    .name = "lcp_itf_pair_add_del_reply",
    .handler = vl_api_lcp_itf_pair_add_del_reply_t_handler,
    .endian = vl_api_lcp_itf_pair_add_del_reply_t_endian,
    .format_fn = vl_api_lcp_itf_pair_add_del_reply_t_format,
    .size = sizeof(vl_api_lcp_itf_pair_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_lcp_itf_pair_add_del_reply_t_tojson,
    .fromjson = vl_api_lcp_itf_pair_add_del_reply_t_fromjson,
    .calc_size = vl_api_lcp_itf_pair_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "lcp_itf_pair_add_del", api_lcp_itf_pair_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_LCP_ITF_PAIR_ADD_DEL_V2_REPLY + msg_id_base,
    .name = "lcp_itf_pair_add_del_v2_reply",
    .handler = vl_api_lcp_itf_pair_add_del_v2_reply_t_handler,
    .endian = vl_api_lcp_itf_pair_add_del_v2_reply_t_endian,
    .format_fn = vl_api_lcp_itf_pair_add_del_v2_reply_t_format,
    .size = sizeof(vl_api_lcp_itf_pair_add_del_v2_reply_t),
    .traced = 1,
    .tojson = vl_api_lcp_itf_pair_add_del_v2_reply_t_tojson,
    .fromjson = vl_api_lcp_itf_pair_add_del_v2_reply_t_fromjson,
    .calc_size = vl_api_lcp_itf_pair_add_del_v2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "lcp_itf_pair_add_del_v2", api_lcp_itf_pair_add_del_v2);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_LCP_ITF_PAIR_ADD_DEL_V3_REPLY + msg_id_base,
    .name = "lcp_itf_pair_add_del_v3_reply",
    .handler = vl_api_lcp_itf_pair_add_del_v3_reply_t_handler,
    .endian = vl_api_lcp_itf_pair_add_del_v3_reply_t_endian,
    .format_fn = vl_api_lcp_itf_pair_add_del_v3_reply_t_format,
    .size = sizeof(vl_api_lcp_itf_pair_add_del_v3_reply_t),
    .traced = 1,
    .tojson = vl_api_lcp_itf_pair_add_del_v3_reply_t_tojson,
    .fromjson = vl_api_lcp_itf_pair_add_del_v3_reply_t_fromjson,
    .calc_size = vl_api_lcp_itf_pair_add_del_v3_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "lcp_itf_pair_add_del_v3", api_lcp_itf_pair_add_del_v3);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_LCP_ETHERTYPE_ENABLE_REPLY + msg_id_base,
    .name = "lcp_ethertype_enable_reply",
    .handler = vl_api_lcp_ethertype_enable_reply_t_handler,
    .endian = vl_api_lcp_ethertype_enable_reply_t_endian,
    .format_fn = vl_api_lcp_ethertype_enable_reply_t_format,
    .size = sizeof(vl_api_lcp_ethertype_enable_reply_t),
    .traced = 1,
    .tojson = vl_api_lcp_ethertype_enable_reply_t_tojson,
    .fromjson = vl_api_lcp_ethertype_enable_reply_t_fromjson,
    .calc_size = vl_api_lcp_ethertype_enable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "lcp_ethertype_enable", api_lcp_ethertype_enable);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_LCP_ETHERTYPE_GET_REPLY + msg_id_base,
    .name = "lcp_ethertype_get_reply",
    .handler = vl_api_lcp_ethertype_get_reply_t_handler,
    .endian = vl_api_lcp_ethertype_get_reply_t_endian,
    .format_fn = vl_api_lcp_ethertype_get_reply_t_format,
    .size = sizeof(vl_api_lcp_ethertype_get_reply_t),
    .traced = 1,
    .tojson = vl_api_lcp_ethertype_get_reply_t_tojson,
    .fromjson = vl_api_lcp_ethertype_get_reply_t_fromjson,
    .calc_size = vl_api_lcp_ethertype_get_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "lcp_ethertype_get", api_lcp_ethertype_get);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_LCP_ITF_PAIR_REPLACE_BEGIN_REPLY + msg_id_base,
    .name = "lcp_itf_pair_replace_begin_reply",
    .handler = vl_api_lcp_itf_pair_replace_begin_reply_t_handler,
    .endian = vl_api_lcp_itf_pair_replace_begin_reply_t_endian,
    .format_fn = vl_api_lcp_itf_pair_replace_begin_reply_t_format,
    .size = sizeof(vl_api_lcp_itf_pair_replace_begin_reply_t),
    .traced = 1,
    .tojson = vl_api_lcp_itf_pair_replace_begin_reply_t_tojson,
    .fromjson = vl_api_lcp_itf_pair_replace_begin_reply_t_fromjson,
    .calc_size = vl_api_lcp_itf_pair_replace_begin_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "lcp_itf_pair_replace_begin", api_lcp_itf_pair_replace_begin);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_LCP_ITF_PAIR_REPLACE_END_REPLY + msg_id_base,
    .name = "lcp_itf_pair_replace_end_reply",
    .handler = vl_api_lcp_itf_pair_replace_end_reply_t_handler,
    .endian = vl_api_lcp_itf_pair_replace_end_reply_t_endian,
    .format_fn = vl_api_lcp_itf_pair_replace_end_reply_t_format,
    .size = sizeof(vl_api_lcp_itf_pair_replace_end_reply_t),
    .traced = 1,
    .tojson = vl_api_lcp_itf_pair_replace_end_reply_t_tojson,
    .fromjson = vl_api_lcp_itf_pair_replace_end_reply_t_fromjson,
    .calc_size = vl_api_lcp_itf_pair_replace_end_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "lcp_itf_pair_replace_end", api_lcp_itf_pair_replace_end);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   lcp_test_main_t * mainp = &lcp_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("lcp_a76b917e");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "lcp plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
