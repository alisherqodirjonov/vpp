#define vl_endianfun            /* define message structures */
#include "af_packet.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "af_packet.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "af_packet.api.h"
#undef vl_printfun

/* Generation not supported (vl_api_af_packet_create_reply_t_handler()) */
/* Generation not supported (vl_api_af_packet_create_v2_reply_t_handler()) */
/* Generation not supported (vl_api_af_packet_create_v3_reply_t_handler()) */
#ifndef VL_API_AF_PACKET_DELETE_REPLY_T_HANDLER
static void
vl_api_af_packet_delete_reply_t_handler (vl_api_af_packet_delete_reply_t * mp) {
   vat_main_t * vam = af_packet_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_AF_PACKET_SET_L4_CKSUM_OFFLOAD_REPLY_T_HANDLER
static void
vl_api_af_packet_set_l4_cksum_offload_reply_t_handler (vl_api_af_packet_set_l4_cksum_offload_reply_t * mp) {
   vat_main_t * vam = af_packet_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_af_packet_details_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_AF_PACKET_CREATE_REPLY + msg_id_base,
    .name = "af_packet_create_reply",
    .handler = vl_api_af_packet_create_reply_t_handler,
    .endian = vl_api_af_packet_create_reply_t_endian,
    .format_fn = vl_api_af_packet_create_reply_t_format,
    .size = sizeof(vl_api_af_packet_create_reply_t),
    .traced = 1,
    .tojson = vl_api_af_packet_create_reply_t_tojson,
    .fromjson = vl_api_af_packet_create_reply_t_fromjson,
    .calc_size = vl_api_af_packet_create_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "af_packet_create", api_af_packet_create);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_AF_PACKET_CREATE_V2_REPLY + msg_id_base,
    .name = "af_packet_create_v2_reply",
    .handler = vl_api_af_packet_create_v2_reply_t_handler,
    .endian = vl_api_af_packet_create_v2_reply_t_endian,
    .format_fn = vl_api_af_packet_create_v2_reply_t_format,
    .size = sizeof(vl_api_af_packet_create_v2_reply_t),
    .traced = 1,
    .tojson = vl_api_af_packet_create_v2_reply_t_tojson,
    .fromjson = vl_api_af_packet_create_v2_reply_t_fromjson,
    .calc_size = vl_api_af_packet_create_v2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "af_packet_create_v2", api_af_packet_create_v2);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_AF_PACKET_CREATE_V3_REPLY + msg_id_base,
    .name = "af_packet_create_v3_reply",
    .handler = vl_api_af_packet_create_v3_reply_t_handler,
    .endian = vl_api_af_packet_create_v3_reply_t_endian,
    .format_fn = vl_api_af_packet_create_v3_reply_t_format,
    .size = sizeof(vl_api_af_packet_create_v3_reply_t),
    .traced = 1,
    .tojson = vl_api_af_packet_create_v3_reply_t_tojson,
    .fromjson = vl_api_af_packet_create_v3_reply_t_fromjson,
    .calc_size = vl_api_af_packet_create_v3_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "af_packet_create_v3", api_af_packet_create_v3);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_AF_PACKET_DELETE_REPLY + msg_id_base,
    .name = "af_packet_delete_reply",
    .handler = vl_api_af_packet_delete_reply_t_handler,
    .endian = vl_api_af_packet_delete_reply_t_endian,
    .format_fn = vl_api_af_packet_delete_reply_t_format,
    .size = sizeof(vl_api_af_packet_delete_reply_t),
    .traced = 1,
    .tojson = vl_api_af_packet_delete_reply_t_tojson,
    .fromjson = vl_api_af_packet_delete_reply_t_fromjson,
    .calc_size = vl_api_af_packet_delete_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "af_packet_delete", api_af_packet_delete);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_AF_PACKET_SET_L4_CKSUM_OFFLOAD_REPLY + msg_id_base,
    .name = "af_packet_set_l4_cksum_offload_reply",
    .handler = vl_api_af_packet_set_l4_cksum_offload_reply_t_handler,
    .endian = vl_api_af_packet_set_l4_cksum_offload_reply_t_endian,
    .format_fn = vl_api_af_packet_set_l4_cksum_offload_reply_t_format,
    .size = sizeof(vl_api_af_packet_set_l4_cksum_offload_reply_t),
    .traced = 1,
    .tojson = vl_api_af_packet_set_l4_cksum_offload_reply_t_tojson,
    .fromjson = vl_api_af_packet_set_l4_cksum_offload_reply_t_fromjson,
    .calc_size = vl_api_af_packet_set_l4_cksum_offload_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "af_packet_set_l4_cksum_offload", api_af_packet_set_l4_cksum_offload);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_AF_PACKET_DETAILS + msg_id_base,
    .name = "af_packet_details",
    .handler = vl_api_af_packet_details_t_handler,
    .endian = vl_api_af_packet_details_t_endian,
    .format_fn = vl_api_af_packet_details_t_format,
    .size = sizeof(vl_api_af_packet_details_t),
    .traced = 1,
    .tojson = vl_api_af_packet_details_t_tojson,
    .fromjson = vl_api_af_packet_details_t_fromjson,
    .calc_size = vl_api_af_packet_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "af_packet_dump", api_af_packet_dump);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   af_packet_test_main_t * mainp = &af_packet_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("af_packet_720ee900");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "af_packet plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
