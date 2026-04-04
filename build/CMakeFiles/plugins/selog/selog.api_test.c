#define vl_endianfun            /* define message structures */
#include "selog.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "selog.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "selog.api.h"
#undef vl_printfun

#ifndef VL_API_SELOG_GET_SHM_REPLY_T_HANDLER
static void
vl_api_selog_get_shm_reply_t_handler (vl_api_selog_get_shm_reply_t * mp) {
   vat_main_t * vam = selog_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_selog_get_string_table_reply_t_handler()) */
/* Generation not supported (vl_api_selog_track_details_t_handler()) */
/* Generation not supported (vl_api_selog_event_type_details_t_handler()) */
/* Generation not supported (vl_api_selog_event_type_string_details_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SELOG_GET_SHM_REPLY + msg_id_base,
    .name = "selog_get_shm_reply",
    .handler = vl_api_selog_get_shm_reply_t_handler,
    .endian = vl_api_selog_get_shm_reply_t_endian,
    .format_fn = vl_api_selog_get_shm_reply_t_format,
    .size = sizeof(vl_api_selog_get_shm_reply_t),
    .traced = 1,
    .tojson = vl_api_selog_get_shm_reply_t_tojson,
    .fromjson = vl_api_selog_get_shm_reply_t_fromjson,
    .calc_size = vl_api_selog_get_shm_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "selog_get_shm", api_selog_get_shm);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SELOG_GET_STRING_TABLE_REPLY + msg_id_base,
    .name = "selog_get_string_table_reply",
    .handler = vl_api_selog_get_string_table_reply_t_handler,
    .endian = vl_api_selog_get_string_table_reply_t_endian,
    .format_fn = vl_api_selog_get_string_table_reply_t_format,
    .size = sizeof(vl_api_selog_get_string_table_reply_t),
    .traced = 1,
    .tojson = vl_api_selog_get_string_table_reply_t_tojson,
    .fromjson = vl_api_selog_get_string_table_reply_t_fromjson,
    .calc_size = vl_api_selog_get_string_table_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "selog_get_string_table", api_selog_get_string_table);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SELOG_TRACK_DETAILS + msg_id_base,
    .name = "selog_track_details",
    .handler = vl_api_selog_track_details_t_handler,
    .endian = vl_api_selog_track_details_t_endian,
    .format_fn = vl_api_selog_track_details_t_format,
    .size = sizeof(vl_api_selog_track_details_t),
    .traced = 1,
    .tojson = vl_api_selog_track_details_t_tojson,
    .fromjson = vl_api_selog_track_details_t_fromjson,
    .calc_size = vl_api_selog_track_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "selog_track_dump", api_selog_track_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SELOG_EVENT_TYPE_DETAILS + msg_id_base,
    .name = "selog_event_type_details",
    .handler = vl_api_selog_event_type_details_t_handler,
    .endian = vl_api_selog_event_type_details_t_endian,
    .format_fn = vl_api_selog_event_type_details_t_format,
    .size = sizeof(vl_api_selog_event_type_details_t),
    .traced = 1,
    .tojson = vl_api_selog_event_type_details_t_tojson,
    .fromjson = vl_api_selog_event_type_details_t_fromjson,
    .calc_size = vl_api_selog_event_type_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "selog_event_type_dump", api_selog_event_type_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SELOG_EVENT_TYPE_STRING_DETAILS + msg_id_base,
    .name = "selog_event_type_string_details",
    .handler = vl_api_selog_event_type_string_details_t_handler,
    .endian = vl_api_selog_event_type_string_details_t_endian,
    .format_fn = vl_api_selog_event_type_string_details_t_format,
    .size = sizeof(vl_api_selog_event_type_string_details_t),
    .traced = 1,
    .tojson = vl_api_selog_event_type_string_details_t_tojson,
    .fromjson = vl_api_selog_event_type_string_details_t_fromjson,
    .calc_size = vl_api_selog_event_type_string_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "selog_event_type_string_dump", api_selog_event_type_string_dump);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   selog_test_main_t * mainp = &selog_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("selog_58ce3561");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "selog plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
