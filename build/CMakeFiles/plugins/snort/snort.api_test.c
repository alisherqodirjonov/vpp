#define vl_endianfun            /* define message structures */
#include "snort.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "snort.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "snort.api.h"
#undef vl_printfun

/* Generation not supported (vl_api_snort_instance_get_reply_t_handler()) */
/* Generation not supported (vl_api_snort_interface_get_reply_t_handler()) */
/* Generation not supported (vl_api_snort_client_get_reply_t_handler()) */
/* Generation not supported (vl_api_snort_instance_create_reply_t_handler()) */
/* Generation not supported (vl_api_snort_instance_delete_reply_t_handler()) */
/* Generation not supported (vl_api_snort_client_disconnect_reply_t_handler()) */
/* Generation not supported (vl_api_snort_instance_disconnect_reply_t_handler()) */
/* Generation not supported (vl_api_snort_interface_attach_reply_t_handler()) */
/* Generation not supported (vl_api_snort_interface_detach_reply_t_handler()) */
/* Generation not supported (vl_api_snort_input_mode_get_reply_t_handler()) */
/* Generation not supported (vl_api_snort_input_mode_set_reply_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SNORT_INSTANCE_GET_REPLY + msg_id_base,
    .name = "snort_instance_get_reply",
    .handler = vl_api_snort_instance_get_reply_t_handler,
    .endian = vl_api_snort_instance_get_reply_t_endian,
    .format_fn = vl_api_snort_instance_get_reply_t_format,
    .size = sizeof(vl_api_snort_instance_get_reply_t),
    .traced = 1,
    .tojson = vl_api_snort_instance_get_reply_t_tojson,
    .fromjson = vl_api_snort_instance_get_reply_t_fromjson,
    .calc_size = vl_api_snort_instance_get_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "snort_instance_get", api_snort_instance_get);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SNORT_INTERFACE_GET_REPLY + msg_id_base,
    .name = "snort_interface_get_reply",
    .handler = vl_api_snort_interface_get_reply_t_handler,
    .endian = vl_api_snort_interface_get_reply_t_endian,
    .format_fn = vl_api_snort_interface_get_reply_t_format,
    .size = sizeof(vl_api_snort_interface_get_reply_t),
    .traced = 1,
    .tojson = vl_api_snort_interface_get_reply_t_tojson,
    .fromjson = vl_api_snort_interface_get_reply_t_fromjson,
    .calc_size = vl_api_snort_interface_get_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "snort_interface_get", api_snort_interface_get);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SNORT_CLIENT_GET_REPLY + msg_id_base,
    .name = "snort_client_get_reply",
    .handler = vl_api_snort_client_get_reply_t_handler,
    .endian = vl_api_snort_client_get_reply_t_endian,
    .format_fn = vl_api_snort_client_get_reply_t_format,
    .size = sizeof(vl_api_snort_client_get_reply_t),
    .traced = 1,
    .tojson = vl_api_snort_client_get_reply_t_tojson,
    .fromjson = vl_api_snort_client_get_reply_t_fromjson,
    .calc_size = vl_api_snort_client_get_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "snort_client_get", api_snort_client_get);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SNORT_INSTANCE_CREATE_REPLY + msg_id_base,
    .name = "snort_instance_create_reply",
    .handler = vl_api_snort_instance_create_reply_t_handler,
    .endian = vl_api_snort_instance_create_reply_t_endian,
    .format_fn = vl_api_snort_instance_create_reply_t_format,
    .size = sizeof(vl_api_snort_instance_create_reply_t),
    .traced = 1,
    .tojson = vl_api_snort_instance_create_reply_t_tojson,
    .fromjson = vl_api_snort_instance_create_reply_t_fromjson,
    .calc_size = vl_api_snort_instance_create_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "snort_instance_create", api_snort_instance_create);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SNORT_INSTANCE_DELETE_REPLY + msg_id_base,
    .name = "snort_instance_delete_reply",
    .handler = vl_api_snort_instance_delete_reply_t_handler,
    .endian = vl_api_snort_instance_delete_reply_t_endian,
    .format_fn = vl_api_snort_instance_delete_reply_t_format,
    .size = sizeof(vl_api_snort_instance_delete_reply_t),
    .traced = 1,
    .tojson = vl_api_snort_instance_delete_reply_t_tojson,
    .fromjson = vl_api_snort_instance_delete_reply_t_fromjson,
    .calc_size = vl_api_snort_instance_delete_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "snort_instance_delete", api_snort_instance_delete);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SNORT_CLIENT_DISCONNECT_REPLY + msg_id_base,
    .name = "snort_client_disconnect_reply",
    .handler = vl_api_snort_client_disconnect_reply_t_handler,
    .endian = vl_api_snort_client_disconnect_reply_t_endian,
    .format_fn = vl_api_snort_client_disconnect_reply_t_format,
    .size = sizeof(vl_api_snort_client_disconnect_reply_t),
    .traced = 1,
    .tojson = vl_api_snort_client_disconnect_reply_t_tojson,
    .fromjson = vl_api_snort_client_disconnect_reply_t_fromjson,
    .calc_size = vl_api_snort_client_disconnect_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "snort_client_disconnect", api_snort_client_disconnect);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SNORT_INSTANCE_DISCONNECT_REPLY + msg_id_base,
    .name = "snort_instance_disconnect_reply",
    .handler = vl_api_snort_instance_disconnect_reply_t_handler,
    .endian = vl_api_snort_instance_disconnect_reply_t_endian,
    .format_fn = vl_api_snort_instance_disconnect_reply_t_format,
    .size = sizeof(vl_api_snort_instance_disconnect_reply_t),
    .traced = 1,
    .tojson = vl_api_snort_instance_disconnect_reply_t_tojson,
    .fromjson = vl_api_snort_instance_disconnect_reply_t_fromjson,
    .calc_size = vl_api_snort_instance_disconnect_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "snort_instance_disconnect", api_snort_instance_disconnect);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SNORT_INTERFACE_ATTACH_REPLY + msg_id_base,
    .name = "snort_interface_attach_reply",
    .handler = vl_api_snort_interface_attach_reply_t_handler,
    .endian = vl_api_snort_interface_attach_reply_t_endian,
    .format_fn = vl_api_snort_interface_attach_reply_t_format,
    .size = sizeof(vl_api_snort_interface_attach_reply_t),
    .traced = 1,
    .tojson = vl_api_snort_interface_attach_reply_t_tojson,
    .fromjson = vl_api_snort_interface_attach_reply_t_fromjson,
    .calc_size = vl_api_snort_interface_attach_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "snort_interface_attach", api_snort_interface_attach);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SNORT_INTERFACE_DETACH_REPLY + msg_id_base,
    .name = "snort_interface_detach_reply",
    .handler = vl_api_snort_interface_detach_reply_t_handler,
    .endian = vl_api_snort_interface_detach_reply_t_endian,
    .format_fn = vl_api_snort_interface_detach_reply_t_format,
    .size = sizeof(vl_api_snort_interface_detach_reply_t),
    .traced = 1,
    .tojson = vl_api_snort_interface_detach_reply_t_tojson,
    .fromjson = vl_api_snort_interface_detach_reply_t_fromjson,
    .calc_size = vl_api_snort_interface_detach_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "snort_interface_detach", api_snort_interface_detach);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SNORT_INPUT_MODE_GET_REPLY + msg_id_base,
    .name = "snort_input_mode_get_reply",
    .handler = vl_api_snort_input_mode_get_reply_t_handler,
    .endian = vl_api_snort_input_mode_get_reply_t_endian,
    .format_fn = vl_api_snort_input_mode_get_reply_t_format,
    .size = sizeof(vl_api_snort_input_mode_get_reply_t),
    .traced = 1,
    .tojson = vl_api_snort_input_mode_get_reply_t_tojson,
    .fromjson = vl_api_snort_input_mode_get_reply_t_fromjson,
    .calc_size = vl_api_snort_input_mode_get_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "snort_input_mode_get", api_snort_input_mode_get);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SNORT_INPUT_MODE_SET_REPLY + msg_id_base,
    .name = "snort_input_mode_set_reply",
    .handler = vl_api_snort_input_mode_set_reply_t_handler,
    .endian = vl_api_snort_input_mode_set_reply_t_endian,
    .format_fn = vl_api_snort_input_mode_set_reply_t_format,
    .size = sizeof(vl_api_snort_input_mode_set_reply_t),
    .traced = 1,
    .tojson = vl_api_snort_input_mode_set_reply_t_tojson,
    .fromjson = vl_api_snort_input_mode_set_reply_t_fromjson,
    .calc_size = vl_api_snort_input_mode_set_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "snort_input_mode_set", api_snort_input_mode_set);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   snort_test_main_t * mainp = &snort_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("snort_f89115d4");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "snort plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
