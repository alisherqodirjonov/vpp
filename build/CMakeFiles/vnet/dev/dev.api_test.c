#define vl_endianfun            /* define message structures */
#include "dev.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "dev.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "dev.api.h"
#undef vl_printfun

/* Generation not supported (vl_api_dev_attach_reply_t_handler()) */
/* Generation not supported (vl_api_dev_detach_reply_t_handler()) */
/* Generation not supported (vl_api_dev_create_port_if_reply_t_handler()) */
/* Generation not supported (vl_api_dev_remove_port_if_reply_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DEV_ATTACH_REPLY + msg_id_base,
    .name = "dev_attach_reply",
    .handler = vl_api_dev_attach_reply_t_handler,
    .endian = vl_api_dev_attach_reply_t_endian,
    .format_fn = vl_api_dev_attach_reply_t_format,
    .size = sizeof(vl_api_dev_attach_reply_t),
    .traced = 1,
    .tojson = vl_api_dev_attach_reply_t_tojson,
    .fromjson = vl_api_dev_attach_reply_t_fromjson,
    .calc_size = vl_api_dev_attach_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "dev_attach", api_dev_attach);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DEV_DETACH_REPLY + msg_id_base,
    .name = "dev_detach_reply",
    .handler = vl_api_dev_detach_reply_t_handler,
    .endian = vl_api_dev_detach_reply_t_endian,
    .format_fn = vl_api_dev_detach_reply_t_format,
    .size = sizeof(vl_api_dev_detach_reply_t),
    .traced = 1,
    .tojson = vl_api_dev_detach_reply_t_tojson,
    .fromjson = vl_api_dev_detach_reply_t_fromjson,
    .calc_size = vl_api_dev_detach_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "dev_detach", api_dev_detach);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DEV_CREATE_PORT_IF_REPLY + msg_id_base,
    .name = "dev_create_port_if_reply",
    .handler = vl_api_dev_create_port_if_reply_t_handler,
    .endian = vl_api_dev_create_port_if_reply_t_endian,
    .format_fn = vl_api_dev_create_port_if_reply_t_format,
    .size = sizeof(vl_api_dev_create_port_if_reply_t),
    .traced = 1,
    .tojson = vl_api_dev_create_port_if_reply_t_tojson,
    .fromjson = vl_api_dev_create_port_if_reply_t_fromjson,
    .calc_size = vl_api_dev_create_port_if_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "dev_create_port_if", api_dev_create_port_if);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DEV_REMOVE_PORT_IF_REPLY + msg_id_base,
    .name = "dev_remove_port_if_reply",
    .handler = vl_api_dev_remove_port_if_reply_t_handler,
    .endian = vl_api_dev_remove_port_if_reply_t_endian,
    .format_fn = vl_api_dev_remove_port_if_reply_t_format,
    .size = sizeof(vl_api_dev_remove_port_if_reply_t),
    .traced = 1,
    .tojson = vl_api_dev_remove_port_if_reply_t_tojson,
    .fromjson = vl_api_dev_remove_port_if_reply_t_fromjson,
    .calc_size = vl_api_dev_remove_port_if_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "dev_remove_port_if", api_dev_remove_port_if);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   dev_test_main_t * mainp = &dev_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("dev_86eacf88");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "dev plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
