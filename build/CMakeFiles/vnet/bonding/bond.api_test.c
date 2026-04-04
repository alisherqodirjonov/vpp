#define vl_endianfun            /* define message structures */
#include "bond.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "bond.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "bond.api.h"
#undef vl_printfun

/* Generation not supported (vl_api_bond_create_reply_t_handler()) */
/* Generation not supported (vl_api_bond_create2_reply_t_handler()) */
#ifndef VL_API_BOND_DELETE_REPLY_T_HANDLER
static void
vl_api_bond_delete_reply_t_handler (vl_api_bond_delete_reply_t * mp) {
   vat_main_t * vam = bond_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_bond_enslave_reply_t_handler()) */
/* Generation not supported (vl_api_bond_add_member_reply_t_handler()) */
#ifndef VL_API_BOND_DETACH_SLAVE_REPLY_T_HANDLER
static void
vl_api_bond_detach_slave_reply_t_handler (vl_api_bond_detach_slave_reply_t * mp) {
   vat_main_t * vam = bond_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_BOND_DETACH_MEMBER_REPLY_T_HANDLER
static void
vl_api_bond_detach_member_reply_t_handler (vl_api_bond_detach_member_reply_t * mp) {
   vat_main_t * vam = bond_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_sw_interface_bond_details_t_handler()) */
/* Generation not supported (vl_api_sw_bond_interface_details_t_handler()) */
/* Generation not supported (vl_api_sw_interface_slave_details_t_handler()) */
/* Generation not supported (vl_api_sw_member_interface_details_t_handler()) */
#ifndef VL_API_SW_INTERFACE_SET_BOND_WEIGHT_REPLY_T_HANDLER
static void
vl_api_sw_interface_set_bond_weight_reply_t_handler (vl_api_sw_interface_set_bond_weight_reply_t * mp) {
   vat_main_t * vam = bond_test_main.vat_main;
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
    .id = VL_API_BOND_CREATE_REPLY + msg_id_base,
    .name = "bond_create_reply",
    .handler = vl_api_bond_create_reply_t_handler,
    .endian = vl_api_bond_create_reply_t_endian,
    .format_fn = vl_api_bond_create_reply_t_format,
    .size = sizeof(vl_api_bond_create_reply_t),
    .traced = 1,
    .tojson = vl_api_bond_create_reply_t_tojson,
    .fromjson = vl_api_bond_create_reply_t_fromjson,
    .calc_size = vl_api_bond_create_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bond_create", api_bond_create);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BOND_CREATE2_REPLY + msg_id_base,
    .name = "bond_create2_reply",
    .handler = vl_api_bond_create2_reply_t_handler,
    .endian = vl_api_bond_create2_reply_t_endian,
    .format_fn = vl_api_bond_create2_reply_t_format,
    .size = sizeof(vl_api_bond_create2_reply_t),
    .traced = 1,
    .tojson = vl_api_bond_create2_reply_t_tojson,
    .fromjson = vl_api_bond_create2_reply_t_fromjson,
    .calc_size = vl_api_bond_create2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bond_create2", api_bond_create2);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BOND_DELETE_REPLY + msg_id_base,
    .name = "bond_delete_reply",
    .handler = vl_api_bond_delete_reply_t_handler,
    .endian = vl_api_bond_delete_reply_t_endian,
    .format_fn = vl_api_bond_delete_reply_t_format,
    .size = sizeof(vl_api_bond_delete_reply_t),
    .traced = 1,
    .tojson = vl_api_bond_delete_reply_t_tojson,
    .fromjson = vl_api_bond_delete_reply_t_fromjson,
    .calc_size = vl_api_bond_delete_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bond_delete", api_bond_delete);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BOND_ENSLAVE_REPLY + msg_id_base,
    .name = "bond_enslave_reply",
    .handler = vl_api_bond_enslave_reply_t_handler,
    .endian = vl_api_bond_enslave_reply_t_endian,
    .format_fn = vl_api_bond_enslave_reply_t_format,
    .size = sizeof(vl_api_bond_enslave_reply_t),
    .traced = 1,
    .tojson = vl_api_bond_enslave_reply_t_tojson,
    .fromjson = vl_api_bond_enslave_reply_t_fromjson,
    .calc_size = vl_api_bond_enslave_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bond_enslave", api_bond_enslave);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BOND_ADD_MEMBER_REPLY + msg_id_base,
    .name = "bond_add_member_reply",
    .handler = vl_api_bond_add_member_reply_t_handler,
    .endian = vl_api_bond_add_member_reply_t_endian,
    .format_fn = vl_api_bond_add_member_reply_t_format,
    .size = sizeof(vl_api_bond_add_member_reply_t),
    .traced = 1,
    .tojson = vl_api_bond_add_member_reply_t_tojson,
    .fromjson = vl_api_bond_add_member_reply_t_fromjson,
    .calc_size = vl_api_bond_add_member_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bond_add_member", api_bond_add_member);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BOND_DETACH_SLAVE_REPLY + msg_id_base,
    .name = "bond_detach_slave_reply",
    .handler = vl_api_bond_detach_slave_reply_t_handler,
    .endian = vl_api_bond_detach_slave_reply_t_endian,
    .format_fn = vl_api_bond_detach_slave_reply_t_format,
    .size = sizeof(vl_api_bond_detach_slave_reply_t),
    .traced = 1,
    .tojson = vl_api_bond_detach_slave_reply_t_tojson,
    .fromjson = vl_api_bond_detach_slave_reply_t_fromjson,
    .calc_size = vl_api_bond_detach_slave_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bond_detach_slave", api_bond_detach_slave);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BOND_DETACH_MEMBER_REPLY + msg_id_base,
    .name = "bond_detach_member_reply",
    .handler = vl_api_bond_detach_member_reply_t_handler,
    .endian = vl_api_bond_detach_member_reply_t_endian,
    .format_fn = vl_api_bond_detach_member_reply_t_format,
    .size = sizeof(vl_api_bond_detach_member_reply_t),
    .traced = 1,
    .tojson = vl_api_bond_detach_member_reply_t_tojson,
    .fromjson = vl_api_bond_detach_member_reply_t_fromjson,
    .calc_size = vl_api_bond_detach_member_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bond_detach_member", api_bond_detach_member);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_BOND_DETAILS + msg_id_base,
    .name = "sw_interface_bond_details",
    .handler = vl_api_sw_interface_bond_details_t_handler,
    .endian = vl_api_sw_interface_bond_details_t_endian,
    .format_fn = vl_api_sw_interface_bond_details_t_format,
    .size = sizeof(vl_api_sw_interface_bond_details_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_bond_details_t_tojson,
    .fromjson = vl_api_sw_interface_bond_details_t_fromjson,
    .calc_size = vl_api_sw_interface_bond_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_bond_dump", api_sw_interface_bond_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_BOND_INTERFACE_DETAILS + msg_id_base,
    .name = "sw_bond_interface_details",
    .handler = vl_api_sw_bond_interface_details_t_handler,
    .endian = vl_api_sw_bond_interface_details_t_endian,
    .format_fn = vl_api_sw_bond_interface_details_t_format,
    .size = sizeof(vl_api_sw_bond_interface_details_t),
    .traced = 1,
    .tojson = vl_api_sw_bond_interface_details_t_tojson,
    .fromjson = vl_api_sw_bond_interface_details_t_fromjson,
    .calc_size = vl_api_sw_bond_interface_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_bond_interface_dump", api_sw_bond_interface_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_SLAVE_DETAILS + msg_id_base,
    .name = "sw_interface_slave_details",
    .handler = vl_api_sw_interface_slave_details_t_handler,
    .endian = vl_api_sw_interface_slave_details_t_endian,
    .format_fn = vl_api_sw_interface_slave_details_t_format,
    .size = sizeof(vl_api_sw_interface_slave_details_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_slave_details_t_tojson,
    .fromjson = vl_api_sw_interface_slave_details_t_fromjson,
    .calc_size = vl_api_sw_interface_slave_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_slave_dump", api_sw_interface_slave_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_MEMBER_INTERFACE_DETAILS + msg_id_base,
    .name = "sw_member_interface_details",
    .handler = vl_api_sw_member_interface_details_t_handler,
    .endian = vl_api_sw_member_interface_details_t_endian,
    .format_fn = vl_api_sw_member_interface_details_t_format,
    .size = sizeof(vl_api_sw_member_interface_details_t),
    .traced = 1,
    .tojson = vl_api_sw_member_interface_details_t_tojson,
    .fromjson = vl_api_sw_member_interface_details_t_fromjson,
    .calc_size = vl_api_sw_member_interface_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_member_interface_dump", api_sw_member_interface_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_SET_BOND_WEIGHT_REPLY + msg_id_base,
    .name = "sw_interface_set_bond_weight_reply",
    .handler = vl_api_sw_interface_set_bond_weight_reply_t_handler,
    .endian = vl_api_sw_interface_set_bond_weight_reply_t_endian,
    .format_fn = vl_api_sw_interface_set_bond_weight_reply_t_format,
    .size = sizeof(vl_api_sw_interface_set_bond_weight_reply_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_set_bond_weight_reply_t_tojson,
    .fromjson = vl_api_sw_interface_set_bond_weight_reply_t_fromjson,
    .calc_size = vl_api_sw_interface_set_bond_weight_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_set_bond_weight", api_sw_interface_set_bond_weight);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   bond_test_main_t * mainp = &bond_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("bond_727f50bc");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "bond plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
