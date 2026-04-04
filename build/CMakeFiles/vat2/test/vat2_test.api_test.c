#define vl_endianfun            /* define message structures */
#include "vat2_test.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "vat2_test.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "vat2_test.api.h"
#undef vl_printfun

#ifndef VL_API_TEST_PREFIX_REPLY_T_HANDLER
static void
vl_api_test_prefix_reply_t_handler (vl_api_test_prefix_reply_t * mp) {
   vat_main_t * vam = vat2_test_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_TEST_ENUM_REPLY_T_HANDLER
static void
vl_api_test_enum_reply_t_handler (vl_api_test_enum_reply_t * mp) {
   vat_main_t * vam = vat2_test_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_TEST_STRING_REPLY_T_HANDLER
static void
vl_api_test_string_reply_t_handler (vl_api_test_string_reply_t * mp) {
   vat_main_t * vam = vat2_test_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_TEST_STRING2_REPLY_T_HANDLER
static void
vl_api_test_string2_reply_t_handler (vl_api_test_string2_reply_t * mp) {
   vat_main_t * vam = vat2_test_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_TEST_VLA_REPLY_T_HANDLER
static void
vl_api_test_vla_reply_t_handler (vl_api_test_vla_reply_t * mp) {
   vat_main_t * vam = vat2_test_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_TEST_VLA2_REPLY_T_HANDLER
static void
vl_api_test_vla2_reply_t_handler (vl_api_test_vla2_reply_t * mp) {
   vat_main_t * vam = vat2_test_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_TEST_VLA3_REPLY_T_HANDLER
static void
vl_api_test_vla3_reply_t_handler (vl_api_test_vla3_reply_t * mp) {
   vat_main_t * vam = vat2_test_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_TEST_VLA4_REPLY_T_HANDLER
static void
vl_api_test_vla4_reply_t_handler (vl_api_test_vla4_reply_t * mp) {
   vat_main_t * vam = vat2_test_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_TEST_VLA5_REPLY_T_HANDLER
static void
vl_api_test_vla5_reply_t_handler (vl_api_test_vla5_reply_t * mp) {
   vat_main_t * vam = vat2_test_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_TEST_ADDRESSES_REPLY_T_HANDLER
static void
vl_api_test_addresses_reply_t_handler (vl_api_test_addresses_reply_t * mp) {
   vat_main_t * vam = vat2_test_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_TEST_ADDRESSES2_REPLY_T_HANDLER
static void
vl_api_test_addresses2_reply_t_handler (vl_api_test_addresses2_reply_t * mp) {
   vat_main_t * vam = vat2_test_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_TEST_ADDRESSES3_REPLY_T_HANDLER
static void
vl_api_test_addresses3_reply_t_handler (vl_api_test_addresses3_reply_t * mp) {
   vat_main_t * vam = vat2_test_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_TEST_EMPTY_REPLY_T_HANDLER
static void
vl_api_test_empty_reply_t_handler (vl_api_test_empty_reply_t * mp) {
   vat_main_t * vam = vat2_test_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_TEST_INTERFACE_REPLY_T_HANDLER
static void
vl_api_test_interface_reply_t_handler (vl_api_test_interface_reply_t * mp) {
   vat_main_t * vam = vat2_test_test_main.vat_main;
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
    .id = VL_API_TEST_PREFIX_REPLY + msg_id_base,
    .name = "test_prefix_reply",
    .handler = vl_api_test_prefix_reply_t_handler,
    .endian = vl_api_test_prefix_reply_t_endian,
    .format_fn = vl_api_test_prefix_reply_t_format,
    .size = sizeof(vl_api_test_prefix_reply_t),
    .traced = 1,
    .tojson = vl_api_test_prefix_reply_t_tojson,
    .fromjson = vl_api_test_prefix_reply_t_fromjson,
    .calc_size = vl_api_test_prefix_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "test_prefix", api_test_prefix);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_TEST_ENUM_REPLY + msg_id_base,
    .name = "test_enum_reply",
    .handler = vl_api_test_enum_reply_t_handler,
    .endian = vl_api_test_enum_reply_t_endian,
    .format_fn = vl_api_test_enum_reply_t_format,
    .size = sizeof(vl_api_test_enum_reply_t),
    .traced = 1,
    .tojson = vl_api_test_enum_reply_t_tojson,
    .fromjson = vl_api_test_enum_reply_t_fromjson,
    .calc_size = vl_api_test_enum_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "test_enum", api_test_enum);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_TEST_STRING_REPLY + msg_id_base,
    .name = "test_string_reply",
    .handler = vl_api_test_string_reply_t_handler,
    .endian = vl_api_test_string_reply_t_endian,
    .format_fn = vl_api_test_string_reply_t_format,
    .size = sizeof(vl_api_test_string_reply_t),
    .traced = 1,
    .tojson = vl_api_test_string_reply_t_tojson,
    .fromjson = vl_api_test_string_reply_t_fromjson,
    .calc_size = vl_api_test_string_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "test_string", api_test_string);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_TEST_STRING2_REPLY + msg_id_base,
    .name = "test_string2_reply",
    .handler = vl_api_test_string2_reply_t_handler,
    .endian = vl_api_test_string2_reply_t_endian,
    .format_fn = vl_api_test_string2_reply_t_format,
    .size = sizeof(vl_api_test_string2_reply_t),
    .traced = 1,
    .tojson = vl_api_test_string2_reply_t_tojson,
    .fromjson = vl_api_test_string2_reply_t_fromjson,
    .calc_size = vl_api_test_string2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "test_string2", api_test_string2);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_TEST_VLA_REPLY + msg_id_base,
    .name = "test_vla_reply",
    .handler = vl_api_test_vla_reply_t_handler,
    .endian = vl_api_test_vla_reply_t_endian,
    .format_fn = vl_api_test_vla_reply_t_format,
    .size = sizeof(vl_api_test_vla_reply_t),
    .traced = 1,
    .tojson = vl_api_test_vla_reply_t_tojson,
    .fromjson = vl_api_test_vla_reply_t_fromjson,
    .calc_size = vl_api_test_vla_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "test_vla", api_test_vla);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_TEST_VLA2_REPLY + msg_id_base,
    .name = "test_vla2_reply",
    .handler = vl_api_test_vla2_reply_t_handler,
    .endian = vl_api_test_vla2_reply_t_endian,
    .format_fn = vl_api_test_vla2_reply_t_format,
    .size = sizeof(vl_api_test_vla2_reply_t),
    .traced = 1,
    .tojson = vl_api_test_vla2_reply_t_tojson,
    .fromjson = vl_api_test_vla2_reply_t_fromjson,
    .calc_size = vl_api_test_vla2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "test_vla2", api_test_vla2);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_TEST_VLA3_REPLY + msg_id_base,
    .name = "test_vla3_reply",
    .handler = vl_api_test_vla3_reply_t_handler,
    .endian = vl_api_test_vla3_reply_t_endian,
    .format_fn = vl_api_test_vla3_reply_t_format,
    .size = sizeof(vl_api_test_vla3_reply_t),
    .traced = 1,
    .tojson = vl_api_test_vla3_reply_t_tojson,
    .fromjson = vl_api_test_vla3_reply_t_fromjson,
    .calc_size = vl_api_test_vla3_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "test_vla3", api_test_vla3);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_TEST_VLA4_REPLY + msg_id_base,
    .name = "test_vla4_reply",
    .handler = vl_api_test_vla4_reply_t_handler,
    .endian = vl_api_test_vla4_reply_t_endian,
    .format_fn = vl_api_test_vla4_reply_t_format,
    .size = sizeof(vl_api_test_vla4_reply_t),
    .traced = 1,
    .tojson = vl_api_test_vla4_reply_t_tojson,
    .fromjson = vl_api_test_vla4_reply_t_fromjson,
    .calc_size = vl_api_test_vla4_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "test_vla4", api_test_vla4);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_TEST_VLA5_REPLY + msg_id_base,
    .name = "test_vla5_reply",
    .handler = vl_api_test_vla5_reply_t_handler,
    .endian = vl_api_test_vla5_reply_t_endian,
    .format_fn = vl_api_test_vla5_reply_t_format,
    .size = sizeof(vl_api_test_vla5_reply_t),
    .traced = 1,
    .tojson = vl_api_test_vla5_reply_t_tojson,
    .fromjson = vl_api_test_vla5_reply_t_fromjson,
    .calc_size = vl_api_test_vla5_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "test_vla5", api_test_vla5);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_TEST_ADDRESSES_REPLY + msg_id_base,
    .name = "test_addresses_reply",
    .handler = vl_api_test_addresses_reply_t_handler,
    .endian = vl_api_test_addresses_reply_t_endian,
    .format_fn = vl_api_test_addresses_reply_t_format,
    .size = sizeof(vl_api_test_addresses_reply_t),
    .traced = 1,
    .tojson = vl_api_test_addresses_reply_t_tojson,
    .fromjson = vl_api_test_addresses_reply_t_fromjson,
    .calc_size = vl_api_test_addresses_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "test_addresses", api_test_addresses);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_TEST_ADDRESSES2_REPLY + msg_id_base,
    .name = "test_addresses2_reply",
    .handler = vl_api_test_addresses2_reply_t_handler,
    .endian = vl_api_test_addresses2_reply_t_endian,
    .format_fn = vl_api_test_addresses2_reply_t_format,
    .size = sizeof(vl_api_test_addresses2_reply_t),
    .traced = 1,
    .tojson = vl_api_test_addresses2_reply_t_tojson,
    .fromjson = vl_api_test_addresses2_reply_t_fromjson,
    .calc_size = vl_api_test_addresses2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "test_addresses2", api_test_addresses2);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_TEST_ADDRESSES3_REPLY + msg_id_base,
    .name = "test_addresses3_reply",
    .handler = vl_api_test_addresses3_reply_t_handler,
    .endian = vl_api_test_addresses3_reply_t_endian,
    .format_fn = vl_api_test_addresses3_reply_t_format,
    .size = sizeof(vl_api_test_addresses3_reply_t),
    .traced = 1,
    .tojson = vl_api_test_addresses3_reply_t_tojson,
    .fromjson = vl_api_test_addresses3_reply_t_fromjson,
    .calc_size = vl_api_test_addresses3_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "test_addresses3", api_test_addresses3);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_TEST_EMPTY_REPLY + msg_id_base,
    .name = "test_empty_reply",
    .handler = vl_api_test_empty_reply_t_handler,
    .endian = vl_api_test_empty_reply_t_endian,
    .format_fn = vl_api_test_empty_reply_t_format,
    .size = sizeof(vl_api_test_empty_reply_t),
    .traced = 1,
    .tojson = vl_api_test_empty_reply_t_tojson,
    .fromjson = vl_api_test_empty_reply_t_fromjson,
    .calc_size = vl_api_test_empty_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "test_empty", api_test_empty);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_TEST_INTERFACE_REPLY + msg_id_base,
    .name = "test_interface_reply",
    .handler = vl_api_test_interface_reply_t_handler,
    .endian = vl_api_test_interface_reply_t_endian,
    .format_fn = vl_api_test_interface_reply_t_format,
    .size = sizeof(vl_api_test_interface_reply_t),
    .traced = 1,
    .tojson = vl_api_test_interface_reply_t_tojson,
    .fromjson = vl_api_test_interface_reply_t_fromjson,
    .calc_size = vl_api_test_interface_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "test_interface", api_test_interface);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   vat2_test_test_main_t * mainp = &vat2_test_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("vat2_test_6787fedc");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "vat2_test plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
