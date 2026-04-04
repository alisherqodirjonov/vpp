#define vl_endianfun		/* define message structures */
#include "flowprobe.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "flowprobe.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "flowprobe.api.h"
#undef vl_printfun

#include "flowprobe.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("flowprobe_668f737a", VL_MSG_FLOWPROBE_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_flowprobe);
   vl_msg_api_add_msg_name_crc (am, "flowprobe_tx_interface_add_del_b782c976",
                                VL_API_FLOWPROBE_TX_INTERFACE_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "flowprobe_tx_interface_add_del_reply_e8d4e804",
                                VL_API_FLOWPROBE_TX_INTERFACE_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "flowprobe_interface_add_del_3420739c",
                                VL_API_FLOWPROBE_INTERFACE_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "flowprobe_interface_add_del_reply_e8d4e804",
                                VL_API_FLOWPROBE_INTERFACE_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "flowprobe_interface_dump_f9e6675e",
                                VL_API_FLOWPROBE_INTERFACE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "flowprobe_interface_details_427d77e0",
                                VL_API_FLOWPROBE_INTERFACE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "flowprobe_params_baa46c09",
                                VL_API_FLOWPROBE_PARAMS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "flowprobe_params_reply_e8d4e804",
                                VL_API_FLOWPROBE_PARAMS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "flowprobe_set_params_baa46c09",
                                VL_API_FLOWPROBE_SET_PARAMS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "flowprobe_set_params_reply_e8d4e804",
                                VL_API_FLOWPROBE_SET_PARAMS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "flowprobe_get_params_51077d14",
                                VL_API_FLOWPROBE_GET_PARAMS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "flowprobe_get_params_reply_f350d621",
                                VL_API_FLOWPROBE_GET_PARAMS_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_FLOWPROBE_TX_INTERFACE_ADD_DEL + msg_id_base,
   .name = "flowprobe_tx_interface_add_del",
   .handler = vl_api_flowprobe_tx_interface_add_del_t_handler,
   .endian = vl_api_flowprobe_tx_interface_add_del_t_endian,
   .format_fn = vl_api_flowprobe_tx_interface_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_flowprobe_tx_interface_add_del_t_tojson,
   .fromjson = vl_api_flowprobe_tx_interface_add_del_t_fromjson,
   .calc_size = vl_api_flowprobe_tx_interface_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_FLOWPROBE_TX_INTERFACE_ADD_DEL_REPLY + msg_id_base,
  .name = "flowprobe_tx_interface_add_del_reply",
  .handler = 0,
  .endian = vl_api_flowprobe_tx_interface_add_del_reply_t_endian,
  .format_fn = vl_api_flowprobe_tx_interface_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_flowprobe_tx_interface_add_del_reply_t_tojson,
  .fromjson = vl_api_flowprobe_tx_interface_add_del_reply_t_fromjson,
  .calc_size = vl_api_flowprobe_tx_interface_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_FLOWPROBE_INTERFACE_ADD_DEL + msg_id_base,
   .name = "flowprobe_interface_add_del",
   .handler = vl_api_flowprobe_interface_add_del_t_handler,
   .endian = vl_api_flowprobe_interface_add_del_t_endian,
   .format_fn = vl_api_flowprobe_interface_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_flowprobe_interface_add_del_t_tojson,
   .fromjson = vl_api_flowprobe_interface_add_del_t_fromjson,
   .calc_size = vl_api_flowprobe_interface_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_FLOWPROBE_INTERFACE_ADD_DEL_REPLY + msg_id_base,
  .name = "flowprobe_interface_add_del_reply",
  .handler = 0,
  .endian = vl_api_flowprobe_interface_add_del_reply_t_endian,
  .format_fn = vl_api_flowprobe_interface_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_flowprobe_interface_add_del_reply_t_tojson,
  .fromjson = vl_api_flowprobe_interface_add_del_reply_t_fromjson,
  .calc_size = vl_api_flowprobe_interface_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_FLOWPROBE_INTERFACE_DUMP + msg_id_base,
   .name = "flowprobe_interface_dump",
   .handler = vl_api_flowprobe_interface_dump_t_handler,
   .endian = vl_api_flowprobe_interface_dump_t_endian,
   .format_fn = vl_api_flowprobe_interface_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_flowprobe_interface_dump_t_tojson,
   .fromjson = vl_api_flowprobe_interface_dump_t_fromjson,
   .calc_size = vl_api_flowprobe_interface_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_FLOWPROBE_INTERFACE_DETAILS + msg_id_base,
  .name = "flowprobe_interface_details",
  .handler = 0,
  .endian = vl_api_flowprobe_interface_details_t_endian,
  .format_fn = vl_api_flowprobe_interface_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_flowprobe_interface_details_t_tojson,
  .fromjson = vl_api_flowprobe_interface_details_t_fromjson,
  .calc_size = vl_api_flowprobe_interface_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_FLOWPROBE_PARAMS + msg_id_base,
   .name = "flowprobe_params",
   .handler = vl_api_flowprobe_params_t_handler,
   .endian = vl_api_flowprobe_params_t_endian,
   .format_fn = vl_api_flowprobe_params_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_flowprobe_params_t_tojson,
   .fromjson = vl_api_flowprobe_params_t_fromjson,
   .calc_size = vl_api_flowprobe_params_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_FLOWPROBE_PARAMS_REPLY + msg_id_base,
  .name = "flowprobe_params_reply",
  .handler = 0,
  .endian = vl_api_flowprobe_params_reply_t_endian,
  .format_fn = vl_api_flowprobe_params_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_flowprobe_params_reply_t_tojson,
  .fromjson = vl_api_flowprobe_params_reply_t_fromjson,
  .calc_size = vl_api_flowprobe_params_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_FLOWPROBE_SET_PARAMS + msg_id_base,
   .name = "flowprobe_set_params",
   .handler = vl_api_flowprobe_set_params_t_handler,
   .endian = vl_api_flowprobe_set_params_t_endian,
   .format_fn = vl_api_flowprobe_set_params_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_flowprobe_set_params_t_tojson,
   .fromjson = vl_api_flowprobe_set_params_t_fromjson,
   .calc_size = vl_api_flowprobe_set_params_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_FLOWPROBE_SET_PARAMS_REPLY + msg_id_base,
  .name = "flowprobe_set_params_reply",
  .handler = 0,
  .endian = vl_api_flowprobe_set_params_reply_t_endian,
  .format_fn = vl_api_flowprobe_set_params_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_flowprobe_set_params_reply_t_tojson,
  .fromjson = vl_api_flowprobe_set_params_reply_t_fromjson,
  .calc_size = vl_api_flowprobe_set_params_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_FLOWPROBE_GET_PARAMS + msg_id_base,
   .name = "flowprobe_get_params",
   .handler = vl_api_flowprobe_get_params_t_handler,
   .endian = vl_api_flowprobe_get_params_t_endian,
   .format_fn = vl_api_flowprobe_get_params_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_flowprobe_get_params_t_tojson,
   .fromjson = vl_api_flowprobe_get_params_t_fromjson,
   .calc_size = vl_api_flowprobe_get_params_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_FLOWPROBE_GET_PARAMS_REPLY + msg_id_base,
  .name = "flowprobe_get_params_reply",
  .handler = 0,
  .endian = vl_api_flowprobe_get_params_reply_t_endian,
  .format_fn = vl_api_flowprobe_get_params_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_flowprobe_get_params_reply_t_tojson,
  .fromjson = vl_api_flowprobe_get_params_reply_t_fromjson,
  .calc_size = vl_api_flowprobe_get_params_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
