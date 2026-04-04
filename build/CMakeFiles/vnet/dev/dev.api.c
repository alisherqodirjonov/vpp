#define vl_endianfun		/* define message structures */
#include "dev.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "dev.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "dev.api.h"
#undef vl_printfun

#include "dev.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("dev_86eacf88", VL_MSG_DEV_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_dev);
   vl_msg_api_add_msg_name_crc (am, "dev_attach_44b725fc",
                                VL_API_DEV_ATTACH + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dev_attach_reply_6082b181",
                                VL_API_DEV_ATTACH_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dev_detach_afae52d6",
                                VL_API_DEV_DETACH + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dev_detach_reply_c8d74455",
                                VL_API_DEV_DETACH_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dev_create_port_if_dbdf06f3",
                                VL_API_DEV_CREATE_PORT_IF + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dev_create_port_if_reply_243c2374",
                                VL_API_DEV_CREATE_PORT_IF_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dev_remove_port_if_529cb13f",
                                VL_API_DEV_REMOVE_PORT_IF + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dev_remove_port_if_reply_c8d74455",
                                VL_API_DEV_REMOVE_PORT_IF_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DEV_ATTACH + msg_id_base,
   .name = "dev_attach",
   .handler = vl_api_dev_attach_t_handler,
   .endian = vl_api_dev_attach_t_endian,
   .format_fn = vl_api_dev_attach_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_dev_attach_t_tojson,
   .fromjson = vl_api_dev_attach_t_fromjson,
   .calc_size = vl_api_dev_attach_t_calc_size,
   .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DEV_ATTACH_REPLY + msg_id_base,
  .name = "dev_attach_reply",
  .handler = 0,
  .endian = vl_api_dev_attach_reply_t_endian,
  .format_fn = vl_api_dev_attach_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_dev_attach_reply_t_tojson,
  .fromjson = vl_api_dev_attach_reply_t_fromjson,
  .calc_size = vl_api_dev_attach_reply_t_calc_size,
  .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DEV_DETACH + msg_id_base,
   .name = "dev_detach",
   .handler = vl_api_dev_detach_t_handler,
   .endian = vl_api_dev_detach_t_endian,
   .format_fn = vl_api_dev_detach_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_dev_detach_t_tojson,
   .fromjson = vl_api_dev_detach_t_fromjson,
   .calc_size = vl_api_dev_detach_t_calc_size,
   .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DEV_DETACH_REPLY + msg_id_base,
  .name = "dev_detach_reply",
  .handler = 0,
  .endian = vl_api_dev_detach_reply_t_endian,
  .format_fn = vl_api_dev_detach_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_dev_detach_reply_t_tojson,
  .fromjson = vl_api_dev_detach_reply_t_fromjson,
  .calc_size = vl_api_dev_detach_reply_t_calc_size,
  .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DEV_CREATE_PORT_IF + msg_id_base,
   .name = "dev_create_port_if",
   .handler = vl_api_dev_create_port_if_t_handler,
   .endian = vl_api_dev_create_port_if_t_endian,
   .format_fn = vl_api_dev_create_port_if_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_dev_create_port_if_t_tojson,
   .fromjson = vl_api_dev_create_port_if_t_fromjson,
   .calc_size = vl_api_dev_create_port_if_t_calc_size,
   .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DEV_CREATE_PORT_IF_REPLY + msg_id_base,
  .name = "dev_create_port_if_reply",
  .handler = 0,
  .endian = vl_api_dev_create_port_if_reply_t_endian,
  .format_fn = vl_api_dev_create_port_if_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_dev_create_port_if_reply_t_tojson,
  .fromjson = vl_api_dev_create_port_if_reply_t_fromjson,
  .calc_size = vl_api_dev_create_port_if_reply_t_calc_size,
  .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DEV_REMOVE_PORT_IF + msg_id_base,
   .name = "dev_remove_port_if",
   .handler = vl_api_dev_remove_port_if_t_handler,
   .endian = vl_api_dev_remove_port_if_t_endian,
   .format_fn = vl_api_dev_remove_port_if_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_dev_remove_port_if_t_tojson,
   .fromjson = vl_api_dev_remove_port_if_t_fromjson,
   .calc_size = vl_api_dev_remove_port_if_t_calc_size,
   .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DEV_REMOVE_PORT_IF_REPLY + msg_id_base,
  .name = "dev_remove_port_if_reply",
  .handler = 0,
  .endian = vl_api_dev_remove_port_if_reply_t_endian,
  .format_fn = vl_api_dev_remove_port_if_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_dev_remove_port_if_reply_t_tojson,
  .fromjson = vl_api_dev_remove_port_if_reply_t_fromjson,
  .calc_size = vl_api_dev_remove_port_if_reply_t_calc_size,
  .is_autoendian = 1};
   vl_msg_api_config (&c);
   return msg_id_base;
}
