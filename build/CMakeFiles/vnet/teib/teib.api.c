#define vl_endianfun		/* define message structures */
#include "teib.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "teib.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "teib.api.h"
#undef vl_printfun

#include "teib.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("teib_1c9f7540", VL_MSG_TEIB_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_teib);
   vl_msg_api_add_msg_name_crc (am, "teib_entry_add_del_8016cfd2",
                                VL_API_TEIB_ENTRY_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "teib_entry_add_del_reply_e8d4e804",
                                VL_API_TEIB_ENTRY_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "teib_dump_51077d14",
                                VL_API_TEIB_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "teib_details_981ee1a1",
                                VL_API_TEIB_DETAILS + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_TEIB_ENTRY_ADD_DEL + msg_id_base,
   .name = "teib_entry_add_del",
   .handler = vl_api_teib_entry_add_del_t_handler,
   .endian = vl_api_teib_entry_add_del_t_endian,
   .format_fn = vl_api_teib_entry_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_teib_entry_add_del_t_tojson,
   .fromjson = vl_api_teib_entry_add_del_t_fromjson,
   .calc_size = vl_api_teib_entry_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_TEIB_ENTRY_ADD_DEL_REPLY + msg_id_base,
  .name = "teib_entry_add_del_reply",
  .handler = 0,
  .endian = vl_api_teib_entry_add_del_reply_t_endian,
  .format_fn = vl_api_teib_entry_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_teib_entry_add_del_reply_t_tojson,
  .fromjson = vl_api_teib_entry_add_del_reply_t_fromjson,
  .calc_size = vl_api_teib_entry_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_TEIB_DUMP + msg_id_base,
   .name = "teib_dump",
   .handler = vl_api_teib_dump_t_handler,
   .endian = vl_api_teib_dump_t_endian,
   .format_fn = vl_api_teib_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_teib_dump_t_tojson,
   .fromjson = vl_api_teib_dump_t_fromjson,
   .calc_size = vl_api_teib_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_TEIB_DETAILS + msg_id_base,
  .name = "teib_details",
  .handler = 0,
  .endian = vl_api_teib_details_t_endian,
  .format_fn = vl_api_teib_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_teib_details_t_tojson,
  .fromjson = vl_api_teib_details_t_fromjson,
  .calc_size = vl_api_teib_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
