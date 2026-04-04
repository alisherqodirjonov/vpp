#define vl_endianfun		/* define message structures */
#include "nsh.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "nsh.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "nsh.api.h"
#undef vl_printfun

#include "nsh.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("nsh_2d586141", VL_MSG_NSH_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_nsh);
   vl_msg_api_add_msg_name_crc (am, "nsh_add_del_entry_7dea480b",
                                VL_API_NSH_ADD_DEL_ENTRY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nsh_add_del_entry_reply_6296a9eb",
                                VL_API_NSH_ADD_DEL_ENTRY_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nsh_entry_dump_cdaf8ccb",
                                VL_API_NSH_ENTRY_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nsh_entry_details_046fb556",
                                VL_API_NSH_ENTRY_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nsh_add_del_map_0a0f42b0",
                                VL_API_NSH_ADD_DEL_MAP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nsh_add_del_map_reply_b2b127ef",
                                VL_API_NSH_ADD_DEL_MAP_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nsh_map_dump_8fc06b82",
                                VL_API_NSH_MAP_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nsh_map_details_2fefcf49",
                                VL_API_NSH_MAP_DETAILS + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NSH_ADD_DEL_ENTRY + msg_id_base,
   .name = "nsh_add_del_entry",
   .handler = vl_api_nsh_add_del_entry_t_handler,
   .endian = vl_api_nsh_add_del_entry_t_endian,
   .format_fn = vl_api_nsh_add_del_entry_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nsh_add_del_entry_t_tojson,
   .fromjson = vl_api_nsh_add_del_entry_t_fromjson,
   .calc_size = vl_api_nsh_add_del_entry_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NSH_ADD_DEL_ENTRY_REPLY + msg_id_base,
  .name = "nsh_add_del_entry_reply",
  .handler = 0,
  .endian = vl_api_nsh_add_del_entry_reply_t_endian,
  .format_fn = vl_api_nsh_add_del_entry_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nsh_add_del_entry_reply_t_tojson,
  .fromjson = vl_api_nsh_add_del_entry_reply_t_fromjson,
  .calc_size = vl_api_nsh_add_del_entry_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NSH_ENTRY_DUMP + msg_id_base,
   .name = "nsh_entry_dump",
   .handler = vl_api_nsh_entry_dump_t_handler,
   .endian = vl_api_nsh_entry_dump_t_endian,
   .format_fn = vl_api_nsh_entry_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nsh_entry_dump_t_tojson,
   .fromjson = vl_api_nsh_entry_dump_t_fromjson,
   .calc_size = vl_api_nsh_entry_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NSH_ENTRY_DETAILS + msg_id_base,
  .name = "nsh_entry_details",
  .handler = 0,
  .endian = vl_api_nsh_entry_details_t_endian,
  .format_fn = vl_api_nsh_entry_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nsh_entry_details_t_tojson,
  .fromjson = vl_api_nsh_entry_details_t_fromjson,
  .calc_size = vl_api_nsh_entry_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NSH_ADD_DEL_MAP + msg_id_base,
   .name = "nsh_add_del_map",
   .handler = vl_api_nsh_add_del_map_t_handler,
   .endian = vl_api_nsh_add_del_map_t_endian,
   .format_fn = vl_api_nsh_add_del_map_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nsh_add_del_map_t_tojson,
   .fromjson = vl_api_nsh_add_del_map_t_fromjson,
   .calc_size = vl_api_nsh_add_del_map_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NSH_ADD_DEL_MAP_REPLY + msg_id_base,
  .name = "nsh_add_del_map_reply",
  .handler = 0,
  .endian = vl_api_nsh_add_del_map_reply_t_endian,
  .format_fn = vl_api_nsh_add_del_map_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nsh_add_del_map_reply_t_tojson,
  .fromjson = vl_api_nsh_add_del_map_reply_t_fromjson,
  .calc_size = vl_api_nsh_add_del_map_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NSH_MAP_DUMP + msg_id_base,
   .name = "nsh_map_dump",
   .handler = vl_api_nsh_map_dump_t_handler,
   .endian = vl_api_nsh_map_dump_t_endian,
   .format_fn = vl_api_nsh_map_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nsh_map_dump_t_tojson,
   .fromjson = vl_api_nsh_map_dump_t_fromjson,
   .calc_size = vl_api_nsh_map_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NSH_MAP_DETAILS + msg_id_base,
  .name = "nsh_map_details",
  .handler = 0,
  .endian = vl_api_nsh_map_details_t_endian,
  .format_fn = vl_api_nsh_map_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nsh_map_details_t_tojson,
  .fromjson = vl_api_nsh_map_details_t_fromjson,
  .calc_size = vl_api_nsh_map_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
