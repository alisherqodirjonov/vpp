#define vl_endianfun		/* define message structures */
#include "bier.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "bier.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "bier.api.h"
#undef vl_printfun

#include "bier.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("bier_48fa264f", VL_MSG_BIER_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_bier);
   vl_msg_api_add_msg_name_crc (am, "bier_table_add_del_35e59209",
                                VL_API_BIER_TABLE_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bier_table_add_del_reply_e8d4e804",
                                VL_API_BIER_TABLE_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bier_table_dump_51077d14",
                                VL_API_BIER_TABLE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bier_table_details_fc44a9dd",
                                VL_API_BIER_TABLE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bier_route_add_del_fd02f3ea",
                                VL_API_BIER_ROUTE_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bier_route_add_del_reply_e8d4e804",
                                VL_API_BIER_ROUTE_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bier_route_dump_38339846",
                                VL_API_BIER_ROUTE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bier_route_details_4008caee",
                                VL_API_BIER_ROUTE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bier_imp_add_3856dc3d",
                                VL_API_BIER_IMP_ADD + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bier_imp_add_reply_d49c5793",
                                VL_API_BIER_IMP_ADD_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bier_imp_del_7d45edf6",
                                VL_API_BIER_IMP_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bier_imp_del_reply_e8d4e804",
                                VL_API_BIER_IMP_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bier_imp_dump_51077d14",
                                VL_API_BIER_IMP_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bier_imp_details_b76192df",
                                VL_API_BIER_IMP_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bier_disp_table_add_del_889657ac",
                                VL_API_BIER_DISP_TABLE_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bier_disp_table_add_del_reply_e8d4e804",
                                VL_API_BIER_DISP_TABLE_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bier_disp_table_dump_51077d14",
                                VL_API_BIER_DISP_TABLE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bier_disp_table_details_d27942c0",
                                VL_API_BIER_DISP_TABLE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bier_disp_entry_add_del_9eb80cb4",
                                VL_API_BIER_DISP_ENTRY_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bier_disp_entry_add_del_reply_e8d4e804",
                                VL_API_BIER_DISP_ENTRY_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bier_disp_entry_dump_b5fa54ad",
                                VL_API_BIER_DISP_ENTRY_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bier_disp_entry_details_84c218f1",
                                VL_API_BIER_DISP_ENTRY_DETAILS + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BIER_TABLE_ADD_DEL + msg_id_base,
   .name = "bier_table_add_del",
   .handler = vl_api_bier_table_add_del_t_handler,
   .endian = vl_api_bier_table_add_del_t_endian,
   .format_fn = vl_api_bier_table_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bier_table_add_del_t_tojson,
   .fromjson = vl_api_bier_table_add_del_t_fromjson,
   .calc_size = vl_api_bier_table_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BIER_TABLE_ADD_DEL_REPLY + msg_id_base,
  .name = "bier_table_add_del_reply",
  .handler = 0,
  .endian = vl_api_bier_table_add_del_reply_t_endian,
  .format_fn = vl_api_bier_table_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bier_table_add_del_reply_t_tojson,
  .fromjson = vl_api_bier_table_add_del_reply_t_fromjson,
  .calc_size = vl_api_bier_table_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BIER_TABLE_DUMP + msg_id_base,
   .name = "bier_table_dump",
   .handler = vl_api_bier_table_dump_t_handler,
   .endian = vl_api_bier_table_dump_t_endian,
   .format_fn = vl_api_bier_table_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bier_table_dump_t_tojson,
   .fromjson = vl_api_bier_table_dump_t_fromjson,
   .calc_size = vl_api_bier_table_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BIER_TABLE_DETAILS + msg_id_base,
  .name = "bier_table_details",
  .handler = 0,
  .endian = vl_api_bier_table_details_t_endian,
  .format_fn = vl_api_bier_table_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bier_table_details_t_tojson,
  .fromjson = vl_api_bier_table_details_t_fromjson,
  .calc_size = vl_api_bier_table_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BIER_ROUTE_ADD_DEL + msg_id_base,
   .name = "bier_route_add_del",
   .handler = vl_api_bier_route_add_del_t_handler,
   .endian = vl_api_bier_route_add_del_t_endian,
   .format_fn = vl_api_bier_route_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bier_route_add_del_t_tojson,
   .fromjson = vl_api_bier_route_add_del_t_fromjson,
   .calc_size = vl_api_bier_route_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BIER_ROUTE_ADD_DEL_REPLY + msg_id_base,
  .name = "bier_route_add_del_reply",
  .handler = 0,
  .endian = vl_api_bier_route_add_del_reply_t_endian,
  .format_fn = vl_api_bier_route_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bier_route_add_del_reply_t_tojson,
  .fromjson = vl_api_bier_route_add_del_reply_t_fromjson,
  .calc_size = vl_api_bier_route_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BIER_ROUTE_DUMP + msg_id_base,
   .name = "bier_route_dump",
   .handler = vl_api_bier_route_dump_t_handler,
   .endian = vl_api_bier_route_dump_t_endian,
   .format_fn = vl_api_bier_route_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bier_route_dump_t_tojson,
   .fromjson = vl_api_bier_route_dump_t_fromjson,
   .calc_size = vl_api_bier_route_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BIER_ROUTE_DETAILS + msg_id_base,
  .name = "bier_route_details",
  .handler = 0,
  .endian = vl_api_bier_route_details_t_endian,
  .format_fn = vl_api_bier_route_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bier_route_details_t_tojson,
  .fromjson = vl_api_bier_route_details_t_fromjson,
  .calc_size = vl_api_bier_route_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BIER_IMP_ADD + msg_id_base,
   .name = "bier_imp_add",
   .handler = vl_api_bier_imp_add_t_handler,
   .endian = vl_api_bier_imp_add_t_endian,
   .format_fn = vl_api_bier_imp_add_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bier_imp_add_t_tojson,
   .fromjson = vl_api_bier_imp_add_t_fromjson,
   .calc_size = vl_api_bier_imp_add_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BIER_IMP_ADD_REPLY + msg_id_base,
  .name = "bier_imp_add_reply",
  .handler = 0,
  .endian = vl_api_bier_imp_add_reply_t_endian,
  .format_fn = vl_api_bier_imp_add_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bier_imp_add_reply_t_tojson,
  .fromjson = vl_api_bier_imp_add_reply_t_fromjson,
  .calc_size = vl_api_bier_imp_add_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BIER_IMP_DEL + msg_id_base,
   .name = "bier_imp_del",
   .handler = vl_api_bier_imp_del_t_handler,
   .endian = vl_api_bier_imp_del_t_endian,
   .format_fn = vl_api_bier_imp_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bier_imp_del_t_tojson,
   .fromjson = vl_api_bier_imp_del_t_fromjson,
   .calc_size = vl_api_bier_imp_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BIER_IMP_DEL_REPLY + msg_id_base,
  .name = "bier_imp_del_reply",
  .handler = 0,
  .endian = vl_api_bier_imp_del_reply_t_endian,
  .format_fn = vl_api_bier_imp_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bier_imp_del_reply_t_tojson,
  .fromjson = vl_api_bier_imp_del_reply_t_fromjson,
  .calc_size = vl_api_bier_imp_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BIER_IMP_DUMP + msg_id_base,
   .name = "bier_imp_dump",
   .handler = vl_api_bier_imp_dump_t_handler,
   .endian = vl_api_bier_imp_dump_t_endian,
   .format_fn = vl_api_bier_imp_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bier_imp_dump_t_tojson,
   .fromjson = vl_api_bier_imp_dump_t_fromjson,
   .calc_size = vl_api_bier_imp_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BIER_IMP_DETAILS + msg_id_base,
  .name = "bier_imp_details",
  .handler = 0,
  .endian = vl_api_bier_imp_details_t_endian,
  .format_fn = vl_api_bier_imp_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bier_imp_details_t_tojson,
  .fromjson = vl_api_bier_imp_details_t_fromjson,
  .calc_size = vl_api_bier_imp_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BIER_DISP_TABLE_ADD_DEL + msg_id_base,
   .name = "bier_disp_table_add_del",
   .handler = vl_api_bier_disp_table_add_del_t_handler,
   .endian = vl_api_bier_disp_table_add_del_t_endian,
   .format_fn = vl_api_bier_disp_table_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bier_disp_table_add_del_t_tojson,
   .fromjson = vl_api_bier_disp_table_add_del_t_fromjson,
   .calc_size = vl_api_bier_disp_table_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BIER_DISP_TABLE_ADD_DEL_REPLY + msg_id_base,
  .name = "bier_disp_table_add_del_reply",
  .handler = 0,
  .endian = vl_api_bier_disp_table_add_del_reply_t_endian,
  .format_fn = vl_api_bier_disp_table_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bier_disp_table_add_del_reply_t_tojson,
  .fromjson = vl_api_bier_disp_table_add_del_reply_t_fromjson,
  .calc_size = vl_api_bier_disp_table_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BIER_DISP_TABLE_DUMP + msg_id_base,
   .name = "bier_disp_table_dump",
   .handler = vl_api_bier_disp_table_dump_t_handler,
   .endian = vl_api_bier_disp_table_dump_t_endian,
   .format_fn = vl_api_bier_disp_table_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bier_disp_table_dump_t_tojson,
   .fromjson = vl_api_bier_disp_table_dump_t_fromjson,
   .calc_size = vl_api_bier_disp_table_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BIER_DISP_TABLE_DETAILS + msg_id_base,
  .name = "bier_disp_table_details",
  .handler = 0,
  .endian = vl_api_bier_disp_table_details_t_endian,
  .format_fn = vl_api_bier_disp_table_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bier_disp_table_details_t_tojson,
  .fromjson = vl_api_bier_disp_table_details_t_fromjson,
  .calc_size = vl_api_bier_disp_table_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BIER_DISP_ENTRY_ADD_DEL + msg_id_base,
   .name = "bier_disp_entry_add_del",
   .handler = vl_api_bier_disp_entry_add_del_t_handler,
   .endian = vl_api_bier_disp_entry_add_del_t_endian,
   .format_fn = vl_api_bier_disp_entry_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bier_disp_entry_add_del_t_tojson,
   .fromjson = vl_api_bier_disp_entry_add_del_t_fromjson,
   .calc_size = vl_api_bier_disp_entry_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BIER_DISP_ENTRY_ADD_DEL_REPLY + msg_id_base,
  .name = "bier_disp_entry_add_del_reply",
  .handler = 0,
  .endian = vl_api_bier_disp_entry_add_del_reply_t_endian,
  .format_fn = vl_api_bier_disp_entry_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bier_disp_entry_add_del_reply_t_tojson,
  .fromjson = vl_api_bier_disp_entry_add_del_reply_t_fromjson,
  .calc_size = vl_api_bier_disp_entry_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BIER_DISP_ENTRY_DUMP + msg_id_base,
   .name = "bier_disp_entry_dump",
   .handler = vl_api_bier_disp_entry_dump_t_handler,
   .endian = vl_api_bier_disp_entry_dump_t_endian,
   .format_fn = vl_api_bier_disp_entry_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bier_disp_entry_dump_t_tojson,
   .fromjson = vl_api_bier_disp_entry_dump_t_fromjson,
   .calc_size = vl_api_bier_disp_entry_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BIER_DISP_ENTRY_DETAILS + msg_id_base,
  .name = "bier_disp_entry_details",
  .handler = 0,
  .endian = vl_api_bier_disp_entry_details_t_endian,
  .format_fn = vl_api_bier_disp_entry_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bier_disp_entry_details_t_tojson,
  .fromjson = vl_api_bier_disp_entry_details_t_fromjson,
  .calc_size = vl_api_bier_disp_entry_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
