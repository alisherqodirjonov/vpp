#define vl_endianfun		/* define message structures */
#include "qos.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "qos.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "qos.api.h"
#undef vl_printfun

#include "qos.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("qos_ad857fa4", VL_MSG_QOS_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_qos);
   vl_msg_api_add_msg_name_crc (am, "qos_store_enable_disable_f3abcc8b",
                                VL_API_QOS_STORE_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "qos_store_enable_disable_reply_e8d4e804",
                                VL_API_QOS_STORE_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "qos_store_dump_51077d14",
                                VL_API_QOS_STORE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "qos_store_details_3ee0aad7",
                                VL_API_QOS_STORE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "qos_record_enable_disable_2f1a4a38",
                                VL_API_QOS_RECORD_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "qos_record_enable_disable_reply_e8d4e804",
                                VL_API_QOS_RECORD_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "qos_record_dump_51077d14",
                                VL_API_QOS_RECORD_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "qos_record_details_a425d4d3",
                                VL_API_QOS_RECORD_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "qos_egress_map_update_6d1c065f",
                                VL_API_QOS_EGRESS_MAP_UPDATE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "qos_egress_map_update_reply_e8d4e804",
                                VL_API_QOS_EGRESS_MAP_UPDATE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "qos_egress_map_delete_3a91bde5",
                                VL_API_QOS_EGRESS_MAP_DELETE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "qos_egress_map_delete_reply_e8d4e804",
                                VL_API_QOS_EGRESS_MAP_DELETE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "qos_egress_map_dump_51077d14",
                                VL_API_QOS_EGRESS_MAP_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "qos_egress_map_details_46c5653c",
                                VL_API_QOS_EGRESS_MAP_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "qos_mark_enable_disable_1a010f74",
                                VL_API_QOS_MARK_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "qos_mark_enable_disable_reply_e8d4e804",
                                VL_API_QOS_MARK_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "qos_mark_dump_f9e6675e",
                                VL_API_QOS_MARK_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "qos_mark_details_89fe81a9",
                                VL_API_QOS_MARK_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "qos_mark_details_reply_e8d4e804",
                                VL_API_QOS_MARK_DETAILS_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_QOS_STORE_ENABLE_DISABLE + msg_id_base,
   .name = "qos_store_enable_disable",
   .handler = vl_api_qos_store_enable_disable_t_handler,
   .endian = vl_api_qos_store_enable_disable_t_endian,
   .format_fn = vl_api_qos_store_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_qos_store_enable_disable_t_tojson,
   .fromjson = vl_api_qos_store_enable_disable_t_fromjson,
   .calc_size = vl_api_qos_store_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_QOS_STORE_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "qos_store_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_qos_store_enable_disable_reply_t_endian,
  .format_fn = vl_api_qos_store_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_qos_store_enable_disable_reply_t_tojson,
  .fromjson = vl_api_qos_store_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_qos_store_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_QOS_STORE_DUMP + msg_id_base,
   .name = "qos_store_dump",
   .handler = vl_api_qos_store_dump_t_handler,
   .endian = vl_api_qos_store_dump_t_endian,
   .format_fn = vl_api_qos_store_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_qos_store_dump_t_tojson,
   .fromjson = vl_api_qos_store_dump_t_fromjson,
   .calc_size = vl_api_qos_store_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_QOS_STORE_DETAILS + msg_id_base,
  .name = "qos_store_details",
  .handler = 0,
  .endian = vl_api_qos_store_details_t_endian,
  .format_fn = vl_api_qos_store_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_qos_store_details_t_tojson,
  .fromjson = vl_api_qos_store_details_t_fromjson,
  .calc_size = vl_api_qos_store_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_QOS_RECORD_ENABLE_DISABLE + msg_id_base,
   .name = "qos_record_enable_disable",
   .handler = vl_api_qos_record_enable_disable_t_handler,
   .endian = vl_api_qos_record_enable_disable_t_endian,
   .format_fn = vl_api_qos_record_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_qos_record_enable_disable_t_tojson,
   .fromjson = vl_api_qos_record_enable_disable_t_fromjson,
   .calc_size = vl_api_qos_record_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_QOS_RECORD_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "qos_record_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_qos_record_enable_disable_reply_t_endian,
  .format_fn = vl_api_qos_record_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_qos_record_enable_disable_reply_t_tojson,
  .fromjson = vl_api_qos_record_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_qos_record_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_QOS_RECORD_DUMP + msg_id_base,
   .name = "qos_record_dump",
   .handler = vl_api_qos_record_dump_t_handler,
   .endian = vl_api_qos_record_dump_t_endian,
   .format_fn = vl_api_qos_record_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_qos_record_dump_t_tojson,
   .fromjson = vl_api_qos_record_dump_t_fromjson,
   .calc_size = vl_api_qos_record_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_QOS_RECORD_DETAILS + msg_id_base,
  .name = "qos_record_details",
  .handler = 0,
  .endian = vl_api_qos_record_details_t_endian,
  .format_fn = vl_api_qos_record_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_qos_record_details_t_tojson,
  .fromjson = vl_api_qos_record_details_t_fromjson,
  .calc_size = vl_api_qos_record_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_QOS_EGRESS_MAP_UPDATE + msg_id_base,
   .name = "qos_egress_map_update",
   .handler = vl_api_qos_egress_map_update_t_handler,
   .endian = vl_api_qos_egress_map_update_t_endian,
   .format_fn = vl_api_qos_egress_map_update_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_qos_egress_map_update_t_tojson,
   .fromjson = vl_api_qos_egress_map_update_t_fromjson,
   .calc_size = vl_api_qos_egress_map_update_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_QOS_EGRESS_MAP_UPDATE_REPLY + msg_id_base,
  .name = "qos_egress_map_update_reply",
  .handler = 0,
  .endian = vl_api_qos_egress_map_update_reply_t_endian,
  .format_fn = vl_api_qos_egress_map_update_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_qos_egress_map_update_reply_t_tojson,
  .fromjson = vl_api_qos_egress_map_update_reply_t_fromjson,
  .calc_size = vl_api_qos_egress_map_update_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_QOS_EGRESS_MAP_DELETE + msg_id_base,
   .name = "qos_egress_map_delete",
   .handler = vl_api_qos_egress_map_delete_t_handler,
   .endian = vl_api_qos_egress_map_delete_t_endian,
   .format_fn = vl_api_qos_egress_map_delete_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_qos_egress_map_delete_t_tojson,
   .fromjson = vl_api_qos_egress_map_delete_t_fromjson,
   .calc_size = vl_api_qos_egress_map_delete_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_QOS_EGRESS_MAP_DELETE_REPLY + msg_id_base,
  .name = "qos_egress_map_delete_reply",
  .handler = 0,
  .endian = vl_api_qos_egress_map_delete_reply_t_endian,
  .format_fn = vl_api_qos_egress_map_delete_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_qos_egress_map_delete_reply_t_tojson,
  .fromjson = vl_api_qos_egress_map_delete_reply_t_fromjson,
  .calc_size = vl_api_qos_egress_map_delete_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_QOS_EGRESS_MAP_DUMP + msg_id_base,
   .name = "qos_egress_map_dump",
   .handler = vl_api_qos_egress_map_dump_t_handler,
   .endian = vl_api_qos_egress_map_dump_t_endian,
   .format_fn = vl_api_qos_egress_map_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_qos_egress_map_dump_t_tojson,
   .fromjson = vl_api_qos_egress_map_dump_t_fromjson,
   .calc_size = vl_api_qos_egress_map_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_QOS_EGRESS_MAP_DETAILS + msg_id_base,
  .name = "qos_egress_map_details",
  .handler = 0,
  .endian = vl_api_qos_egress_map_details_t_endian,
  .format_fn = vl_api_qos_egress_map_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_qos_egress_map_details_t_tojson,
  .fromjson = vl_api_qos_egress_map_details_t_fromjson,
  .calc_size = vl_api_qos_egress_map_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_QOS_MARK_ENABLE_DISABLE + msg_id_base,
   .name = "qos_mark_enable_disable",
   .handler = vl_api_qos_mark_enable_disable_t_handler,
   .endian = vl_api_qos_mark_enable_disable_t_endian,
   .format_fn = vl_api_qos_mark_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_qos_mark_enable_disable_t_tojson,
   .fromjson = vl_api_qos_mark_enable_disable_t_fromjson,
   .calc_size = vl_api_qos_mark_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_QOS_MARK_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "qos_mark_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_qos_mark_enable_disable_reply_t_endian,
  .format_fn = vl_api_qos_mark_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_qos_mark_enable_disable_reply_t_tojson,
  .fromjson = vl_api_qos_mark_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_qos_mark_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_QOS_MARK_DUMP + msg_id_base,
   .name = "qos_mark_dump",
   .handler = vl_api_qos_mark_dump_t_handler,
   .endian = vl_api_qos_mark_dump_t_endian,
   .format_fn = vl_api_qos_mark_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_qos_mark_dump_t_tojson,
   .fromjson = vl_api_qos_mark_dump_t_fromjson,
   .calc_size = vl_api_qos_mark_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_QOS_MARK_DETAILS + msg_id_base,
  .name = "qos_mark_details",
  .handler = 0,
  .endian = vl_api_qos_mark_details_t_endian,
  .format_fn = vl_api_qos_mark_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_qos_mark_details_t_tojson,
  .fromjson = vl_api_qos_mark_details_t_fromjson,
  .calc_size = vl_api_qos_mark_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
