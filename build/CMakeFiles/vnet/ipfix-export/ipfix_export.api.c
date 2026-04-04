#define vl_endianfun		/* define message structures */
#include "ipfix_export.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "ipfix_export.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "ipfix_export.api.h"
#undef vl_printfun

#include "ipfix_export.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("ipfix_export_e118ab1c", VL_MSG_IPFIX_EXPORT_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_ipfix_export);
   vl_msg_api_add_msg_name_crc (am, "set_ipfix_exporter_5530c8a0",
                                VL_API_SET_IPFIX_EXPORTER + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "set_ipfix_exporter_reply_e8d4e804",
                                VL_API_SET_IPFIX_EXPORTER_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipfix_exporter_dump_51077d14",
                                VL_API_IPFIX_EXPORTER_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipfix_exporter_details_0dedbfe4",
                                VL_API_IPFIX_EXPORTER_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipfix_exporter_create_delete_0753a768",
                                VL_API_IPFIX_EXPORTER_CREATE_DELETE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipfix_exporter_create_delete_reply_9ffac24b",
                                VL_API_IPFIX_EXPORTER_CREATE_DELETE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipfix_all_exporter_get_f75ba505",
                                VL_API_IPFIX_ALL_EXPORTER_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipfix_all_exporter_get_reply_53b48f5d",
                                VL_API_IPFIX_ALL_EXPORTER_GET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipfix_all_exporter_details_0dedbfe4",
                                VL_API_IPFIX_ALL_EXPORTER_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "set_ipfix_classify_stream_c9cbe053",
                                VL_API_SET_IPFIX_CLASSIFY_STREAM + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "set_ipfix_classify_stream_reply_e8d4e804",
                                VL_API_SET_IPFIX_CLASSIFY_STREAM_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipfix_classify_stream_dump_51077d14",
                                VL_API_IPFIX_CLASSIFY_STREAM_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipfix_classify_stream_details_2903539d",
                                VL_API_IPFIX_CLASSIFY_STREAM_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipfix_classify_table_add_del_3e449bb9",
                                VL_API_IPFIX_CLASSIFY_TABLE_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipfix_classify_table_add_del_reply_e8d4e804",
                                VL_API_IPFIX_CLASSIFY_TABLE_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipfix_classify_table_dump_51077d14",
                                VL_API_IPFIX_CLASSIFY_TABLE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipfix_classify_table_details_1af8c28c",
                                VL_API_IPFIX_CLASSIFY_TABLE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipfix_flush_51077d14",
                                VL_API_IPFIX_FLUSH + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipfix_flush_reply_e8d4e804",
                                VL_API_IPFIX_FLUSH_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPFIX_ALL_EXPORTER_GET + msg_id_base,
   .name = "ipfix_all_exporter_get",
   .handler = vl_api_ipfix_all_exporter_get_t_handler,
   .endian = vl_api_ipfix_all_exporter_get_t_endian,
   .format_fn = vl_api_ipfix_all_exporter_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipfix_all_exporter_get_t_tojson,
   .fromjson = vl_api_ipfix_all_exporter_get_t_fromjson,
   .calc_size = vl_api_ipfix_all_exporter_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPFIX_ALL_EXPORTER_GET_REPLY + msg_id_base,
  .name = "ipfix_all_exporter_get_reply",
  .handler = 0,
  .endian = vl_api_ipfix_all_exporter_get_reply_t_endian,
  .format_fn = vl_api_ipfix_all_exporter_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipfix_all_exporter_get_reply_t_tojson,
  .fromjson = vl_api_ipfix_all_exporter_get_reply_t_fromjson,
  .calc_size = vl_api_ipfix_all_exporter_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPFIX_ALL_EXPORTER_DETAILS + msg_id_base,
  .name = "ipfix_all_exporter_details",
  .handler = 0,
  .endian = vl_api_ipfix_all_exporter_details_t_endian,
  .format_fn = vl_api_ipfix_all_exporter_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipfix_all_exporter_details_t_tojson,
  .fromjson = vl_api_ipfix_all_exporter_details_t_fromjson,
  .calc_size = vl_api_ipfix_all_exporter_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SET_IPFIX_EXPORTER + msg_id_base,
   .name = "set_ipfix_exporter",
   .handler = vl_api_set_ipfix_exporter_t_handler,
   .endian = vl_api_set_ipfix_exporter_t_endian,
   .format_fn = vl_api_set_ipfix_exporter_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_set_ipfix_exporter_t_tojson,
   .fromjson = vl_api_set_ipfix_exporter_t_fromjson,
   .calc_size = vl_api_set_ipfix_exporter_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SET_IPFIX_EXPORTER_REPLY + msg_id_base,
  .name = "set_ipfix_exporter_reply",
  .handler = 0,
  .endian = vl_api_set_ipfix_exporter_reply_t_endian,
  .format_fn = vl_api_set_ipfix_exporter_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_set_ipfix_exporter_reply_t_tojson,
  .fromjson = vl_api_set_ipfix_exporter_reply_t_fromjson,
  .calc_size = vl_api_set_ipfix_exporter_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPFIX_EXPORTER_DUMP + msg_id_base,
   .name = "ipfix_exporter_dump",
   .handler = vl_api_ipfix_exporter_dump_t_handler,
   .endian = vl_api_ipfix_exporter_dump_t_endian,
   .format_fn = vl_api_ipfix_exporter_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipfix_exporter_dump_t_tojson,
   .fromjson = vl_api_ipfix_exporter_dump_t_fromjson,
   .calc_size = vl_api_ipfix_exporter_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPFIX_EXPORTER_DETAILS + msg_id_base,
  .name = "ipfix_exporter_details",
  .handler = 0,
  .endian = vl_api_ipfix_exporter_details_t_endian,
  .format_fn = vl_api_ipfix_exporter_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipfix_exporter_details_t_tojson,
  .fromjson = vl_api_ipfix_exporter_details_t_fromjson,
  .calc_size = vl_api_ipfix_exporter_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPFIX_EXPORTER_CREATE_DELETE + msg_id_base,
   .name = "ipfix_exporter_create_delete",
   .handler = vl_api_ipfix_exporter_create_delete_t_handler,
   .endian = vl_api_ipfix_exporter_create_delete_t_endian,
   .format_fn = vl_api_ipfix_exporter_create_delete_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipfix_exporter_create_delete_t_tojson,
   .fromjson = vl_api_ipfix_exporter_create_delete_t_fromjson,
   .calc_size = vl_api_ipfix_exporter_create_delete_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPFIX_EXPORTER_CREATE_DELETE_REPLY + msg_id_base,
  .name = "ipfix_exporter_create_delete_reply",
  .handler = 0,
  .endian = vl_api_ipfix_exporter_create_delete_reply_t_endian,
  .format_fn = vl_api_ipfix_exporter_create_delete_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipfix_exporter_create_delete_reply_t_tojson,
  .fromjson = vl_api_ipfix_exporter_create_delete_reply_t_fromjson,
  .calc_size = vl_api_ipfix_exporter_create_delete_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SET_IPFIX_CLASSIFY_STREAM + msg_id_base,
   .name = "set_ipfix_classify_stream",
   .handler = vl_api_set_ipfix_classify_stream_t_handler,
   .endian = vl_api_set_ipfix_classify_stream_t_endian,
   .format_fn = vl_api_set_ipfix_classify_stream_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_set_ipfix_classify_stream_t_tojson,
   .fromjson = vl_api_set_ipfix_classify_stream_t_fromjson,
   .calc_size = vl_api_set_ipfix_classify_stream_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SET_IPFIX_CLASSIFY_STREAM_REPLY + msg_id_base,
  .name = "set_ipfix_classify_stream_reply",
  .handler = 0,
  .endian = vl_api_set_ipfix_classify_stream_reply_t_endian,
  .format_fn = vl_api_set_ipfix_classify_stream_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_set_ipfix_classify_stream_reply_t_tojson,
  .fromjson = vl_api_set_ipfix_classify_stream_reply_t_fromjson,
  .calc_size = vl_api_set_ipfix_classify_stream_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPFIX_CLASSIFY_STREAM_DUMP + msg_id_base,
   .name = "ipfix_classify_stream_dump",
   .handler = vl_api_ipfix_classify_stream_dump_t_handler,
   .endian = vl_api_ipfix_classify_stream_dump_t_endian,
   .format_fn = vl_api_ipfix_classify_stream_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipfix_classify_stream_dump_t_tojson,
   .fromjson = vl_api_ipfix_classify_stream_dump_t_fromjson,
   .calc_size = vl_api_ipfix_classify_stream_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPFIX_CLASSIFY_STREAM_DETAILS + msg_id_base,
  .name = "ipfix_classify_stream_details",
  .handler = 0,
  .endian = vl_api_ipfix_classify_stream_details_t_endian,
  .format_fn = vl_api_ipfix_classify_stream_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipfix_classify_stream_details_t_tojson,
  .fromjson = vl_api_ipfix_classify_stream_details_t_fromjson,
  .calc_size = vl_api_ipfix_classify_stream_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPFIX_CLASSIFY_TABLE_ADD_DEL + msg_id_base,
   .name = "ipfix_classify_table_add_del",
   .handler = vl_api_ipfix_classify_table_add_del_t_handler,
   .endian = vl_api_ipfix_classify_table_add_del_t_endian,
   .format_fn = vl_api_ipfix_classify_table_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipfix_classify_table_add_del_t_tojson,
   .fromjson = vl_api_ipfix_classify_table_add_del_t_fromjson,
   .calc_size = vl_api_ipfix_classify_table_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPFIX_CLASSIFY_TABLE_ADD_DEL_REPLY + msg_id_base,
  .name = "ipfix_classify_table_add_del_reply",
  .handler = 0,
  .endian = vl_api_ipfix_classify_table_add_del_reply_t_endian,
  .format_fn = vl_api_ipfix_classify_table_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipfix_classify_table_add_del_reply_t_tojson,
  .fromjson = vl_api_ipfix_classify_table_add_del_reply_t_fromjson,
  .calc_size = vl_api_ipfix_classify_table_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPFIX_CLASSIFY_TABLE_DUMP + msg_id_base,
   .name = "ipfix_classify_table_dump",
   .handler = vl_api_ipfix_classify_table_dump_t_handler,
   .endian = vl_api_ipfix_classify_table_dump_t_endian,
   .format_fn = vl_api_ipfix_classify_table_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipfix_classify_table_dump_t_tojson,
   .fromjson = vl_api_ipfix_classify_table_dump_t_fromjson,
   .calc_size = vl_api_ipfix_classify_table_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPFIX_CLASSIFY_TABLE_DETAILS + msg_id_base,
  .name = "ipfix_classify_table_details",
  .handler = 0,
  .endian = vl_api_ipfix_classify_table_details_t_endian,
  .format_fn = vl_api_ipfix_classify_table_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipfix_classify_table_details_t_tojson,
  .fromjson = vl_api_ipfix_classify_table_details_t_fromjson,
  .calc_size = vl_api_ipfix_classify_table_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPFIX_FLUSH + msg_id_base,
   .name = "ipfix_flush",
   .handler = vl_api_ipfix_flush_t_handler,
   .endian = vl_api_ipfix_flush_t_endian,
   .format_fn = vl_api_ipfix_flush_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipfix_flush_t_tojson,
   .fromjson = vl_api_ipfix_flush_t_fromjson,
   .calc_size = vl_api_ipfix_flush_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPFIX_FLUSH_REPLY + msg_id_base,
  .name = "ipfix_flush_reply",
  .handler = 0,
  .endian = vl_api_ipfix_flush_reply_t_endian,
  .format_fn = vl_api_ipfix_flush_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipfix_flush_reply_t_tojson,
  .fromjson = vl_api_ipfix_flush_reply_t_fromjson,
  .calc_size = vl_api_ipfix_flush_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
