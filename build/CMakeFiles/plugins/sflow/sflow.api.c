#define vl_endianfun		/* define message structures */
#include "sflow.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "sflow.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "sflow.api.h"
#undef vl_printfun

#include "sflow.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("sflow_ba88ab74", VL_MSG_SFLOW_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_sflow);
   vl_msg_api_add_msg_name_crc (am, "sflow_enable_disable_8499814f",
                                VL_API_SFLOW_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sflow_enable_disable_reply_e8d4e804",
                                VL_API_SFLOW_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sflow_sampling_rate_get_51077d14",
                                VL_API_SFLOW_SAMPLING_RATE_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sflow_sampling_rate_get_reply_9c8c8236",
                                VL_API_SFLOW_SAMPLING_RATE_GET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sflow_sampling_rate_set_94778f50",
                                VL_API_SFLOW_SAMPLING_RATE_SET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sflow_sampling_rate_set_reply_e8d4e804",
                                VL_API_SFLOW_SAMPLING_RATE_SET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sflow_polling_interval_set_7f19cb51",
                                VL_API_SFLOW_POLLING_INTERVAL_SET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sflow_polling_interval_set_reply_e8d4e804",
                                VL_API_SFLOW_POLLING_INTERVAL_SET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sflow_polling_interval_get_51077d14",
                                VL_API_SFLOW_POLLING_INTERVAL_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sflow_polling_interval_get_reply_e929801c",
                                VL_API_SFLOW_POLLING_INTERVAL_GET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sflow_header_bytes_set_5baf56f3",
                                VL_API_SFLOW_HEADER_BYTES_SET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sflow_header_bytes_set_reply_e8d4e804",
                                VL_API_SFLOW_HEADER_BYTES_SET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sflow_header_bytes_get_51077d14",
                                VL_API_SFLOW_HEADER_BYTES_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sflow_header_bytes_get_reply_624c95b9",
                                VL_API_SFLOW_HEADER_BYTES_GET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sflow_direction_set_fbca6f34",
                                VL_API_SFLOW_DIRECTION_SET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sflow_direction_set_reply_e8d4e804",
                                VL_API_SFLOW_DIRECTION_SET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sflow_direction_get_51077d14",
                                VL_API_SFLOW_DIRECTION_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sflow_direction_get_reply_f3316252",
                                VL_API_SFLOW_DIRECTION_GET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sflow_drop_monitoring_set_100b1e04",
                                VL_API_SFLOW_DROP_MONITORING_SET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sflow_drop_monitoring_set_reply_e8d4e804",
                                VL_API_SFLOW_DROP_MONITORING_SET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sflow_drop_monitoring_get_51077d14",
                                VL_API_SFLOW_DROP_MONITORING_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sflow_drop_monitoring_get_reply_b56ae30e",
                                VL_API_SFLOW_DROP_MONITORING_GET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sflow_interface_dump_451a727d",
                                VL_API_SFLOW_INTERFACE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sflow_interface_details_b7b9143f",
                                VL_API_SFLOW_INTERFACE_DETAILS + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SFLOW_ENABLE_DISABLE + msg_id_base,
   .name = "sflow_enable_disable",
   .handler = vl_api_sflow_enable_disable_t_handler,
   .endian = vl_api_sflow_enable_disable_t_endian,
   .format_fn = vl_api_sflow_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sflow_enable_disable_t_tojson,
   .fromjson = vl_api_sflow_enable_disable_t_fromjson,
   .calc_size = vl_api_sflow_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SFLOW_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "sflow_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_sflow_enable_disable_reply_t_endian,
  .format_fn = vl_api_sflow_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sflow_enable_disable_reply_t_tojson,
  .fromjson = vl_api_sflow_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_sflow_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SFLOW_SAMPLING_RATE_GET + msg_id_base,
   .name = "sflow_sampling_rate_get",
   .handler = vl_api_sflow_sampling_rate_get_t_handler,
   .endian = vl_api_sflow_sampling_rate_get_t_endian,
   .format_fn = vl_api_sflow_sampling_rate_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sflow_sampling_rate_get_t_tojson,
   .fromjson = vl_api_sflow_sampling_rate_get_t_fromjson,
   .calc_size = vl_api_sflow_sampling_rate_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SFLOW_SAMPLING_RATE_GET_REPLY + msg_id_base,
  .name = "sflow_sampling_rate_get_reply",
  .handler = 0,
  .endian = vl_api_sflow_sampling_rate_get_reply_t_endian,
  .format_fn = vl_api_sflow_sampling_rate_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sflow_sampling_rate_get_reply_t_tojson,
  .fromjson = vl_api_sflow_sampling_rate_get_reply_t_fromjson,
  .calc_size = vl_api_sflow_sampling_rate_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SFLOW_SAMPLING_RATE_SET + msg_id_base,
   .name = "sflow_sampling_rate_set",
   .handler = vl_api_sflow_sampling_rate_set_t_handler,
   .endian = vl_api_sflow_sampling_rate_set_t_endian,
   .format_fn = vl_api_sflow_sampling_rate_set_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sflow_sampling_rate_set_t_tojson,
   .fromjson = vl_api_sflow_sampling_rate_set_t_fromjson,
   .calc_size = vl_api_sflow_sampling_rate_set_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SFLOW_SAMPLING_RATE_SET_REPLY + msg_id_base,
  .name = "sflow_sampling_rate_set_reply",
  .handler = 0,
  .endian = vl_api_sflow_sampling_rate_set_reply_t_endian,
  .format_fn = vl_api_sflow_sampling_rate_set_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sflow_sampling_rate_set_reply_t_tojson,
  .fromjson = vl_api_sflow_sampling_rate_set_reply_t_fromjson,
  .calc_size = vl_api_sflow_sampling_rate_set_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SFLOW_POLLING_INTERVAL_SET + msg_id_base,
   .name = "sflow_polling_interval_set",
   .handler = vl_api_sflow_polling_interval_set_t_handler,
   .endian = vl_api_sflow_polling_interval_set_t_endian,
   .format_fn = vl_api_sflow_polling_interval_set_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sflow_polling_interval_set_t_tojson,
   .fromjson = vl_api_sflow_polling_interval_set_t_fromjson,
   .calc_size = vl_api_sflow_polling_interval_set_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SFLOW_POLLING_INTERVAL_SET_REPLY + msg_id_base,
  .name = "sflow_polling_interval_set_reply",
  .handler = 0,
  .endian = vl_api_sflow_polling_interval_set_reply_t_endian,
  .format_fn = vl_api_sflow_polling_interval_set_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sflow_polling_interval_set_reply_t_tojson,
  .fromjson = vl_api_sflow_polling_interval_set_reply_t_fromjson,
  .calc_size = vl_api_sflow_polling_interval_set_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SFLOW_POLLING_INTERVAL_GET + msg_id_base,
   .name = "sflow_polling_interval_get",
   .handler = vl_api_sflow_polling_interval_get_t_handler,
   .endian = vl_api_sflow_polling_interval_get_t_endian,
   .format_fn = vl_api_sflow_polling_interval_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sflow_polling_interval_get_t_tojson,
   .fromjson = vl_api_sflow_polling_interval_get_t_fromjson,
   .calc_size = vl_api_sflow_polling_interval_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SFLOW_POLLING_INTERVAL_GET_REPLY + msg_id_base,
  .name = "sflow_polling_interval_get_reply",
  .handler = 0,
  .endian = vl_api_sflow_polling_interval_get_reply_t_endian,
  .format_fn = vl_api_sflow_polling_interval_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sflow_polling_interval_get_reply_t_tojson,
  .fromjson = vl_api_sflow_polling_interval_get_reply_t_fromjson,
  .calc_size = vl_api_sflow_polling_interval_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SFLOW_HEADER_BYTES_SET + msg_id_base,
   .name = "sflow_header_bytes_set",
   .handler = vl_api_sflow_header_bytes_set_t_handler,
   .endian = vl_api_sflow_header_bytes_set_t_endian,
   .format_fn = vl_api_sflow_header_bytes_set_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sflow_header_bytes_set_t_tojson,
   .fromjson = vl_api_sflow_header_bytes_set_t_fromjson,
   .calc_size = vl_api_sflow_header_bytes_set_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SFLOW_HEADER_BYTES_SET_REPLY + msg_id_base,
  .name = "sflow_header_bytes_set_reply",
  .handler = 0,
  .endian = vl_api_sflow_header_bytes_set_reply_t_endian,
  .format_fn = vl_api_sflow_header_bytes_set_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sflow_header_bytes_set_reply_t_tojson,
  .fromjson = vl_api_sflow_header_bytes_set_reply_t_fromjson,
  .calc_size = vl_api_sflow_header_bytes_set_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SFLOW_HEADER_BYTES_GET + msg_id_base,
   .name = "sflow_header_bytes_get",
   .handler = vl_api_sflow_header_bytes_get_t_handler,
   .endian = vl_api_sflow_header_bytes_get_t_endian,
   .format_fn = vl_api_sflow_header_bytes_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sflow_header_bytes_get_t_tojson,
   .fromjson = vl_api_sflow_header_bytes_get_t_fromjson,
   .calc_size = vl_api_sflow_header_bytes_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SFLOW_HEADER_BYTES_GET_REPLY + msg_id_base,
  .name = "sflow_header_bytes_get_reply",
  .handler = 0,
  .endian = vl_api_sflow_header_bytes_get_reply_t_endian,
  .format_fn = vl_api_sflow_header_bytes_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sflow_header_bytes_get_reply_t_tojson,
  .fromjson = vl_api_sflow_header_bytes_get_reply_t_fromjson,
  .calc_size = vl_api_sflow_header_bytes_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SFLOW_DIRECTION_SET + msg_id_base,
   .name = "sflow_direction_set",
   .handler = vl_api_sflow_direction_set_t_handler,
   .endian = vl_api_sflow_direction_set_t_endian,
   .format_fn = vl_api_sflow_direction_set_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sflow_direction_set_t_tojson,
   .fromjson = vl_api_sflow_direction_set_t_fromjson,
   .calc_size = vl_api_sflow_direction_set_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SFLOW_DIRECTION_SET_REPLY + msg_id_base,
  .name = "sflow_direction_set_reply",
  .handler = 0,
  .endian = vl_api_sflow_direction_set_reply_t_endian,
  .format_fn = vl_api_sflow_direction_set_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sflow_direction_set_reply_t_tojson,
  .fromjson = vl_api_sflow_direction_set_reply_t_fromjson,
  .calc_size = vl_api_sflow_direction_set_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SFLOW_DIRECTION_GET + msg_id_base,
   .name = "sflow_direction_get",
   .handler = vl_api_sflow_direction_get_t_handler,
   .endian = vl_api_sflow_direction_get_t_endian,
   .format_fn = vl_api_sflow_direction_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sflow_direction_get_t_tojson,
   .fromjson = vl_api_sflow_direction_get_t_fromjson,
   .calc_size = vl_api_sflow_direction_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SFLOW_DIRECTION_GET_REPLY + msg_id_base,
  .name = "sflow_direction_get_reply",
  .handler = 0,
  .endian = vl_api_sflow_direction_get_reply_t_endian,
  .format_fn = vl_api_sflow_direction_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sflow_direction_get_reply_t_tojson,
  .fromjson = vl_api_sflow_direction_get_reply_t_fromjson,
  .calc_size = vl_api_sflow_direction_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SFLOW_DROP_MONITORING_SET + msg_id_base,
   .name = "sflow_drop_monitoring_set",
   .handler = vl_api_sflow_drop_monitoring_set_t_handler,
   .endian = vl_api_sflow_drop_monitoring_set_t_endian,
   .format_fn = vl_api_sflow_drop_monitoring_set_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sflow_drop_monitoring_set_t_tojson,
   .fromjson = vl_api_sflow_drop_monitoring_set_t_fromjson,
   .calc_size = vl_api_sflow_drop_monitoring_set_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SFLOW_DROP_MONITORING_SET_REPLY + msg_id_base,
  .name = "sflow_drop_monitoring_set_reply",
  .handler = 0,
  .endian = vl_api_sflow_drop_monitoring_set_reply_t_endian,
  .format_fn = vl_api_sflow_drop_monitoring_set_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sflow_drop_monitoring_set_reply_t_tojson,
  .fromjson = vl_api_sflow_drop_monitoring_set_reply_t_fromjson,
  .calc_size = vl_api_sflow_drop_monitoring_set_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SFLOW_DROP_MONITORING_GET + msg_id_base,
   .name = "sflow_drop_monitoring_get",
   .handler = vl_api_sflow_drop_monitoring_get_t_handler,
   .endian = vl_api_sflow_drop_monitoring_get_t_endian,
   .format_fn = vl_api_sflow_drop_monitoring_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sflow_drop_monitoring_get_t_tojson,
   .fromjson = vl_api_sflow_drop_monitoring_get_t_fromjson,
   .calc_size = vl_api_sflow_drop_monitoring_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SFLOW_DROP_MONITORING_GET_REPLY + msg_id_base,
  .name = "sflow_drop_monitoring_get_reply",
  .handler = 0,
  .endian = vl_api_sflow_drop_monitoring_get_reply_t_endian,
  .format_fn = vl_api_sflow_drop_monitoring_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sflow_drop_monitoring_get_reply_t_tojson,
  .fromjson = vl_api_sflow_drop_monitoring_get_reply_t_fromjson,
  .calc_size = vl_api_sflow_drop_monitoring_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SFLOW_INTERFACE_DUMP + msg_id_base,
   .name = "sflow_interface_dump",
   .handler = vl_api_sflow_interface_dump_t_handler,
   .endian = vl_api_sflow_interface_dump_t_endian,
   .format_fn = vl_api_sflow_interface_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sflow_interface_dump_t_tojson,
   .fromjson = vl_api_sflow_interface_dump_t_fromjson,
   .calc_size = vl_api_sflow_interface_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SFLOW_INTERFACE_DETAILS + msg_id_base,
  .name = "sflow_interface_details",
  .handler = 0,
  .endian = vl_api_sflow_interface_details_t_endian,
  .format_fn = vl_api_sflow_interface_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sflow_interface_details_t_tojson,
  .fromjson = vl_api_sflow_interface_details_t_fromjson,
  .calc_size = vl_api_sflow_interface_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
