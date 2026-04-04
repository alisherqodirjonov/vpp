#define vl_endianfun		/* define message structures */
#include "selog.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "selog.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "selog.api.h"
#undef vl_printfun

#include "selog.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("selog_58ce3561", VL_MSG_SELOG_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_selog);
   vl_msg_api_add_msg_name_crc (am, "selog_get_shm_51077d14",
                                VL_API_SELOG_GET_SHM + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "selog_get_shm_reply_e8d4e804",
                                VL_API_SELOG_GET_SHM_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "selog_get_string_table_51077d14",
                                VL_API_SELOG_GET_STRING_TABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "selog_get_string_table_reply_17fc26aa",
                                VL_API_SELOG_GET_STRING_TABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "selog_track_dump_51077d14",
                                VL_API_SELOG_TRACK_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "selog_track_details_33dce766",
                                VL_API_SELOG_TRACK_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "selog_event_type_dump_51077d14",
                                VL_API_SELOG_EVENT_TYPE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "selog_event_type_details_745bca80",
                                VL_API_SELOG_EVENT_TYPE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "selog_event_type_string_dump_6a7f2680",
                                VL_API_SELOG_EVENT_TYPE_STRING_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "selog_event_type_string_details_3718921d",
                                VL_API_SELOG_EVENT_TYPE_STRING_DETAILS + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SELOG_GET_SHM + msg_id_base,
   .name = "selog_get_shm",
   .handler = vl_api_selog_get_shm_t_handler,
   .endian = vl_api_selog_get_shm_t_endian,
   .format_fn = vl_api_selog_get_shm_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_selog_get_shm_t_tojson,
   .fromjson = vl_api_selog_get_shm_t_fromjson,
   .calc_size = vl_api_selog_get_shm_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SELOG_GET_SHM_REPLY + msg_id_base,
  .name = "selog_get_shm_reply",
  .handler = 0,
  .endian = vl_api_selog_get_shm_reply_t_endian,
  .format_fn = vl_api_selog_get_shm_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_selog_get_shm_reply_t_tojson,
  .fromjson = vl_api_selog_get_shm_reply_t_fromjson,
  .calc_size = vl_api_selog_get_shm_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SELOG_GET_STRING_TABLE + msg_id_base,
   .name = "selog_get_string_table",
   .handler = vl_api_selog_get_string_table_t_handler,
   .endian = vl_api_selog_get_string_table_t_endian,
   .format_fn = vl_api_selog_get_string_table_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_selog_get_string_table_t_tojson,
   .fromjson = vl_api_selog_get_string_table_t_fromjson,
   .calc_size = vl_api_selog_get_string_table_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SELOG_GET_STRING_TABLE_REPLY + msg_id_base,
  .name = "selog_get_string_table_reply",
  .handler = 0,
  .endian = vl_api_selog_get_string_table_reply_t_endian,
  .format_fn = vl_api_selog_get_string_table_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_selog_get_string_table_reply_t_tojson,
  .fromjson = vl_api_selog_get_string_table_reply_t_fromjson,
  .calc_size = vl_api_selog_get_string_table_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SELOG_TRACK_DUMP + msg_id_base,
   .name = "selog_track_dump",
   .handler = vl_api_selog_track_dump_t_handler,
   .endian = vl_api_selog_track_dump_t_endian,
   .format_fn = vl_api_selog_track_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_selog_track_dump_t_tojson,
   .fromjson = vl_api_selog_track_dump_t_fromjson,
   .calc_size = vl_api_selog_track_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SELOG_TRACK_DETAILS + msg_id_base,
  .name = "selog_track_details",
  .handler = 0,
  .endian = vl_api_selog_track_details_t_endian,
  .format_fn = vl_api_selog_track_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_selog_track_details_t_tojson,
  .fromjson = vl_api_selog_track_details_t_fromjson,
  .calc_size = vl_api_selog_track_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SELOG_EVENT_TYPE_DUMP + msg_id_base,
   .name = "selog_event_type_dump",
   .handler = vl_api_selog_event_type_dump_t_handler,
   .endian = vl_api_selog_event_type_dump_t_endian,
   .format_fn = vl_api_selog_event_type_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_selog_event_type_dump_t_tojson,
   .fromjson = vl_api_selog_event_type_dump_t_fromjson,
   .calc_size = vl_api_selog_event_type_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SELOG_EVENT_TYPE_DETAILS + msg_id_base,
  .name = "selog_event_type_details",
  .handler = 0,
  .endian = vl_api_selog_event_type_details_t_endian,
  .format_fn = vl_api_selog_event_type_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_selog_event_type_details_t_tojson,
  .fromjson = vl_api_selog_event_type_details_t_fromjson,
  .calc_size = vl_api_selog_event_type_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SELOG_EVENT_TYPE_STRING_DUMP + msg_id_base,
   .name = "selog_event_type_string_dump",
   .handler = vl_api_selog_event_type_string_dump_t_handler,
   .endian = vl_api_selog_event_type_string_dump_t_endian,
   .format_fn = vl_api_selog_event_type_string_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_selog_event_type_string_dump_t_tojson,
   .fromjson = vl_api_selog_event_type_string_dump_t_fromjson,
   .calc_size = vl_api_selog_event_type_string_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SELOG_EVENT_TYPE_STRING_DETAILS + msg_id_base,
  .name = "selog_event_type_string_details",
  .handler = 0,
  .endian = vl_api_selog_event_type_string_details_t_endian,
  .format_fn = vl_api_selog_event_type_string_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_selog_event_type_string_details_t_tojson,
  .fromjson = vl_api_selog_event_type_string_details_t_fromjson,
  .calc_size = vl_api_selog_event_type_string_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
