#define vl_endianfun		/* define message structures */
#include "memif.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "memif.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "memif.api.h"
#undef vl_printfun

#include "memif.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("memif_bf42b70a", VL_MSG_MEMIF_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_memif);
   vl_msg_api_add_msg_name_crc (am, "memif_socket_filename_add_del_a2ce1a10",
                                VL_API_MEMIF_SOCKET_FILENAME_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "memif_socket_filename_add_del_reply_e8d4e804",
                                VL_API_MEMIF_SOCKET_FILENAME_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "memif_socket_filename_add_del_v2_34223bdf",
                                VL_API_MEMIF_SOCKET_FILENAME_ADD_DEL_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "memif_socket_filename_add_del_v2_reply_9f29bdb9",
                                VL_API_MEMIF_SOCKET_FILENAME_ADD_DEL_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "memif_create_b1b25061",
                                VL_API_MEMIF_CREATE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "memif_create_reply_5383d31f",
                                VL_API_MEMIF_CREATE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "memif_create_v2_8c7de5f7",
                                VL_API_MEMIF_CREATE_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "memif_create_v2_reply_5383d31f",
                                VL_API_MEMIF_CREATE_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "memif_delete_f9e6675e",
                                VL_API_MEMIF_DELETE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "memif_delete_reply_e8d4e804",
                                VL_API_MEMIF_DELETE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "memif_socket_filename_details_7ff326f7",
                                VL_API_MEMIF_SOCKET_FILENAME_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "memif_socket_filename_dump_51077d14",
                                VL_API_MEMIF_SOCKET_FILENAME_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "memif_details_da34feb9",
                                VL_API_MEMIF_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "memif_dump_51077d14",
                                VL_API_MEMIF_DUMP + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MEMIF_SOCKET_FILENAME_ADD_DEL + msg_id_base,
   .name = "memif_socket_filename_add_del",
   .handler = vl_api_memif_socket_filename_add_del_t_handler,
   .endian = vl_api_memif_socket_filename_add_del_t_endian,
   .format_fn = vl_api_memif_socket_filename_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_memif_socket_filename_add_del_t_tojson,
   .fromjson = vl_api_memif_socket_filename_add_del_t_fromjson,
   .calc_size = vl_api_memif_socket_filename_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MEMIF_SOCKET_FILENAME_ADD_DEL_REPLY + msg_id_base,
  .name = "memif_socket_filename_add_del_reply",
  .handler = 0,
  .endian = vl_api_memif_socket_filename_add_del_reply_t_endian,
  .format_fn = vl_api_memif_socket_filename_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_memif_socket_filename_add_del_reply_t_tojson,
  .fromjson = vl_api_memif_socket_filename_add_del_reply_t_fromjson,
  .calc_size = vl_api_memif_socket_filename_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MEMIF_SOCKET_FILENAME_ADD_DEL_V2 + msg_id_base,
   .name = "memif_socket_filename_add_del_v2",
   .handler = vl_api_memif_socket_filename_add_del_v2_t_handler,
   .endian = vl_api_memif_socket_filename_add_del_v2_t_endian,
   .format_fn = vl_api_memif_socket_filename_add_del_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_memif_socket_filename_add_del_v2_t_tojson,
   .fromjson = vl_api_memif_socket_filename_add_del_v2_t_fromjson,
   .calc_size = vl_api_memif_socket_filename_add_del_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MEMIF_SOCKET_FILENAME_ADD_DEL_V2_REPLY + msg_id_base,
  .name = "memif_socket_filename_add_del_v2_reply",
  .handler = 0,
  .endian = vl_api_memif_socket_filename_add_del_v2_reply_t_endian,
  .format_fn = vl_api_memif_socket_filename_add_del_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_memif_socket_filename_add_del_v2_reply_t_tojson,
  .fromjson = vl_api_memif_socket_filename_add_del_v2_reply_t_fromjson,
  .calc_size = vl_api_memif_socket_filename_add_del_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MEMIF_CREATE + msg_id_base,
   .name = "memif_create",
   .handler = vl_api_memif_create_t_handler,
   .endian = vl_api_memif_create_t_endian,
   .format_fn = vl_api_memif_create_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_memif_create_t_tojson,
   .fromjson = vl_api_memif_create_t_fromjson,
   .calc_size = vl_api_memif_create_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MEMIF_CREATE_REPLY + msg_id_base,
  .name = "memif_create_reply",
  .handler = 0,
  .endian = vl_api_memif_create_reply_t_endian,
  .format_fn = vl_api_memif_create_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_memif_create_reply_t_tojson,
  .fromjson = vl_api_memif_create_reply_t_fromjson,
  .calc_size = vl_api_memif_create_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MEMIF_CREATE_V2 + msg_id_base,
   .name = "memif_create_v2",
   .handler = vl_api_memif_create_v2_t_handler,
   .endian = vl_api_memif_create_v2_t_endian,
   .format_fn = vl_api_memif_create_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_memif_create_v2_t_tojson,
   .fromjson = vl_api_memif_create_v2_t_fromjson,
   .calc_size = vl_api_memif_create_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MEMIF_CREATE_V2_REPLY + msg_id_base,
  .name = "memif_create_v2_reply",
  .handler = 0,
  .endian = vl_api_memif_create_v2_reply_t_endian,
  .format_fn = vl_api_memif_create_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_memif_create_v2_reply_t_tojson,
  .fromjson = vl_api_memif_create_v2_reply_t_fromjson,
  .calc_size = vl_api_memif_create_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MEMIF_DELETE + msg_id_base,
   .name = "memif_delete",
   .handler = vl_api_memif_delete_t_handler,
   .endian = vl_api_memif_delete_t_endian,
   .format_fn = vl_api_memif_delete_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_memif_delete_t_tojson,
   .fromjson = vl_api_memif_delete_t_fromjson,
   .calc_size = vl_api_memif_delete_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MEMIF_DELETE_REPLY + msg_id_base,
  .name = "memif_delete_reply",
  .handler = 0,
  .endian = vl_api_memif_delete_reply_t_endian,
  .format_fn = vl_api_memif_delete_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_memif_delete_reply_t_tojson,
  .fromjson = vl_api_memif_delete_reply_t_fromjson,
  .calc_size = vl_api_memif_delete_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MEMIF_SOCKET_FILENAME_DUMP + msg_id_base,
   .name = "memif_socket_filename_dump",
   .handler = vl_api_memif_socket_filename_dump_t_handler,
   .endian = vl_api_memif_socket_filename_dump_t_endian,
   .format_fn = vl_api_memif_socket_filename_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_memif_socket_filename_dump_t_tojson,
   .fromjson = vl_api_memif_socket_filename_dump_t_fromjson,
   .calc_size = vl_api_memif_socket_filename_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MEMIF_SOCKET_FILENAME_DETAILS + msg_id_base,
  .name = "memif_socket_filename_details",
  .handler = 0,
  .endian = vl_api_memif_socket_filename_details_t_endian,
  .format_fn = vl_api_memif_socket_filename_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_memif_socket_filename_details_t_tojson,
  .fromjson = vl_api_memif_socket_filename_details_t_fromjson,
  .calc_size = vl_api_memif_socket_filename_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MEMIF_DUMP + msg_id_base,
   .name = "memif_dump",
   .handler = vl_api_memif_dump_t_handler,
   .endian = vl_api_memif_dump_t_endian,
   .format_fn = vl_api_memif_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_memif_dump_t_tojson,
   .fromjson = vl_api_memif_dump_t_fromjson,
   .calc_size = vl_api_memif_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MEMIF_DETAILS + msg_id_base,
  .name = "memif_details",
  .handler = 0,
  .endian = vl_api_memif_details_t_endian,
  .format_fn = vl_api_memif_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_memif_details_t_tojson,
  .fromjson = vl_api_memif_details_t_fromjson,
  .calc_size = vl_api_memif_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
