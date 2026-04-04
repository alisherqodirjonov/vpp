#define vl_endianfun		/* define message structures */
#include "pipe.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "pipe.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "pipe.api.h"
#undef vl_printfun

#include "pipe.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("pipe_bf185589", VL_MSG_PIPE_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_pipe);
   vl_msg_api_add_msg_name_crc (am, "pipe_create_bb263bd3",
                                VL_API_PIPE_CREATE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pipe_create_reply_b7ce310c",
                                VL_API_PIPE_CREATE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pipe_delete_f9e6675e",
                                VL_API_PIPE_DELETE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pipe_delete_reply_e8d4e804",
                                VL_API_PIPE_DELETE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pipe_dump_51077d14",
                                VL_API_PIPE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pipe_details_c52b799d",
                                VL_API_PIPE_DETAILS + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_PIPE_CREATE + msg_id_base,
   .name = "pipe_create",
   .handler = vl_api_pipe_create_t_handler,
   .endian = vl_api_pipe_create_t_endian,
   .format_fn = vl_api_pipe_create_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_pipe_create_t_tojson,
   .fromjson = vl_api_pipe_create_t_fromjson,
   .calc_size = vl_api_pipe_create_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_PIPE_CREATE_REPLY + msg_id_base,
  .name = "pipe_create_reply",
  .handler = 0,
  .endian = vl_api_pipe_create_reply_t_endian,
  .format_fn = vl_api_pipe_create_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_pipe_create_reply_t_tojson,
  .fromjson = vl_api_pipe_create_reply_t_fromjson,
  .calc_size = vl_api_pipe_create_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_PIPE_DELETE + msg_id_base,
   .name = "pipe_delete",
   .handler = vl_api_pipe_delete_t_handler,
   .endian = vl_api_pipe_delete_t_endian,
   .format_fn = vl_api_pipe_delete_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_pipe_delete_t_tojson,
   .fromjson = vl_api_pipe_delete_t_fromjson,
   .calc_size = vl_api_pipe_delete_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_PIPE_DELETE_REPLY + msg_id_base,
  .name = "pipe_delete_reply",
  .handler = 0,
  .endian = vl_api_pipe_delete_reply_t_endian,
  .format_fn = vl_api_pipe_delete_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_pipe_delete_reply_t_tojson,
  .fromjson = vl_api_pipe_delete_reply_t_fromjson,
  .calc_size = vl_api_pipe_delete_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_PIPE_DUMP + msg_id_base,
   .name = "pipe_dump",
   .handler = vl_api_pipe_dump_t_handler,
   .endian = vl_api_pipe_dump_t_endian,
   .format_fn = vl_api_pipe_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_pipe_dump_t_tojson,
   .fromjson = vl_api_pipe_dump_t_fromjson,
   .calc_size = vl_api_pipe_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_PIPE_DETAILS + msg_id_base,
  .name = "pipe_details",
  .handler = 0,
  .endian = vl_api_pipe_details_t_endian,
  .format_fn = vl_api_pipe_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_pipe_details_t_tojson,
  .fromjson = vl_api_pipe_details_t_fromjson,
  .calc_size = vl_api_pipe_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
