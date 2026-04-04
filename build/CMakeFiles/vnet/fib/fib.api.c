#define vl_endianfun		/* define message structures */
#include "fib.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "fib.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "fib.api.h"
#undef vl_printfun

#include "fib.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("fib_d97c97e5", VL_MSG_FIB_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_fib);
   vl_msg_api_add_msg_name_crc (am, "fib_source_add_b3ac2aec",
                                VL_API_FIB_SOURCE_ADD + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "fib_source_add_reply_604fd6f1",
                                VL_API_FIB_SOURCE_ADD_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "fib_source_dump_51077d14",
                                VL_API_FIB_SOURCE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "fib_source_details_8668acdb",
                                VL_API_FIB_SOURCE_DETAILS + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_FIB_SOURCE_ADD + msg_id_base,
   .name = "fib_source_add",
   .handler = vl_api_fib_source_add_t_handler,
   .endian = vl_api_fib_source_add_t_endian,
   .format_fn = vl_api_fib_source_add_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_fib_source_add_t_tojson,
   .fromjson = vl_api_fib_source_add_t_fromjson,
   .calc_size = vl_api_fib_source_add_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_FIB_SOURCE_ADD_REPLY + msg_id_base,
  .name = "fib_source_add_reply",
  .handler = 0,
  .endian = vl_api_fib_source_add_reply_t_endian,
  .format_fn = vl_api_fib_source_add_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_fib_source_add_reply_t_tojson,
  .fromjson = vl_api_fib_source_add_reply_t_fromjson,
  .calc_size = vl_api_fib_source_add_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_FIB_SOURCE_DUMP + msg_id_base,
   .name = "fib_source_dump",
   .handler = vl_api_fib_source_dump_t_handler,
   .endian = vl_api_fib_source_dump_t_endian,
   .format_fn = vl_api_fib_source_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_fib_source_dump_t_tojson,
   .fromjson = vl_api_fib_source_dump_t_fromjson,
   .calc_size = vl_api_fib_source_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_FIB_SOURCE_DETAILS + msg_id_base,
  .name = "fib_source_details",
  .handler = 0,
  .endian = vl_api_fib_source_details_t_endian,
  .format_fn = vl_api_fib_source_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_fib_source_details_t_tojson,
  .fromjson = vl_api_fib_source_details_t_fromjson,
  .calc_size = vl_api_fib_source_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
