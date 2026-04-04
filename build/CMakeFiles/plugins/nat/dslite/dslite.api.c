#define vl_endianfun		/* define message structures */
#include "dslite.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "dslite.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "dslite.api.h"
#undef vl_printfun

#include "dslite.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("dslite_4bc15f82", VL_MSG_DSLITE_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_dslite);
   vl_msg_api_add_msg_name_crc (am, "dslite_add_del_pool_addr_range_de2a5b02",
                                VL_API_DSLITE_ADD_DEL_POOL_ADDR_RANGE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dslite_add_del_pool_addr_range_reply_e8d4e804",
                                VL_API_DSLITE_ADD_DEL_POOL_ADDR_RANGE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dslite_address_dump_51077d14",
                                VL_API_DSLITE_ADDRESS_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dslite_address_details_ec26d648",
                                VL_API_DSLITE_ADDRESS_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dslite_set_aftr_addr_78b50fdf",
                                VL_API_DSLITE_SET_AFTR_ADDR + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dslite_set_aftr_addr_reply_e8d4e804",
                                VL_API_DSLITE_SET_AFTR_ADDR_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dslite_get_aftr_addr_51077d14",
                                VL_API_DSLITE_GET_AFTR_ADDR + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dslite_get_aftr_addr_reply_8e23608e",
                                VL_API_DSLITE_GET_AFTR_ADDR_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dslite_set_b4_addr_78b50fdf",
                                VL_API_DSLITE_SET_B4_ADDR + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dslite_set_b4_addr_reply_e8d4e804",
                                VL_API_DSLITE_SET_B4_ADDR_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dslite_get_b4_addr_51077d14",
                                VL_API_DSLITE_GET_B4_ADDR + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dslite_get_b4_addr_reply_8e23608e",
                                VL_API_DSLITE_GET_B4_ADDR_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DSLITE_ADD_DEL_POOL_ADDR_RANGE + msg_id_base,
   .name = "dslite_add_del_pool_addr_range",
   .handler = vl_api_dslite_add_del_pool_addr_range_t_handler,
   .endian = vl_api_dslite_add_del_pool_addr_range_t_endian,
   .format_fn = vl_api_dslite_add_del_pool_addr_range_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_dslite_add_del_pool_addr_range_t_tojson,
   .fromjson = vl_api_dslite_add_del_pool_addr_range_t_fromjson,
   .calc_size = vl_api_dslite_add_del_pool_addr_range_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DSLITE_ADD_DEL_POOL_ADDR_RANGE_REPLY + msg_id_base,
  .name = "dslite_add_del_pool_addr_range_reply",
  .handler = 0,
  .endian = vl_api_dslite_add_del_pool_addr_range_reply_t_endian,
  .format_fn = vl_api_dslite_add_del_pool_addr_range_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_dslite_add_del_pool_addr_range_reply_t_tojson,
  .fromjson = vl_api_dslite_add_del_pool_addr_range_reply_t_fromjson,
  .calc_size = vl_api_dslite_add_del_pool_addr_range_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DSLITE_ADDRESS_DUMP + msg_id_base,
   .name = "dslite_address_dump",
   .handler = vl_api_dslite_address_dump_t_handler,
   .endian = vl_api_dslite_address_dump_t_endian,
   .format_fn = vl_api_dslite_address_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_dslite_address_dump_t_tojson,
   .fromjson = vl_api_dslite_address_dump_t_fromjson,
   .calc_size = vl_api_dslite_address_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DSLITE_ADDRESS_DETAILS + msg_id_base,
  .name = "dslite_address_details",
  .handler = 0,
  .endian = vl_api_dslite_address_details_t_endian,
  .format_fn = vl_api_dslite_address_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_dslite_address_details_t_tojson,
  .fromjson = vl_api_dslite_address_details_t_fromjson,
  .calc_size = vl_api_dslite_address_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DSLITE_SET_AFTR_ADDR + msg_id_base,
   .name = "dslite_set_aftr_addr",
   .handler = vl_api_dslite_set_aftr_addr_t_handler,
   .endian = vl_api_dslite_set_aftr_addr_t_endian,
   .format_fn = vl_api_dslite_set_aftr_addr_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_dslite_set_aftr_addr_t_tojson,
   .fromjson = vl_api_dslite_set_aftr_addr_t_fromjson,
   .calc_size = vl_api_dslite_set_aftr_addr_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DSLITE_SET_AFTR_ADDR_REPLY + msg_id_base,
  .name = "dslite_set_aftr_addr_reply",
  .handler = 0,
  .endian = vl_api_dslite_set_aftr_addr_reply_t_endian,
  .format_fn = vl_api_dslite_set_aftr_addr_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_dslite_set_aftr_addr_reply_t_tojson,
  .fromjson = vl_api_dslite_set_aftr_addr_reply_t_fromjson,
  .calc_size = vl_api_dslite_set_aftr_addr_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DSLITE_GET_AFTR_ADDR + msg_id_base,
   .name = "dslite_get_aftr_addr",
   .handler = vl_api_dslite_get_aftr_addr_t_handler,
   .endian = vl_api_dslite_get_aftr_addr_t_endian,
   .format_fn = vl_api_dslite_get_aftr_addr_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_dslite_get_aftr_addr_t_tojson,
   .fromjson = vl_api_dslite_get_aftr_addr_t_fromjson,
   .calc_size = vl_api_dslite_get_aftr_addr_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DSLITE_GET_AFTR_ADDR_REPLY + msg_id_base,
  .name = "dslite_get_aftr_addr_reply",
  .handler = 0,
  .endian = vl_api_dslite_get_aftr_addr_reply_t_endian,
  .format_fn = vl_api_dslite_get_aftr_addr_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_dslite_get_aftr_addr_reply_t_tojson,
  .fromjson = vl_api_dslite_get_aftr_addr_reply_t_fromjson,
  .calc_size = vl_api_dslite_get_aftr_addr_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DSLITE_SET_B4_ADDR + msg_id_base,
   .name = "dslite_set_b4_addr",
   .handler = vl_api_dslite_set_b4_addr_t_handler,
   .endian = vl_api_dslite_set_b4_addr_t_endian,
   .format_fn = vl_api_dslite_set_b4_addr_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_dslite_set_b4_addr_t_tojson,
   .fromjson = vl_api_dslite_set_b4_addr_t_fromjson,
   .calc_size = vl_api_dslite_set_b4_addr_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DSLITE_SET_B4_ADDR_REPLY + msg_id_base,
  .name = "dslite_set_b4_addr_reply",
  .handler = 0,
  .endian = vl_api_dslite_set_b4_addr_reply_t_endian,
  .format_fn = vl_api_dslite_set_b4_addr_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_dslite_set_b4_addr_reply_t_tojson,
  .fromjson = vl_api_dslite_set_b4_addr_reply_t_fromjson,
  .calc_size = vl_api_dslite_set_b4_addr_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DSLITE_GET_B4_ADDR + msg_id_base,
   .name = "dslite_get_b4_addr",
   .handler = vl_api_dslite_get_b4_addr_t_handler,
   .endian = vl_api_dslite_get_b4_addr_t_endian,
   .format_fn = vl_api_dslite_get_b4_addr_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_dslite_get_b4_addr_t_tojson,
   .fromjson = vl_api_dslite_get_b4_addr_t_fromjson,
   .calc_size = vl_api_dslite_get_b4_addr_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DSLITE_GET_B4_ADDR_REPLY + msg_id_base,
  .name = "dslite_get_b4_addr_reply",
  .handler = 0,
  .endian = vl_api_dslite_get_b4_addr_reply_t_endian,
  .format_fn = vl_api_dslite_get_b4_addr_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_dslite_get_b4_addr_reply_t_tojson,
  .fromjson = vl_api_dslite_get_b4_addr_reply_t_fromjson,
  .calc_size = vl_api_dslite_get_b4_addr_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
