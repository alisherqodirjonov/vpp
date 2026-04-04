#define vl_endianfun		/* define message structures */
#include "vat2_test.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "vat2_test.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "vat2_test.api.h"
#undef vl_printfun

#include "vat2_test.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("vat2_test_6787fedc", VL_MSG_VAT2_TEST_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_vat2_test);
   vl_msg_api_add_msg_name_crc (am, "test_prefix_d866c1a9",
                                VL_API_TEST_PREFIX + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "test_prefix_reply_e8d4e804",
                                VL_API_TEST_PREFIX_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "test_enum_e3190a2e",
                                VL_API_TEST_ENUM + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "test_enum_reply_e8d4e804",
                                VL_API_TEST_ENUM_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "test_string_3955d673",
                                VL_API_TEST_STRING + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "test_string_reply_e8d4e804",
                                VL_API_TEST_STRING_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "test_string2_64a8785b",
                                VL_API_TEST_STRING2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "test_string2_reply_e8d4e804",
                                VL_API_TEST_STRING2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "test_vla_5d944dfc",
                                VL_API_TEST_VLA + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "test_vla_reply_e8d4e804",
                                VL_API_TEST_VLA_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "test_vla2_471f6687",
                                VL_API_TEST_VLA2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "test_vla2_reply_e8d4e804",
                                VL_API_TEST_VLA2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "test_vla3_bac4a968",
                                VL_API_TEST_VLA3 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "test_vla3_reply_e8d4e804",
                                VL_API_TEST_VLA3_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "test_vla4_c061d9d1",
                                VL_API_TEST_VLA4 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "test_vla4_reply_e8d4e804",
                                VL_API_TEST_VLA4_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "test_vla5_09b0e1f3",
                                VL_API_TEST_VLA5 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "test_vla5_reply_e8d4e804",
                                VL_API_TEST_VLA5_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "test_addresses_2bef955c",
                                VL_API_TEST_ADDRESSES + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "test_addresses_reply_e8d4e804",
                                VL_API_TEST_ADDRESSES_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "test_addresses2_ff01dd23",
                                VL_API_TEST_ADDRESSES2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "test_addresses2_reply_e8d4e804",
                                VL_API_TEST_ADDRESSES2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "test_addresses3_7f3e48a1",
                                VL_API_TEST_ADDRESSES3 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "test_addresses3_reply_e8d4e804",
                                VL_API_TEST_ADDRESSES3_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "test_empty_51077d14",
                                VL_API_TEST_EMPTY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "test_empty_reply_e8d4e804",
                                VL_API_TEST_EMPTY_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "test_interface_00e34dc0",
                                VL_API_TEST_INTERFACE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "test_interface_reply_e8d4e804",
                                VL_API_TEST_INTERFACE_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_TEST_PREFIX + msg_id_base,
   .name = "test_prefix",
   .handler = vl_api_test_prefix_t_handler,
   .endian = vl_api_test_prefix_t_endian,
   .format_fn = vl_api_test_prefix_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_test_prefix_t_tojson,
   .fromjson = vl_api_test_prefix_t_fromjson,
   .calc_size = vl_api_test_prefix_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_TEST_PREFIX_REPLY + msg_id_base,
  .name = "test_prefix_reply",
  .handler = 0,
  .endian = vl_api_test_prefix_reply_t_endian,
  .format_fn = vl_api_test_prefix_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_test_prefix_reply_t_tojson,
  .fromjson = vl_api_test_prefix_reply_t_fromjson,
  .calc_size = vl_api_test_prefix_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_TEST_ENUM + msg_id_base,
   .name = "test_enum",
   .handler = vl_api_test_enum_t_handler,
   .endian = vl_api_test_enum_t_endian,
   .format_fn = vl_api_test_enum_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_test_enum_t_tojson,
   .fromjson = vl_api_test_enum_t_fromjson,
   .calc_size = vl_api_test_enum_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_TEST_ENUM_REPLY + msg_id_base,
  .name = "test_enum_reply",
  .handler = 0,
  .endian = vl_api_test_enum_reply_t_endian,
  .format_fn = vl_api_test_enum_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_test_enum_reply_t_tojson,
  .fromjson = vl_api_test_enum_reply_t_fromjson,
  .calc_size = vl_api_test_enum_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_TEST_STRING + msg_id_base,
   .name = "test_string",
   .handler = vl_api_test_string_t_handler,
   .endian = vl_api_test_string_t_endian,
   .format_fn = vl_api_test_string_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_test_string_t_tojson,
   .fromjson = vl_api_test_string_t_fromjson,
   .calc_size = vl_api_test_string_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_TEST_STRING_REPLY + msg_id_base,
  .name = "test_string_reply",
  .handler = 0,
  .endian = vl_api_test_string_reply_t_endian,
  .format_fn = vl_api_test_string_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_test_string_reply_t_tojson,
  .fromjson = vl_api_test_string_reply_t_fromjson,
  .calc_size = vl_api_test_string_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_TEST_STRING2 + msg_id_base,
   .name = "test_string2",
   .handler = vl_api_test_string2_t_handler,
   .endian = vl_api_test_string2_t_endian,
   .format_fn = vl_api_test_string2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_test_string2_t_tojson,
   .fromjson = vl_api_test_string2_t_fromjson,
   .calc_size = vl_api_test_string2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_TEST_STRING2_REPLY + msg_id_base,
  .name = "test_string2_reply",
  .handler = 0,
  .endian = vl_api_test_string2_reply_t_endian,
  .format_fn = vl_api_test_string2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_test_string2_reply_t_tojson,
  .fromjson = vl_api_test_string2_reply_t_fromjson,
  .calc_size = vl_api_test_string2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_TEST_VLA + msg_id_base,
   .name = "test_vla",
   .handler = vl_api_test_vla_t_handler,
   .endian = vl_api_test_vla_t_endian,
   .format_fn = vl_api_test_vla_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_test_vla_t_tojson,
   .fromjson = vl_api_test_vla_t_fromjson,
   .calc_size = vl_api_test_vla_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_TEST_VLA_REPLY + msg_id_base,
  .name = "test_vla_reply",
  .handler = 0,
  .endian = vl_api_test_vla_reply_t_endian,
  .format_fn = vl_api_test_vla_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_test_vla_reply_t_tojson,
  .fromjson = vl_api_test_vla_reply_t_fromjson,
  .calc_size = vl_api_test_vla_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_TEST_VLA2 + msg_id_base,
   .name = "test_vla2",
   .handler = vl_api_test_vla2_t_handler,
   .endian = vl_api_test_vla2_t_endian,
   .format_fn = vl_api_test_vla2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_test_vla2_t_tojson,
   .fromjson = vl_api_test_vla2_t_fromjson,
   .calc_size = vl_api_test_vla2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_TEST_VLA2_REPLY + msg_id_base,
  .name = "test_vla2_reply",
  .handler = 0,
  .endian = vl_api_test_vla2_reply_t_endian,
  .format_fn = vl_api_test_vla2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_test_vla2_reply_t_tojson,
  .fromjson = vl_api_test_vla2_reply_t_fromjson,
  .calc_size = vl_api_test_vla2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_TEST_VLA3 + msg_id_base,
   .name = "test_vla3",
   .handler = vl_api_test_vla3_t_handler,
   .endian = vl_api_test_vla3_t_endian,
   .format_fn = vl_api_test_vla3_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_test_vla3_t_tojson,
   .fromjson = vl_api_test_vla3_t_fromjson,
   .calc_size = vl_api_test_vla3_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_TEST_VLA3_REPLY + msg_id_base,
  .name = "test_vla3_reply",
  .handler = 0,
  .endian = vl_api_test_vla3_reply_t_endian,
  .format_fn = vl_api_test_vla3_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_test_vla3_reply_t_tojson,
  .fromjson = vl_api_test_vla3_reply_t_fromjson,
  .calc_size = vl_api_test_vla3_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_TEST_VLA4 + msg_id_base,
   .name = "test_vla4",
   .handler = vl_api_test_vla4_t_handler,
   .endian = vl_api_test_vla4_t_endian,
   .format_fn = vl_api_test_vla4_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_test_vla4_t_tojson,
   .fromjson = vl_api_test_vla4_t_fromjson,
   .calc_size = vl_api_test_vla4_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_TEST_VLA4_REPLY + msg_id_base,
  .name = "test_vla4_reply",
  .handler = 0,
  .endian = vl_api_test_vla4_reply_t_endian,
  .format_fn = vl_api_test_vla4_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_test_vla4_reply_t_tojson,
  .fromjson = vl_api_test_vla4_reply_t_fromjson,
  .calc_size = vl_api_test_vla4_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_TEST_VLA5 + msg_id_base,
   .name = "test_vla5",
   .handler = vl_api_test_vla5_t_handler,
   .endian = vl_api_test_vla5_t_endian,
   .format_fn = vl_api_test_vla5_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_test_vla5_t_tojson,
   .fromjson = vl_api_test_vla5_t_fromjson,
   .calc_size = vl_api_test_vla5_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_TEST_VLA5_REPLY + msg_id_base,
  .name = "test_vla5_reply",
  .handler = 0,
  .endian = vl_api_test_vla5_reply_t_endian,
  .format_fn = vl_api_test_vla5_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_test_vla5_reply_t_tojson,
  .fromjson = vl_api_test_vla5_reply_t_fromjson,
  .calc_size = vl_api_test_vla5_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_TEST_ADDRESSES + msg_id_base,
   .name = "test_addresses",
   .handler = vl_api_test_addresses_t_handler,
   .endian = vl_api_test_addresses_t_endian,
   .format_fn = vl_api_test_addresses_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_test_addresses_t_tojson,
   .fromjson = vl_api_test_addresses_t_fromjson,
   .calc_size = vl_api_test_addresses_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_TEST_ADDRESSES_REPLY + msg_id_base,
  .name = "test_addresses_reply",
  .handler = 0,
  .endian = vl_api_test_addresses_reply_t_endian,
  .format_fn = vl_api_test_addresses_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_test_addresses_reply_t_tojson,
  .fromjson = vl_api_test_addresses_reply_t_fromjson,
  .calc_size = vl_api_test_addresses_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_TEST_ADDRESSES2 + msg_id_base,
   .name = "test_addresses2",
   .handler = vl_api_test_addresses2_t_handler,
   .endian = vl_api_test_addresses2_t_endian,
   .format_fn = vl_api_test_addresses2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_test_addresses2_t_tojson,
   .fromjson = vl_api_test_addresses2_t_fromjson,
   .calc_size = vl_api_test_addresses2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_TEST_ADDRESSES2_REPLY + msg_id_base,
  .name = "test_addresses2_reply",
  .handler = 0,
  .endian = vl_api_test_addresses2_reply_t_endian,
  .format_fn = vl_api_test_addresses2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_test_addresses2_reply_t_tojson,
  .fromjson = vl_api_test_addresses2_reply_t_fromjson,
  .calc_size = vl_api_test_addresses2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_TEST_ADDRESSES3 + msg_id_base,
   .name = "test_addresses3",
   .handler = vl_api_test_addresses3_t_handler,
   .endian = vl_api_test_addresses3_t_endian,
   .format_fn = vl_api_test_addresses3_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_test_addresses3_t_tojson,
   .fromjson = vl_api_test_addresses3_t_fromjson,
   .calc_size = vl_api_test_addresses3_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_TEST_ADDRESSES3_REPLY + msg_id_base,
  .name = "test_addresses3_reply",
  .handler = 0,
  .endian = vl_api_test_addresses3_reply_t_endian,
  .format_fn = vl_api_test_addresses3_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_test_addresses3_reply_t_tojson,
  .fromjson = vl_api_test_addresses3_reply_t_fromjson,
  .calc_size = vl_api_test_addresses3_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_TEST_EMPTY + msg_id_base,
   .name = "test_empty",
   .handler = vl_api_test_empty_t_handler,
   .endian = vl_api_test_empty_t_endian,
   .format_fn = vl_api_test_empty_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_test_empty_t_tojson,
   .fromjson = vl_api_test_empty_t_fromjson,
   .calc_size = vl_api_test_empty_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_TEST_EMPTY_REPLY + msg_id_base,
  .name = "test_empty_reply",
  .handler = 0,
  .endian = vl_api_test_empty_reply_t_endian,
  .format_fn = vl_api_test_empty_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_test_empty_reply_t_tojson,
  .fromjson = vl_api_test_empty_reply_t_fromjson,
  .calc_size = vl_api_test_empty_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_TEST_INTERFACE + msg_id_base,
   .name = "test_interface",
   .handler = vl_api_test_interface_t_handler,
   .endian = vl_api_test_interface_t_endian,
   .format_fn = vl_api_test_interface_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_test_interface_t_tojson,
   .fromjson = vl_api_test_interface_t_fromjson,
   .calc_size = vl_api_test_interface_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_TEST_INTERFACE_REPLY + msg_id_base,
  .name = "test_interface_reply",
  .handler = 0,
  .endian = vl_api_test_interface_reply_t_endian,
  .format_fn = vl_api_test_interface_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_test_interface_reply_t_tojson,
  .fromjson = vl_api_test_interface_reply_t_fromjson,
  .calc_size = vl_api_test_interface_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
