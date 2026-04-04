#define vl_endianfun		/* define message structures */
#include "bond.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "bond.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "bond.api.h"
#undef vl_printfun

#include "bond.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("bond_727f50bc", VL_MSG_BOND_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_bond);
   vl_msg_api_add_msg_name_crc (am, "bond_create_f1dbd4ff",
                                VL_API_BOND_CREATE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bond_create_reply_5383d31f",
                                VL_API_BOND_CREATE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bond_create2_912fda76",
                                VL_API_BOND_CREATE2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bond_create2_reply_5383d31f",
                                VL_API_BOND_CREATE2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bond_delete_f9e6675e",
                                VL_API_BOND_DELETE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bond_delete_reply_e8d4e804",
                                VL_API_BOND_DELETE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bond_enslave_e7d14948",
                                VL_API_BOND_ENSLAVE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bond_enslave_reply_e8d4e804",
                                VL_API_BOND_ENSLAVE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bond_add_member_e7d14948",
                                VL_API_BOND_ADD_MEMBER + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bond_add_member_reply_e8d4e804",
                                VL_API_BOND_ADD_MEMBER_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bond_detach_slave_f9e6675e",
                                VL_API_BOND_DETACH_SLAVE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bond_detach_slave_reply_e8d4e804",
                                VL_API_BOND_DETACH_SLAVE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bond_detach_member_f9e6675e",
                                VL_API_BOND_DETACH_MEMBER + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bond_detach_member_reply_e8d4e804",
                                VL_API_BOND_DETACH_MEMBER_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_bond_dump_51077d14",
                                VL_API_SW_INTERFACE_BOND_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_bond_details_bb7c929b",
                                VL_API_SW_INTERFACE_BOND_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_bond_interface_dump_f9e6675e",
                                VL_API_SW_BOND_INTERFACE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_bond_interface_details_9428a69c",
                                VL_API_SW_BOND_INTERFACE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_slave_dump_f9e6675e",
                                VL_API_SW_INTERFACE_SLAVE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_slave_details_3c4a0e23",
                                VL_API_SW_INTERFACE_SLAVE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_member_interface_dump_f9e6675e",
                                VL_API_SW_MEMBER_INTERFACE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_member_interface_details_3c4a0e23",
                                VL_API_SW_MEMBER_INTERFACE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_bond_weight_deb510a0",
                                VL_API_SW_INTERFACE_SET_BOND_WEIGHT + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_bond_weight_reply_e8d4e804",
                                VL_API_SW_INTERFACE_SET_BOND_WEIGHT_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BOND_CREATE + msg_id_base,
   .name = "bond_create",
   .handler = vl_api_bond_create_t_handler,
   .endian = vl_api_bond_create_t_endian,
   .format_fn = vl_api_bond_create_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bond_create_t_tojson,
   .fromjson = vl_api_bond_create_t_fromjson,
   .calc_size = vl_api_bond_create_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BOND_CREATE_REPLY + msg_id_base,
  .name = "bond_create_reply",
  .handler = 0,
  .endian = vl_api_bond_create_reply_t_endian,
  .format_fn = vl_api_bond_create_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bond_create_reply_t_tojson,
  .fromjson = vl_api_bond_create_reply_t_fromjson,
  .calc_size = vl_api_bond_create_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BOND_CREATE2 + msg_id_base,
   .name = "bond_create2",
   .handler = vl_api_bond_create2_t_handler,
   .endian = vl_api_bond_create2_t_endian,
   .format_fn = vl_api_bond_create2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bond_create2_t_tojson,
   .fromjson = vl_api_bond_create2_t_fromjson,
   .calc_size = vl_api_bond_create2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BOND_CREATE2_REPLY + msg_id_base,
  .name = "bond_create2_reply",
  .handler = 0,
  .endian = vl_api_bond_create2_reply_t_endian,
  .format_fn = vl_api_bond_create2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bond_create2_reply_t_tojson,
  .fromjson = vl_api_bond_create2_reply_t_fromjson,
  .calc_size = vl_api_bond_create2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BOND_DELETE + msg_id_base,
   .name = "bond_delete",
   .handler = vl_api_bond_delete_t_handler,
   .endian = vl_api_bond_delete_t_endian,
   .format_fn = vl_api_bond_delete_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bond_delete_t_tojson,
   .fromjson = vl_api_bond_delete_t_fromjson,
   .calc_size = vl_api_bond_delete_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BOND_DELETE_REPLY + msg_id_base,
  .name = "bond_delete_reply",
  .handler = 0,
  .endian = vl_api_bond_delete_reply_t_endian,
  .format_fn = vl_api_bond_delete_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bond_delete_reply_t_tojson,
  .fromjson = vl_api_bond_delete_reply_t_fromjson,
  .calc_size = vl_api_bond_delete_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BOND_ENSLAVE + msg_id_base,
   .name = "bond_enslave",
   .handler = vl_api_bond_enslave_t_handler,
   .endian = vl_api_bond_enslave_t_endian,
   .format_fn = vl_api_bond_enslave_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bond_enslave_t_tojson,
   .fromjson = vl_api_bond_enslave_t_fromjson,
   .calc_size = vl_api_bond_enslave_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BOND_ENSLAVE_REPLY + msg_id_base,
  .name = "bond_enslave_reply",
  .handler = 0,
  .endian = vl_api_bond_enslave_reply_t_endian,
  .format_fn = vl_api_bond_enslave_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bond_enslave_reply_t_tojson,
  .fromjson = vl_api_bond_enslave_reply_t_fromjson,
  .calc_size = vl_api_bond_enslave_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BOND_ADD_MEMBER + msg_id_base,
   .name = "bond_add_member",
   .handler = vl_api_bond_add_member_t_handler,
   .endian = vl_api_bond_add_member_t_endian,
   .format_fn = vl_api_bond_add_member_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bond_add_member_t_tojson,
   .fromjson = vl_api_bond_add_member_t_fromjson,
   .calc_size = vl_api_bond_add_member_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BOND_ADD_MEMBER_REPLY + msg_id_base,
  .name = "bond_add_member_reply",
  .handler = 0,
  .endian = vl_api_bond_add_member_reply_t_endian,
  .format_fn = vl_api_bond_add_member_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bond_add_member_reply_t_tojson,
  .fromjson = vl_api_bond_add_member_reply_t_fromjson,
  .calc_size = vl_api_bond_add_member_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BOND_DETACH_SLAVE + msg_id_base,
   .name = "bond_detach_slave",
   .handler = vl_api_bond_detach_slave_t_handler,
   .endian = vl_api_bond_detach_slave_t_endian,
   .format_fn = vl_api_bond_detach_slave_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bond_detach_slave_t_tojson,
   .fromjson = vl_api_bond_detach_slave_t_fromjson,
   .calc_size = vl_api_bond_detach_slave_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BOND_DETACH_SLAVE_REPLY + msg_id_base,
  .name = "bond_detach_slave_reply",
  .handler = 0,
  .endian = vl_api_bond_detach_slave_reply_t_endian,
  .format_fn = vl_api_bond_detach_slave_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bond_detach_slave_reply_t_tojson,
  .fromjson = vl_api_bond_detach_slave_reply_t_fromjson,
  .calc_size = vl_api_bond_detach_slave_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BOND_DETACH_MEMBER + msg_id_base,
   .name = "bond_detach_member",
   .handler = vl_api_bond_detach_member_t_handler,
   .endian = vl_api_bond_detach_member_t_endian,
   .format_fn = vl_api_bond_detach_member_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bond_detach_member_t_tojson,
   .fromjson = vl_api_bond_detach_member_t_fromjson,
   .calc_size = vl_api_bond_detach_member_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BOND_DETACH_MEMBER_REPLY + msg_id_base,
  .name = "bond_detach_member_reply",
  .handler = 0,
  .endian = vl_api_bond_detach_member_reply_t_endian,
  .format_fn = vl_api_bond_detach_member_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bond_detach_member_reply_t_tojson,
  .fromjson = vl_api_bond_detach_member_reply_t_fromjson,
  .calc_size = vl_api_bond_detach_member_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_BOND_DUMP + msg_id_base,
   .name = "sw_interface_bond_dump",
   .handler = vl_api_sw_interface_bond_dump_t_handler,
   .endian = vl_api_sw_interface_bond_dump_t_endian,
   .format_fn = vl_api_sw_interface_bond_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_bond_dump_t_tojson,
   .fromjson = vl_api_sw_interface_bond_dump_t_fromjson,
   .calc_size = vl_api_sw_interface_bond_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_BOND_DETAILS + msg_id_base,
  .name = "sw_interface_bond_details",
  .handler = 0,
  .endian = vl_api_sw_interface_bond_details_t_endian,
  .format_fn = vl_api_sw_interface_bond_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_bond_details_t_tojson,
  .fromjson = vl_api_sw_interface_bond_details_t_fromjson,
  .calc_size = vl_api_sw_interface_bond_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_BOND_INTERFACE_DUMP + msg_id_base,
   .name = "sw_bond_interface_dump",
   .handler = vl_api_sw_bond_interface_dump_t_handler,
   .endian = vl_api_sw_bond_interface_dump_t_endian,
   .format_fn = vl_api_sw_bond_interface_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_bond_interface_dump_t_tojson,
   .fromjson = vl_api_sw_bond_interface_dump_t_fromjson,
   .calc_size = vl_api_sw_bond_interface_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_BOND_INTERFACE_DETAILS + msg_id_base,
  .name = "sw_bond_interface_details",
  .handler = 0,
  .endian = vl_api_sw_bond_interface_details_t_endian,
  .format_fn = vl_api_sw_bond_interface_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_bond_interface_details_t_tojson,
  .fromjson = vl_api_sw_bond_interface_details_t_fromjson,
  .calc_size = vl_api_sw_bond_interface_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_SLAVE_DUMP + msg_id_base,
   .name = "sw_interface_slave_dump",
   .handler = vl_api_sw_interface_slave_dump_t_handler,
   .endian = vl_api_sw_interface_slave_dump_t_endian,
   .format_fn = vl_api_sw_interface_slave_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_slave_dump_t_tojson,
   .fromjson = vl_api_sw_interface_slave_dump_t_fromjson,
   .calc_size = vl_api_sw_interface_slave_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_SLAVE_DETAILS + msg_id_base,
  .name = "sw_interface_slave_details",
  .handler = 0,
  .endian = vl_api_sw_interface_slave_details_t_endian,
  .format_fn = vl_api_sw_interface_slave_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_slave_details_t_tojson,
  .fromjson = vl_api_sw_interface_slave_details_t_fromjson,
  .calc_size = vl_api_sw_interface_slave_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_MEMBER_INTERFACE_DUMP + msg_id_base,
   .name = "sw_member_interface_dump",
   .handler = vl_api_sw_member_interface_dump_t_handler,
   .endian = vl_api_sw_member_interface_dump_t_endian,
   .format_fn = vl_api_sw_member_interface_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_member_interface_dump_t_tojson,
   .fromjson = vl_api_sw_member_interface_dump_t_fromjson,
   .calc_size = vl_api_sw_member_interface_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_MEMBER_INTERFACE_DETAILS + msg_id_base,
  .name = "sw_member_interface_details",
  .handler = 0,
  .endian = vl_api_sw_member_interface_details_t_endian,
  .format_fn = vl_api_sw_member_interface_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_member_interface_details_t_tojson,
  .fromjson = vl_api_sw_member_interface_details_t_fromjson,
  .calc_size = vl_api_sw_member_interface_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_SET_BOND_WEIGHT + msg_id_base,
   .name = "sw_interface_set_bond_weight",
   .handler = vl_api_sw_interface_set_bond_weight_t_handler,
   .endian = vl_api_sw_interface_set_bond_weight_t_endian,
   .format_fn = vl_api_sw_interface_set_bond_weight_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_set_bond_weight_t_tojson,
   .fromjson = vl_api_sw_interface_set_bond_weight_t_fromjson,
   .calc_size = vl_api_sw_interface_set_bond_weight_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_SET_BOND_WEIGHT_REPLY + msg_id_base,
  .name = "sw_interface_set_bond_weight_reply",
  .handler = 0,
  .endian = vl_api_sw_interface_set_bond_weight_reply_t_endian,
  .format_fn = vl_api_sw_interface_set_bond_weight_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_set_bond_weight_reply_t_tojson,
  .fromjson = vl_api_sw_interface_set_bond_weight_reply_t_fromjson,
  .calc_size = vl_api_sw_interface_set_bond_weight_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
