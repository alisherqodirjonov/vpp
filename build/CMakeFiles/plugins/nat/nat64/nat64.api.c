#define vl_endianfun		/* define message structures */
#include "nat64.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "nat64.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "nat64.api.h"
#undef vl_printfun

#include "nat64.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("nat64_b1b82fcf", VL_MSG_NAT64_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_nat64);
   vl_msg_api_add_msg_name_crc (am, "nat64_plugin_enable_disable_45948b90",
                                VL_API_NAT64_PLUGIN_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat64_plugin_enable_disable_reply_e8d4e804",
                                VL_API_NAT64_PLUGIN_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat64_set_timeouts_d4746b16",
                                VL_API_NAT64_SET_TIMEOUTS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat64_set_timeouts_reply_e8d4e804",
                                VL_API_NAT64_SET_TIMEOUTS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat64_get_timeouts_51077d14",
                                VL_API_NAT64_GET_TIMEOUTS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat64_get_timeouts_reply_3c4df4e1",
                                VL_API_NAT64_GET_TIMEOUTS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat64_add_del_pool_addr_range_a3b944e3",
                                VL_API_NAT64_ADD_DEL_POOL_ADDR_RANGE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat64_add_del_pool_addr_range_reply_e8d4e804",
                                VL_API_NAT64_ADD_DEL_POOL_ADDR_RANGE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat64_pool_addr_dump_51077d14",
                                VL_API_NAT64_POOL_ADDR_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat64_pool_addr_details_9bb99cdb",
                                VL_API_NAT64_POOL_ADDR_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat64_add_del_interface_f3699b83",
                                VL_API_NAT64_ADD_DEL_INTERFACE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat64_add_del_interface_reply_e8d4e804",
                                VL_API_NAT64_ADD_DEL_INTERFACE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat64_interface_dump_51077d14",
                                VL_API_NAT64_INTERFACE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat64_interface_details_5d286289",
                                VL_API_NAT64_INTERFACE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat64_add_del_static_bib_1c404de5",
                                VL_API_NAT64_ADD_DEL_STATIC_BIB + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat64_add_del_static_bib_reply_e8d4e804",
                                VL_API_NAT64_ADD_DEL_STATIC_BIB_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat64_bib_dump_cfcb6b75",
                                VL_API_NAT64_BIB_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat64_bib_details_43bc3ddf",
                                VL_API_NAT64_BIB_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat64_st_dump_cfcb6b75",
                                VL_API_NAT64_ST_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat64_st_details_dd3361ed",
                                VL_API_NAT64_ST_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat64_add_del_prefix_727b2f4c",
                                VL_API_NAT64_ADD_DEL_PREFIX + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat64_add_del_prefix_reply_e8d4e804",
                                VL_API_NAT64_ADD_DEL_PREFIX_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat64_prefix_dump_51077d14",
                                VL_API_NAT64_PREFIX_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat64_prefix_details_20568de3",
                                VL_API_NAT64_PREFIX_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat64_add_del_interface_addr_47d6e753",
                                VL_API_NAT64_ADD_DEL_INTERFACE_ADDR + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat64_add_del_interface_addr_reply_e8d4e804",
                                VL_API_NAT64_ADD_DEL_INTERFACE_ADDR_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT64_PLUGIN_ENABLE_DISABLE + msg_id_base,
   .name = "nat64_plugin_enable_disable",
   .handler = vl_api_nat64_plugin_enable_disable_t_handler,
   .endian = vl_api_nat64_plugin_enable_disable_t_endian,
   .format_fn = vl_api_nat64_plugin_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat64_plugin_enable_disable_t_tojson,
   .fromjson = vl_api_nat64_plugin_enable_disable_t_fromjson,
   .calc_size = vl_api_nat64_plugin_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT64_PLUGIN_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "nat64_plugin_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_nat64_plugin_enable_disable_reply_t_endian,
  .format_fn = vl_api_nat64_plugin_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat64_plugin_enable_disable_reply_t_tojson,
  .fromjson = vl_api_nat64_plugin_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_nat64_plugin_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT64_SET_TIMEOUTS + msg_id_base,
   .name = "nat64_set_timeouts",
   .handler = vl_api_nat64_set_timeouts_t_handler,
   .endian = vl_api_nat64_set_timeouts_t_endian,
   .format_fn = vl_api_nat64_set_timeouts_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat64_set_timeouts_t_tojson,
   .fromjson = vl_api_nat64_set_timeouts_t_fromjson,
   .calc_size = vl_api_nat64_set_timeouts_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT64_SET_TIMEOUTS_REPLY + msg_id_base,
  .name = "nat64_set_timeouts_reply",
  .handler = 0,
  .endian = vl_api_nat64_set_timeouts_reply_t_endian,
  .format_fn = vl_api_nat64_set_timeouts_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat64_set_timeouts_reply_t_tojson,
  .fromjson = vl_api_nat64_set_timeouts_reply_t_fromjson,
  .calc_size = vl_api_nat64_set_timeouts_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT64_GET_TIMEOUTS + msg_id_base,
   .name = "nat64_get_timeouts",
   .handler = vl_api_nat64_get_timeouts_t_handler,
   .endian = vl_api_nat64_get_timeouts_t_endian,
   .format_fn = vl_api_nat64_get_timeouts_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat64_get_timeouts_t_tojson,
   .fromjson = vl_api_nat64_get_timeouts_t_fromjson,
   .calc_size = vl_api_nat64_get_timeouts_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT64_GET_TIMEOUTS_REPLY + msg_id_base,
  .name = "nat64_get_timeouts_reply",
  .handler = 0,
  .endian = vl_api_nat64_get_timeouts_reply_t_endian,
  .format_fn = vl_api_nat64_get_timeouts_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat64_get_timeouts_reply_t_tojson,
  .fromjson = vl_api_nat64_get_timeouts_reply_t_fromjson,
  .calc_size = vl_api_nat64_get_timeouts_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT64_ADD_DEL_POOL_ADDR_RANGE + msg_id_base,
   .name = "nat64_add_del_pool_addr_range",
   .handler = vl_api_nat64_add_del_pool_addr_range_t_handler,
   .endian = vl_api_nat64_add_del_pool_addr_range_t_endian,
   .format_fn = vl_api_nat64_add_del_pool_addr_range_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat64_add_del_pool_addr_range_t_tojson,
   .fromjson = vl_api_nat64_add_del_pool_addr_range_t_fromjson,
   .calc_size = vl_api_nat64_add_del_pool_addr_range_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT64_ADD_DEL_POOL_ADDR_RANGE_REPLY + msg_id_base,
  .name = "nat64_add_del_pool_addr_range_reply",
  .handler = 0,
  .endian = vl_api_nat64_add_del_pool_addr_range_reply_t_endian,
  .format_fn = vl_api_nat64_add_del_pool_addr_range_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat64_add_del_pool_addr_range_reply_t_tojson,
  .fromjson = vl_api_nat64_add_del_pool_addr_range_reply_t_fromjson,
  .calc_size = vl_api_nat64_add_del_pool_addr_range_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT64_POOL_ADDR_DUMP + msg_id_base,
   .name = "nat64_pool_addr_dump",
   .handler = vl_api_nat64_pool_addr_dump_t_handler,
   .endian = vl_api_nat64_pool_addr_dump_t_endian,
   .format_fn = vl_api_nat64_pool_addr_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat64_pool_addr_dump_t_tojson,
   .fromjson = vl_api_nat64_pool_addr_dump_t_fromjson,
   .calc_size = vl_api_nat64_pool_addr_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT64_POOL_ADDR_DETAILS + msg_id_base,
  .name = "nat64_pool_addr_details",
  .handler = 0,
  .endian = vl_api_nat64_pool_addr_details_t_endian,
  .format_fn = vl_api_nat64_pool_addr_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat64_pool_addr_details_t_tojson,
  .fromjson = vl_api_nat64_pool_addr_details_t_fromjson,
  .calc_size = vl_api_nat64_pool_addr_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT64_ADD_DEL_INTERFACE + msg_id_base,
   .name = "nat64_add_del_interface",
   .handler = vl_api_nat64_add_del_interface_t_handler,
   .endian = vl_api_nat64_add_del_interface_t_endian,
   .format_fn = vl_api_nat64_add_del_interface_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat64_add_del_interface_t_tojson,
   .fromjson = vl_api_nat64_add_del_interface_t_fromjson,
   .calc_size = vl_api_nat64_add_del_interface_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT64_ADD_DEL_INTERFACE_REPLY + msg_id_base,
  .name = "nat64_add_del_interface_reply",
  .handler = 0,
  .endian = vl_api_nat64_add_del_interface_reply_t_endian,
  .format_fn = vl_api_nat64_add_del_interface_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat64_add_del_interface_reply_t_tojson,
  .fromjson = vl_api_nat64_add_del_interface_reply_t_fromjson,
  .calc_size = vl_api_nat64_add_del_interface_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT64_INTERFACE_DUMP + msg_id_base,
   .name = "nat64_interface_dump",
   .handler = vl_api_nat64_interface_dump_t_handler,
   .endian = vl_api_nat64_interface_dump_t_endian,
   .format_fn = vl_api_nat64_interface_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat64_interface_dump_t_tojson,
   .fromjson = vl_api_nat64_interface_dump_t_fromjson,
   .calc_size = vl_api_nat64_interface_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT64_INTERFACE_DETAILS + msg_id_base,
  .name = "nat64_interface_details",
  .handler = 0,
  .endian = vl_api_nat64_interface_details_t_endian,
  .format_fn = vl_api_nat64_interface_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat64_interface_details_t_tojson,
  .fromjson = vl_api_nat64_interface_details_t_fromjson,
  .calc_size = vl_api_nat64_interface_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT64_ADD_DEL_STATIC_BIB + msg_id_base,
   .name = "nat64_add_del_static_bib",
   .handler = vl_api_nat64_add_del_static_bib_t_handler,
   .endian = vl_api_nat64_add_del_static_bib_t_endian,
   .format_fn = vl_api_nat64_add_del_static_bib_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat64_add_del_static_bib_t_tojson,
   .fromjson = vl_api_nat64_add_del_static_bib_t_fromjson,
   .calc_size = vl_api_nat64_add_del_static_bib_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT64_ADD_DEL_STATIC_BIB_REPLY + msg_id_base,
  .name = "nat64_add_del_static_bib_reply",
  .handler = 0,
  .endian = vl_api_nat64_add_del_static_bib_reply_t_endian,
  .format_fn = vl_api_nat64_add_del_static_bib_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat64_add_del_static_bib_reply_t_tojson,
  .fromjson = vl_api_nat64_add_del_static_bib_reply_t_fromjson,
  .calc_size = vl_api_nat64_add_del_static_bib_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT64_BIB_DUMP + msg_id_base,
   .name = "nat64_bib_dump",
   .handler = vl_api_nat64_bib_dump_t_handler,
   .endian = vl_api_nat64_bib_dump_t_endian,
   .format_fn = vl_api_nat64_bib_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat64_bib_dump_t_tojson,
   .fromjson = vl_api_nat64_bib_dump_t_fromjson,
   .calc_size = vl_api_nat64_bib_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT64_BIB_DETAILS + msg_id_base,
  .name = "nat64_bib_details",
  .handler = 0,
  .endian = vl_api_nat64_bib_details_t_endian,
  .format_fn = vl_api_nat64_bib_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat64_bib_details_t_tojson,
  .fromjson = vl_api_nat64_bib_details_t_fromjson,
  .calc_size = vl_api_nat64_bib_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT64_ST_DUMP + msg_id_base,
   .name = "nat64_st_dump",
   .handler = vl_api_nat64_st_dump_t_handler,
   .endian = vl_api_nat64_st_dump_t_endian,
   .format_fn = vl_api_nat64_st_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat64_st_dump_t_tojson,
   .fromjson = vl_api_nat64_st_dump_t_fromjson,
   .calc_size = vl_api_nat64_st_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT64_ST_DETAILS + msg_id_base,
  .name = "nat64_st_details",
  .handler = 0,
  .endian = vl_api_nat64_st_details_t_endian,
  .format_fn = vl_api_nat64_st_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat64_st_details_t_tojson,
  .fromjson = vl_api_nat64_st_details_t_fromjson,
  .calc_size = vl_api_nat64_st_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT64_ADD_DEL_PREFIX + msg_id_base,
   .name = "nat64_add_del_prefix",
   .handler = vl_api_nat64_add_del_prefix_t_handler,
   .endian = vl_api_nat64_add_del_prefix_t_endian,
   .format_fn = vl_api_nat64_add_del_prefix_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat64_add_del_prefix_t_tojson,
   .fromjson = vl_api_nat64_add_del_prefix_t_fromjson,
   .calc_size = vl_api_nat64_add_del_prefix_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT64_ADD_DEL_PREFIX_REPLY + msg_id_base,
  .name = "nat64_add_del_prefix_reply",
  .handler = 0,
  .endian = vl_api_nat64_add_del_prefix_reply_t_endian,
  .format_fn = vl_api_nat64_add_del_prefix_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat64_add_del_prefix_reply_t_tojson,
  .fromjson = vl_api_nat64_add_del_prefix_reply_t_fromjson,
  .calc_size = vl_api_nat64_add_del_prefix_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT64_PREFIX_DUMP + msg_id_base,
   .name = "nat64_prefix_dump",
   .handler = vl_api_nat64_prefix_dump_t_handler,
   .endian = vl_api_nat64_prefix_dump_t_endian,
   .format_fn = vl_api_nat64_prefix_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat64_prefix_dump_t_tojson,
   .fromjson = vl_api_nat64_prefix_dump_t_fromjson,
   .calc_size = vl_api_nat64_prefix_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT64_PREFIX_DETAILS + msg_id_base,
  .name = "nat64_prefix_details",
  .handler = 0,
  .endian = vl_api_nat64_prefix_details_t_endian,
  .format_fn = vl_api_nat64_prefix_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat64_prefix_details_t_tojson,
  .fromjson = vl_api_nat64_prefix_details_t_fromjson,
  .calc_size = vl_api_nat64_prefix_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT64_ADD_DEL_INTERFACE_ADDR + msg_id_base,
   .name = "nat64_add_del_interface_addr",
   .handler = vl_api_nat64_add_del_interface_addr_t_handler,
   .endian = vl_api_nat64_add_del_interface_addr_t_endian,
   .format_fn = vl_api_nat64_add_del_interface_addr_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat64_add_del_interface_addr_t_tojson,
   .fromjson = vl_api_nat64_add_del_interface_addr_t_fromjson,
   .calc_size = vl_api_nat64_add_del_interface_addr_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT64_ADD_DEL_INTERFACE_ADDR_REPLY + msg_id_base,
  .name = "nat64_add_del_interface_addr_reply",
  .handler = 0,
  .endian = vl_api_nat64_add_del_interface_addr_reply_t_endian,
  .format_fn = vl_api_nat64_add_del_interface_addr_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat64_add_del_interface_addr_reply_t_tojson,
  .fromjson = vl_api_nat64_add_del_interface_addr_reply_t_fromjson,
  .calc_size = vl_api_nat64_add_del_interface_addr_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
