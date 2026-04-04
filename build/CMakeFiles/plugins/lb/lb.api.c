#define vl_endianfun		/* define message structures */
#include "lb.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "lb.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "lb.api.h"
#undef vl_printfun

#include "lb.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("lb_31818767", VL_MSG_LB_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_lb);
   vl_msg_api_add_msg_name_crc (am, "lb_conf_56cd3261",
                                VL_API_LB_CONF + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lb_conf_reply_e8d4e804",
                                VL_API_LB_CONF_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lb_add_del_vip_6fa569c7",
                                VL_API_LB_ADD_DEL_VIP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lb_add_del_vip_reply_e8d4e804",
                                VL_API_LB_ADD_DEL_VIP_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lb_add_del_vip_v2_7c520e0f",
                                VL_API_LB_ADD_DEL_VIP_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lb_add_del_vip_v2_reply_e8d4e804",
                                VL_API_LB_ADD_DEL_VIP_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lb_add_del_as_35d72500",
                                VL_API_LB_ADD_DEL_AS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lb_add_del_as_reply_e8d4e804",
                                VL_API_LB_ADD_DEL_AS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lb_flush_vip_1063f819",
                                VL_API_LB_FLUSH_VIP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lb_flush_vip_reply_e8d4e804",
                                VL_API_LB_FLUSH_VIP_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lb_vip_dump_56110cb7",
                                VL_API_LB_VIP_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lb_vip_details_1329ec9b",
                                VL_API_LB_VIP_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lb_as_dump_1063f819",
                                VL_API_LB_AS_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lb_as_details_8d24c29e",
                                VL_API_LB_AS_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lb_add_del_intf_nat4_47d6e753",
                                VL_API_LB_ADD_DEL_INTF_NAT4 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lb_add_del_intf_nat4_reply_e8d4e804",
                                VL_API_LB_ADD_DEL_INTF_NAT4_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lb_add_del_intf_nat6_47d6e753",
                                VL_API_LB_ADD_DEL_INTF_NAT6 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lb_add_del_intf_nat6_reply_e8d4e804",
                                VL_API_LB_ADD_DEL_INTF_NAT6_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LB_CONF + msg_id_base,
   .name = "lb_conf",
   .handler = vl_api_lb_conf_t_handler,
   .endian = vl_api_lb_conf_t_endian,
   .format_fn = vl_api_lb_conf_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lb_conf_t_tojson,
   .fromjson = vl_api_lb_conf_t_fromjson,
   .calc_size = vl_api_lb_conf_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LB_CONF_REPLY + msg_id_base,
  .name = "lb_conf_reply",
  .handler = 0,
  .endian = vl_api_lb_conf_reply_t_endian,
  .format_fn = vl_api_lb_conf_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lb_conf_reply_t_tojson,
  .fromjson = vl_api_lb_conf_reply_t_fromjson,
  .calc_size = vl_api_lb_conf_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LB_ADD_DEL_VIP + msg_id_base,
   .name = "lb_add_del_vip",
   .handler = vl_api_lb_add_del_vip_t_handler,
   .endian = vl_api_lb_add_del_vip_t_endian,
   .format_fn = vl_api_lb_add_del_vip_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lb_add_del_vip_t_tojson,
   .fromjson = vl_api_lb_add_del_vip_t_fromjson,
   .calc_size = vl_api_lb_add_del_vip_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LB_ADD_DEL_VIP_REPLY + msg_id_base,
  .name = "lb_add_del_vip_reply",
  .handler = 0,
  .endian = vl_api_lb_add_del_vip_reply_t_endian,
  .format_fn = vl_api_lb_add_del_vip_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lb_add_del_vip_reply_t_tojson,
  .fromjson = vl_api_lb_add_del_vip_reply_t_fromjson,
  .calc_size = vl_api_lb_add_del_vip_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LB_ADD_DEL_VIP_V2 + msg_id_base,
   .name = "lb_add_del_vip_v2",
   .handler = vl_api_lb_add_del_vip_v2_t_handler,
   .endian = vl_api_lb_add_del_vip_v2_t_endian,
   .format_fn = vl_api_lb_add_del_vip_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lb_add_del_vip_v2_t_tojson,
   .fromjson = vl_api_lb_add_del_vip_v2_t_fromjson,
   .calc_size = vl_api_lb_add_del_vip_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LB_ADD_DEL_VIP_V2_REPLY + msg_id_base,
  .name = "lb_add_del_vip_v2_reply",
  .handler = 0,
  .endian = vl_api_lb_add_del_vip_v2_reply_t_endian,
  .format_fn = vl_api_lb_add_del_vip_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lb_add_del_vip_v2_reply_t_tojson,
  .fromjson = vl_api_lb_add_del_vip_v2_reply_t_fromjson,
  .calc_size = vl_api_lb_add_del_vip_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LB_ADD_DEL_AS + msg_id_base,
   .name = "lb_add_del_as",
   .handler = vl_api_lb_add_del_as_t_handler,
   .endian = vl_api_lb_add_del_as_t_endian,
   .format_fn = vl_api_lb_add_del_as_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lb_add_del_as_t_tojson,
   .fromjson = vl_api_lb_add_del_as_t_fromjson,
   .calc_size = vl_api_lb_add_del_as_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LB_ADD_DEL_AS_REPLY + msg_id_base,
  .name = "lb_add_del_as_reply",
  .handler = 0,
  .endian = vl_api_lb_add_del_as_reply_t_endian,
  .format_fn = vl_api_lb_add_del_as_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lb_add_del_as_reply_t_tojson,
  .fromjson = vl_api_lb_add_del_as_reply_t_fromjson,
  .calc_size = vl_api_lb_add_del_as_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LB_FLUSH_VIP + msg_id_base,
   .name = "lb_flush_vip",
   .handler = vl_api_lb_flush_vip_t_handler,
   .endian = vl_api_lb_flush_vip_t_endian,
   .format_fn = vl_api_lb_flush_vip_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lb_flush_vip_t_tojson,
   .fromjson = vl_api_lb_flush_vip_t_fromjson,
   .calc_size = vl_api_lb_flush_vip_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LB_FLUSH_VIP_REPLY + msg_id_base,
  .name = "lb_flush_vip_reply",
  .handler = 0,
  .endian = vl_api_lb_flush_vip_reply_t_endian,
  .format_fn = vl_api_lb_flush_vip_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lb_flush_vip_reply_t_tojson,
  .fromjson = vl_api_lb_flush_vip_reply_t_fromjson,
  .calc_size = vl_api_lb_flush_vip_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LB_VIP_DUMP + msg_id_base,
   .name = "lb_vip_dump",
   .handler = vl_api_lb_vip_dump_t_handler,
   .endian = vl_api_lb_vip_dump_t_endian,
   .format_fn = vl_api_lb_vip_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lb_vip_dump_t_tojson,
   .fromjson = vl_api_lb_vip_dump_t_fromjson,
   .calc_size = vl_api_lb_vip_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LB_VIP_DETAILS + msg_id_base,
  .name = "lb_vip_details",
  .handler = 0,
  .endian = vl_api_lb_vip_details_t_endian,
  .format_fn = vl_api_lb_vip_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lb_vip_details_t_tojson,
  .fromjson = vl_api_lb_vip_details_t_fromjson,
  .calc_size = vl_api_lb_vip_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LB_AS_DUMP + msg_id_base,
   .name = "lb_as_dump",
   .handler = vl_api_lb_as_dump_t_handler,
   .endian = vl_api_lb_as_dump_t_endian,
   .format_fn = vl_api_lb_as_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lb_as_dump_t_tojson,
   .fromjson = vl_api_lb_as_dump_t_fromjson,
   .calc_size = vl_api_lb_as_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LB_AS_DETAILS + msg_id_base,
  .name = "lb_as_details",
  .handler = 0,
  .endian = vl_api_lb_as_details_t_endian,
  .format_fn = vl_api_lb_as_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lb_as_details_t_tojson,
  .fromjson = vl_api_lb_as_details_t_fromjson,
  .calc_size = vl_api_lb_as_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LB_ADD_DEL_INTF_NAT4 + msg_id_base,
   .name = "lb_add_del_intf_nat4",
   .handler = vl_api_lb_add_del_intf_nat4_t_handler,
   .endian = vl_api_lb_add_del_intf_nat4_t_endian,
   .format_fn = vl_api_lb_add_del_intf_nat4_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lb_add_del_intf_nat4_t_tojson,
   .fromjson = vl_api_lb_add_del_intf_nat4_t_fromjson,
   .calc_size = vl_api_lb_add_del_intf_nat4_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LB_ADD_DEL_INTF_NAT4_REPLY + msg_id_base,
  .name = "lb_add_del_intf_nat4_reply",
  .handler = 0,
  .endian = vl_api_lb_add_del_intf_nat4_reply_t_endian,
  .format_fn = vl_api_lb_add_del_intf_nat4_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lb_add_del_intf_nat4_reply_t_tojson,
  .fromjson = vl_api_lb_add_del_intf_nat4_reply_t_fromjson,
  .calc_size = vl_api_lb_add_del_intf_nat4_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LB_ADD_DEL_INTF_NAT6 + msg_id_base,
   .name = "lb_add_del_intf_nat6",
   .handler = vl_api_lb_add_del_intf_nat6_t_handler,
   .endian = vl_api_lb_add_del_intf_nat6_t_endian,
   .format_fn = vl_api_lb_add_del_intf_nat6_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lb_add_del_intf_nat6_t_tojson,
   .fromjson = vl_api_lb_add_del_intf_nat6_t_fromjson,
   .calc_size = vl_api_lb_add_del_intf_nat6_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LB_ADD_DEL_INTF_NAT6_REPLY + msg_id_base,
  .name = "lb_add_del_intf_nat6_reply",
  .handler = 0,
  .endian = vl_api_lb_add_del_intf_nat6_reply_t_endian,
  .format_fn = vl_api_lb_add_del_intf_nat6_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lb_add_del_intf_nat6_reply_t_tojson,
  .fromjson = vl_api_lb_add_del_intf_nat6_reply_t_fromjson,
  .calc_size = vl_api_lb_add_del_intf_nat6_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
