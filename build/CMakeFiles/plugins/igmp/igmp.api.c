#define vl_endianfun		/* define message structures */
#include "igmp.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "igmp.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "igmp.api.h"
#undef vl_printfun

#include "igmp.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("igmp_2fd2bd5e", VL_MSG_IGMP_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_igmp);
   vl_msg_api_add_msg_name_crc (am, "igmp_listen_19a49f1e",
                                VL_API_IGMP_LISTEN + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "igmp_listen_reply_e8d4e804",
                                VL_API_IGMP_LISTEN_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "igmp_enable_disable_b1edfb96",
                                VL_API_IGMP_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "igmp_enable_disable_reply_e8d4e804",
                                VL_API_IGMP_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "igmp_proxy_device_add_del_0b9be9ce",
                                VL_API_IGMP_PROXY_DEVICE_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "igmp_proxy_device_add_del_reply_e8d4e804",
                                VL_API_IGMP_PROXY_DEVICE_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "igmp_proxy_device_add_del_interface_1a9ec24a",
                                VL_API_IGMP_PROXY_DEVICE_ADD_DEL_INTERFACE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "igmp_proxy_device_add_del_interface_reply_e8d4e804",
                                VL_API_IGMP_PROXY_DEVICE_ADD_DEL_INTERFACE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "igmp_dump_f9e6675e",
                                VL_API_IGMP_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "igmp_details_38f09929",
                                VL_API_IGMP_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "igmp_clear_interface_f9e6675e",
                                VL_API_IGMP_CLEAR_INTERFACE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "igmp_clear_interface_reply_e8d4e804",
                                VL_API_IGMP_CLEAR_INTERFACE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "want_igmp_events_cfaccc1f",
                                VL_API_WANT_IGMP_EVENTS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "want_igmp_events_reply_e8d4e804",
                                VL_API_WANT_IGMP_EVENTS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "igmp_event_85fe93ec",
                                VL_API_IGMP_EVENT + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "igmp_group_prefix_set_5b14a5ce",
                                VL_API_IGMP_GROUP_PREFIX_SET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "igmp_group_prefix_set_reply_e8d4e804",
                                VL_API_IGMP_GROUP_PREFIX_SET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "igmp_group_prefix_dump_51077d14",
                                VL_API_IGMP_GROUP_PREFIX_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "igmp_group_prefix_details_259ccd81",
                                VL_API_IGMP_GROUP_PREFIX_DETAILS + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_WANT_IGMP_EVENTS + msg_id_base,
   .name = "want_igmp_events",
   .handler = vl_api_want_igmp_events_t_handler,
   .endian = vl_api_want_igmp_events_t_endian,
   .format_fn = vl_api_want_igmp_events_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_want_igmp_events_t_tojson,
   .fromjson = vl_api_want_igmp_events_t_fromjson,
   .calc_size = vl_api_want_igmp_events_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_WANT_IGMP_EVENTS_REPLY + msg_id_base,
  .name = "want_igmp_events_reply",
  .handler = 0,
  .endian = vl_api_want_igmp_events_reply_t_endian,
  .format_fn = vl_api_want_igmp_events_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_want_igmp_events_reply_t_tojson,
  .fromjson = vl_api_want_igmp_events_reply_t_fromjson,
  .calc_size = vl_api_want_igmp_events_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IGMP_LISTEN + msg_id_base,
   .name = "igmp_listen",
   .handler = vl_api_igmp_listen_t_handler,
   .endian = vl_api_igmp_listen_t_endian,
   .format_fn = vl_api_igmp_listen_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_igmp_listen_t_tojson,
   .fromjson = vl_api_igmp_listen_t_fromjson,
   .calc_size = vl_api_igmp_listen_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IGMP_LISTEN_REPLY + msg_id_base,
  .name = "igmp_listen_reply",
  .handler = 0,
  .endian = vl_api_igmp_listen_reply_t_endian,
  .format_fn = vl_api_igmp_listen_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_igmp_listen_reply_t_tojson,
  .fromjson = vl_api_igmp_listen_reply_t_fromjson,
  .calc_size = vl_api_igmp_listen_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IGMP_ENABLE_DISABLE + msg_id_base,
   .name = "igmp_enable_disable",
   .handler = vl_api_igmp_enable_disable_t_handler,
   .endian = vl_api_igmp_enable_disable_t_endian,
   .format_fn = vl_api_igmp_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_igmp_enable_disable_t_tojson,
   .fromjson = vl_api_igmp_enable_disable_t_fromjson,
   .calc_size = vl_api_igmp_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IGMP_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "igmp_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_igmp_enable_disable_reply_t_endian,
  .format_fn = vl_api_igmp_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_igmp_enable_disable_reply_t_tojson,
  .fromjson = vl_api_igmp_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_igmp_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IGMP_PROXY_DEVICE_ADD_DEL + msg_id_base,
   .name = "igmp_proxy_device_add_del",
   .handler = vl_api_igmp_proxy_device_add_del_t_handler,
   .endian = vl_api_igmp_proxy_device_add_del_t_endian,
   .format_fn = vl_api_igmp_proxy_device_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_igmp_proxy_device_add_del_t_tojson,
   .fromjson = vl_api_igmp_proxy_device_add_del_t_fromjson,
   .calc_size = vl_api_igmp_proxy_device_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IGMP_PROXY_DEVICE_ADD_DEL_REPLY + msg_id_base,
  .name = "igmp_proxy_device_add_del_reply",
  .handler = 0,
  .endian = vl_api_igmp_proxy_device_add_del_reply_t_endian,
  .format_fn = vl_api_igmp_proxy_device_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_igmp_proxy_device_add_del_reply_t_tojson,
  .fromjson = vl_api_igmp_proxy_device_add_del_reply_t_fromjson,
  .calc_size = vl_api_igmp_proxy_device_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IGMP_PROXY_DEVICE_ADD_DEL_INTERFACE + msg_id_base,
   .name = "igmp_proxy_device_add_del_interface",
   .handler = vl_api_igmp_proxy_device_add_del_interface_t_handler,
   .endian = vl_api_igmp_proxy_device_add_del_interface_t_endian,
   .format_fn = vl_api_igmp_proxy_device_add_del_interface_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_igmp_proxy_device_add_del_interface_t_tojson,
   .fromjson = vl_api_igmp_proxy_device_add_del_interface_t_fromjson,
   .calc_size = vl_api_igmp_proxy_device_add_del_interface_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IGMP_PROXY_DEVICE_ADD_DEL_INTERFACE_REPLY + msg_id_base,
  .name = "igmp_proxy_device_add_del_interface_reply",
  .handler = 0,
  .endian = vl_api_igmp_proxy_device_add_del_interface_reply_t_endian,
  .format_fn = vl_api_igmp_proxy_device_add_del_interface_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_igmp_proxy_device_add_del_interface_reply_t_tojson,
  .fromjson = vl_api_igmp_proxy_device_add_del_interface_reply_t_fromjson,
  .calc_size = vl_api_igmp_proxy_device_add_del_interface_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IGMP_DUMP + msg_id_base,
   .name = "igmp_dump",
   .handler = vl_api_igmp_dump_t_handler,
   .endian = vl_api_igmp_dump_t_endian,
   .format_fn = vl_api_igmp_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_igmp_dump_t_tojson,
   .fromjson = vl_api_igmp_dump_t_fromjson,
   .calc_size = vl_api_igmp_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IGMP_DETAILS + msg_id_base,
  .name = "igmp_details",
  .handler = 0,
  .endian = vl_api_igmp_details_t_endian,
  .format_fn = vl_api_igmp_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_igmp_details_t_tojson,
  .fromjson = vl_api_igmp_details_t_fromjson,
  .calc_size = vl_api_igmp_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IGMP_CLEAR_INTERFACE + msg_id_base,
   .name = "igmp_clear_interface",
   .handler = vl_api_igmp_clear_interface_t_handler,
   .endian = vl_api_igmp_clear_interface_t_endian,
   .format_fn = vl_api_igmp_clear_interface_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_igmp_clear_interface_t_tojson,
   .fromjson = vl_api_igmp_clear_interface_t_fromjson,
   .calc_size = vl_api_igmp_clear_interface_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IGMP_CLEAR_INTERFACE_REPLY + msg_id_base,
  .name = "igmp_clear_interface_reply",
  .handler = 0,
  .endian = vl_api_igmp_clear_interface_reply_t_endian,
  .format_fn = vl_api_igmp_clear_interface_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_igmp_clear_interface_reply_t_tojson,
  .fromjson = vl_api_igmp_clear_interface_reply_t_fromjson,
  .calc_size = vl_api_igmp_clear_interface_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IGMP_GROUP_PREFIX_SET + msg_id_base,
   .name = "igmp_group_prefix_set",
   .handler = vl_api_igmp_group_prefix_set_t_handler,
   .endian = vl_api_igmp_group_prefix_set_t_endian,
   .format_fn = vl_api_igmp_group_prefix_set_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_igmp_group_prefix_set_t_tojson,
   .fromjson = vl_api_igmp_group_prefix_set_t_fromjson,
   .calc_size = vl_api_igmp_group_prefix_set_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IGMP_GROUP_PREFIX_SET_REPLY + msg_id_base,
  .name = "igmp_group_prefix_set_reply",
  .handler = 0,
  .endian = vl_api_igmp_group_prefix_set_reply_t_endian,
  .format_fn = vl_api_igmp_group_prefix_set_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_igmp_group_prefix_set_reply_t_tojson,
  .fromjson = vl_api_igmp_group_prefix_set_reply_t_fromjson,
  .calc_size = vl_api_igmp_group_prefix_set_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IGMP_GROUP_PREFIX_DUMP + msg_id_base,
   .name = "igmp_group_prefix_dump",
   .handler = vl_api_igmp_group_prefix_dump_t_handler,
   .endian = vl_api_igmp_group_prefix_dump_t_endian,
   .format_fn = vl_api_igmp_group_prefix_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_igmp_group_prefix_dump_t_tojson,
   .fromjson = vl_api_igmp_group_prefix_dump_t_fromjson,
   .calc_size = vl_api_igmp_group_prefix_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IGMP_GROUP_PREFIX_DETAILS + msg_id_base,
  .name = "igmp_group_prefix_details",
  .handler = 0,
  .endian = vl_api_igmp_group_prefix_details_t_endian,
  .format_fn = vl_api_igmp_group_prefix_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_igmp_group_prefix_details_t_tojson,
  .fromjson = vl_api_igmp_group_prefix_details_t_fromjson,
  .calc_size = vl_api_igmp_group_prefix_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
