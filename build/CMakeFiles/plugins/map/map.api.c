#define vl_endianfun		/* define message structures */
#include "map.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "map.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "map.api.h"
#undef vl_printfun

#include "map.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("map_8bf7a18a", VL_MSG_MAP_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_map);
   vl_msg_api_add_msg_name_crc (am, "map_add_domain_249f195c",
                                VL_API_MAP_ADD_DOMAIN + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "map_add_domain_reply_3e6d4e2c",
                                VL_API_MAP_ADD_DOMAIN_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "map_del_domain_8ac76db6",
                                VL_API_MAP_DEL_DOMAIN + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "map_del_domain_reply_e8d4e804",
                                VL_API_MAP_DEL_DOMAIN_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "map_add_del_rule_c65b32f7",
                                VL_API_MAP_ADD_DEL_RULE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "map_add_del_rule_reply_e8d4e804",
                                VL_API_MAP_ADD_DEL_RULE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "map_domains_get_f75ba505",
                                VL_API_MAP_DOMAINS_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "map_domains_get_reply_53b48f5d",
                                VL_API_MAP_DOMAINS_GET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "map_domain_dump_51077d14",
                                VL_API_MAP_DOMAIN_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "map_domain_details_796edb50",
                                VL_API_MAP_DOMAIN_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "map_rule_dump_e43e6ff6",
                                VL_API_MAP_RULE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "map_rule_details_c7cbeea5",
                                VL_API_MAP_RULE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "map_if_enable_disable_59bb32f4",
                                VL_API_MAP_IF_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "map_if_enable_disable_reply_e8d4e804",
                                VL_API_MAP_IF_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "map_summary_stats_51077d14",
                                VL_API_MAP_SUMMARY_STATS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "map_summary_stats_reply_0e4ace0e",
                                VL_API_MAP_SUMMARY_STATS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "map_param_set_fragmentation_9ff54d90",
                                VL_API_MAP_PARAM_SET_FRAGMENTATION + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "map_param_set_fragmentation_reply_e8d4e804",
                                VL_API_MAP_PARAM_SET_FRAGMENTATION_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "map_param_set_icmp_58210cbf",
                                VL_API_MAP_PARAM_SET_ICMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "map_param_set_icmp_reply_e8d4e804",
                                VL_API_MAP_PARAM_SET_ICMP_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "map_param_set_icmp6_5d01f8c1",
                                VL_API_MAP_PARAM_SET_ICMP6 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "map_param_set_icmp6_reply_e8d4e804",
                                VL_API_MAP_PARAM_SET_ICMP6_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "map_param_add_del_pre_resolve_dae5af03",
                                VL_API_MAP_PARAM_ADD_DEL_PRE_RESOLVE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "map_param_add_del_pre_resolve_reply_e8d4e804",
                                VL_API_MAP_PARAM_ADD_DEL_PRE_RESOLVE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "map_param_set_security_check_6abe9836",
                                VL_API_MAP_PARAM_SET_SECURITY_CHECK + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "map_param_set_security_check_reply_e8d4e804",
                                VL_API_MAP_PARAM_SET_SECURITY_CHECK_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "map_param_set_traffic_class_9cac455c",
                                VL_API_MAP_PARAM_SET_TRAFFIC_CLASS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "map_param_set_traffic_class_reply_e8d4e804",
                                VL_API_MAP_PARAM_SET_TRAFFIC_CLASS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "map_param_set_tcp_87a825d9",
                                VL_API_MAP_PARAM_SET_TCP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "map_param_set_tcp_reply_e8d4e804",
                                VL_API_MAP_PARAM_SET_TCP_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "map_param_get_51077d14",
                                VL_API_MAP_PARAM_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "map_param_get_reply_26272c90",
                                VL_API_MAP_PARAM_GET_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MAP_DOMAINS_GET + msg_id_base,
   .name = "map_domains_get",
   .handler = vl_api_map_domains_get_t_handler,
   .endian = vl_api_map_domains_get_t_endian,
   .format_fn = vl_api_map_domains_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_map_domains_get_t_tojson,
   .fromjson = vl_api_map_domains_get_t_fromjson,
   .calc_size = vl_api_map_domains_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MAP_DOMAINS_GET_REPLY + msg_id_base,
  .name = "map_domains_get_reply",
  .handler = 0,
  .endian = vl_api_map_domains_get_reply_t_endian,
  .format_fn = vl_api_map_domains_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_map_domains_get_reply_t_tojson,
  .fromjson = vl_api_map_domains_get_reply_t_fromjson,
  .calc_size = vl_api_map_domains_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MAP_DOMAIN_DETAILS + msg_id_base,
  .name = "map_domain_details",
  .handler = 0,
  .endian = vl_api_map_domain_details_t_endian,
  .format_fn = vl_api_map_domain_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_map_domain_details_t_tojson,
  .fromjson = vl_api_map_domain_details_t_fromjson,
  .calc_size = vl_api_map_domain_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MAP_ADD_DOMAIN + msg_id_base,
   .name = "map_add_domain",
   .handler = vl_api_map_add_domain_t_handler,
   .endian = vl_api_map_add_domain_t_endian,
   .format_fn = vl_api_map_add_domain_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_map_add_domain_t_tojson,
   .fromjson = vl_api_map_add_domain_t_fromjson,
   .calc_size = vl_api_map_add_domain_t_calc_size,
   .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MAP_ADD_DOMAIN_REPLY + msg_id_base,
  .name = "map_add_domain_reply",
  .handler = 0,
  .endian = vl_api_map_add_domain_reply_t_endian,
  .format_fn = vl_api_map_add_domain_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_map_add_domain_reply_t_tojson,
  .fromjson = vl_api_map_add_domain_reply_t_fromjson,
  .calc_size = vl_api_map_add_domain_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MAP_DEL_DOMAIN + msg_id_base,
   .name = "map_del_domain",
   .handler = vl_api_map_del_domain_t_handler,
   .endian = vl_api_map_del_domain_t_endian,
   .format_fn = vl_api_map_del_domain_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_map_del_domain_t_tojson,
   .fromjson = vl_api_map_del_domain_t_fromjson,
   .calc_size = vl_api_map_del_domain_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MAP_DEL_DOMAIN_REPLY + msg_id_base,
  .name = "map_del_domain_reply",
  .handler = 0,
  .endian = vl_api_map_del_domain_reply_t_endian,
  .format_fn = vl_api_map_del_domain_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_map_del_domain_reply_t_tojson,
  .fromjson = vl_api_map_del_domain_reply_t_fromjson,
  .calc_size = vl_api_map_del_domain_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MAP_ADD_DEL_RULE + msg_id_base,
   .name = "map_add_del_rule",
   .handler = vl_api_map_add_del_rule_t_handler,
   .endian = vl_api_map_add_del_rule_t_endian,
   .format_fn = vl_api_map_add_del_rule_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_map_add_del_rule_t_tojson,
   .fromjson = vl_api_map_add_del_rule_t_fromjson,
   .calc_size = vl_api_map_add_del_rule_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MAP_ADD_DEL_RULE_REPLY + msg_id_base,
  .name = "map_add_del_rule_reply",
  .handler = 0,
  .endian = vl_api_map_add_del_rule_reply_t_endian,
  .format_fn = vl_api_map_add_del_rule_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_map_add_del_rule_reply_t_tojson,
  .fromjson = vl_api_map_add_del_rule_reply_t_fromjson,
  .calc_size = vl_api_map_add_del_rule_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MAP_DOMAIN_DUMP + msg_id_base,
   .name = "map_domain_dump",
   .handler = vl_api_map_domain_dump_t_handler,
   .endian = vl_api_map_domain_dump_t_endian,
   .format_fn = vl_api_map_domain_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_map_domain_dump_t_tojson,
   .fromjson = vl_api_map_domain_dump_t_fromjson,
   .calc_size = vl_api_map_domain_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MAP_DOMAIN_DETAILS + msg_id_base,
  .name = "map_domain_details",
  .handler = 0,
  .endian = vl_api_map_domain_details_t_endian,
  .format_fn = vl_api_map_domain_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_map_domain_details_t_tojson,
  .fromjson = vl_api_map_domain_details_t_fromjson,
  .calc_size = vl_api_map_domain_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MAP_RULE_DUMP + msg_id_base,
   .name = "map_rule_dump",
   .handler = vl_api_map_rule_dump_t_handler,
   .endian = vl_api_map_rule_dump_t_endian,
   .format_fn = vl_api_map_rule_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_map_rule_dump_t_tojson,
   .fromjson = vl_api_map_rule_dump_t_fromjson,
   .calc_size = vl_api_map_rule_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MAP_RULE_DETAILS + msg_id_base,
  .name = "map_rule_details",
  .handler = 0,
  .endian = vl_api_map_rule_details_t_endian,
  .format_fn = vl_api_map_rule_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_map_rule_details_t_tojson,
  .fromjson = vl_api_map_rule_details_t_fromjson,
  .calc_size = vl_api_map_rule_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MAP_IF_ENABLE_DISABLE + msg_id_base,
   .name = "map_if_enable_disable",
   .handler = vl_api_map_if_enable_disable_t_handler,
   .endian = vl_api_map_if_enable_disable_t_endian,
   .format_fn = vl_api_map_if_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_map_if_enable_disable_t_tojson,
   .fromjson = vl_api_map_if_enable_disable_t_fromjson,
   .calc_size = vl_api_map_if_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MAP_IF_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "map_if_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_map_if_enable_disable_reply_t_endian,
  .format_fn = vl_api_map_if_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_map_if_enable_disable_reply_t_tojson,
  .fromjson = vl_api_map_if_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_map_if_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MAP_SUMMARY_STATS + msg_id_base,
   .name = "map_summary_stats",
   .handler = vl_api_map_summary_stats_t_handler,
   .endian = vl_api_map_summary_stats_t_endian,
   .format_fn = vl_api_map_summary_stats_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_map_summary_stats_t_tojson,
   .fromjson = vl_api_map_summary_stats_t_fromjson,
   .calc_size = vl_api_map_summary_stats_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MAP_SUMMARY_STATS_REPLY + msg_id_base,
  .name = "map_summary_stats_reply",
  .handler = 0,
  .endian = vl_api_map_summary_stats_reply_t_endian,
  .format_fn = vl_api_map_summary_stats_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_map_summary_stats_reply_t_tojson,
  .fromjson = vl_api_map_summary_stats_reply_t_fromjson,
  .calc_size = vl_api_map_summary_stats_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MAP_PARAM_SET_FRAGMENTATION + msg_id_base,
   .name = "map_param_set_fragmentation",
   .handler = vl_api_map_param_set_fragmentation_t_handler,
   .endian = vl_api_map_param_set_fragmentation_t_endian,
   .format_fn = vl_api_map_param_set_fragmentation_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_map_param_set_fragmentation_t_tojson,
   .fromjson = vl_api_map_param_set_fragmentation_t_fromjson,
   .calc_size = vl_api_map_param_set_fragmentation_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MAP_PARAM_SET_FRAGMENTATION_REPLY + msg_id_base,
  .name = "map_param_set_fragmentation_reply",
  .handler = 0,
  .endian = vl_api_map_param_set_fragmentation_reply_t_endian,
  .format_fn = vl_api_map_param_set_fragmentation_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_map_param_set_fragmentation_reply_t_tojson,
  .fromjson = vl_api_map_param_set_fragmentation_reply_t_fromjson,
  .calc_size = vl_api_map_param_set_fragmentation_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MAP_PARAM_SET_ICMP + msg_id_base,
   .name = "map_param_set_icmp",
   .handler = vl_api_map_param_set_icmp_t_handler,
   .endian = vl_api_map_param_set_icmp_t_endian,
   .format_fn = vl_api_map_param_set_icmp_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_map_param_set_icmp_t_tojson,
   .fromjson = vl_api_map_param_set_icmp_t_fromjson,
   .calc_size = vl_api_map_param_set_icmp_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MAP_PARAM_SET_ICMP_REPLY + msg_id_base,
  .name = "map_param_set_icmp_reply",
  .handler = 0,
  .endian = vl_api_map_param_set_icmp_reply_t_endian,
  .format_fn = vl_api_map_param_set_icmp_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_map_param_set_icmp_reply_t_tojson,
  .fromjson = vl_api_map_param_set_icmp_reply_t_fromjson,
  .calc_size = vl_api_map_param_set_icmp_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MAP_PARAM_SET_ICMP6 + msg_id_base,
   .name = "map_param_set_icmp6",
   .handler = vl_api_map_param_set_icmp6_t_handler,
   .endian = vl_api_map_param_set_icmp6_t_endian,
   .format_fn = vl_api_map_param_set_icmp6_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_map_param_set_icmp6_t_tojson,
   .fromjson = vl_api_map_param_set_icmp6_t_fromjson,
   .calc_size = vl_api_map_param_set_icmp6_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MAP_PARAM_SET_ICMP6_REPLY + msg_id_base,
  .name = "map_param_set_icmp6_reply",
  .handler = 0,
  .endian = vl_api_map_param_set_icmp6_reply_t_endian,
  .format_fn = vl_api_map_param_set_icmp6_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_map_param_set_icmp6_reply_t_tojson,
  .fromjson = vl_api_map_param_set_icmp6_reply_t_fromjson,
  .calc_size = vl_api_map_param_set_icmp6_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MAP_PARAM_ADD_DEL_PRE_RESOLVE + msg_id_base,
   .name = "map_param_add_del_pre_resolve",
   .handler = vl_api_map_param_add_del_pre_resolve_t_handler,
   .endian = vl_api_map_param_add_del_pre_resolve_t_endian,
   .format_fn = vl_api_map_param_add_del_pre_resolve_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_map_param_add_del_pre_resolve_t_tojson,
   .fromjson = vl_api_map_param_add_del_pre_resolve_t_fromjson,
   .calc_size = vl_api_map_param_add_del_pre_resolve_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MAP_PARAM_ADD_DEL_PRE_RESOLVE_REPLY + msg_id_base,
  .name = "map_param_add_del_pre_resolve_reply",
  .handler = 0,
  .endian = vl_api_map_param_add_del_pre_resolve_reply_t_endian,
  .format_fn = vl_api_map_param_add_del_pre_resolve_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_map_param_add_del_pre_resolve_reply_t_tojson,
  .fromjson = vl_api_map_param_add_del_pre_resolve_reply_t_fromjson,
  .calc_size = vl_api_map_param_add_del_pre_resolve_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MAP_PARAM_SET_SECURITY_CHECK + msg_id_base,
   .name = "map_param_set_security_check",
   .handler = vl_api_map_param_set_security_check_t_handler,
   .endian = vl_api_map_param_set_security_check_t_endian,
   .format_fn = vl_api_map_param_set_security_check_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_map_param_set_security_check_t_tojson,
   .fromjson = vl_api_map_param_set_security_check_t_fromjson,
   .calc_size = vl_api_map_param_set_security_check_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MAP_PARAM_SET_SECURITY_CHECK_REPLY + msg_id_base,
  .name = "map_param_set_security_check_reply",
  .handler = 0,
  .endian = vl_api_map_param_set_security_check_reply_t_endian,
  .format_fn = vl_api_map_param_set_security_check_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_map_param_set_security_check_reply_t_tojson,
  .fromjson = vl_api_map_param_set_security_check_reply_t_fromjson,
  .calc_size = vl_api_map_param_set_security_check_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MAP_PARAM_SET_TRAFFIC_CLASS + msg_id_base,
   .name = "map_param_set_traffic_class",
   .handler = vl_api_map_param_set_traffic_class_t_handler,
   .endian = vl_api_map_param_set_traffic_class_t_endian,
   .format_fn = vl_api_map_param_set_traffic_class_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_map_param_set_traffic_class_t_tojson,
   .fromjson = vl_api_map_param_set_traffic_class_t_fromjson,
   .calc_size = vl_api_map_param_set_traffic_class_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MAP_PARAM_SET_TRAFFIC_CLASS_REPLY + msg_id_base,
  .name = "map_param_set_traffic_class_reply",
  .handler = 0,
  .endian = vl_api_map_param_set_traffic_class_reply_t_endian,
  .format_fn = vl_api_map_param_set_traffic_class_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_map_param_set_traffic_class_reply_t_tojson,
  .fromjson = vl_api_map_param_set_traffic_class_reply_t_fromjson,
  .calc_size = vl_api_map_param_set_traffic_class_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MAP_PARAM_SET_TCP + msg_id_base,
   .name = "map_param_set_tcp",
   .handler = vl_api_map_param_set_tcp_t_handler,
   .endian = vl_api_map_param_set_tcp_t_endian,
   .format_fn = vl_api_map_param_set_tcp_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_map_param_set_tcp_t_tojson,
   .fromjson = vl_api_map_param_set_tcp_t_fromjson,
   .calc_size = vl_api_map_param_set_tcp_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MAP_PARAM_SET_TCP_REPLY + msg_id_base,
  .name = "map_param_set_tcp_reply",
  .handler = 0,
  .endian = vl_api_map_param_set_tcp_reply_t_endian,
  .format_fn = vl_api_map_param_set_tcp_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_map_param_set_tcp_reply_t_tojson,
  .fromjson = vl_api_map_param_set_tcp_reply_t_fromjson,
  .calc_size = vl_api_map_param_set_tcp_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MAP_PARAM_GET + msg_id_base,
   .name = "map_param_get",
   .handler = vl_api_map_param_get_t_handler,
   .endian = vl_api_map_param_get_t_endian,
   .format_fn = vl_api_map_param_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_map_param_get_t_tojson,
   .fromjson = vl_api_map_param_get_t_fromjson,
   .calc_size = vl_api_map_param_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MAP_PARAM_GET_REPLY + msg_id_base,
  .name = "map_param_get_reply",
  .handler = 0,
  .endian = vl_api_map_param_get_reply_t_endian,
  .format_fn = vl_api_map_param_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_map_param_get_reply_t_tojson,
  .fromjson = vl_api_map_param_get_reply_t_fromjson,
  .calc_size = vl_api_map_param_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
vlib_error_desc_t map_error_counters[] = {
  {
   .name = "none",
   .desc = "valid MAP packets",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "bad_protocol",
   .desc = "bad protocol",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "sec_check",
   .desc = "security check failed",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "encap_sec_check",
   .desc = "encap security check failed",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "decap_sec_check",
   .desc = "decap security check failed",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "icmp",
   .desc = "unable to translate ICMP",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "icmp_relay",
   .desc = "unable to relay ICMP",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "unknown",
   .desc = "unknown",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "no_binding",
   .desc = "no binding",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "no_domain",
   .desc = "no domain",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "fragmented",
   .desc = "packet is a fragment",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "fragment_memory",
   .desc = "could not cache fragment",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "fragment_malformed",
   .desc = "fragment has unexpected format",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "fragment_dropped",
   .desc = "dropped cached fragment",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "malformed",
   .desc = "malformed packet",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "df_set",
   .desc = "can't fragment, DF set",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "time_exceeded",
   .desc = "time exceeded",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
};
