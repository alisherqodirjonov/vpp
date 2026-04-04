#define vl_endianfun		/* define message structures */
#include "ip_neighbor.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "ip_neighbor.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "ip_neighbor.api.h"
#undef vl_printfun

#include "ip_neighbor.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("ip_neighbor_8bbbad7c", VL_MSG_IP_NEIGHBOR_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_ip_neighbor);
   vl_msg_api_add_msg_name_crc (am, "ip_neighbor_add_del_0607c257",
                                VL_API_IP_NEIGHBOR_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_neighbor_add_del_reply_1992deab",
                                VL_API_IP_NEIGHBOR_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_neighbor_dump_d817a484",
                                VL_API_IP_NEIGHBOR_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_neighbor_details_e29d79f0",
                                VL_API_IP_NEIGHBOR_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_neighbor_config_f4a5cf44",
                                VL_API_IP_NEIGHBOR_CONFIG + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_neighbor_config_reply_e8d4e804",
                                VL_API_IP_NEIGHBOR_CONFIG_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_neighbor_config_get_a5db7bf7",
                                VL_API_IP_NEIGHBOR_CONFIG_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_neighbor_config_get_reply_798e6fdd",
                                VL_API_IP_NEIGHBOR_CONFIG_GET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_neighbor_replace_begin_51077d14",
                                VL_API_IP_NEIGHBOR_REPLACE_BEGIN + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_neighbor_replace_begin_reply_e8d4e804",
                                VL_API_IP_NEIGHBOR_REPLACE_BEGIN_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_neighbor_replace_end_51077d14",
                                VL_API_IP_NEIGHBOR_REPLACE_END + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_neighbor_replace_end_reply_e8d4e804",
                                VL_API_IP_NEIGHBOR_REPLACE_END_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_neighbor_flush_16aa35d2",
                                VL_API_IP_NEIGHBOR_FLUSH + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_neighbor_flush_reply_e8d4e804",
                                VL_API_IP_NEIGHBOR_FLUSH_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "want_ip_neighbor_events_73e70a86",
                                VL_API_WANT_IP_NEIGHBOR_EVENTS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "want_ip_neighbor_events_reply_e8d4e804",
                                VL_API_WANT_IP_NEIGHBOR_EVENTS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_neighbor_event_bdb092b2",
                                VL_API_IP_NEIGHBOR_EVENT + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "want_ip_neighbor_events_v2_73e70a86",
                                VL_API_WANT_IP_NEIGHBOR_EVENTS_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "want_ip_neighbor_events_v2_reply_e8d4e804",
                                VL_API_WANT_IP_NEIGHBOR_EVENTS_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_neighbor_event_v2_c1d53dc0",
                                VL_API_IP_NEIGHBOR_EVENT_V2 + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_WANT_IP_NEIGHBOR_EVENTS + msg_id_base,
   .name = "want_ip_neighbor_events",
   .handler = vl_api_want_ip_neighbor_events_t_handler,
   .endian = vl_api_want_ip_neighbor_events_t_endian,
   .format_fn = vl_api_want_ip_neighbor_events_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_want_ip_neighbor_events_t_tojson,
   .fromjson = vl_api_want_ip_neighbor_events_t_fromjson,
   .calc_size = vl_api_want_ip_neighbor_events_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_WANT_IP_NEIGHBOR_EVENTS_REPLY + msg_id_base,
  .name = "want_ip_neighbor_events_reply",
  .handler = 0,
  .endian = vl_api_want_ip_neighbor_events_reply_t_endian,
  .format_fn = vl_api_want_ip_neighbor_events_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_want_ip_neighbor_events_reply_t_tojson,
  .fromjson = vl_api_want_ip_neighbor_events_reply_t_fromjson,
  .calc_size = vl_api_want_ip_neighbor_events_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_WANT_IP_NEIGHBOR_EVENTS_V2 + msg_id_base,
   .name = "want_ip_neighbor_events_v2",
   .handler = vl_api_want_ip_neighbor_events_v2_t_handler,
   .endian = vl_api_want_ip_neighbor_events_v2_t_endian,
   .format_fn = vl_api_want_ip_neighbor_events_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_want_ip_neighbor_events_v2_t_tojson,
   .fromjson = vl_api_want_ip_neighbor_events_v2_t_fromjson,
   .calc_size = vl_api_want_ip_neighbor_events_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_WANT_IP_NEIGHBOR_EVENTS_V2_REPLY + msg_id_base,
  .name = "want_ip_neighbor_events_v2_reply",
  .handler = 0,
  .endian = vl_api_want_ip_neighbor_events_v2_reply_t_endian,
  .format_fn = vl_api_want_ip_neighbor_events_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_want_ip_neighbor_events_v2_reply_t_tojson,
  .fromjson = vl_api_want_ip_neighbor_events_v2_reply_t_fromjson,
  .calc_size = vl_api_want_ip_neighbor_events_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_NEIGHBOR_ADD_DEL + msg_id_base,
   .name = "ip_neighbor_add_del",
   .handler = vl_api_ip_neighbor_add_del_t_handler,
   .endian = vl_api_ip_neighbor_add_del_t_endian,
   .format_fn = vl_api_ip_neighbor_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_neighbor_add_del_t_tojson,
   .fromjson = vl_api_ip_neighbor_add_del_t_fromjson,
   .calc_size = vl_api_ip_neighbor_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_NEIGHBOR_ADD_DEL_REPLY + msg_id_base,
  .name = "ip_neighbor_add_del_reply",
  .handler = 0,
  .endian = vl_api_ip_neighbor_add_del_reply_t_endian,
  .format_fn = vl_api_ip_neighbor_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_neighbor_add_del_reply_t_tojson,
  .fromjson = vl_api_ip_neighbor_add_del_reply_t_fromjson,
  .calc_size = vl_api_ip_neighbor_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_NEIGHBOR_DUMP + msg_id_base,
   .name = "ip_neighbor_dump",
   .handler = vl_api_ip_neighbor_dump_t_handler,
   .endian = vl_api_ip_neighbor_dump_t_endian,
   .format_fn = vl_api_ip_neighbor_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_neighbor_dump_t_tojson,
   .fromjson = vl_api_ip_neighbor_dump_t_fromjson,
   .calc_size = vl_api_ip_neighbor_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_NEIGHBOR_DETAILS + msg_id_base,
  .name = "ip_neighbor_details",
  .handler = 0,
  .endian = vl_api_ip_neighbor_details_t_endian,
  .format_fn = vl_api_ip_neighbor_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_neighbor_details_t_tojson,
  .fromjson = vl_api_ip_neighbor_details_t_fromjson,
  .calc_size = vl_api_ip_neighbor_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_NEIGHBOR_CONFIG + msg_id_base,
   .name = "ip_neighbor_config",
   .handler = vl_api_ip_neighbor_config_t_handler,
   .endian = vl_api_ip_neighbor_config_t_endian,
   .format_fn = vl_api_ip_neighbor_config_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_neighbor_config_t_tojson,
   .fromjson = vl_api_ip_neighbor_config_t_fromjson,
   .calc_size = vl_api_ip_neighbor_config_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_NEIGHBOR_CONFIG_REPLY + msg_id_base,
  .name = "ip_neighbor_config_reply",
  .handler = 0,
  .endian = vl_api_ip_neighbor_config_reply_t_endian,
  .format_fn = vl_api_ip_neighbor_config_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_neighbor_config_reply_t_tojson,
  .fromjson = vl_api_ip_neighbor_config_reply_t_fromjson,
  .calc_size = vl_api_ip_neighbor_config_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_NEIGHBOR_CONFIG_GET + msg_id_base,
   .name = "ip_neighbor_config_get",
   .handler = vl_api_ip_neighbor_config_get_t_handler,
   .endian = vl_api_ip_neighbor_config_get_t_endian,
   .format_fn = vl_api_ip_neighbor_config_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_neighbor_config_get_t_tojson,
   .fromjson = vl_api_ip_neighbor_config_get_t_fromjson,
   .calc_size = vl_api_ip_neighbor_config_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_NEIGHBOR_CONFIG_GET_REPLY + msg_id_base,
  .name = "ip_neighbor_config_get_reply",
  .handler = 0,
  .endian = vl_api_ip_neighbor_config_get_reply_t_endian,
  .format_fn = vl_api_ip_neighbor_config_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_neighbor_config_get_reply_t_tojson,
  .fromjson = vl_api_ip_neighbor_config_get_reply_t_fromjson,
  .calc_size = vl_api_ip_neighbor_config_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_NEIGHBOR_REPLACE_BEGIN + msg_id_base,
   .name = "ip_neighbor_replace_begin",
   .handler = vl_api_ip_neighbor_replace_begin_t_handler,
   .endian = vl_api_ip_neighbor_replace_begin_t_endian,
   .format_fn = vl_api_ip_neighbor_replace_begin_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_neighbor_replace_begin_t_tojson,
   .fromjson = vl_api_ip_neighbor_replace_begin_t_fromjson,
   .calc_size = vl_api_ip_neighbor_replace_begin_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_NEIGHBOR_REPLACE_BEGIN_REPLY + msg_id_base,
  .name = "ip_neighbor_replace_begin_reply",
  .handler = 0,
  .endian = vl_api_ip_neighbor_replace_begin_reply_t_endian,
  .format_fn = vl_api_ip_neighbor_replace_begin_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_neighbor_replace_begin_reply_t_tojson,
  .fromjson = vl_api_ip_neighbor_replace_begin_reply_t_fromjson,
  .calc_size = vl_api_ip_neighbor_replace_begin_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_NEIGHBOR_REPLACE_END + msg_id_base,
   .name = "ip_neighbor_replace_end",
   .handler = vl_api_ip_neighbor_replace_end_t_handler,
   .endian = vl_api_ip_neighbor_replace_end_t_endian,
   .format_fn = vl_api_ip_neighbor_replace_end_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_neighbor_replace_end_t_tojson,
   .fromjson = vl_api_ip_neighbor_replace_end_t_fromjson,
   .calc_size = vl_api_ip_neighbor_replace_end_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_NEIGHBOR_REPLACE_END_REPLY + msg_id_base,
  .name = "ip_neighbor_replace_end_reply",
  .handler = 0,
  .endian = vl_api_ip_neighbor_replace_end_reply_t_endian,
  .format_fn = vl_api_ip_neighbor_replace_end_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_neighbor_replace_end_reply_t_tojson,
  .fromjson = vl_api_ip_neighbor_replace_end_reply_t_fromjson,
  .calc_size = vl_api_ip_neighbor_replace_end_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_NEIGHBOR_FLUSH + msg_id_base,
   .name = "ip_neighbor_flush",
   .handler = vl_api_ip_neighbor_flush_t_handler,
   .endian = vl_api_ip_neighbor_flush_t_endian,
   .format_fn = vl_api_ip_neighbor_flush_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_neighbor_flush_t_tojson,
   .fromjson = vl_api_ip_neighbor_flush_t_fromjson,
   .calc_size = vl_api_ip_neighbor_flush_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_NEIGHBOR_FLUSH_REPLY + msg_id_base,
  .name = "ip_neighbor_flush_reply",
  .handler = 0,
  .endian = vl_api_ip_neighbor_flush_reply_t_endian,
  .format_fn = vl_api_ip_neighbor_flush_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_neighbor_flush_reply_t_tojson,
  .fromjson = vl_api_ip_neighbor_flush_reply_t_fromjson,
  .calc_size = vl_api_ip_neighbor_flush_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
vlib_error_desc_t ip4_neighbor_error_counters[] = {
  {
   .name = "throttled",
   .desc = "ARP requests throttled",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "resolved",
   .desc = "ARP requests resolved",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "no_buffers",
   .desc = "ARP requests out of buffer",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "request_sent",
   .desc = "ARP requests sent",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "non_arp_adj",
   .desc = "ARPs to non-ARP adjacencies",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "no_source_address",
   .desc = "no source address for ARP request",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
};
vlib_error_desc_t ip6_neighbor_error_counters[] = {
  {
   .name = "throttled",
   .desc = "throttled",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "drop",
   .desc = "address overflow drops",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "request_sent",
   .desc = "neighbor solicitations sent",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "no_source_address",
   .desc = "no source address for ND solicitation",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "no_buffers",
   .desc = "no buffers",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
};
