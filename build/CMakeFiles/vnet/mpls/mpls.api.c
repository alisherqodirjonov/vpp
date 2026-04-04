#define vl_endianfun		/* define message structures */
#include "mpls.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "mpls.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "mpls.api.h"
#undef vl_printfun

#include "mpls.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("mpls_85e5987f", VL_MSG_MPLS_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_mpls);
   vl_msg_api_add_msg_name_crc (am, "mpls_ip_bind_unbind_c7533b32",
                                VL_API_MPLS_IP_BIND_UNBIND + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "mpls_ip_bind_unbind_reply_e8d4e804",
                                VL_API_MPLS_IP_BIND_UNBIND_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "mpls_tunnel_add_del_44350ac1",
                                VL_API_MPLS_TUNNEL_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "mpls_tunnel_add_del_reply_afb01472",
                                VL_API_MPLS_TUNNEL_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "mpls_tunnel_dump_f9e6675e",
                                VL_API_MPLS_TUNNEL_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "mpls_tunnel_details_57118ae3",
                                VL_API_MPLS_TUNNEL_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "mpls_interface_dump_f9e6675e",
                                VL_API_MPLS_INTERFACE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "mpls_interface_details_0b45011c",
                                VL_API_MPLS_INTERFACE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "mpls_table_add_del_57817512",
                                VL_API_MPLS_TABLE_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "mpls_table_add_del_reply_e8d4e804",
                                VL_API_MPLS_TABLE_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "mpls_table_dump_51077d14",
                                VL_API_MPLS_TABLE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "mpls_table_details_f03ecdc8",
                                VL_API_MPLS_TABLE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "mpls_route_add_del_8e1d1e07",
                                VL_API_MPLS_ROUTE_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "mpls_route_add_del_reply_1992deab",
                                VL_API_MPLS_ROUTE_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "mpls_route_dump_935fdefa",
                                VL_API_MPLS_ROUTE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "mpls_route_details_9b5043dc",
                                VL_API_MPLS_ROUTE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_mpls_enable_ae6cfcfb",
                                VL_API_SW_INTERFACE_SET_MPLS_ENABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_mpls_enable_reply_e8d4e804",
                                VL_API_SW_INTERFACE_SET_MPLS_ENABLE_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MPLS_IP_BIND_UNBIND + msg_id_base,
   .name = "mpls_ip_bind_unbind",
   .handler = vl_api_mpls_ip_bind_unbind_t_handler,
   .endian = vl_api_mpls_ip_bind_unbind_t_endian,
   .format_fn = vl_api_mpls_ip_bind_unbind_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_mpls_ip_bind_unbind_t_tojson,
   .fromjson = vl_api_mpls_ip_bind_unbind_t_fromjson,
   .calc_size = vl_api_mpls_ip_bind_unbind_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MPLS_IP_BIND_UNBIND_REPLY + msg_id_base,
  .name = "mpls_ip_bind_unbind_reply",
  .handler = 0,
  .endian = vl_api_mpls_ip_bind_unbind_reply_t_endian,
  .format_fn = vl_api_mpls_ip_bind_unbind_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_mpls_ip_bind_unbind_reply_t_tojson,
  .fromjson = vl_api_mpls_ip_bind_unbind_reply_t_fromjson,
  .calc_size = vl_api_mpls_ip_bind_unbind_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MPLS_TUNNEL_ADD_DEL + msg_id_base,
   .name = "mpls_tunnel_add_del",
   .handler = vl_api_mpls_tunnel_add_del_t_handler,
   .endian = vl_api_mpls_tunnel_add_del_t_endian,
   .format_fn = vl_api_mpls_tunnel_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_mpls_tunnel_add_del_t_tojson,
   .fromjson = vl_api_mpls_tunnel_add_del_t_fromjson,
   .calc_size = vl_api_mpls_tunnel_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MPLS_TUNNEL_ADD_DEL_REPLY + msg_id_base,
  .name = "mpls_tunnel_add_del_reply",
  .handler = 0,
  .endian = vl_api_mpls_tunnel_add_del_reply_t_endian,
  .format_fn = vl_api_mpls_tunnel_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_mpls_tunnel_add_del_reply_t_tojson,
  .fromjson = vl_api_mpls_tunnel_add_del_reply_t_fromjson,
  .calc_size = vl_api_mpls_tunnel_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MPLS_TUNNEL_DUMP + msg_id_base,
   .name = "mpls_tunnel_dump",
   .handler = vl_api_mpls_tunnel_dump_t_handler,
   .endian = vl_api_mpls_tunnel_dump_t_endian,
   .format_fn = vl_api_mpls_tunnel_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_mpls_tunnel_dump_t_tojson,
   .fromjson = vl_api_mpls_tunnel_dump_t_fromjson,
   .calc_size = vl_api_mpls_tunnel_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MPLS_TUNNEL_DETAILS + msg_id_base,
  .name = "mpls_tunnel_details",
  .handler = 0,
  .endian = vl_api_mpls_tunnel_details_t_endian,
  .format_fn = vl_api_mpls_tunnel_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_mpls_tunnel_details_t_tojson,
  .fromjson = vl_api_mpls_tunnel_details_t_fromjson,
  .calc_size = vl_api_mpls_tunnel_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MPLS_INTERFACE_DUMP + msg_id_base,
   .name = "mpls_interface_dump",
   .handler = vl_api_mpls_interface_dump_t_handler,
   .endian = vl_api_mpls_interface_dump_t_endian,
   .format_fn = vl_api_mpls_interface_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_mpls_interface_dump_t_tojson,
   .fromjson = vl_api_mpls_interface_dump_t_fromjson,
   .calc_size = vl_api_mpls_interface_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MPLS_INTERFACE_DETAILS + msg_id_base,
  .name = "mpls_interface_details",
  .handler = 0,
  .endian = vl_api_mpls_interface_details_t_endian,
  .format_fn = vl_api_mpls_interface_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_mpls_interface_details_t_tojson,
  .fromjson = vl_api_mpls_interface_details_t_fromjson,
  .calc_size = vl_api_mpls_interface_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MPLS_TABLE_ADD_DEL + msg_id_base,
   .name = "mpls_table_add_del",
   .handler = vl_api_mpls_table_add_del_t_handler,
   .endian = vl_api_mpls_table_add_del_t_endian,
   .format_fn = vl_api_mpls_table_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_mpls_table_add_del_t_tojson,
   .fromjson = vl_api_mpls_table_add_del_t_fromjson,
   .calc_size = vl_api_mpls_table_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MPLS_TABLE_ADD_DEL_REPLY + msg_id_base,
  .name = "mpls_table_add_del_reply",
  .handler = 0,
  .endian = vl_api_mpls_table_add_del_reply_t_endian,
  .format_fn = vl_api_mpls_table_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_mpls_table_add_del_reply_t_tojson,
  .fromjson = vl_api_mpls_table_add_del_reply_t_fromjson,
  .calc_size = vl_api_mpls_table_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MPLS_TABLE_DUMP + msg_id_base,
   .name = "mpls_table_dump",
   .handler = vl_api_mpls_table_dump_t_handler,
   .endian = vl_api_mpls_table_dump_t_endian,
   .format_fn = vl_api_mpls_table_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_mpls_table_dump_t_tojson,
   .fromjson = vl_api_mpls_table_dump_t_fromjson,
   .calc_size = vl_api_mpls_table_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MPLS_TABLE_DETAILS + msg_id_base,
  .name = "mpls_table_details",
  .handler = 0,
  .endian = vl_api_mpls_table_details_t_endian,
  .format_fn = vl_api_mpls_table_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_mpls_table_details_t_tojson,
  .fromjson = vl_api_mpls_table_details_t_fromjson,
  .calc_size = vl_api_mpls_table_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MPLS_ROUTE_ADD_DEL + msg_id_base,
   .name = "mpls_route_add_del",
   .handler = vl_api_mpls_route_add_del_t_handler,
   .endian = vl_api_mpls_route_add_del_t_endian,
   .format_fn = vl_api_mpls_route_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_mpls_route_add_del_t_tojson,
   .fromjson = vl_api_mpls_route_add_del_t_fromjson,
   .calc_size = vl_api_mpls_route_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MPLS_ROUTE_ADD_DEL_REPLY + msg_id_base,
  .name = "mpls_route_add_del_reply",
  .handler = 0,
  .endian = vl_api_mpls_route_add_del_reply_t_endian,
  .format_fn = vl_api_mpls_route_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_mpls_route_add_del_reply_t_tojson,
  .fromjson = vl_api_mpls_route_add_del_reply_t_fromjson,
  .calc_size = vl_api_mpls_route_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MPLS_ROUTE_DUMP + msg_id_base,
   .name = "mpls_route_dump",
   .handler = vl_api_mpls_route_dump_t_handler,
   .endian = vl_api_mpls_route_dump_t_endian,
   .format_fn = vl_api_mpls_route_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_mpls_route_dump_t_tojson,
   .fromjson = vl_api_mpls_route_dump_t_fromjson,
   .calc_size = vl_api_mpls_route_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MPLS_ROUTE_DETAILS + msg_id_base,
  .name = "mpls_route_details",
  .handler = 0,
  .endian = vl_api_mpls_route_details_t_endian,
  .format_fn = vl_api_mpls_route_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_mpls_route_details_t_tojson,
  .fromjson = vl_api_mpls_route_details_t_fromjson,
  .calc_size = vl_api_mpls_route_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_SET_MPLS_ENABLE + msg_id_base,
   .name = "sw_interface_set_mpls_enable",
   .handler = vl_api_sw_interface_set_mpls_enable_t_handler,
   .endian = vl_api_sw_interface_set_mpls_enable_t_endian,
   .format_fn = vl_api_sw_interface_set_mpls_enable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_set_mpls_enable_t_tojson,
   .fromjson = vl_api_sw_interface_set_mpls_enable_t_fromjson,
   .calc_size = vl_api_sw_interface_set_mpls_enable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_SET_MPLS_ENABLE_REPLY + msg_id_base,
  .name = "sw_interface_set_mpls_enable_reply",
  .handler = 0,
  .endian = vl_api_sw_interface_set_mpls_enable_reply_t_endian,
  .format_fn = vl_api_sw_interface_set_mpls_enable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_set_mpls_enable_reply_t_tojson,
  .fromjson = vl_api_sw_interface_set_mpls_enable_reply_t_fromjson,
  .calc_size = vl_api_sw_interface_set_mpls_enable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
vlib_error_desc_t mpls_error_counters[] = {
  {
   .name = "none",
   .desc = "no error",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "unknown_protocol",
   .desc = "unknown protocol",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "unsupported_version",
   .desc = "unsupported version",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "pkts_decap",
   .desc = "MPLS input packets decapsulated",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "pkts_encap",
   .desc = "MPLS output packets encapsulated",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "pkts_need_frag",
   .desc = "MPLS output packets needs fragmentation",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "no_label",
   .desc = "MPLS no label for fib/dst",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "ttl_expired",
   .desc = "MPLS ttl expired",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "s_not_set",
   .desc = "MPLS s-bit not set",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "bad_label",
   .desc = "invalid FIB id in label",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "not_ip4",
   .desc = "non-ip4 packets dropped",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "disallowed_fib",
   .desc = "disallowed FIB id",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "not_enabled",
   .desc = "MPLS not enabled",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "drop",
   .desc = "MPLS DROP DPO",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "punt",
   .desc = "MPLS PUNT DPO",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
};
