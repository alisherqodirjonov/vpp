#define vl_endianfun		/* define message structures */
#include "arp.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "arp.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "arp.api.h"
#undef vl_printfun

#include "arp.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("arp_cfdf7292", VL_MSG_ARP_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_arp);
   vl_msg_api_add_msg_name_crc (am, "proxy_arp_add_del_1823c3e7",
                                VL_API_PROXY_ARP_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "proxy_arp_add_del_reply_e8d4e804",
                                VL_API_PROXY_ARP_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "proxy_arp_dump_51077d14",
                                VL_API_PROXY_ARP_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "proxy_arp_details_5b948673",
                                VL_API_PROXY_ARP_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "proxy_arp_intfc_enable_disable_ae6cfcfb",
                                VL_API_PROXY_ARP_INTFC_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "proxy_arp_intfc_enable_disable_reply_e8d4e804",
                                VL_API_PROXY_ARP_INTFC_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "proxy_arp_intfc_dump_51077d14",
                                VL_API_PROXY_ARP_INTFC_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "proxy_arp_intfc_details_f6458e5f",
                                VL_API_PROXY_ARP_INTFC_DETAILS + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_PROXY_ARP_ADD_DEL + msg_id_base,
   .name = "proxy_arp_add_del",
   .handler = vl_api_proxy_arp_add_del_t_handler,
   .endian = vl_api_proxy_arp_add_del_t_endian,
   .format_fn = vl_api_proxy_arp_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_proxy_arp_add_del_t_tojson,
   .fromjson = vl_api_proxy_arp_add_del_t_fromjson,
   .calc_size = vl_api_proxy_arp_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_PROXY_ARP_ADD_DEL_REPLY + msg_id_base,
  .name = "proxy_arp_add_del_reply",
  .handler = 0,
  .endian = vl_api_proxy_arp_add_del_reply_t_endian,
  .format_fn = vl_api_proxy_arp_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_proxy_arp_add_del_reply_t_tojson,
  .fromjson = vl_api_proxy_arp_add_del_reply_t_fromjson,
  .calc_size = vl_api_proxy_arp_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_PROXY_ARP_DUMP + msg_id_base,
   .name = "proxy_arp_dump",
   .handler = vl_api_proxy_arp_dump_t_handler,
   .endian = vl_api_proxy_arp_dump_t_endian,
   .format_fn = vl_api_proxy_arp_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_proxy_arp_dump_t_tojson,
   .fromjson = vl_api_proxy_arp_dump_t_fromjson,
   .calc_size = vl_api_proxy_arp_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_PROXY_ARP_DETAILS + msg_id_base,
  .name = "proxy_arp_details",
  .handler = 0,
  .endian = vl_api_proxy_arp_details_t_endian,
  .format_fn = vl_api_proxy_arp_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_proxy_arp_details_t_tojson,
  .fromjson = vl_api_proxy_arp_details_t_fromjson,
  .calc_size = vl_api_proxy_arp_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_PROXY_ARP_INTFC_ENABLE_DISABLE + msg_id_base,
   .name = "proxy_arp_intfc_enable_disable",
   .handler = vl_api_proxy_arp_intfc_enable_disable_t_handler,
   .endian = vl_api_proxy_arp_intfc_enable_disable_t_endian,
   .format_fn = vl_api_proxy_arp_intfc_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_proxy_arp_intfc_enable_disable_t_tojson,
   .fromjson = vl_api_proxy_arp_intfc_enable_disable_t_fromjson,
   .calc_size = vl_api_proxy_arp_intfc_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_PROXY_ARP_INTFC_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "proxy_arp_intfc_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_proxy_arp_intfc_enable_disable_reply_t_endian,
  .format_fn = vl_api_proxy_arp_intfc_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_proxy_arp_intfc_enable_disable_reply_t_tojson,
  .fromjson = vl_api_proxy_arp_intfc_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_proxy_arp_intfc_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_PROXY_ARP_INTFC_DUMP + msg_id_base,
   .name = "proxy_arp_intfc_dump",
   .handler = vl_api_proxy_arp_intfc_dump_t_handler,
   .endian = vl_api_proxy_arp_intfc_dump_t_endian,
   .format_fn = vl_api_proxy_arp_intfc_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_proxy_arp_intfc_dump_t_tojson,
   .fromjson = vl_api_proxy_arp_intfc_dump_t_fromjson,
   .calc_size = vl_api_proxy_arp_intfc_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_PROXY_ARP_INTFC_DETAILS + msg_id_base,
  .name = "proxy_arp_intfc_details",
  .handler = 0,
  .endian = vl_api_proxy_arp_intfc_details_t_endian,
  .format_fn = vl_api_proxy_arp_intfc_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_proxy_arp_intfc_details_t_tojson,
  .fromjson = vl_api_proxy_arp_intfc_details_t_fromjson,
  .calc_size = vl_api_proxy_arp_intfc_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
vlib_error_desc_t arp_error_counters[] = {
  {
   .name = "replies_sent",
   .desc = "ARP replies sent",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "disabled",
   .desc = "ARP Disabled",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "l2_type_not_ethernet",
   .desc = "L2 type not ethernet",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "l3_type_not_ip4",
   .desc = "L3 type not IP4",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "l3_src_address_not_local",
   .desc = "IP4 source address not local to subnet",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "l3_dst_address_not_local",
   .desc = "IP4 destination address not local to subnet",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "l3_dst_address_unset",
   .desc = "IP4 destination address is unset",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "l3_src_address_is_local",
   .desc = "IP4 source address matches local interface",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "l3_src_address_learned",
   .desc = "ARP request IP4 source address learned",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "replies_received",
   .desc = "ARP replies received",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "opcode_not_request",
   .desc = "ARP opcode not request",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "proxy_arp_replies_sent",
   .desc = "Proxy ARP replies sent",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "l2_address_mismatch",
   .desc = "ARP hw addr does not match L2 frame src addr",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "gratuitous_arp",
   .desc = "ARP probe or announcement dropped",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "interface_no_table",
   .desc = "Interface is not mapped to an IP table",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "interface_not_ip_enabled",
   .desc = "Interface is not IP enabled",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "unnumbered_mismatch",
   .desc = "RX interface is unnumbered to different subnet",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
};
