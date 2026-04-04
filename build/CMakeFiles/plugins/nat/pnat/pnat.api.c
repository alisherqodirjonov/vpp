#define vl_endianfun		/* define message structures */
#include "pnat.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "pnat.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "pnat.api.h"
#undef vl_printfun

#include "pnat.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("pnat_ec06ec84", VL_MSG_PNAT_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_pnat);
   vl_msg_api_add_msg_name_crc (am, "pnat_binding_add_946ee0b7",
                                VL_API_PNAT_BINDING_ADD + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pnat_binding_add_reply_4cd980a7",
                                VL_API_PNAT_BINDING_ADD_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pnat_binding_add_v2_946ee0b7",
                                VL_API_PNAT_BINDING_ADD_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pnat_binding_add_v2_reply_4cd980a7",
                                VL_API_PNAT_BINDING_ADD_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pnat_binding_del_9259df7b",
                                VL_API_PNAT_BINDING_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pnat_binding_del_reply_e8d4e804",
                                VL_API_PNAT_BINDING_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pnat_binding_attach_6e074232",
                                VL_API_PNAT_BINDING_ATTACH + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pnat_binding_attach_reply_e8d4e804",
                                VL_API_PNAT_BINDING_ATTACH_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pnat_binding_detach_6e074232",
                                VL_API_PNAT_BINDING_DETACH + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pnat_binding_detach_reply_e8d4e804",
                                VL_API_PNAT_BINDING_DETACH_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pnat_bindings_get_f75ba505",
                                VL_API_PNAT_BINDINGS_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pnat_bindings_get_reply_53b48f5d",
                                VL_API_PNAT_BINDINGS_GET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pnat_bindings_details_08fb2815",
                                VL_API_PNAT_BINDINGS_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pnat_interfaces_get_f75ba505",
                                VL_API_PNAT_INTERFACES_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pnat_interfaces_get_reply_53b48f5d",
                                VL_API_PNAT_INTERFACES_GET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pnat_interfaces_details_4cb09493",
                                VL_API_PNAT_INTERFACES_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pnat_flow_lookup_1ef8747c",
                                VL_API_PNAT_FLOW_LOOKUP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pnat_flow_lookup_reply_4cd980a7",
                                VL_API_PNAT_FLOW_LOOKUP_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_PNAT_BINDINGS_GET + msg_id_base,
   .name = "pnat_bindings_get",
   .handler = vl_api_pnat_bindings_get_t_handler,
   .endian = vl_api_pnat_bindings_get_t_endian,
   .format_fn = vl_api_pnat_bindings_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_pnat_bindings_get_t_tojson,
   .fromjson = vl_api_pnat_bindings_get_t_fromjson,
   .calc_size = vl_api_pnat_bindings_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_PNAT_BINDINGS_GET_REPLY + msg_id_base,
  .name = "pnat_bindings_get_reply",
  .handler = 0,
  .endian = vl_api_pnat_bindings_get_reply_t_endian,
  .format_fn = vl_api_pnat_bindings_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_pnat_bindings_get_reply_t_tojson,
  .fromjson = vl_api_pnat_bindings_get_reply_t_fromjson,
  .calc_size = vl_api_pnat_bindings_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_PNAT_BINDINGS_DETAILS + msg_id_base,
  .name = "pnat_bindings_details",
  .handler = 0,
  .endian = vl_api_pnat_bindings_details_t_endian,
  .format_fn = vl_api_pnat_bindings_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_pnat_bindings_details_t_tojson,
  .fromjson = vl_api_pnat_bindings_details_t_fromjson,
  .calc_size = vl_api_pnat_bindings_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_PNAT_INTERFACES_GET + msg_id_base,
   .name = "pnat_interfaces_get",
   .handler = vl_api_pnat_interfaces_get_t_handler,
   .endian = vl_api_pnat_interfaces_get_t_endian,
   .format_fn = vl_api_pnat_interfaces_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_pnat_interfaces_get_t_tojson,
   .fromjson = vl_api_pnat_interfaces_get_t_fromjson,
   .calc_size = vl_api_pnat_interfaces_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_PNAT_INTERFACES_GET_REPLY + msg_id_base,
  .name = "pnat_interfaces_get_reply",
  .handler = 0,
  .endian = vl_api_pnat_interfaces_get_reply_t_endian,
  .format_fn = vl_api_pnat_interfaces_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_pnat_interfaces_get_reply_t_tojson,
  .fromjson = vl_api_pnat_interfaces_get_reply_t_fromjson,
  .calc_size = vl_api_pnat_interfaces_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_PNAT_INTERFACES_DETAILS + msg_id_base,
  .name = "pnat_interfaces_details",
  .handler = 0,
  .endian = vl_api_pnat_interfaces_details_t_endian,
  .format_fn = vl_api_pnat_interfaces_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_pnat_interfaces_details_t_tojson,
  .fromjson = vl_api_pnat_interfaces_details_t_fromjson,
  .calc_size = vl_api_pnat_interfaces_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_PNAT_BINDING_ADD + msg_id_base,
   .name = "pnat_binding_add",
   .handler = vl_api_pnat_binding_add_t_handler,
   .endian = vl_api_pnat_binding_add_t_endian,
   .format_fn = vl_api_pnat_binding_add_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_pnat_binding_add_t_tojson,
   .fromjson = vl_api_pnat_binding_add_t_fromjson,
   .calc_size = vl_api_pnat_binding_add_t_calc_size,
   .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_PNAT_BINDING_ADD_REPLY + msg_id_base,
  .name = "pnat_binding_add_reply",
  .handler = 0,
  .endian = vl_api_pnat_binding_add_reply_t_endian,
  .format_fn = vl_api_pnat_binding_add_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_pnat_binding_add_reply_t_tojson,
  .fromjson = vl_api_pnat_binding_add_reply_t_fromjson,
  .calc_size = vl_api_pnat_binding_add_reply_t_calc_size,
  .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_PNAT_BINDING_ADD_V2 + msg_id_base,
   .name = "pnat_binding_add_v2",
   .handler = vl_api_pnat_binding_add_v2_t_handler,
   .endian = vl_api_pnat_binding_add_v2_t_endian,
   .format_fn = vl_api_pnat_binding_add_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_pnat_binding_add_v2_t_tojson,
   .fromjson = vl_api_pnat_binding_add_v2_t_fromjson,
   .calc_size = vl_api_pnat_binding_add_v2_t_calc_size,
   .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_PNAT_BINDING_ADD_V2_REPLY + msg_id_base,
  .name = "pnat_binding_add_v2_reply",
  .handler = 0,
  .endian = vl_api_pnat_binding_add_v2_reply_t_endian,
  .format_fn = vl_api_pnat_binding_add_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_pnat_binding_add_v2_reply_t_tojson,
  .fromjson = vl_api_pnat_binding_add_v2_reply_t_fromjson,
  .calc_size = vl_api_pnat_binding_add_v2_reply_t_calc_size,
  .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_PNAT_BINDING_DEL + msg_id_base,
   .name = "pnat_binding_del",
   .handler = vl_api_pnat_binding_del_t_handler,
   .endian = vl_api_pnat_binding_del_t_endian,
   .format_fn = vl_api_pnat_binding_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_pnat_binding_del_t_tojson,
   .fromjson = vl_api_pnat_binding_del_t_fromjson,
   .calc_size = vl_api_pnat_binding_del_t_calc_size,
   .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_PNAT_BINDING_DEL_REPLY + msg_id_base,
  .name = "pnat_binding_del_reply",
  .handler = 0,
  .endian = vl_api_pnat_binding_del_reply_t_endian,
  .format_fn = vl_api_pnat_binding_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_pnat_binding_del_reply_t_tojson,
  .fromjson = vl_api_pnat_binding_del_reply_t_fromjson,
  .calc_size = vl_api_pnat_binding_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_PNAT_BINDING_ATTACH + msg_id_base,
   .name = "pnat_binding_attach",
   .handler = vl_api_pnat_binding_attach_t_handler,
   .endian = vl_api_pnat_binding_attach_t_endian,
   .format_fn = vl_api_pnat_binding_attach_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_pnat_binding_attach_t_tojson,
   .fromjson = vl_api_pnat_binding_attach_t_fromjson,
   .calc_size = vl_api_pnat_binding_attach_t_calc_size,
   .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_PNAT_BINDING_ATTACH_REPLY + msg_id_base,
  .name = "pnat_binding_attach_reply",
  .handler = 0,
  .endian = vl_api_pnat_binding_attach_reply_t_endian,
  .format_fn = vl_api_pnat_binding_attach_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_pnat_binding_attach_reply_t_tojson,
  .fromjson = vl_api_pnat_binding_attach_reply_t_fromjson,
  .calc_size = vl_api_pnat_binding_attach_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_PNAT_BINDING_DETACH + msg_id_base,
   .name = "pnat_binding_detach",
   .handler = vl_api_pnat_binding_detach_t_handler,
   .endian = vl_api_pnat_binding_detach_t_endian,
   .format_fn = vl_api_pnat_binding_detach_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_pnat_binding_detach_t_tojson,
   .fromjson = vl_api_pnat_binding_detach_t_fromjson,
   .calc_size = vl_api_pnat_binding_detach_t_calc_size,
   .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_PNAT_BINDING_DETACH_REPLY + msg_id_base,
  .name = "pnat_binding_detach_reply",
  .handler = 0,
  .endian = vl_api_pnat_binding_detach_reply_t_endian,
  .format_fn = vl_api_pnat_binding_detach_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_pnat_binding_detach_reply_t_tojson,
  .fromjson = vl_api_pnat_binding_detach_reply_t_fromjson,
  .calc_size = vl_api_pnat_binding_detach_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_PNAT_FLOW_LOOKUP + msg_id_base,
   .name = "pnat_flow_lookup",
   .handler = vl_api_pnat_flow_lookup_t_handler,
   .endian = vl_api_pnat_flow_lookup_t_endian,
   .format_fn = vl_api_pnat_flow_lookup_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_pnat_flow_lookup_t_tojson,
   .fromjson = vl_api_pnat_flow_lookup_t_fromjson,
   .calc_size = vl_api_pnat_flow_lookup_t_calc_size,
   .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_PNAT_FLOW_LOOKUP_REPLY + msg_id_base,
  .name = "pnat_flow_lookup_reply",
  .handler = 0,
  .endian = vl_api_pnat_flow_lookup_reply_t_endian,
  .format_fn = vl_api_pnat_flow_lookup_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_pnat_flow_lookup_reply_t_tojson,
  .fromjson = vl_api_pnat_flow_lookup_reply_t_fromjson,
  .calc_size = vl_api_pnat_flow_lookup_reply_t_calc_size,
  .is_autoendian = 1};
   vl_msg_api_config (&c);
   return msg_id_base;
}
vlib_error_desc_t pnat_error_counters[] = {
  {
   .name = "none",
   .desc = "successfully rewritten",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "rewrite",
   .desc = "rewrite failed",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "tooshort",
   .desc = "packet too short for rewrite",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
};
