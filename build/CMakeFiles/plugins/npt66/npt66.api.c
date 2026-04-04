#define vl_endianfun		/* define message structures */
#include "npt66.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "npt66.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "npt66.api.h"
#undef vl_printfun

#include "npt66.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("npt66_41148766", VL_MSG_NPT66_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_npt66);
   vl_msg_api_add_msg_name_crc (am, "npt66_binding_add_del_8aa10a52",
                                VL_API_NPT66_BINDING_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "npt66_binding_add_del_reply_e8d4e804",
                                VL_API_NPT66_BINDING_ADD_DEL_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NPT66_BINDING_ADD_DEL + msg_id_base,
   .name = "npt66_binding_add_del",
   .handler = vl_api_npt66_binding_add_del_t_handler,
   .endian = vl_api_npt66_binding_add_del_t_endian,
   .format_fn = vl_api_npt66_binding_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_npt66_binding_add_del_t_tojson,
   .fromjson = vl_api_npt66_binding_add_del_t_fromjson,
   .calc_size = vl_api_npt66_binding_add_del_t_calc_size,
   .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NPT66_BINDING_ADD_DEL_REPLY + msg_id_base,
  .name = "npt66_binding_add_del_reply",
  .handler = 0,
  .endian = vl_api_npt66_binding_add_del_reply_t_endian,
  .format_fn = vl_api_npt66_binding_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_npt66_binding_add_del_reply_t_tojson,
  .fromjson = vl_api_npt66_binding_add_del_reply_t_fromjson,
  .calc_size = vl_api_npt66_binding_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
vlib_error_desc_t npt66_error_counters[] = {
  {
   .name = "rx",
   .desc = "packets translated from external to internal",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "tx",
   .desc = "packets translated from internal to external",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "translation",
   .desc = "packet translation failed",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "icmp6_checksum",
   .desc = "ICMP6 checksum validation failed",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "icmp6_truncated",
   .desc = "ICMP6 packet truncated",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
};
