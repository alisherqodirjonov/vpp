#define vl_endianfun		/* define message structures */
#include "lcp.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "lcp.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "lcp.api.h"
#undef vl_printfun

#include "lcp.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("lcp_a76b917e", VL_MSG_LCP_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_lcp);
   vl_msg_api_add_msg_name_crc (am, "lcp_default_ns_set_69749409",
                                VL_API_LCP_DEFAULT_NS_SET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lcp_default_ns_set_reply_e8d4e804",
                                VL_API_LCP_DEFAULT_NS_SET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lcp_default_ns_get_51077d14",
                                VL_API_LCP_DEFAULT_NS_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lcp_default_ns_get_reply_5102feee",
                                VL_API_LCP_DEFAULT_NS_GET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lcp_itf_pair_add_del_40482b80",
                                VL_API_LCP_ITF_PAIR_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lcp_itf_pair_add_del_reply_e8d4e804",
                                VL_API_LCP_ITF_PAIR_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lcp_itf_pair_add_del_v2_40482b80",
                                VL_API_LCP_ITF_PAIR_ADD_DEL_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lcp_itf_pair_add_del_v2_reply_39452f52",
                                VL_API_LCP_ITF_PAIR_ADD_DEL_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lcp_itf_pair_add_del_v3_40482b80",
                                VL_API_LCP_ITF_PAIR_ADD_DEL_V3 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lcp_itf_pair_add_del_v3_reply_c2502663",
                                VL_API_LCP_ITF_PAIR_ADD_DEL_V3_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lcp_itf_pair_get_f75ba505",
                                VL_API_LCP_ITF_PAIR_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lcp_itf_pair_get_reply_53b48f5d",
                                VL_API_LCP_ITF_PAIR_GET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lcp_itf_pair_get_v2_47250981",
                                VL_API_LCP_ITF_PAIR_GET_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lcp_itf_pair_get_v2_reply_53b48f5d",
                                VL_API_LCP_ITF_PAIR_GET_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lcp_itf_pair_details_8b5481af",
                                VL_API_LCP_ITF_PAIR_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lcp_ethertype_enable_f893dae1",
                                VL_API_LCP_ETHERTYPE_ENABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lcp_ethertype_enable_reply_e8d4e804",
                                VL_API_LCP_ETHERTYPE_ENABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lcp_ethertype_get_51077d14",
                                VL_API_LCP_ETHERTYPE_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lcp_ethertype_get_reply_db48c31e",
                                VL_API_LCP_ETHERTYPE_GET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lcp_itf_pair_replace_begin_51077d14",
                                VL_API_LCP_ITF_PAIR_REPLACE_BEGIN + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lcp_itf_pair_replace_begin_reply_e8d4e804",
                                VL_API_LCP_ITF_PAIR_REPLACE_BEGIN_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lcp_itf_pair_replace_end_51077d14",
                                VL_API_LCP_ITF_PAIR_REPLACE_END + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lcp_itf_pair_replace_end_reply_e8d4e804",
                                VL_API_LCP_ITF_PAIR_REPLACE_END_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LCP_ITF_PAIR_GET + msg_id_base,
   .name = "lcp_itf_pair_get",
   .handler = vl_api_lcp_itf_pair_get_t_handler,
   .endian = vl_api_lcp_itf_pair_get_t_endian,
   .format_fn = vl_api_lcp_itf_pair_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lcp_itf_pair_get_t_tojson,
   .fromjson = vl_api_lcp_itf_pair_get_t_fromjson,
   .calc_size = vl_api_lcp_itf_pair_get_t_calc_size,
   .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LCP_ITF_PAIR_GET_REPLY + msg_id_base,
  .name = "lcp_itf_pair_get_reply",
  .handler = 0,
  .endian = vl_api_lcp_itf_pair_get_reply_t_endian,
  .format_fn = vl_api_lcp_itf_pair_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lcp_itf_pair_get_reply_t_tojson,
  .fromjson = vl_api_lcp_itf_pair_get_reply_t_fromjson,
  .calc_size = vl_api_lcp_itf_pair_get_reply_t_calc_size,
  .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LCP_ITF_PAIR_DETAILS + msg_id_base,
  .name = "lcp_itf_pair_details",
  .handler = 0,
  .endian = vl_api_lcp_itf_pair_details_t_endian,
  .format_fn = vl_api_lcp_itf_pair_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lcp_itf_pair_details_t_tojson,
  .fromjson = vl_api_lcp_itf_pair_details_t_fromjson,
  .calc_size = vl_api_lcp_itf_pair_details_t_calc_size,
  .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LCP_ITF_PAIR_GET_V2 + msg_id_base,
   .name = "lcp_itf_pair_get_v2",
   .handler = vl_api_lcp_itf_pair_get_v2_t_handler,
   .endian = vl_api_lcp_itf_pair_get_v2_t_endian,
   .format_fn = vl_api_lcp_itf_pair_get_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lcp_itf_pair_get_v2_t_tojson,
   .fromjson = vl_api_lcp_itf_pair_get_v2_t_fromjson,
   .calc_size = vl_api_lcp_itf_pair_get_v2_t_calc_size,
   .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LCP_ITF_PAIR_GET_V2_REPLY + msg_id_base,
  .name = "lcp_itf_pair_get_v2_reply",
  .handler = 0,
  .endian = vl_api_lcp_itf_pair_get_v2_reply_t_endian,
  .format_fn = vl_api_lcp_itf_pair_get_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lcp_itf_pair_get_v2_reply_t_tojson,
  .fromjson = vl_api_lcp_itf_pair_get_v2_reply_t_fromjson,
  .calc_size = vl_api_lcp_itf_pair_get_v2_reply_t_calc_size,
  .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LCP_ITF_PAIR_DETAILS + msg_id_base,
  .name = "lcp_itf_pair_details",
  .handler = 0,
  .endian = vl_api_lcp_itf_pair_details_t_endian,
  .format_fn = vl_api_lcp_itf_pair_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lcp_itf_pair_details_t_tojson,
  .fromjson = vl_api_lcp_itf_pair_details_t_fromjson,
  .calc_size = vl_api_lcp_itf_pair_details_t_calc_size,
  .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LCP_DEFAULT_NS_SET + msg_id_base,
   .name = "lcp_default_ns_set",
   .handler = vl_api_lcp_default_ns_set_t_handler,
   .endian = vl_api_lcp_default_ns_set_t_endian,
   .format_fn = vl_api_lcp_default_ns_set_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lcp_default_ns_set_t_tojson,
   .fromjson = vl_api_lcp_default_ns_set_t_fromjson,
   .calc_size = vl_api_lcp_default_ns_set_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LCP_DEFAULT_NS_SET_REPLY + msg_id_base,
  .name = "lcp_default_ns_set_reply",
  .handler = 0,
  .endian = vl_api_lcp_default_ns_set_reply_t_endian,
  .format_fn = vl_api_lcp_default_ns_set_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lcp_default_ns_set_reply_t_tojson,
  .fromjson = vl_api_lcp_default_ns_set_reply_t_fromjson,
  .calc_size = vl_api_lcp_default_ns_set_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LCP_DEFAULT_NS_GET + msg_id_base,
   .name = "lcp_default_ns_get",
   .handler = vl_api_lcp_default_ns_get_t_handler,
   .endian = vl_api_lcp_default_ns_get_t_endian,
   .format_fn = vl_api_lcp_default_ns_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lcp_default_ns_get_t_tojson,
   .fromjson = vl_api_lcp_default_ns_get_t_fromjson,
   .calc_size = vl_api_lcp_default_ns_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LCP_DEFAULT_NS_GET_REPLY + msg_id_base,
  .name = "lcp_default_ns_get_reply",
  .handler = 0,
  .endian = vl_api_lcp_default_ns_get_reply_t_endian,
  .format_fn = vl_api_lcp_default_ns_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lcp_default_ns_get_reply_t_tojson,
  .fromjson = vl_api_lcp_default_ns_get_reply_t_fromjson,
  .calc_size = vl_api_lcp_default_ns_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LCP_ITF_PAIR_ADD_DEL + msg_id_base,
   .name = "lcp_itf_pair_add_del",
   .handler = vl_api_lcp_itf_pair_add_del_t_handler,
   .endian = vl_api_lcp_itf_pair_add_del_t_endian,
   .format_fn = vl_api_lcp_itf_pair_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lcp_itf_pair_add_del_t_tojson,
   .fromjson = vl_api_lcp_itf_pair_add_del_t_fromjson,
   .calc_size = vl_api_lcp_itf_pair_add_del_t_calc_size,
   .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LCP_ITF_PAIR_ADD_DEL_REPLY + msg_id_base,
  .name = "lcp_itf_pair_add_del_reply",
  .handler = 0,
  .endian = vl_api_lcp_itf_pair_add_del_reply_t_endian,
  .format_fn = vl_api_lcp_itf_pair_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lcp_itf_pair_add_del_reply_t_tojson,
  .fromjson = vl_api_lcp_itf_pair_add_del_reply_t_fromjson,
  .calc_size = vl_api_lcp_itf_pair_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LCP_ITF_PAIR_ADD_DEL_V2 + msg_id_base,
   .name = "lcp_itf_pair_add_del_v2",
   .handler = vl_api_lcp_itf_pair_add_del_v2_t_handler,
   .endian = vl_api_lcp_itf_pair_add_del_v2_t_endian,
   .format_fn = vl_api_lcp_itf_pair_add_del_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lcp_itf_pair_add_del_v2_t_tojson,
   .fromjson = vl_api_lcp_itf_pair_add_del_v2_t_fromjson,
   .calc_size = vl_api_lcp_itf_pair_add_del_v2_t_calc_size,
   .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LCP_ITF_PAIR_ADD_DEL_V2_REPLY + msg_id_base,
  .name = "lcp_itf_pair_add_del_v2_reply",
  .handler = 0,
  .endian = vl_api_lcp_itf_pair_add_del_v2_reply_t_endian,
  .format_fn = vl_api_lcp_itf_pair_add_del_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lcp_itf_pair_add_del_v2_reply_t_tojson,
  .fromjson = vl_api_lcp_itf_pair_add_del_v2_reply_t_fromjson,
  .calc_size = vl_api_lcp_itf_pair_add_del_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LCP_ITF_PAIR_ADD_DEL_V3 + msg_id_base,
   .name = "lcp_itf_pair_add_del_v3",
   .handler = vl_api_lcp_itf_pair_add_del_v3_t_handler,
   .endian = vl_api_lcp_itf_pair_add_del_v3_t_endian,
   .format_fn = vl_api_lcp_itf_pair_add_del_v3_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lcp_itf_pair_add_del_v3_t_tojson,
   .fromjson = vl_api_lcp_itf_pair_add_del_v3_t_fromjson,
   .calc_size = vl_api_lcp_itf_pair_add_del_v3_t_calc_size,
   .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LCP_ITF_PAIR_ADD_DEL_V3_REPLY + msg_id_base,
  .name = "lcp_itf_pair_add_del_v3_reply",
  .handler = 0,
  .endian = vl_api_lcp_itf_pair_add_del_v3_reply_t_endian,
  .format_fn = vl_api_lcp_itf_pair_add_del_v3_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lcp_itf_pair_add_del_v3_reply_t_tojson,
  .fromjson = vl_api_lcp_itf_pair_add_del_v3_reply_t_fromjson,
  .calc_size = vl_api_lcp_itf_pair_add_del_v3_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LCP_ETHERTYPE_ENABLE + msg_id_base,
   .name = "lcp_ethertype_enable",
   .handler = vl_api_lcp_ethertype_enable_t_handler,
   .endian = vl_api_lcp_ethertype_enable_t_endian,
   .format_fn = vl_api_lcp_ethertype_enable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lcp_ethertype_enable_t_tojson,
   .fromjson = vl_api_lcp_ethertype_enable_t_fromjson,
   .calc_size = vl_api_lcp_ethertype_enable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LCP_ETHERTYPE_ENABLE_REPLY + msg_id_base,
  .name = "lcp_ethertype_enable_reply",
  .handler = 0,
  .endian = vl_api_lcp_ethertype_enable_reply_t_endian,
  .format_fn = vl_api_lcp_ethertype_enable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lcp_ethertype_enable_reply_t_tojson,
  .fromjson = vl_api_lcp_ethertype_enable_reply_t_fromjson,
  .calc_size = vl_api_lcp_ethertype_enable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LCP_ETHERTYPE_GET + msg_id_base,
   .name = "lcp_ethertype_get",
   .handler = vl_api_lcp_ethertype_get_t_handler,
   .endian = vl_api_lcp_ethertype_get_t_endian,
   .format_fn = vl_api_lcp_ethertype_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lcp_ethertype_get_t_tojson,
   .fromjson = vl_api_lcp_ethertype_get_t_fromjson,
   .calc_size = vl_api_lcp_ethertype_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LCP_ETHERTYPE_GET_REPLY + msg_id_base,
  .name = "lcp_ethertype_get_reply",
  .handler = 0,
  .endian = vl_api_lcp_ethertype_get_reply_t_endian,
  .format_fn = vl_api_lcp_ethertype_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lcp_ethertype_get_reply_t_tojson,
  .fromjson = vl_api_lcp_ethertype_get_reply_t_fromjson,
  .calc_size = vl_api_lcp_ethertype_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LCP_ITF_PAIR_REPLACE_BEGIN + msg_id_base,
   .name = "lcp_itf_pair_replace_begin",
   .handler = vl_api_lcp_itf_pair_replace_begin_t_handler,
   .endian = vl_api_lcp_itf_pair_replace_begin_t_endian,
   .format_fn = vl_api_lcp_itf_pair_replace_begin_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lcp_itf_pair_replace_begin_t_tojson,
   .fromjson = vl_api_lcp_itf_pair_replace_begin_t_fromjson,
   .calc_size = vl_api_lcp_itf_pair_replace_begin_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LCP_ITF_PAIR_REPLACE_BEGIN_REPLY + msg_id_base,
  .name = "lcp_itf_pair_replace_begin_reply",
  .handler = 0,
  .endian = vl_api_lcp_itf_pair_replace_begin_reply_t_endian,
  .format_fn = vl_api_lcp_itf_pair_replace_begin_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lcp_itf_pair_replace_begin_reply_t_tojson,
  .fromjson = vl_api_lcp_itf_pair_replace_begin_reply_t_fromjson,
  .calc_size = vl_api_lcp_itf_pair_replace_begin_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LCP_ITF_PAIR_REPLACE_END + msg_id_base,
   .name = "lcp_itf_pair_replace_end",
   .handler = vl_api_lcp_itf_pair_replace_end_t_handler,
   .endian = vl_api_lcp_itf_pair_replace_end_t_endian,
   .format_fn = vl_api_lcp_itf_pair_replace_end_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lcp_itf_pair_replace_end_t_tojson,
   .fromjson = vl_api_lcp_itf_pair_replace_end_t_fromjson,
   .calc_size = vl_api_lcp_itf_pair_replace_end_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LCP_ITF_PAIR_REPLACE_END_REPLY + msg_id_base,
  .name = "lcp_itf_pair_replace_end_reply",
  .handler = 0,
  .endian = vl_api_lcp_itf_pair_replace_end_reply_t_endian,
  .format_fn = vl_api_lcp_itf_pair_replace_end_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lcp_itf_pair_replace_end_reply_t_tojson,
  .fromjson = vl_api_lcp_itf_pair_replace_end_reply_t_fromjson,
  .calc_size = vl_api_lcp_itf_pair_replace_end_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
vlib_error_desc_t linuxcp_error_counters[] = {
  {
   .name = "packets",
   .desc = "ARP packets processed",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "copies",
   .desc = "ARP replies copied to host",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
};
