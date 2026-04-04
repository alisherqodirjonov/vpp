#define vl_endianfun		/* define message structures */
#include "sr_pt.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "sr_pt.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "sr_pt.api.h"
#undef vl_printfun

#include "sr_pt.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("sr_pt_5464570e", VL_MSG_SR_PT_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_sr_pt);
   vl_msg_api_add_msg_name_crc (am, "sr_pt_iface_dump_51077d14",
                                VL_API_SR_PT_IFACE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_pt_iface_details_1f472f85",
                                VL_API_SR_PT_IFACE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_pt_iface_add_852c0cda",
                                VL_API_SR_PT_IFACE_ADD + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_pt_iface_add_reply_e8d4e804",
                                VL_API_SR_PT_IFACE_ADD_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_pt_iface_del_f9e6675e",
                                VL_API_SR_PT_IFACE_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_pt_iface_del_reply_e8d4e804",
                                VL_API_SR_PT_IFACE_DEL_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SR_PT_IFACE_DUMP + msg_id_base,
   .name = "sr_pt_iface_dump",
   .handler = vl_api_sr_pt_iface_dump_t_handler,
   .endian = vl_api_sr_pt_iface_dump_t_endian,
   .format_fn = vl_api_sr_pt_iface_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sr_pt_iface_dump_t_tojson,
   .fromjson = vl_api_sr_pt_iface_dump_t_fromjson,
   .calc_size = vl_api_sr_pt_iface_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SR_PT_IFACE_DETAILS + msg_id_base,
  .name = "sr_pt_iface_details",
  .handler = 0,
  .endian = vl_api_sr_pt_iface_details_t_endian,
  .format_fn = vl_api_sr_pt_iface_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sr_pt_iface_details_t_tojson,
  .fromjson = vl_api_sr_pt_iface_details_t_fromjson,
  .calc_size = vl_api_sr_pt_iface_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SR_PT_IFACE_ADD + msg_id_base,
   .name = "sr_pt_iface_add",
   .handler = vl_api_sr_pt_iface_add_t_handler,
   .endian = vl_api_sr_pt_iface_add_t_endian,
   .format_fn = vl_api_sr_pt_iface_add_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sr_pt_iface_add_t_tojson,
   .fromjson = vl_api_sr_pt_iface_add_t_fromjson,
   .calc_size = vl_api_sr_pt_iface_add_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SR_PT_IFACE_ADD_REPLY + msg_id_base,
  .name = "sr_pt_iface_add_reply",
  .handler = 0,
  .endian = vl_api_sr_pt_iface_add_reply_t_endian,
  .format_fn = vl_api_sr_pt_iface_add_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sr_pt_iface_add_reply_t_tojson,
  .fromjson = vl_api_sr_pt_iface_add_reply_t_fromjson,
  .calc_size = vl_api_sr_pt_iface_add_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SR_PT_IFACE_DEL + msg_id_base,
   .name = "sr_pt_iface_del",
   .handler = vl_api_sr_pt_iface_del_t_handler,
   .endian = vl_api_sr_pt_iface_del_t_endian,
   .format_fn = vl_api_sr_pt_iface_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sr_pt_iface_del_t_tojson,
   .fromjson = vl_api_sr_pt_iface_del_t_fromjson,
   .calc_size = vl_api_sr_pt_iface_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SR_PT_IFACE_DEL_REPLY + msg_id_base,
  .name = "sr_pt_iface_del_reply",
  .handler = 0,
  .endian = vl_api_sr_pt_iface_del_reply_t_endian,
  .format_fn = vl_api_sr_pt_iface_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sr_pt_iface_del_reply_t_tojson,
  .fromjson = vl_api_sr_pt_iface_del_reply_t_fromjson,
  .calc_size = vl_api_sr_pt_iface_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
