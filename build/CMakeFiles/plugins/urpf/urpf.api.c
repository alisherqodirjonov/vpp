#define vl_endianfun		/* define message structures */
#include "urpf.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "urpf.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "urpf.api.h"
#undef vl_printfun

#include "urpf.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("urpf_0abec9cd", VL_MSG_URPF_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_urpf);
   vl_msg_api_add_msg_name_crc (am, "urpf_update_cc274cd1",
                                VL_API_URPF_UPDATE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "urpf_update_reply_e8d4e804",
                                VL_API_URPF_UPDATE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "urpf_update_v2_b873d028",
                                VL_API_URPF_UPDATE_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "urpf_update_v2_reply_e8d4e804",
                                VL_API_URPF_UPDATE_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "urpf_interface_dump_f9e6675e",
                                VL_API_URPF_INTERFACE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "urpf_interface_details_f94b5374",
                                VL_API_URPF_INTERFACE_DETAILS + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_URPF_UPDATE + msg_id_base,
   .name = "urpf_update",
   .handler = vl_api_urpf_update_t_handler,
   .endian = vl_api_urpf_update_t_endian,
   .format_fn = vl_api_urpf_update_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_urpf_update_t_tojson,
   .fromjson = vl_api_urpf_update_t_fromjson,
   .calc_size = vl_api_urpf_update_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_URPF_UPDATE_REPLY + msg_id_base,
  .name = "urpf_update_reply",
  .handler = 0,
  .endian = vl_api_urpf_update_reply_t_endian,
  .format_fn = vl_api_urpf_update_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_urpf_update_reply_t_tojson,
  .fromjson = vl_api_urpf_update_reply_t_fromjson,
  .calc_size = vl_api_urpf_update_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_URPF_UPDATE_V2 + msg_id_base,
   .name = "urpf_update_v2",
   .handler = vl_api_urpf_update_v2_t_handler,
   .endian = vl_api_urpf_update_v2_t_endian,
   .format_fn = vl_api_urpf_update_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_urpf_update_v2_t_tojson,
   .fromjson = vl_api_urpf_update_v2_t_fromjson,
   .calc_size = vl_api_urpf_update_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_URPF_UPDATE_V2_REPLY + msg_id_base,
  .name = "urpf_update_v2_reply",
  .handler = 0,
  .endian = vl_api_urpf_update_v2_reply_t_endian,
  .format_fn = vl_api_urpf_update_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_urpf_update_v2_reply_t_tojson,
  .fromjson = vl_api_urpf_update_v2_reply_t_fromjson,
  .calc_size = vl_api_urpf_update_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_URPF_INTERFACE_DUMP + msg_id_base,
   .name = "urpf_interface_dump",
   .handler = vl_api_urpf_interface_dump_t_handler,
   .endian = vl_api_urpf_interface_dump_t_endian,
   .format_fn = vl_api_urpf_interface_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_urpf_interface_dump_t_tojson,
   .fromjson = vl_api_urpf_interface_dump_t_fromjson,
   .calc_size = vl_api_urpf_interface_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_URPF_INTERFACE_DETAILS + msg_id_base,
  .name = "urpf_interface_details",
  .handler = 0,
  .endian = vl_api_urpf_interface_details_t_endian,
  .format_fn = vl_api_urpf_interface_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_urpf_interface_details_t_tojson,
  .fromjson = vl_api_urpf_interface_details_t_fromjson,
  .calc_size = vl_api_urpf_interface_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
