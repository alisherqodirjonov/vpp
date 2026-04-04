#define vl_endianfun		/* define message structures */
#include "idpf.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "idpf.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "idpf.api.h"
#undef vl_printfun

#include "idpf.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("idpf_7bc56cb6", VL_MSG_IDPF_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_idpf);
   vl_msg_api_add_msg_name_crc (am, "idpf_create_2ba86d91",
                                VL_API_IDPF_CREATE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "idpf_create_reply_5383d31f",
                                VL_API_IDPF_CREATE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "idpf_delete_f9e6675e",
                                VL_API_IDPF_DELETE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "idpf_delete_reply_e8d4e804",
                                VL_API_IDPF_DELETE_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IDPF_CREATE + msg_id_base,
   .name = "idpf_create",
   .handler = vl_api_idpf_create_t_handler,
   .endian = vl_api_idpf_create_t_endian,
   .format_fn = vl_api_idpf_create_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_idpf_create_t_tojson,
   .fromjson = vl_api_idpf_create_t_fromjson,
   .calc_size = vl_api_idpf_create_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IDPF_CREATE_REPLY + msg_id_base,
  .name = "idpf_create_reply",
  .handler = 0,
  .endian = vl_api_idpf_create_reply_t_endian,
  .format_fn = vl_api_idpf_create_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_idpf_create_reply_t_tojson,
  .fromjson = vl_api_idpf_create_reply_t_fromjson,
  .calc_size = vl_api_idpf_create_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IDPF_DELETE + msg_id_base,
   .name = "idpf_delete",
   .handler = vl_api_idpf_delete_t_handler,
   .endian = vl_api_idpf_delete_t_endian,
   .format_fn = vl_api_idpf_delete_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_idpf_delete_t_tojson,
   .fromjson = vl_api_idpf_delete_t_fromjson,
   .calc_size = vl_api_idpf_delete_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IDPF_DELETE_REPLY + msg_id_base,
  .name = "idpf_delete_reply",
  .handler = 0,
  .endian = vl_api_idpf_delete_reply_t_endian,
  .format_fn = vl_api_idpf_delete_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_idpf_delete_reply_t_tojson,
  .fromjson = vl_api_idpf_delete_reply_t_fromjson,
  .calc_size = vl_api_idpf_delete_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
