#define vl_endianfun		/* define message structures */
#include "snort.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "snort.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "snort.api.h"
#undef vl_printfun

#include "snort.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("snort_f89115d4", VL_MSG_SNORT_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_snort);
   vl_msg_api_add_msg_name_crc (am, "snort_instance_create_248cc390",
                                VL_API_SNORT_INSTANCE_CREATE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "snort_instance_create_reply_e63a3fba",
                                VL_API_SNORT_INSTANCE_CREATE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "snort_instance_delete_6981211a",
                                VL_API_SNORT_INSTANCE_DELETE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "snort_instance_delete_reply_e8d4e804",
                                VL_API_SNORT_INSTANCE_DELETE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "snort_client_disconnect_30a221a6",
                                VL_API_SNORT_CLIENT_DISCONNECT + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "snort_client_disconnect_reply_e8d4e804",
                                VL_API_SNORT_CLIENT_DISCONNECT_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "snort_instance_disconnect_6981211a",
                                VL_API_SNORT_INSTANCE_DISCONNECT + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "snort_instance_disconnect_reply_e8d4e804",
                                VL_API_SNORT_INSTANCE_DISCONNECT_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "snort_interface_attach_79ceda89",
                                VL_API_SNORT_INTERFACE_ATTACH + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "snort_interface_attach_reply_e8d4e804",
                                VL_API_SNORT_INTERFACE_ATTACH_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "snort_interface_detach_529cb13f",
                                VL_API_SNORT_INTERFACE_DETACH + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "snort_interface_detach_reply_e8d4e804",
                                VL_API_SNORT_INTERFACE_DETACH_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "snort_input_mode_get_51077d14",
                                VL_API_SNORT_INPUT_MODE_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "snort_input_mode_get_reply_a18796bf",
                                VL_API_SNORT_INPUT_MODE_GET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "snort_input_mode_set_d595d008",
                                VL_API_SNORT_INPUT_MODE_SET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "snort_input_mode_set_reply_e8d4e804",
                                VL_API_SNORT_INPUT_MODE_SET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "snort_instance_get_07c37475",
                                VL_API_SNORT_INSTANCE_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "snort_instance_get_reply_53b48f5d",
                                VL_API_SNORT_INSTANCE_GET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "snort_instance_details_abb60d49",
                                VL_API_SNORT_INSTANCE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "snort_interface_get_765a2424",
                                VL_API_SNORT_INTERFACE_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "snort_interface_get_reply_53b48f5d",
                                VL_API_SNORT_INTERFACE_GET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "snort_interface_details_52c75990",
                                VL_API_SNORT_INTERFACE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "snort_client_get_51d54b70",
                                VL_API_SNORT_CLIENT_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "snort_client_get_reply_53b48f5d",
                                VL_API_SNORT_CLIENT_GET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "snort_client_details_7e29e6f5",
                                VL_API_SNORT_CLIENT_DETAILS + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SNORT_INSTANCE_GET + msg_id_base,
   .name = "snort_instance_get",
   .handler = vl_api_snort_instance_get_t_handler,
   .endian = vl_api_snort_instance_get_t_endian,
   .format_fn = vl_api_snort_instance_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_snort_instance_get_t_tojson,
   .fromjson = vl_api_snort_instance_get_t_fromjson,
   .calc_size = vl_api_snort_instance_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SNORT_INSTANCE_GET_REPLY + msg_id_base,
  .name = "snort_instance_get_reply",
  .handler = 0,
  .endian = vl_api_snort_instance_get_reply_t_endian,
  .format_fn = vl_api_snort_instance_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_snort_instance_get_reply_t_tojson,
  .fromjson = vl_api_snort_instance_get_reply_t_fromjson,
  .calc_size = vl_api_snort_instance_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SNORT_INSTANCE_DETAILS + msg_id_base,
  .name = "snort_instance_details",
  .handler = 0,
  .endian = vl_api_snort_instance_details_t_endian,
  .format_fn = vl_api_snort_instance_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_snort_instance_details_t_tojson,
  .fromjson = vl_api_snort_instance_details_t_fromjson,
  .calc_size = vl_api_snort_instance_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SNORT_INTERFACE_GET + msg_id_base,
   .name = "snort_interface_get",
   .handler = vl_api_snort_interface_get_t_handler,
   .endian = vl_api_snort_interface_get_t_endian,
   .format_fn = vl_api_snort_interface_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_snort_interface_get_t_tojson,
   .fromjson = vl_api_snort_interface_get_t_fromjson,
   .calc_size = vl_api_snort_interface_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SNORT_INTERFACE_GET_REPLY + msg_id_base,
  .name = "snort_interface_get_reply",
  .handler = 0,
  .endian = vl_api_snort_interface_get_reply_t_endian,
  .format_fn = vl_api_snort_interface_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_snort_interface_get_reply_t_tojson,
  .fromjson = vl_api_snort_interface_get_reply_t_fromjson,
  .calc_size = vl_api_snort_interface_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SNORT_INTERFACE_DETAILS + msg_id_base,
  .name = "snort_interface_details",
  .handler = 0,
  .endian = vl_api_snort_interface_details_t_endian,
  .format_fn = vl_api_snort_interface_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_snort_interface_details_t_tojson,
  .fromjson = vl_api_snort_interface_details_t_fromjson,
  .calc_size = vl_api_snort_interface_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SNORT_CLIENT_GET + msg_id_base,
   .name = "snort_client_get",
   .handler = vl_api_snort_client_get_t_handler,
   .endian = vl_api_snort_client_get_t_endian,
   .format_fn = vl_api_snort_client_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_snort_client_get_t_tojson,
   .fromjson = vl_api_snort_client_get_t_fromjson,
   .calc_size = vl_api_snort_client_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SNORT_CLIENT_GET_REPLY + msg_id_base,
  .name = "snort_client_get_reply",
  .handler = 0,
  .endian = vl_api_snort_client_get_reply_t_endian,
  .format_fn = vl_api_snort_client_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_snort_client_get_reply_t_tojson,
  .fromjson = vl_api_snort_client_get_reply_t_fromjson,
  .calc_size = vl_api_snort_client_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SNORT_CLIENT_DETAILS + msg_id_base,
  .name = "snort_client_details",
  .handler = 0,
  .endian = vl_api_snort_client_details_t_endian,
  .format_fn = vl_api_snort_client_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_snort_client_details_t_tojson,
  .fromjson = vl_api_snort_client_details_t_fromjson,
  .calc_size = vl_api_snort_client_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SNORT_INSTANCE_CREATE + msg_id_base,
   .name = "snort_instance_create",
   .handler = vl_api_snort_instance_create_t_handler,
   .endian = vl_api_snort_instance_create_t_endian,
   .format_fn = vl_api_snort_instance_create_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_snort_instance_create_t_tojson,
   .fromjson = vl_api_snort_instance_create_t_fromjson,
   .calc_size = vl_api_snort_instance_create_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SNORT_INSTANCE_CREATE_REPLY + msg_id_base,
  .name = "snort_instance_create_reply",
  .handler = 0,
  .endian = vl_api_snort_instance_create_reply_t_endian,
  .format_fn = vl_api_snort_instance_create_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_snort_instance_create_reply_t_tojson,
  .fromjson = vl_api_snort_instance_create_reply_t_fromjson,
  .calc_size = vl_api_snort_instance_create_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SNORT_INSTANCE_DELETE + msg_id_base,
   .name = "snort_instance_delete",
   .handler = vl_api_snort_instance_delete_t_handler,
   .endian = vl_api_snort_instance_delete_t_endian,
   .format_fn = vl_api_snort_instance_delete_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_snort_instance_delete_t_tojson,
   .fromjson = vl_api_snort_instance_delete_t_fromjson,
   .calc_size = vl_api_snort_instance_delete_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SNORT_INSTANCE_DELETE_REPLY + msg_id_base,
  .name = "snort_instance_delete_reply",
  .handler = 0,
  .endian = vl_api_snort_instance_delete_reply_t_endian,
  .format_fn = vl_api_snort_instance_delete_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_snort_instance_delete_reply_t_tojson,
  .fromjson = vl_api_snort_instance_delete_reply_t_fromjson,
  .calc_size = vl_api_snort_instance_delete_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SNORT_CLIENT_DISCONNECT + msg_id_base,
   .name = "snort_client_disconnect",
   .handler = vl_api_snort_client_disconnect_t_handler,
   .endian = vl_api_snort_client_disconnect_t_endian,
   .format_fn = vl_api_snort_client_disconnect_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_snort_client_disconnect_t_tojson,
   .fromjson = vl_api_snort_client_disconnect_t_fromjson,
   .calc_size = vl_api_snort_client_disconnect_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SNORT_CLIENT_DISCONNECT_REPLY + msg_id_base,
  .name = "snort_client_disconnect_reply",
  .handler = 0,
  .endian = vl_api_snort_client_disconnect_reply_t_endian,
  .format_fn = vl_api_snort_client_disconnect_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_snort_client_disconnect_reply_t_tojson,
  .fromjson = vl_api_snort_client_disconnect_reply_t_fromjson,
  .calc_size = vl_api_snort_client_disconnect_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SNORT_INSTANCE_DISCONNECT + msg_id_base,
   .name = "snort_instance_disconnect",
   .handler = vl_api_snort_instance_disconnect_t_handler,
   .endian = vl_api_snort_instance_disconnect_t_endian,
   .format_fn = vl_api_snort_instance_disconnect_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_snort_instance_disconnect_t_tojson,
   .fromjson = vl_api_snort_instance_disconnect_t_fromjson,
   .calc_size = vl_api_snort_instance_disconnect_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SNORT_INSTANCE_DISCONNECT_REPLY + msg_id_base,
  .name = "snort_instance_disconnect_reply",
  .handler = 0,
  .endian = vl_api_snort_instance_disconnect_reply_t_endian,
  .format_fn = vl_api_snort_instance_disconnect_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_snort_instance_disconnect_reply_t_tojson,
  .fromjson = vl_api_snort_instance_disconnect_reply_t_fromjson,
  .calc_size = vl_api_snort_instance_disconnect_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SNORT_INTERFACE_ATTACH + msg_id_base,
   .name = "snort_interface_attach",
   .handler = vl_api_snort_interface_attach_t_handler,
   .endian = vl_api_snort_interface_attach_t_endian,
   .format_fn = vl_api_snort_interface_attach_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_snort_interface_attach_t_tojson,
   .fromjson = vl_api_snort_interface_attach_t_fromjson,
   .calc_size = vl_api_snort_interface_attach_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SNORT_INTERFACE_ATTACH_REPLY + msg_id_base,
  .name = "snort_interface_attach_reply",
  .handler = 0,
  .endian = vl_api_snort_interface_attach_reply_t_endian,
  .format_fn = vl_api_snort_interface_attach_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_snort_interface_attach_reply_t_tojson,
  .fromjson = vl_api_snort_interface_attach_reply_t_fromjson,
  .calc_size = vl_api_snort_interface_attach_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SNORT_INTERFACE_DETACH + msg_id_base,
   .name = "snort_interface_detach",
   .handler = vl_api_snort_interface_detach_t_handler,
   .endian = vl_api_snort_interface_detach_t_endian,
   .format_fn = vl_api_snort_interface_detach_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_snort_interface_detach_t_tojson,
   .fromjson = vl_api_snort_interface_detach_t_fromjson,
   .calc_size = vl_api_snort_interface_detach_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SNORT_INTERFACE_DETACH_REPLY + msg_id_base,
  .name = "snort_interface_detach_reply",
  .handler = 0,
  .endian = vl_api_snort_interface_detach_reply_t_endian,
  .format_fn = vl_api_snort_interface_detach_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_snort_interface_detach_reply_t_tojson,
  .fromjson = vl_api_snort_interface_detach_reply_t_fromjson,
  .calc_size = vl_api_snort_interface_detach_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SNORT_INPUT_MODE_GET + msg_id_base,
   .name = "snort_input_mode_get",
   .handler = vl_api_snort_input_mode_get_t_handler,
   .endian = vl_api_snort_input_mode_get_t_endian,
   .format_fn = vl_api_snort_input_mode_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_snort_input_mode_get_t_tojson,
   .fromjson = vl_api_snort_input_mode_get_t_fromjson,
   .calc_size = vl_api_snort_input_mode_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SNORT_INPUT_MODE_GET_REPLY + msg_id_base,
  .name = "snort_input_mode_get_reply",
  .handler = 0,
  .endian = vl_api_snort_input_mode_get_reply_t_endian,
  .format_fn = vl_api_snort_input_mode_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_snort_input_mode_get_reply_t_tojson,
  .fromjson = vl_api_snort_input_mode_get_reply_t_fromjson,
  .calc_size = vl_api_snort_input_mode_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SNORT_INPUT_MODE_SET + msg_id_base,
   .name = "snort_input_mode_set",
   .handler = vl_api_snort_input_mode_set_t_handler,
   .endian = vl_api_snort_input_mode_set_t_endian,
   .format_fn = vl_api_snort_input_mode_set_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_snort_input_mode_set_t_tojson,
   .fromjson = vl_api_snort_input_mode_set_t_fromjson,
   .calc_size = vl_api_snort_input_mode_set_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SNORT_INPUT_MODE_SET_REPLY + msg_id_base,
  .name = "snort_input_mode_set_reply",
  .handler = 0,
  .endian = vl_api_snort_input_mode_set_reply_t_endian,
  .format_fn = vl_api_snort_input_mode_set_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_snort_input_mode_set_reply_t_tojson,
  .fromjson = vl_api_snort_input_mode_set_reply_t_fromjson,
  .calc_size = vl_api_snort_input_mode_set_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
