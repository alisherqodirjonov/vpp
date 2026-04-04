#define vl_endianfun		/* define message structures */
#include "vmxnet3.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "vmxnet3.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "vmxnet3.api.h"
#undef vl_printfun

#include "vmxnet3.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("vmxnet3_233e078b", VL_MSG_VMXNET3_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_vmxnet3);
   vl_msg_api_add_msg_name_crc (am, "vmxnet3_create_71a07314",
                                VL_API_VMXNET3_CREATE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "vmxnet3_create_reply_5383d31f",
                                VL_API_VMXNET3_CREATE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "vmxnet3_delete_f9e6675e",
                                VL_API_VMXNET3_DELETE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "vmxnet3_delete_reply_e8d4e804",
                                VL_API_VMXNET3_DELETE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "vmxnet3_details_6a1a5498",
                                VL_API_VMXNET3_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "vmxnet3_dump_51077d14",
                                VL_API_VMXNET3_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_vmxnet3_interface_dump_f9e6675e",
                                VL_API_SW_VMXNET3_INTERFACE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_vmxnet3_interface_details_6a1a5498",
                                VL_API_SW_VMXNET3_INTERFACE_DETAILS + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_VMXNET3_CREATE + msg_id_base,
   .name = "vmxnet3_create",
   .handler = vl_api_vmxnet3_create_t_handler,
   .endian = vl_api_vmxnet3_create_t_endian,
   .format_fn = vl_api_vmxnet3_create_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_vmxnet3_create_t_tojson,
   .fromjson = vl_api_vmxnet3_create_t_fromjson,
   .calc_size = vl_api_vmxnet3_create_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_VMXNET3_CREATE_REPLY + msg_id_base,
  .name = "vmxnet3_create_reply",
  .handler = 0,
  .endian = vl_api_vmxnet3_create_reply_t_endian,
  .format_fn = vl_api_vmxnet3_create_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_vmxnet3_create_reply_t_tojson,
  .fromjson = vl_api_vmxnet3_create_reply_t_fromjson,
  .calc_size = vl_api_vmxnet3_create_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_VMXNET3_DELETE + msg_id_base,
   .name = "vmxnet3_delete",
   .handler = vl_api_vmxnet3_delete_t_handler,
   .endian = vl_api_vmxnet3_delete_t_endian,
   .format_fn = vl_api_vmxnet3_delete_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_vmxnet3_delete_t_tojson,
   .fromjson = vl_api_vmxnet3_delete_t_fromjson,
   .calc_size = vl_api_vmxnet3_delete_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_VMXNET3_DELETE_REPLY + msg_id_base,
  .name = "vmxnet3_delete_reply",
  .handler = 0,
  .endian = vl_api_vmxnet3_delete_reply_t_endian,
  .format_fn = vl_api_vmxnet3_delete_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_vmxnet3_delete_reply_t_tojson,
  .fromjson = vl_api_vmxnet3_delete_reply_t_fromjson,
  .calc_size = vl_api_vmxnet3_delete_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_VMXNET3_DUMP + msg_id_base,
   .name = "vmxnet3_dump",
   .handler = vl_api_vmxnet3_dump_t_handler,
   .endian = vl_api_vmxnet3_dump_t_endian,
   .format_fn = vl_api_vmxnet3_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_vmxnet3_dump_t_tojson,
   .fromjson = vl_api_vmxnet3_dump_t_fromjson,
   .calc_size = vl_api_vmxnet3_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_VMXNET3_DETAILS + msg_id_base,
  .name = "vmxnet3_details",
  .handler = 0,
  .endian = vl_api_vmxnet3_details_t_endian,
  .format_fn = vl_api_vmxnet3_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_vmxnet3_details_t_tojson,
  .fromjson = vl_api_vmxnet3_details_t_fromjson,
  .calc_size = vl_api_vmxnet3_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_VMXNET3_INTERFACE_DUMP + msg_id_base,
   .name = "sw_vmxnet3_interface_dump",
   .handler = vl_api_sw_vmxnet3_interface_dump_t_handler,
   .endian = vl_api_sw_vmxnet3_interface_dump_t_endian,
   .format_fn = vl_api_sw_vmxnet3_interface_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_vmxnet3_interface_dump_t_tojson,
   .fromjson = vl_api_sw_vmxnet3_interface_dump_t_fromjson,
   .calc_size = vl_api_sw_vmxnet3_interface_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_VMXNET3_INTERFACE_DETAILS + msg_id_base,
  .name = "sw_vmxnet3_interface_details",
  .handler = 0,
  .endian = vl_api_sw_vmxnet3_interface_details_t_endian,
  .format_fn = vl_api_sw_vmxnet3_interface_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_vmxnet3_interface_details_t_tojson,
  .fromjson = vl_api_sw_vmxnet3_interface_details_t_fromjson,
  .calc_size = vl_api_sw_vmxnet3_interface_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
