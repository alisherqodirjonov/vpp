#define vl_endianfun		/* define message structures */
#include "lacp.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "lacp.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "lacp.api.h"
#undef vl_printfun

#include "lacp.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("lacp_8975258e", VL_MSG_LACP_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_lacp);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_lacp_dump_51077d14",
                                VL_API_SW_INTERFACE_LACP_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_lacp_details_d9a83d2f",
                                VL_API_SW_INTERFACE_LACP_DETAILS + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_LACP_DUMP + msg_id_base,
   .name = "sw_interface_lacp_dump",
   .handler = vl_api_sw_interface_lacp_dump_t_handler,
   .endian = vl_api_sw_interface_lacp_dump_t_endian,
   .format_fn = vl_api_sw_interface_lacp_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_lacp_dump_t_tojson,
   .fromjson = vl_api_sw_interface_lacp_dump_t_fromjson,
   .calc_size = vl_api_sw_interface_lacp_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_LACP_DETAILS + msg_id_base,
  .name = "sw_interface_lacp_details",
  .handler = 0,
  .endian = vl_api_sw_interface_lacp_details_t_endian,
  .format_fn = vl_api_sw_interface_lacp_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_lacp_details_t_tojson,
  .fromjson = vl_api_sw_interface_lacp_details_t_fromjson,
  .calc_size = vl_api_sw_interface_lacp_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
