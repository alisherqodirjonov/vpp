#define vl_endianfun		/* define message structures */
#include "ioam_vxlan_gpe.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "ioam_vxlan_gpe.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "ioam_vxlan_gpe.api.h"
#undef vl_printfun

#include "ioam_vxlan_gpe.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("ioam_vxlan_gpe_b9e086eb", VL_MSG_IOAM_VXLAN_GPE_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_ioam_vxlan_gpe);
   vl_msg_api_add_msg_name_crc (am, "vxlan_gpe_ioam_enable_2481bef7",
                                VL_API_VXLAN_GPE_IOAM_ENABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "vxlan_gpe_ioam_enable_reply_e8d4e804",
                                VL_API_VXLAN_GPE_IOAM_ENABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "vxlan_gpe_ioam_disable_6b16a45e",
                                VL_API_VXLAN_GPE_IOAM_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "vxlan_gpe_ioam_disable_reply_e8d4e804",
                                VL_API_VXLAN_GPE_IOAM_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "vxlan_gpe_ioam_vni_enable_0fbb5fb1",
                                VL_API_VXLAN_GPE_IOAM_VNI_ENABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "vxlan_gpe_ioam_vni_enable_reply_e8d4e804",
                                VL_API_VXLAN_GPE_IOAM_VNI_ENABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "vxlan_gpe_ioam_vni_disable_0fbb5fb1",
                                VL_API_VXLAN_GPE_IOAM_VNI_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "vxlan_gpe_ioam_vni_disable_reply_e8d4e804",
                                VL_API_VXLAN_GPE_IOAM_VNI_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "vxlan_gpe_ioam_transit_enable_3d3ec657",
                                VL_API_VXLAN_GPE_IOAM_TRANSIT_ENABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "vxlan_gpe_ioam_transit_enable_reply_e8d4e804",
                                VL_API_VXLAN_GPE_IOAM_TRANSIT_ENABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "vxlan_gpe_ioam_transit_disable_3d3ec657",
                                VL_API_VXLAN_GPE_IOAM_TRANSIT_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "vxlan_gpe_ioam_transit_disable_reply_e8d4e804",
                                VL_API_VXLAN_GPE_IOAM_TRANSIT_DISABLE_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_VXLAN_GPE_IOAM_ENABLE + msg_id_base,
   .name = "vxlan_gpe_ioam_enable",
   .handler = vl_api_vxlan_gpe_ioam_enable_t_handler,
   .endian = vl_api_vxlan_gpe_ioam_enable_t_endian,
   .format_fn = vl_api_vxlan_gpe_ioam_enable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_vxlan_gpe_ioam_enable_t_tojson,
   .fromjson = vl_api_vxlan_gpe_ioam_enable_t_fromjson,
   .calc_size = vl_api_vxlan_gpe_ioam_enable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_VXLAN_GPE_IOAM_ENABLE_REPLY + msg_id_base,
  .name = "vxlan_gpe_ioam_enable_reply",
  .handler = 0,
  .endian = vl_api_vxlan_gpe_ioam_enable_reply_t_endian,
  .format_fn = vl_api_vxlan_gpe_ioam_enable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_vxlan_gpe_ioam_enable_reply_t_tojson,
  .fromjson = vl_api_vxlan_gpe_ioam_enable_reply_t_fromjson,
  .calc_size = vl_api_vxlan_gpe_ioam_enable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_VXLAN_GPE_IOAM_DISABLE + msg_id_base,
   .name = "vxlan_gpe_ioam_disable",
   .handler = vl_api_vxlan_gpe_ioam_disable_t_handler,
   .endian = vl_api_vxlan_gpe_ioam_disable_t_endian,
   .format_fn = vl_api_vxlan_gpe_ioam_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_vxlan_gpe_ioam_disable_t_tojson,
   .fromjson = vl_api_vxlan_gpe_ioam_disable_t_fromjson,
   .calc_size = vl_api_vxlan_gpe_ioam_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_VXLAN_GPE_IOAM_DISABLE_REPLY + msg_id_base,
  .name = "vxlan_gpe_ioam_disable_reply",
  .handler = 0,
  .endian = vl_api_vxlan_gpe_ioam_disable_reply_t_endian,
  .format_fn = vl_api_vxlan_gpe_ioam_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_vxlan_gpe_ioam_disable_reply_t_tojson,
  .fromjson = vl_api_vxlan_gpe_ioam_disable_reply_t_fromjson,
  .calc_size = vl_api_vxlan_gpe_ioam_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_VXLAN_GPE_IOAM_VNI_ENABLE + msg_id_base,
   .name = "vxlan_gpe_ioam_vni_enable",
   .handler = vl_api_vxlan_gpe_ioam_vni_enable_t_handler,
   .endian = vl_api_vxlan_gpe_ioam_vni_enable_t_endian,
   .format_fn = vl_api_vxlan_gpe_ioam_vni_enable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_vxlan_gpe_ioam_vni_enable_t_tojson,
   .fromjson = vl_api_vxlan_gpe_ioam_vni_enable_t_fromjson,
   .calc_size = vl_api_vxlan_gpe_ioam_vni_enable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_VXLAN_GPE_IOAM_VNI_ENABLE_REPLY + msg_id_base,
  .name = "vxlan_gpe_ioam_vni_enable_reply",
  .handler = 0,
  .endian = vl_api_vxlan_gpe_ioam_vni_enable_reply_t_endian,
  .format_fn = vl_api_vxlan_gpe_ioam_vni_enable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_vxlan_gpe_ioam_vni_enable_reply_t_tojson,
  .fromjson = vl_api_vxlan_gpe_ioam_vni_enable_reply_t_fromjson,
  .calc_size = vl_api_vxlan_gpe_ioam_vni_enable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_VXLAN_GPE_IOAM_VNI_DISABLE + msg_id_base,
   .name = "vxlan_gpe_ioam_vni_disable",
   .handler = vl_api_vxlan_gpe_ioam_vni_disable_t_handler,
   .endian = vl_api_vxlan_gpe_ioam_vni_disable_t_endian,
   .format_fn = vl_api_vxlan_gpe_ioam_vni_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_vxlan_gpe_ioam_vni_disable_t_tojson,
   .fromjson = vl_api_vxlan_gpe_ioam_vni_disable_t_fromjson,
   .calc_size = vl_api_vxlan_gpe_ioam_vni_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_VXLAN_GPE_IOAM_VNI_DISABLE_REPLY + msg_id_base,
  .name = "vxlan_gpe_ioam_vni_disable_reply",
  .handler = 0,
  .endian = vl_api_vxlan_gpe_ioam_vni_disable_reply_t_endian,
  .format_fn = vl_api_vxlan_gpe_ioam_vni_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_vxlan_gpe_ioam_vni_disable_reply_t_tojson,
  .fromjson = vl_api_vxlan_gpe_ioam_vni_disable_reply_t_fromjson,
  .calc_size = vl_api_vxlan_gpe_ioam_vni_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_VXLAN_GPE_IOAM_TRANSIT_ENABLE + msg_id_base,
   .name = "vxlan_gpe_ioam_transit_enable",
   .handler = vl_api_vxlan_gpe_ioam_transit_enable_t_handler,
   .endian = vl_api_vxlan_gpe_ioam_transit_enable_t_endian,
   .format_fn = vl_api_vxlan_gpe_ioam_transit_enable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_vxlan_gpe_ioam_transit_enable_t_tojson,
   .fromjson = vl_api_vxlan_gpe_ioam_transit_enable_t_fromjson,
   .calc_size = vl_api_vxlan_gpe_ioam_transit_enable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_VXLAN_GPE_IOAM_TRANSIT_ENABLE_REPLY + msg_id_base,
  .name = "vxlan_gpe_ioam_transit_enable_reply",
  .handler = 0,
  .endian = vl_api_vxlan_gpe_ioam_transit_enable_reply_t_endian,
  .format_fn = vl_api_vxlan_gpe_ioam_transit_enable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_vxlan_gpe_ioam_transit_enable_reply_t_tojson,
  .fromjson = vl_api_vxlan_gpe_ioam_transit_enable_reply_t_fromjson,
  .calc_size = vl_api_vxlan_gpe_ioam_transit_enable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_VXLAN_GPE_IOAM_TRANSIT_DISABLE + msg_id_base,
   .name = "vxlan_gpe_ioam_transit_disable",
   .handler = vl_api_vxlan_gpe_ioam_transit_disable_t_handler,
   .endian = vl_api_vxlan_gpe_ioam_transit_disable_t_endian,
   .format_fn = vl_api_vxlan_gpe_ioam_transit_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_vxlan_gpe_ioam_transit_disable_t_tojson,
   .fromjson = vl_api_vxlan_gpe_ioam_transit_disable_t_fromjson,
   .calc_size = vl_api_vxlan_gpe_ioam_transit_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_VXLAN_GPE_IOAM_TRANSIT_DISABLE_REPLY + msg_id_base,
  .name = "vxlan_gpe_ioam_transit_disable_reply",
  .handler = 0,
  .endian = vl_api_vxlan_gpe_ioam_transit_disable_reply_t_endian,
  .format_fn = vl_api_vxlan_gpe_ioam_transit_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_vxlan_gpe_ioam_transit_disable_reply_t_tojson,
  .fromjson = vl_api_vxlan_gpe_ioam_transit_disable_reply_t_fromjson,
  .calc_size = vl_api_vxlan_gpe_ioam_transit_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
