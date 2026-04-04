#define vl_endianfun		/* define message structures */
#include "lisp_gpe.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "lisp_gpe.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "lisp_gpe.api.h"
#undef vl_printfun

#include "lisp_gpe.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("lisp_gpe_29addfc9", VL_MSG_LISP_GPE_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_lisp_gpe);
   vl_msg_api_add_msg_name_crc (am, "gpe_add_del_fwd_entry_f0847644",
                                VL_API_GPE_ADD_DEL_FWD_ENTRY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gpe_add_del_fwd_entry_reply_efe5f176",
                                VL_API_GPE_ADD_DEL_FWD_ENTRY_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gpe_enable_disable_c264d7bf",
                                VL_API_GPE_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gpe_enable_disable_reply_e8d4e804",
                                VL_API_GPE_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gpe_add_del_iface_3ccff273",
                                VL_API_GPE_ADD_DEL_IFACE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gpe_add_del_iface_reply_e8d4e804",
                                VL_API_GPE_ADD_DEL_IFACE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gpe_fwd_entry_vnis_get_51077d14",
                                VL_API_GPE_FWD_ENTRY_VNIS_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gpe_fwd_entry_vnis_get_reply_aa70da20",
                                VL_API_GPE_FWD_ENTRY_VNIS_GET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gpe_fwd_entries_get_8d1f2fe9",
                                VL_API_GPE_FWD_ENTRIES_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gpe_fwd_entries_get_reply_c4844876",
                                VL_API_GPE_FWD_ENTRIES_GET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gpe_fwd_entry_path_dump_39bce980",
                                VL_API_GPE_FWD_ENTRY_PATH_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gpe_fwd_entry_path_details_483df51a",
                                VL_API_GPE_FWD_ENTRY_PATH_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gpe_set_encap_mode_bd819eac",
                                VL_API_GPE_SET_ENCAP_MODE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gpe_set_encap_mode_reply_e8d4e804",
                                VL_API_GPE_SET_ENCAP_MODE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gpe_get_encap_mode_51077d14",
                                VL_API_GPE_GET_ENCAP_MODE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gpe_get_encap_mode_reply_36e3f7ca",
                                VL_API_GPE_GET_ENCAP_MODE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gpe_add_del_native_fwd_rpath_43fc8b54",
                                VL_API_GPE_ADD_DEL_NATIVE_FWD_RPATH + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gpe_add_del_native_fwd_rpath_reply_e8d4e804",
                                VL_API_GPE_ADD_DEL_NATIVE_FWD_RPATH_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gpe_native_fwd_rpaths_get_f652ceb4",
                                VL_API_GPE_NATIVE_FWD_RPATHS_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gpe_native_fwd_rpaths_get_reply_7a1ca5a2",
                                VL_API_GPE_NATIVE_FWD_RPATHS_GET_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_GPE_ADD_DEL_FWD_ENTRY + msg_id_base,
   .name = "gpe_add_del_fwd_entry",
   .handler = vl_api_gpe_add_del_fwd_entry_t_handler,
   .endian = vl_api_gpe_add_del_fwd_entry_t_endian,
   .format_fn = vl_api_gpe_add_del_fwd_entry_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_gpe_add_del_fwd_entry_t_tojson,
   .fromjson = vl_api_gpe_add_del_fwd_entry_t_fromjson,
   .calc_size = vl_api_gpe_add_del_fwd_entry_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_GPE_ADD_DEL_FWD_ENTRY_REPLY + msg_id_base,
  .name = "gpe_add_del_fwd_entry_reply",
  .handler = 0,
  .endian = vl_api_gpe_add_del_fwd_entry_reply_t_endian,
  .format_fn = vl_api_gpe_add_del_fwd_entry_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_gpe_add_del_fwd_entry_reply_t_tojson,
  .fromjson = vl_api_gpe_add_del_fwd_entry_reply_t_fromjson,
  .calc_size = vl_api_gpe_add_del_fwd_entry_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_GPE_ENABLE_DISABLE + msg_id_base,
   .name = "gpe_enable_disable",
   .handler = vl_api_gpe_enable_disable_t_handler,
   .endian = vl_api_gpe_enable_disable_t_endian,
   .format_fn = vl_api_gpe_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_gpe_enable_disable_t_tojson,
   .fromjson = vl_api_gpe_enable_disable_t_fromjson,
   .calc_size = vl_api_gpe_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_GPE_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "gpe_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_gpe_enable_disable_reply_t_endian,
  .format_fn = vl_api_gpe_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_gpe_enable_disable_reply_t_tojson,
  .fromjson = vl_api_gpe_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_gpe_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_GPE_ADD_DEL_IFACE + msg_id_base,
   .name = "gpe_add_del_iface",
   .handler = vl_api_gpe_add_del_iface_t_handler,
   .endian = vl_api_gpe_add_del_iface_t_endian,
   .format_fn = vl_api_gpe_add_del_iface_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_gpe_add_del_iface_t_tojson,
   .fromjson = vl_api_gpe_add_del_iface_t_fromjson,
   .calc_size = vl_api_gpe_add_del_iface_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_GPE_ADD_DEL_IFACE_REPLY + msg_id_base,
  .name = "gpe_add_del_iface_reply",
  .handler = 0,
  .endian = vl_api_gpe_add_del_iface_reply_t_endian,
  .format_fn = vl_api_gpe_add_del_iface_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_gpe_add_del_iface_reply_t_tojson,
  .fromjson = vl_api_gpe_add_del_iface_reply_t_fromjson,
  .calc_size = vl_api_gpe_add_del_iface_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_GPE_FWD_ENTRY_VNIS_GET + msg_id_base,
   .name = "gpe_fwd_entry_vnis_get",
   .handler = vl_api_gpe_fwd_entry_vnis_get_t_handler,
   .endian = vl_api_gpe_fwd_entry_vnis_get_t_endian,
   .format_fn = vl_api_gpe_fwd_entry_vnis_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_gpe_fwd_entry_vnis_get_t_tojson,
   .fromjson = vl_api_gpe_fwd_entry_vnis_get_t_fromjson,
   .calc_size = vl_api_gpe_fwd_entry_vnis_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_GPE_FWD_ENTRY_VNIS_GET_REPLY + msg_id_base,
  .name = "gpe_fwd_entry_vnis_get_reply",
  .handler = 0,
  .endian = vl_api_gpe_fwd_entry_vnis_get_reply_t_endian,
  .format_fn = vl_api_gpe_fwd_entry_vnis_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_gpe_fwd_entry_vnis_get_reply_t_tojson,
  .fromjson = vl_api_gpe_fwd_entry_vnis_get_reply_t_fromjson,
  .calc_size = vl_api_gpe_fwd_entry_vnis_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_GPE_FWD_ENTRIES_GET + msg_id_base,
   .name = "gpe_fwd_entries_get",
   .handler = vl_api_gpe_fwd_entries_get_t_handler,
   .endian = vl_api_gpe_fwd_entries_get_t_endian,
   .format_fn = vl_api_gpe_fwd_entries_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_gpe_fwd_entries_get_t_tojson,
   .fromjson = vl_api_gpe_fwd_entries_get_t_fromjson,
   .calc_size = vl_api_gpe_fwd_entries_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_GPE_FWD_ENTRIES_GET_REPLY + msg_id_base,
  .name = "gpe_fwd_entries_get_reply",
  .handler = 0,
  .endian = vl_api_gpe_fwd_entries_get_reply_t_endian,
  .format_fn = vl_api_gpe_fwd_entries_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_gpe_fwd_entries_get_reply_t_tojson,
  .fromjson = vl_api_gpe_fwd_entries_get_reply_t_fromjson,
  .calc_size = vl_api_gpe_fwd_entries_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_GPE_FWD_ENTRY_PATH_DUMP + msg_id_base,
   .name = "gpe_fwd_entry_path_dump",
   .handler = vl_api_gpe_fwd_entry_path_dump_t_handler,
   .endian = vl_api_gpe_fwd_entry_path_dump_t_endian,
   .format_fn = vl_api_gpe_fwd_entry_path_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_gpe_fwd_entry_path_dump_t_tojson,
   .fromjson = vl_api_gpe_fwd_entry_path_dump_t_fromjson,
   .calc_size = vl_api_gpe_fwd_entry_path_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_GPE_FWD_ENTRY_PATH_DETAILS + msg_id_base,
  .name = "gpe_fwd_entry_path_details",
  .handler = 0,
  .endian = vl_api_gpe_fwd_entry_path_details_t_endian,
  .format_fn = vl_api_gpe_fwd_entry_path_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_gpe_fwd_entry_path_details_t_tojson,
  .fromjson = vl_api_gpe_fwd_entry_path_details_t_fromjson,
  .calc_size = vl_api_gpe_fwd_entry_path_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_GPE_SET_ENCAP_MODE + msg_id_base,
   .name = "gpe_set_encap_mode",
   .handler = vl_api_gpe_set_encap_mode_t_handler,
   .endian = vl_api_gpe_set_encap_mode_t_endian,
   .format_fn = vl_api_gpe_set_encap_mode_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_gpe_set_encap_mode_t_tojson,
   .fromjson = vl_api_gpe_set_encap_mode_t_fromjson,
   .calc_size = vl_api_gpe_set_encap_mode_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_GPE_SET_ENCAP_MODE_REPLY + msg_id_base,
  .name = "gpe_set_encap_mode_reply",
  .handler = 0,
  .endian = vl_api_gpe_set_encap_mode_reply_t_endian,
  .format_fn = vl_api_gpe_set_encap_mode_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_gpe_set_encap_mode_reply_t_tojson,
  .fromjson = vl_api_gpe_set_encap_mode_reply_t_fromjson,
  .calc_size = vl_api_gpe_set_encap_mode_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_GPE_GET_ENCAP_MODE + msg_id_base,
   .name = "gpe_get_encap_mode",
   .handler = vl_api_gpe_get_encap_mode_t_handler,
   .endian = vl_api_gpe_get_encap_mode_t_endian,
   .format_fn = vl_api_gpe_get_encap_mode_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_gpe_get_encap_mode_t_tojson,
   .fromjson = vl_api_gpe_get_encap_mode_t_fromjson,
   .calc_size = vl_api_gpe_get_encap_mode_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_GPE_GET_ENCAP_MODE_REPLY + msg_id_base,
  .name = "gpe_get_encap_mode_reply",
  .handler = 0,
  .endian = vl_api_gpe_get_encap_mode_reply_t_endian,
  .format_fn = vl_api_gpe_get_encap_mode_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_gpe_get_encap_mode_reply_t_tojson,
  .fromjson = vl_api_gpe_get_encap_mode_reply_t_fromjson,
  .calc_size = vl_api_gpe_get_encap_mode_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_GPE_ADD_DEL_NATIVE_FWD_RPATH + msg_id_base,
   .name = "gpe_add_del_native_fwd_rpath",
   .handler = vl_api_gpe_add_del_native_fwd_rpath_t_handler,
   .endian = vl_api_gpe_add_del_native_fwd_rpath_t_endian,
   .format_fn = vl_api_gpe_add_del_native_fwd_rpath_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_gpe_add_del_native_fwd_rpath_t_tojson,
   .fromjson = vl_api_gpe_add_del_native_fwd_rpath_t_fromjson,
   .calc_size = vl_api_gpe_add_del_native_fwd_rpath_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_GPE_ADD_DEL_NATIVE_FWD_RPATH_REPLY + msg_id_base,
  .name = "gpe_add_del_native_fwd_rpath_reply",
  .handler = 0,
  .endian = vl_api_gpe_add_del_native_fwd_rpath_reply_t_endian,
  .format_fn = vl_api_gpe_add_del_native_fwd_rpath_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_gpe_add_del_native_fwd_rpath_reply_t_tojson,
  .fromjson = vl_api_gpe_add_del_native_fwd_rpath_reply_t_fromjson,
  .calc_size = vl_api_gpe_add_del_native_fwd_rpath_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_GPE_NATIVE_FWD_RPATHS_GET + msg_id_base,
   .name = "gpe_native_fwd_rpaths_get",
   .handler = vl_api_gpe_native_fwd_rpaths_get_t_handler,
   .endian = vl_api_gpe_native_fwd_rpaths_get_t_endian,
   .format_fn = vl_api_gpe_native_fwd_rpaths_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_gpe_native_fwd_rpaths_get_t_tojson,
   .fromjson = vl_api_gpe_native_fwd_rpaths_get_t_fromjson,
   .calc_size = vl_api_gpe_native_fwd_rpaths_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_GPE_NATIVE_FWD_RPATHS_GET_REPLY + msg_id_base,
  .name = "gpe_native_fwd_rpaths_get_reply",
  .handler = 0,
  .endian = vl_api_gpe_native_fwd_rpaths_get_reply_t_endian,
  .format_fn = vl_api_gpe_native_fwd_rpaths_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_gpe_native_fwd_rpaths_get_reply_t_tojson,
  .fromjson = vl_api_gpe_native_fwd_rpaths_get_reply_t_fromjson,
  .calc_size = vl_api_gpe_native_fwd_rpaths_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
