#define vl_endianfun		/* define message structures */
#include "lisp.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "lisp.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "lisp.api.h"
#undef vl_printfun

#include "lisp.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("lisp_2ec1dfcd", VL_MSG_LISP_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_lisp);
   vl_msg_api_add_msg_name_crc (am, "lisp_add_del_locator_set_6fcd6471",
                                VL_API_LISP_ADD_DEL_LOCATOR_SET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_add_del_locator_set_reply_b6666db4",
                                VL_API_LISP_ADD_DEL_LOCATOR_SET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_add_del_locator_af4d8f13",
                                VL_API_LISP_ADD_DEL_LOCATOR + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_add_del_locator_reply_e8d4e804",
                                VL_API_LISP_ADD_DEL_LOCATOR_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_add_del_local_eid_4e5a83a2",
                                VL_API_LISP_ADD_DEL_LOCAL_EID + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_add_del_local_eid_reply_e8d4e804",
                                VL_API_LISP_ADD_DEL_LOCAL_EID_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_add_del_map_server_ce19e32d",
                                VL_API_LISP_ADD_DEL_MAP_SERVER + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_add_del_map_server_reply_e8d4e804",
                                VL_API_LISP_ADD_DEL_MAP_SERVER_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_add_del_map_resolver_ce19e32d",
                                VL_API_LISP_ADD_DEL_MAP_RESOLVER + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_add_del_map_resolver_reply_e8d4e804",
                                VL_API_LISP_ADD_DEL_MAP_RESOLVER_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_enable_disable_c264d7bf",
                                VL_API_LISP_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_enable_disable_reply_e8d4e804",
                                VL_API_LISP_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_pitr_set_locator_set_486e2b76",
                                VL_API_LISP_PITR_SET_LOCATOR_SET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_pitr_set_locator_set_reply_e8d4e804",
                                VL_API_LISP_PITR_SET_LOCATOR_SET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_use_petr_d87dbad9",
                                VL_API_LISP_USE_PETR + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_use_petr_reply_e8d4e804",
                                VL_API_LISP_USE_PETR_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_lisp_use_petr_51077d14",
                                VL_API_SHOW_LISP_USE_PETR + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_lisp_use_petr_reply_22b9a4b0",
                                VL_API_SHOW_LISP_USE_PETR_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_lisp_rloc_probe_state_51077d14",
                                VL_API_SHOW_LISP_RLOC_PROBE_STATE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_lisp_rloc_probe_state_reply_e33a377b",
                                VL_API_SHOW_LISP_RLOC_PROBE_STATE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_rloc_probe_enable_disable_c264d7bf",
                                VL_API_LISP_RLOC_PROBE_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_rloc_probe_enable_disable_reply_e8d4e804",
                                VL_API_LISP_RLOC_PROBE_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_map_register_enable_disable_c264d7bf",
                                VL_API_LISP_MAP_REGISTER_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_map_register_enable_disable_reply_e8d4e804",
                                VL_API_LISP_MAP_REGISTER_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_lisp_map_register_state_51077d14",
                                VL_API_SHOW_LISP_MAP_REGISTER_STATE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_lisp_map_register_state_reply_e33a377b",
                                VL_API_SHOW_LISP_MAP_REGISTER_STATE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_map_request_mode_f43c26ae",
                                VL_API_LISP_MAP_REQUEST_MODE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_map_request_mode_reply_e8d4e804",
                                VL_API_LISP_MAP_REQUEST_MODE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_lisp_map_request_mode_51077d14",
                                VL_API_SHOW_LISP_MAP_REQUEST_MODE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_lisp_map_request_mode_reply_5b05038e",
                                VL_API_SHOW_LISP_MAP_REQUEST_MODE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_add_del_remote_mapping_6d5c789e",
                                VL_API_LISP_ADD_DEL_REMOTE_MAPPING + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_add_del_remote_mapping_reply_e8d4e804",
                                VL_API_LISP_ADD_DEL_REMOTE_MAPPING_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_add_del_adjacency_2ce0e6f6",
                                VL_API_LISP_ADD_DEL_ADJACENCY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_add_del_adjacency_reply_e8d4e804",
                                VL_API_LISP_ADD_DEL_ADJACENCY_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_add_del_map_request_itr_rlocs_6be88e45",
                                VL_API_LISP_ADD_DEL_MAP_REQUEST_ITR_RLOCS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_add_del_map_request_itr_rlocs_reply_e8d4e804",
                                VL_API_LISP_ADD_DEL_MAP_REQUEST_ITR_RLOCS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_eid_table_add_del_map_9481416b",
                                VL_API_LISP_EID_TABLE_ADD_DEL_MAP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_eid_table_add_del_map_reply_e8d4e804",
                                VL_API_LISP_EID_TABLE_ADD_DEL_MAP_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_locator_dump_b954fad7",
                                VL_API_LISP_LOCATOR_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_locator_details_2c620ffe",
                                VL_API_LISP_LOCATOR_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_locator_set_details_5b33a105",
                                VL_API_LISP_LOCATOR_SET_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_locator_set_dump_c2cb5922",
                                VL_API_LISP_LOCATOR_SET_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_eid_table_details_1c29f792",
                                VL_API_LISP_EID_TABLE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_eid_table_dump_629468b5",
                                VL_API_LISP_EID_TABLE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_adjacencies_get_reply_807257bf",
                                VL_API_LISP_ADJACENCIES_GET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_adjacencies_get_8d1f2fe9",
                                VL_API_LISP_ADJACENCIES_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_eid_table_map_details_0b6859e2",
                                VL_API_LISP_EID_TABLE_MAP_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_eid_table_map_dump_d6cf0c3d",
                                VL_API_LISP_EID_TABLE_MAP_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_eid_table_vni_dump_51077d14",
                                VL_API_LISP_EID_TABLE_VNI_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_eid_table_vni_details_64abc01e",
                                VL_API_LISP_EID_TABLE_VNI_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_map_resolver_details_3e78fc57",
                                VL_API_LISP_MAP_RESOLVER_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_map_resolver_dump_51077d14",
                                VL_API_LISP_MAP_RESOLVER_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_map_server_details_3e78fc57",
                                VL_API_LISP_MAP_SERVER_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_map_server_dump_51077d14",
                                VL_API_LISP_MAP_SERVER_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_lisp_status_51077d14",
                                VL_API_SHOW_LISP_STATUS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_lisp_status_reply_9e8f10c0",
                                VL_API_SHOW_LISP_STATUS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_get_map_request_itr_rlocs_51077d14",
                                VL_API_LISP_GET_MAP_REQUEST_ITR_RLOCS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lisp_get_map_request_itr_rlocs_reply_76580f3a",
                                VL_API_LISP_GET_MAP_REQUEST_ITR_RLOCS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_lisp_pitr_51077d14",
                                VL_API_SHOW_LISP_PITR + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_lisp_pitr_reply_27aa69b1",
                                VL_API_SHOW_LISP_PITR_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LISP_ADD_DEL_LOCATOR_SET + msg_id_base,
   .name = "lisp_add_del_locator_set",
   .handler = vl_api_lisp_add_del_locator_set_t_handler,
   .endian = vl_api_lisp_add_del_locator_set_t_endian,
   .format_fn = vl_api_lisp_add_del_locator_set_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lisp_add_del_locator_set_t_tojson,
   .fromjson = vl_api_lisp_add_del_locator_set_t_fromjson,
   .calc_size = vl_api_lisp_add_del_locator_set_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LISP_ADD_DEL_LOCATOR_SET_REPLY + msg_id_base,
  .name = "lisp_add_del_locator_set_reply",
  .handler = 0,
  .endian = vl_api_lisp_add_del_locator_set_reply_t_endian,
  .format_fn = vl_api_lisp_add_del_locator_set_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lisp_add_del_locator_set_reply_t_tojson,
  .fromjson = vl_api_lisp_add_del_locator_set_reply_t_fromjson,
  .calc_size = vl_api_lisp_add_del_locator_set_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LISP_ADD_DEL_LOCATOR + msg_id_base,
   .name = "lisp_add_del_locator",
   .handler = vl_api_lisp_add_del_locator_t_handler,
   .endian = vl_api_lisp_add_del_locator_t_endian,
   .format_fn = vl_api_lisp_add_del_locator_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lisp_add_del_locator_t_tojson,
   .fromjson = vl_api_lisp_add_del_locator_t_fromjson,
   .calc_size = vl_api_lisp_add_del_locator_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LISP_ADD_DEL_LOCATOR_REPLY + msg_id_base,
  .name = "lisp_add_del_locator_reply",
  .handler = 0,
  .endian = vl_api_lisp_add_del_locator_reply_t_endian,
  .format_fn = vl_api_lisp_add_del_locator_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lisp_add_del_locator_reply_t_tojson,
  .fromjson = vl_api_lisp_add_del_locator_reply_t_fromjson,
  .calc_size = vl_api_lisp_add_del_locator_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LISP_ADD_DEL_LOCAL_EID + msg_id_base,
   .name = "lisp_add_del_local_eid",
   .handler = vl_api_lisp_add_del_local_eid_t_handler,
   .endian = vl_api_lisp_add_del_local_eid_t_endian,
   .format_fn = vl_api_lisp_add_del_local_eid_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lisp_add_del_local_eid_t_tojson,
   .fromjson = vl_api_lisp_add_del_local_eid_t_fromjson,
   .calc_size = vl_api_lisp_add_del_local_eid_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LISP_ADD_DEL_LOCAL_EID_REPLY + msg_id_base,
  .name = "lisp_add_del_local_eid_reply",
  .handler = 0,
  .endian = vl_api_lisp_add_del_local_eid_reply_t_endian,
  .format_fn = vl_api_lisp_add_del_local_eid_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lisp_add_del_local_eid_reply_t_tojson,
  .fromjson = vl_api_lisp_add_del_local_eid_reply_t_fromjson,
  .calc_size = vl_api_lisp_add_del_local_eid_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LISP_ADD_DEL_MAP_SERVER + msg_id_base,
   .name = "lisp_add_del_map_server",
   .handler = vl_api_lisp_add_del_map_server_t_handler,
   .endian = vl_api_lisp_add_del_map_server_t_endian,
   .format_fn = vl_api_lisp_add_del_map_server_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lisp_add_del_map_server_t_tojson,
   .fromjson = vl_api_lisp_add_del_map_server_t_fromjson,
   .calc_size = vl_api_lisp_add_del_map_server_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LISP_ADD_DEL_MAP_SERVER_REPLY + msg_id_base,
  .name = "lisp_add_del_map_server_reply",
  .handler = 0,
  .endian = vl_api_lisp_add_del_map_server_reply_t_endian,
  .format_fn = vl_api_lisp_add_del_map_server_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lisp_add_del_map_server_reply_t_tojson,
  .fromjson = vl_api_lisp_add_del_map_server_reply_t_fromjson,
  .calc_size = vl_api_lisp_add_del_map_server_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LISP_ADD_DEL_MAP_RESOLVER + msg_id_base,
   .name = "lisp_add_del_map_resolver",
   .handler = vl_api_lisp_add_del_map_resolver_t_handler,
   .endian = vl_api_lisp_add_del_map_resolver_t_endian,
   .format_fn = vl_api_lisp_add_del_map_resolver_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lisp_add_del_map_resolver_t_tojson,
   .fromjson = vl_api_lisp_add_del_map_resolver_t_fromjson,
   .calc_size = vl_api_lisp_add_del_map_resolver_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LISP_ADD_DEL_MAP_RESOLVER_REPLY + msg_id_base,
  .name = "lisp_add_del_map_resolver_reply",
  .handler = 0,
  .endian = vl_api_lisp_add_del_map_resolver_reply_t_endian,
  .format_fn = vl_api_lisp_add_del_map_resolver_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lisp_add_del_map_resolver_reply_t_tojson,
  .fromjson = vl_api_lisp_add_del_map_resolver_reply_t_fromjson,
  .calc_size = vl_api_lisp_add_del_map_resolver_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LISP_ENABLE_DISABLE + msg_id_base,
   .name = "lisp_enable_disable",
   .handler = vl_api_lisp_enable_disable_t_handler,
   .endian = vl_api_lisp_enable_disable_t_endian,
   .format_fn = vl_api_lisp_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lisp_enable_disable_t_tojson,
   .fromjson = vl_api_lisp_enable_disable_t_fromjson,
   .calc_size = vl_api_lisp_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LISP_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "lisp_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_lisp_enable_disable_reply_t_endian,
  .format_fn = vl_api_lisp_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lisp_enable_disable_reply_t_tojson,
  .fromjson = vl_api_lisp_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_lisp_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LISP_PITR_SET_LOCATOR_SET + msg_id_base,
   .name = "lisp_pitr_set_locator_set",
   .handler = vl_api_lisp_pitr_set_locator_set_t_handler,
   .endian = vl_api_lisp_pitr_set_locator_set_t_endian,
   .format_fn = vl_api_lisp_pitr_set_locator_set_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lisp_pitr_set_locator_set_t_tojson,
   .fromjson = vl_api_lisp_pitr_set_locator_set_t_fromjson,
   .calc_size = vl_api_lisp_pitr_set_locator_set_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LISP_PITR_SET_LOCATOR_SET_REPLY + msg_id_base,
  .name = "lisp_pitr_set_locator_set_reply",
  .handler = 0,
  .endian = vl_api_lisp_pitr_set_locator_set_reply_t_endian,
  .format_fn = vl_api_lisp_pitr_set_locator_set_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lisp_pitr_set_locator_set_reply_t_tojson,
  .fromjson = vl_api_lisp_pitr_set_locator_set_reply_t_fromjson,
  .calc_size = vl_api_lisp_pitr_set_locator_set_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LISP_USE_PETR + msg_id_base,
   .name = "lisp_use_petr",
   .handler = vl_api_lisp_use_petr_t_handler,
   .endian = vl_api_lisp_use_petr_t_endian,
   .format_fn = vl_api_lisp_use_petr_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lisp_use_petr_t_tojson,
   .fromjson = vl_api_lisp_use_petr_t_fromjson,
   .calc_size = vl_api_lisp_use_petr_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LISP_USE_PETR_REPLY + msg_id_base,
  .name = "lisp_use_petr_reply",
  .handler = 0,
  .endian = vl_api_lisp_use_petr_reply_t_endian,
  .format_fn = vl_api_lisp_use_petr_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lisp_use_petr_reply_t_tojson,
  .fromjson = vl_api_lisp_use_petr_reply_t_fromjson,
  .calc_size = vl_api_lisp_use_petr_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SHOW_LISP_USE_PETR + msg_id_base,
   .name = "show_lisp_use_petr",
   .handler = vl_api_show_lisp_use_petr_t_handler,
   .endian = vl_api_show_lisp_use_petr_t_endian,
   .format_fn = vl_api_show_lisp_use_petr_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_show_lisp_use_petr_t_tojson,
   .fromjson = vl_api_show_lisp_use_petr_t_fromjson,
   .calc_size = vl_api_show_lisp_use_petr_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SHOW_LISP_USE_PETR_REPLY + msg_id_base,
  .name = "show_lisp_use_petr_reply",
  .handler = 0,
  .endian = vl_api_show_lisp_use_petr_reply_t_endian,
  .format_fn = vl_api_show_lisp_use_petr_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_show_lisp_use_petr_reply_t_tojson,
  .fromjson = vl_api_show_lisp_use_petr_reply_t_fromjson,
  .calc_size = vl_api_show_lisp_use_petr_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SHOW_LISP_RLOC_PROBE_STATE + msg_id_base,
   .name = "show_lisp_rloc_probe_state",
   .handler = vl_api_show_lisp_rloc_probe_state_t_handler,
   .endian = vl_api_show_lisp_rloc_probe_state_t_endian,
   .format_fn = vl_api_show_lisp_rloc_probe_state_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_show_lisp_rloc_probe_state_t_tojson,
   .fromjson = vl_api_show_lisp_rloc_probe_state_t_fromjson,
   .calc_size = vl_api_show_lisp_rloc_probe_state_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SHOW_LISP_RLOC_PROBE_STATE_REPLY + msg_id_base,
  .name = "show_lisp_rloc_probe_state_reply",
  .handler = 0,
  .endian = vl_api_show_lisp_rloc_probe_state_reply_t_endian,
  .format_fn = vl_api_show_lisp_rloc_probe_state_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_show_lisp_rloc_probe_state_reply_t_tojson,
  .fromjson = vl_api_show_lisp_rloc_probe_state_reply_t_fromjson,
  .calc_size = vl_api_show_lisp_rloc_probe_state_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LISP_RLOC_PROBE_ENABLE_DISABLE + msg_id_base,
   .name = "lisp_rloc_probe_enable_disable",
   .handler = vl_api_lisp_rloc_probe_enable_disable_t_handler,
   .endian = vl_api_lisp_rloc_probe_enable_disable_t_endian,
   .format_fn = vl_api_lisp_rloc_probe_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lisp_rloc_probe_enable_disable_t_tojson,
   .fromjson = vl_api_lisp_rloc_probe_enable_disable_t_fromjson,
   .calc_size = vl_api_lisp_rloc_probe_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LISP_RLOC_PROBE_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "lisp_rloc_probe_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_lisp_rloc_probe_enable_disable_reply_t_endian,
  .format_fn = vl_api_lisp_rloc_probe_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lisp_rloc_probe_enable_disable_reply_t_tojson,
  .fromjson = vl_api_lisp_rloc_probe_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_lisp_rloc_probe_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LISP_MAP_REGISTER_ENABLE_DISABLE + msg_id_base,
   .name = "lisp_map_register_enable_disable",
   .handler = vl_api_lisp_map_register_enable_disable_t_handler,
   .endian = vl_api_lisp_map_register_enable_disable_t_endian,
   .format_fn = vl_api_lisp_map_register_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lisp_map_register_enable_disable_t_tojson,
   .fromjson = vl_api_lisp_map_register_enable_disable_t_fromjson,
   .calc_size = vl_api_lisp_map_register_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LISP_MAP_REGISTER_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "lisp_map_register_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_lisp_map_register_enable_disable_reply_t_endian,
  .format_fn = vl_api_lisp_map_register_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lisp_map_register_enable_disable_reply_t_tojson,
  .fromjson = vl_api_lisp_map_register_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_lisp_map_register_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SHOW_LISP_MAP_REGISTER_STATE + msg_id_base,
   .name = "show_lisp_map_register_state",
   .handler = vl_api_show_lisp_map_register_state_t_handler,
   .endian = vl_api_show_lisp_map_register_state_t_endian,
   .format_fn = vl_api_show_lisp_map_register_state_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_show_lisp_map_register_state_t_tojson,
   .fromjson = vl_api_show_lisp_map_register_state_t_fromjson,
   .calc_size = vl_api_show_lisp_map_register_state_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SHOW_LISP_MAP_REGISTER_STATE_REPLY + msg_id_base,
  .name = "show_lisp_map_register_state_reply",
  .handler = 0,
  .endian = vl_api_show_lisp_map_register_state_reply_t_endian,
  .format_fn = vl_api_show_lisp_map_register_state_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_show_lisp_map_register_state_reply_t_tojson,
  .fromjson = vl_api_show_lisp_map_register_state_reply_t_fromjson,
  .calc_size = vl_api_show_lisp_map_register_state_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LISP_MAP_REQUEST_MODE + msg_id_base,
   .name = "lisp_map_request_mode",
   .handler = vl_api_lisp_map_request_mode_t_handler,
   .endian = vl_api_lisp_map_request_mode_t_endian,
   .format_fn = vl_api_lisp_map_request_mode_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lisp_map_request_mode_t_tojson,
   .fromjson = vl_api_lisp_map_request_mode_t_fromjson,
   .calc_size = vl_api_lisp_map_request_mode_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LISP_MAP_REQUEST_MODE_REPLY + msg_id_base,
  .name = "lisp_map_request_mode_reply",
  .handler = 0,
  .endian = vl_api_lisp_map_request_mode_reply_t_endian,
  .format_fn = vl_api_lisp_map_request_mode_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lisp_map_request_mode_reply_t_tojson,
  .fromjson = vl_api_lisp_map_request_mode_reply_t_fromjson,
  .calc_size = vl_api_lisp_map_request_mode_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SHOW_LISP_MAP_REQUEST_MODE + msg_id_base,
   .name = "show_lisp_map_request_mode",
   .handler = vl_api_show_lisp_map_request_mode_t_handler,
   .endian = vl_api_show_lisp_map_request_mode_t_endian,
   .format_fn = vl_api_show_lisp_map_request_mode_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_show_lisp_map_request_mode_t_tojson,
   .fromjson = vl_api_show_lisp_map_request_mode_t_fromjson,
   .calc_size = vl_api_show_lisp_map_request_mode_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SHOW_LISP_MAP_REQUEST_MODE_REPLY + msg_id_base,
  .name = "show_lisp_map_request_mode_reply",
  .handler = 0,
  .endian = vl_api_show_lisp_map_request_mode_reply_t_endian,
  .format_fn = vl_api_show_lisp_map_request_mode_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_show_lisp_map_request_mode_reply_t_tojson,
  .fromjson = vl_api_show_lisp_map_request_mode_reply_t_fromjson,
  .calc_size = vl_api_show_lisp_map_request_mode_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LISP_ADD_DEL_REMOTE_MAPPING + msg_id_base,
   .name = "lisp_add_del_remote_mapping",
   .handler = vl_api_lisp_add_del_remote_mapping_t_handler,
   .endian = vl_api_lisp_add_del_remote_mapping_t_endian,
   .format_fn = vl_api_lisp_add_del_remote_mapping_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lisp_add_del_remote_mapping_t_tojson,
   .fromjson = vl_api_lisp_add_del_remote_mapping_t_fromjson,
   .calc_size = vl_api_lisp_add_del_remote_mapping_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LISP_ADD_DEL_REMOTE_MAPPING_REPLY + msg_id_base,
  .name = "lisp_add_del_remote_mapping_reply",
  .handler = 0,
  .endian = vl_api_lisp_add_del_remote_mapping_reply_t_endian,
  .format_fn = vl_api_lisp_add_del_remote_mapping_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lisp_add_del_remote_mapping_reply_t_tojson,
  .fromjson = vl_api_lisp_add_del_remote_mapping_reply_t_fromjson,
  .calc_size = vl_api_lisp_add_del_remote_mapping_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LISP_ADD_DEL_ADJACENCY + msg_id_base,
   .name = "lisp_add_del_adjacency",
   .handler = vl_api_lisp_add_del_adjacency_t_handler,
   .endian = vl_api_lisp_add_del_adjacency_t_endian,
   .format_fn = vl_api_lisp_add_del_adjacency_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lisp_add_del_adjacency_t_tojson,
   .fromjson = vl_api_lisp_add_del_adjacency_t_fromjson,
   .calc_size = vl_api_lisp_add_del_adjacency_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LISP_ADD_DEL_ADJACENCY_REPLY + msg_id_base,
  .name = "lisp_add_del_adjacency_reply",
  .handler = 0,
  .endian = vl_api_lisp_add_del_adjacency_reply_t_endian,
  .format_fn = vl_api_lisp_add_del_adjacency_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lisp_add_del_adjacency_reply_t_tojson,
  .fromjson = vl_api_lisp_add_del_adjacency_reply_t_fromjson,
  .calc_size = vl_api_lisp_add_del_adjacency_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LISP_ADD_DEL_MAP_REQUEST_ITR_RLOCS + msg_id_base,
   .name = "lisp_add_del_map_request_itr_rlocs",
   .handler = vl_api_lisp_add_del_map_request_itr_rlocs_t_handler,
   .endian = vl_api_lisp_add_del_map_request_itr_rlocs_t_endian,
   .format_fn = vl_api_lisp_add_del_map_request_itr_rlocs_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lisp_add_del_map_request_itr_rlocs_t_tojson,
   .fromjson = vl_api_lisp_add_del_map_request_itr_rlocs_t_fromjson,
   .calc_size = vl_api_lisp_add_del_map_request_itr_rlocs_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LISP_ADD_DEL_MAP_REQUEST_ITR_RLOCS_REPLY + msg_id_base,
  .name = "lisp_add_del_map_request_itr_rlocs_reply",
  .handler = 0,
  .endian = vl_api_lisp_add_del_map_request_itr_rlocs_reply_t_endian,
  .format_fn = vl_api_lisp_add_del_map_request_itr_rlocs_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lisp_add_del_map_request_itr_rlocs_reply_t_tojson,
  .fromjson = vl_api_lisp_add_del_map_request_itr_rlocs_reply_t_fromjson,
  .calc_size = vl_api_lisp_add_del_map_request_itr_rlocs_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LISP_EID_TABLE_ADD_DEL_MAP + msg_id_base,
   .name = "lisp_eid_table_add_del_map",
   .handler = vl_api_lisp_eid_table_add_del_map_t_handler,
   .endian = vl_api_lisp_eid_table_add_del_map_t_endian,
   .format_fn = vl_api_lisp_eid_table_add_del_map_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lisp_eid_table_add_del_map_t_tojson,
   .fromjson = vl_api_lisp_eid_table_add_del_map_t_fromjson,
   .calc_size = vl_api_lisp_eid_table_add_del_map_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LISP_EID_TABLE_ADD_DEL_MAP_REPLY + msg_id_base,
  .name = "lisp_eid_table_add_del_map_reply",
  .handler = 0,
  .endian = vl_api_lisp_eid_table_add_del_map_reply_t_endian,
  .format_fn = vl_api_lisp_eid_table_add_del_map_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lisp_eid_table_add_del_map_reply_t_tojson,
  .fromjson = vl_api_lisp_eid_table_add_del_map_reply_t_fromjson,
  .calc_size = vl_api_lisp_eid_table_add_del_map_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LISP_LOCATOR_DUMP + msg_id_base,
   .name = "lisp_locator_dump",
   .handler = vl_api_lisp_locator_dump_t_handler,
   .endian = vl_api_lisp_locator_dump_t_endian,
   .format_fn = vl_api_lisp_locator_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lisp_locator_dump_t_tojson,
   .fromjson = vl_api_lisp_locator_dump_t_fromjson,
   .calc_size = vl_api_lisp_locator_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LISP_LOCATOR_DETAILS + msg_id_base,
  .name = "lisp_locator_details",
  .handler = 0,
  .endian = vl_api_lisp_locator_details_t_endian,
  .format_fn = vl_api_lisp_locator_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lisp_locator_details_t_tojson,
  .fromjson = vl_api_lisp_locator_details_t_fromjson,
  .calc_size = vl_api_lisp_locator_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LISP_LOCATOR_SET_DUMP + msg_id_base,
   .name = "lisp_locator_set_dump",
   .handler = vl_api_lisp_locator_set_dump_t_handler,
   .endian = vl_api_lisp_locator_set_dump_t_endian,
   .format_fn = vl_api_lisp_locator_set_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lisp_locator_set_dump_t_tojson,
   .fromjson = vl_api_lisp_locator_set_dump_t_fromjson,
   .calc_size = vl_api_lisp_locator_set_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LISP_LOCATOR_SET_DETAILS + msg_id_base,
  .name = "lisp_locator_set_details",
  .handler = 0,
  .endian = vl_api_lisp_locator_set_details_t_endian,
  .format_fn = vl_api_lisp_locator_set_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lisp_locator_set_details_t_tojson,
  .fromjson = vl_api_lisp_locator_set_details_t_fromjson,
  .calc_size = vl_api_lisp_locator_set_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LISP_EID_TABLE_DUMP + msg_id_base,
   .name = "lisp_eid_table_dump",
   .handler = vl_api_lisp_eid_table_dump_t_handler,
   .endian = vl_api_lisp_eid_table_dump_t_endian,
   .format_fn = vl_api_lisp_eid_table_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lisp_eid_table_dump_t_tojson,
   .fromjson = vl_api_lisp_eid_table_dump_t_fromjson,
   .calc_size = vl_api_lisp_eid_table_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LISP_EID_TABLE_DETAILS + msg_id_base,
  .name = "lisp_eid_table_details",
  .handler = 0,
  .endian = vl_api_lisp_eid_table_details_t_endian,
  .format_fn = vl_api_lisp_eid_table_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lisp_eid_table_details_t_tojson,
  .fromjson = vl_api_lisp_eid_table_details_t_fromjson,
  .calc_size = vl_api_lisp_eid_table_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LISP_ADJACENCIES_GET + msg_id_base,
   .name = "lisp_adjacencies_get",
   .handler = vl_api_lisp_adjacencies_get_t_handler,
   .endian = vl_api_lisp_adjacencies_get_t_endian,
   .format_fn = vl_api_lisp_adjacencies_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lisp_adjacencies_get_t_tojson,
   .fromjson = vl_api_lisp_adjacencies_get_t_fromjson,
   .calc_size = vl_api_lisp_adjacencies_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LISP_ADJACENCIES_GET_REPLY + msg_id_base,
  .name = "lisp_adjacencies_get_reply",
  .handler = 0,
  .endian = vl_api_lisp_adjacencies_get_reply_t_endian,
  .format_fn = vl_api_lisp_adjacencies_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lisp_adjacencies_get_reply_t_tojson,
  .fromjson = vl_api_lisp_adjacencies_get_reply_t_fromjson,
  .calc_size = vl_api_lisp_adjacencies_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LISP_EID_TABLE_MAP_DUMP + msg_id_base,
   .name = "lisp_eid_table_map_dump",
   .handler = vl_api_lisp_eid_table_map_dump_t_handler,
   .endian = vl_api_lisp_eid_table_map_dump_t_endian,
   .format_fn = vl_api_lisp_eid_table_map_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lisp_eid_table_map_dump_t_tojson,
   .fromjson = vl_api_lisp_eid_table_map_dump_t_fromjson,
   .calc_size = vl_api_lisp_eid_table_map_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LISP_EID_TABLE_MAP_DETAILS + msg_id_base,
  .name = "lisp_eid_table_map_details",
  .handler = 0,
  .endian = vl_api_lisp_eid_table_map_details_t_endian,
  .format_fn = vl_api_lisp_eid_table_map_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lisp_eid_table_map_details_t_tojson,
  .fromjson = vl_api_lisp_eid_table_map_details_t_fromjson,
  .calc_size = vl_api_lisp_eid_table_map_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LISP_EID_TABLE_VNI_DUMP + msg_id_base,
   .name = "lisp_eid_table_vni_dump",
   .handler = vl_api_lisp_eid_table_vni_dump_t_handler,
   .endian = vl_api_lisp_eid_table_vni_dump_t_endian,
   .format_fn = vl_api_lisp_eid_table_vni_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lisp_eid_table_vni_dump_t_tojson,
   .fromjson = vl_api_lisp_eid_table_vni_dump_t_fromjson,
   .calc_size = vl_api_lisp_eid_table_vni_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LISP_EID_TABLE_VNI_DETAILS + msg_id_base,
  .name = "lisp_eid_table_vni_details",
  .handler = 0,
  .endian = vl_api_lisp_eid_table_vni_details_t_endian,
  .format_fn = vl_api_lisp_eid_table_vni_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lisp_eid_table_vni_details_t_tojson,
  .fromjson = vl_api_lisp_eid_table_vni_details_t_fromjson,
  .calc_size = vl_api_lisp_eid_table_vni_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LISP_MAP_RESOLVER_DUMP + msg_id_base,
   .name = "lisp_map_resolver_dump",
   .handler = vl_api_lisp_map_resolver_dump_t_handler,
   .endian = vl_api_lisp_map_resolver_dump_t_endian,
   .format_fn = vl_api_lisp_map_resolver_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lisp_map_resolver_dump_t_tojson,
   .fromjson = vl_api_lisp_map_resolver_dump_t_fromjson,
   .calc_size = vl_api_lisp_map_resolver_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LISP_MAP_RESOLVER_DETAILS + msg_id_base,
  .name = "lisp_map_resolver_details",
  .handler = 0,
  .endian = vl_api_lisp_map_resolver_details_t_endian,
  .format_fn = vl_api_lisp_map_resolver_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lisp_map_resolver_details_t_tojson,
  .fromjson = vl_api_lisp_map_resolver_details_t_fromjson,
  .calc_size = vl_api_lisp_map_resolver_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LISP_MAP_SERVER_DUMP + msg_id_base,
   .name = "lisp_map_server_dump",
   .handler = vl_api_lisp_map_server_dump_t_handler,
   .endian = vl_api_lisp_map_server_dump_t_endian,
   .format_fn = vl_api_lisp_map_server_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lisp_map_server_dump_t_tojson,
   .fromjson = vl_api_lisp_map_server_dump_t_fromjson,
   .calc_size = vl_api_lisp_map_server_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LISP_MAP_SERVER_DETAILS + msg_id_base,
  .name = "lisp_map_server_details",
  .handler = 0,
  .endian = vl_api_lisp_map_server_details_t_endian,
  .format_fn = vl_api_lisp_map_server_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lisp_map_server_details_t_tojson,
  .fromjson = vl_api_lisp_map_server_details_t_fromjson,
  .calc_size = vl_api_lisp_map_server_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SHOW_LISP_STATUS + msg_id_base,
   .name = "show_lisp_status",
   .handler = vl_api_show_lisp_status_t_handler,
   .endian = vl_api_show_lisp_status_t_endian,
   .format_fn = vl_api_show_lisp_status_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_show_lisp_status_t_tojson,
   .fromjson = vl_api_show_lisp_status_t_fromjson,
   .calc_size = vl_api_show_lisp_status_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SHOW_LISP_STATUS_REPLY + msg_id_base,
  .name = "show_lisp_status_reply",
  .handler = 0,
  .endian = vl_api_show_lisp_status_reply_t_endian,
  .format_fn = vl_api_show_lisp_status_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_show_lisp_status_reply_t_tojson,
  .fromjson = vl_api_show_lisp_status_reply_t_fromjson,
  .calc_size = vl_api_show_lisp_status_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LISP_GET_MAP_REQUEST_ITR_RLOCS + msg_id_base,
   .name = "lisp_get_map_request_itr_rlocs",
   .handler = vl_api_lisp_get_map_request_itr_rlocs_t_handler,
   .endian = vl_api_lisp_get_map_request_itr_rlocs_t_endian,
   .format_fn = vl_api_lisp_get_map_request_itr_rlocs_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lisp_get_map_request_itr_rlocs_t_tojson,
   .fromjson = vl_api_lisp_get_map_request_itr_rlocs_t_fromjson,
   .calc_size = vl_api_lisp_get_map_request_itr_rlocs_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LISP_GET_MAP_REQUEST_ITR_RLOCS_REPLY + msg_id_base,
  .name = "lisp_get_map_request_itr_rlocs_reply",
  .handler = 0,
  .endian = vl_api_lisp_get_map_request_itr_rlocs_reply_t_endian,
  .format_fn = vl_api_lisp_get_map_request_itr_rlocs_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lisp_get_map_request_itr_rlocs_reply_t_tojson,
  .fromjson = vl_api_lisp_get_map_request_itr_rlocs_reply_t_fromjson,
  .calc_size = vl_api_lisp_get_map_request_itr_rlocs_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SHOW_LISP_PITR + msg_id_base,
   .name = "show_lisp_pitr",
   .handler = vl_api_show_lisp_pitr_t_handler,
   .endian = vl_api_show_lisp_pitr_t_endian,
   .format_fn = vl_api_show_lisp_pitr_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_show_lisp_pitr_t_tojson,
   .fromjson = vl_api_show_lisp_pitr_t_fromjson,
   .calc_size = vl_api_show_lisp_pitr_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SHOW_LISP_PITR_REPLY + msg_id_base,
  .name = "show_lisp_pitr_reply",
  .handler = 0,
  .endian = vl_api_show_lisp_pitr_reply_t_endian,
  .format_fn = vl_api_show_lisp_pitr_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_show_lisp_pitr_reply_t_tojson,
  .fromjson = vl_api_show_lisp_pitr_reply_t_fromjson,
  .calc_size = vl_api_show_lisp_pitr_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
