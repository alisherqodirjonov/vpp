#define vl_endianfun            /* define message structures */
#include "ipsec.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "ipsec.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "ipsec.api.h"
#undef vl_printfun

#ifndef VL_API_IPSEC_SPD_ADD_DEL_REPLY_T_HANDLER
static void
vl_api_ipsec_spd_add_del_reply_t_handler (vl_api_ipsec_spd_add_del_reply_t * mp) {
   vat_main_t * vam = ipsec_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IPSEC_INTERFACE_ADD_DEL_SPD_REPLY_T_HANDLER
static void
vl_api_ipsec_interface_add_del_spd_reply_t_handler (vl_api_ipsec_interface_add_del_spd_reply_t * mp) {
   vat_main_t * vam = ipsec_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_ipsec_spd_entry_add_del_reply_t_handler()) */
/* Generation not supported (vl_api_ipsec_spd_entry_add_del_v2_reply_t_handler()) */
/* Generation not supported (vl_api_ipsec_spds_details_t_handler()) */
/* Generation not supported (vl_api_ipsec_spd_details_t_handler()) */
/* Generation not supported (vl_api_ipsec_sad_entry_add_del_reply_t_handler()) */
/* Generation not supported (vl_api_ipsec_sad_entry_add_del_v2_reply_t_handler()) */
/* Generation not supported (vl_api_ipsec_sad_entry_add_del_v3_reply_t_handler()) */
/* Generation not supported (vl_api_ipsec_sad_entry_add_reply_t_handler()) */
/* Generation not supported (vl_api_ipsec_sad_entry_add_v2_reply_t_handler()) */
#ifndef VL_API_IPSEC_SAD_ENTRY_DEL_REPLY_T_HANDLER
static void
vl_api_ipsec_sad_entry_del_reply_t_handler (vl_api_ipsec_sad_entry_del_reply_t * mp) {
   vat_main_t * vam = ipsec_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IPSEC_SAD_BIND_REPLY_T_HANDLER
static void
vl_api_ipsec_sad_bind_reply_t_handler (vl_api_ipsec_sad_bind_reply_t * mp) {
   vat_main_t * vam = ipsec_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IPSEC_SAD_UNBIND_REPLY_T_HANDLER
static void
vl_api_ipsec_sad_unbind_reply_t_handler (vl_api_ipsec_sad_unbind_reply_t * mp) {
   vat_main_t * vam = ipsec_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IPSEC_SAD_ENTRY_UPDATE_REPLY_T_HANDLER
static void
vl_api_ipsec_sad_entry_update_reply_t_handler (vl_api_ipsec_sad_entry_update_reply_t * mp) {
   vat_main_t * vam = ipsec_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IPSEC_TUNNEL_PROTECT_UPDATE_REPLY_T_HANDLER
static void
vl_api_ipsec_tunnel_protect_update_reply_t_handler (vl_api_ipsec_tunnel_protect_update_reply_t * mp) {
   vat_main_t * vam = ipsec_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IPSEC_TUNNEL_PROTECT_DEL_REPLY_T_HANDLER
static void
vl_api_ipsec_tunnel_protect_del_reply_t_handler (vl_api_ipsec_tunnel_protect_del_reply_t * mp) {
   vat_main_t * vam = ipsec_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_ipsec_tunnel_protect_details_t_handler()) */
/* Generation not supported (vl_api_ipsec_spd_interface_details_t_handler()) */
/* Generation not supported (vl_api_ipsec_itf_create_reply_t_handler()) */
#ifndef VL_API_IPSEC_ITF_DELETE_REPLY_T_HANDLER
static void
vl_api_ipsec_itf_delete_reply_t_handler (vl_api_ipsec_itf_delete_reply_t * mp) {
   vat_main_t * vam = ipsec_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_ipsec_itf_details_t_handler()) */
/* Generation not supported (vl_api_ipsec_sa_details_t_handler()) */
/* Generation not supported (vl_api_ipsec_sa_v2_details_t_handler()) */
/* Generation not supported (vl_api_ipsec_sa_v3_details_t_handler()) */
/* Generation not supported (vl_api_ipsec_sa_v4_details_t_handler()) */
/* Generation not supported (vl_api_ipsec_sa_v5_details_t_handler()) */
/* Generation not supported (vl_api_ipsec_backend_details_t_handler()) */
#ifndef VL_API_IPSEC_SELECT_BACKEND_REPLY_T_HANDLER
static void
vl_api_ipsec_select_backend_reply_t_handler (vl_api_ipsec_select_backend_reply_t * mp) {
   vat_main_t * vam = ipsec_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IPSEC_SET_ASYNC_MODE_REPLY_T_HANDLER
static void
vl_api_ipsec_set_async_mode_reply_t_handler (vl_api_ipsec_set_async_mode_reply_t * mp) {
   vat_main_t * vam = ipsec_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPSEC_SPD_ADD_DEL_REPLY + msg_id_base,
    .name = "ipsec_spd_add_del_reply",
    .handler = vl_api_ipsec_spd_add_del_reply_t_handler,
    .endian = vl_api_ipsec_spd_add_del_reply_t_endian,
    .format_fn = vl_api_ipsec_spd_add_del_reply_t_format,
    .size = sizeof(vl_api_ipsec_spd_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_ipsec_spd_add_del_reply_t_tojson,
    .fromjson = vl_api_ipsec_spd_add_del_reply_t_fromjson,
    .calc_size = vl_api_ipsec_spd_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipsec_spd_add_del", api_ipsec_spd_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPSEC_INTERFACE_ADD_DEL_SPD_REPLY + msg_id_base,
    .name = "ipsec_interface_add_del_spd_reply",
    .handler = vl_api_ipsec_interface_add_del_spd_reply_t_handler,
    .endian = vl_api_ipsec_interface_add_del_spd_reply_t_endian,
    .format_fn = vl_api_ipsec_interface_add_del_spd_reply_t_format,
    .size = sizeof(vl_api_ipsec_interface_add_del_spd_reply_t),
    .traced = 1,
    .tojson = vl_api_ipsec_interface_add_del_spd_reply_t_tojson,
    .fromjson = vl_api_ipsec_interface_add_del_spd_reply_t_fromjson,
    .calc_size = vl_api_ipsec_interface_add_del_spd_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipsec_interface_add_del_spd", api_ipsec_interface_add_del_spd);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPSEC_SPD_ENTRY_ADD_DEL_REPLY + msg_id_base,
    .name = "ipsec_spd_entry_add_del_reply",
    .handler = vl_api_ipsec_spd_entry_add_del_reply_t_handler,
    .endian = vl_api_ipsec_spd_entry_add_del_reply_t_endian,
    .format_fn = vl_api_ipsec_spd_entry_add_del_reply_t_format,
    .size = sizeof(vl_api_ipsec_spd_entry_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_ipsec_spd_entry_add_del_reply_t_tojson,
    .fromjson = vl_api_ipsec_spd_entry_add_del_reply_t_fromjson,
    .calc_size = vl_api_ipsec_spd_entry_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipsec_spd_entry_add_del", api_ipsec_spd_entry_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPSEC_SPD_ENTRY_ADD_DEL_V2_REPLY + msg_id_base,
    .name = "ipsec_spd_entry_add_del_v2_reply",
    .handler = vl_api_ipsec_spd_entry_add_del_v2_reply_t_handler,
    .endian = vl_api_ipsec_spd_entry_add_del_v2_reply_t_endian,
    .format_fn = vl_api_ipsec_spd_entry_add_del_v2_reply_t_format,
    .size = sizeof(vl_api_ipsec_spd_entry_add_del_v2_reply_t),
    .traced = 1,
    .tojson = vl_api_ipsec_spd_entry_add_del_v2_reply_t_tojson,
    .fromjson = vl_api_ipsec_spd_entry_add_del_v2_reply_t_fromjson,
    .calc_size = vl_api_ipsec_spd_entry_add_del_v2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipsec_spd_entry_add_del_v2", api_ipsec_spd_entry_add_del_v2);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPSEC_SPDS_DETAILS + msg_id_base,
    .name = "ipsec_spds_details",
    .handler = vl_api_ipsec_spds_details_t_handler,
    .endian = vl_api_ipsec_spds_details_t_endian,
    .format_fn = vl_api_ipsec_spds_details_t_format,
    .size = sizeof(vl_api_ipsec_spds_details_t),
    .traced = 1,
    .tojson = vl_api_ipsec_spds_details_t_tojson,
    .fromjson = vl_api_ipsec_spds_details_t_fromjson,
    .calc_size = vl_api_ipsec_spds_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipsec_spds_dump", api_ipsec_spds_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPSEC_SPD_DETAILS + msg_id_base,
    .name = "ipsec_spd_details",
    .handler = vl_api_ipsec_spd_details_t_handler,
    .endian = vl_api_ipsec_spd_details_t_endian,
    .format_fn = vl_api_ipsec_spd_details_t_format,
    .size = sizeof(vl_api_ipsec_spd_details_t),
    .traced = 1,
    .tojson = vl_api_ipsec_spd_details_t_tojson,
    .fromjson = vl_api_ipsec_spd_details_t_fromjson,
    .calc_size = vl_api_ipsec_spd_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipsec_spd_dump", api_ipsec_spd_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPSEC_SAD_ENTRY_ADD_DEL_REPLY + msg_id_base,
    .name = "ipsec_sad_entry_add_del_reply",
    .handler = vl_api_ipsec_sad_entry_add_del_reply_t_handler,
    .endian = vl_api_ipsec_sad_entry_add_del_reply_t_endian,
    .format_fn = vl_api_ipsec_sad_entry_add_del_reply_t_format,
    .size = sizeof(vl_api_ipsec_sad_entry_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_ipsec_sad_entry_add_del_reply_t_tojson,
    .fromjson = vl_api_ipsec_sad_entry_add_del_reply_t_fromjson,
    .calc_size = vl_api_ipsec_sad_entry_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipsec_sad_entry_add_del", api_ipsec_sad_entry_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPSEC_SAD_ENTRY_ADD_DEL_V2_REPLY + msg_id_base,
    .name = "ipsec_sad_entry_add_del_v2_reply",
    .handler = vl_api_ipsec_sad_entry_add_del_v2_reply_t_handler,
    .endian = vl_api_ipsec_sad_entry_add_del_v2_reply_t_endian,
    .format_fn = vl_api_ipsec_sad_entry_add_del_v2_reply_t_format,
    .size = sizeof(vl_api_ipsec_sad_entry_add_del_v2_reply_t),
    .traced = 1,
    .tojson = vl_api_ipsec_sad_entry_add_del_v2_reply_t_tojson,
    .fromjson = vl_api_ipsec_sad_entry_add_del_v2_reply_t_fromjson,
    .calc_size = vl_api_ipsec_sad_entry_add_del_v2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipsec_sad_entry_add_del_v2", api_ipsec_sad_entry_add_del_v2);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPSEC_SAD_ENTRY_ADD_DEL_V3_REPLY + msg_id_base,
    .name = "ipsec_sad_entry_add_del_v3_reply",
    .handler = vl_api_ipsec_sad_entry_add_del_v3_reply_t_handler,
    .endian = vl_api_ipsec_sad_entry_add_del_v3_reply_t_endian,
    .format_fn = vl_api_ipsec_sad_entry_add_del_v3_reply_t_format,
    .size = sizeof(vl_api_ipsec_sad_entry_add_del_v3_reply_t),
    .traced = 1,
    .tojson = vl_api_ipsec_sad_entry_add_del_v3_reply_t_tojson,
    .fromjson = vl_api_ipsec_sad_entry_add_del_v3_reply_t_fromjson,
    .calc_size = vl_api_ipsec_sad_entry_add_del_v3_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipsec_sad_entry_add_del_v3", api_ipsec_sad_entry_add_del_v3);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPSEC_SAD_ENTRY_ADD_REPLY + msg_id_base,
    .name = "ipsec_sad_entry_add_reply",
    .handler = vl_api_ipsec_sad_entry_add_reply_t_handler,
    .endian = vl_api_ipsec_sad_entry_add_reply_t_endian,
    .format_fn = vl_api_ipsec_sad_entry_add_reply_t_format,
    .size = sizeof(vl_api_ipsec_sad_entry_add_reply_t),
    .traced = 1,
    .tojson = vl_api_ipsec_sad_entry_add_reply_t_tojson,
    .fromjson = vl_api_ipsec_sad_entry_add_reply_t_fromjson,
    .calc_size = vl_api_ipsec_sad_entry_add_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipsec_sad_entry_add", api_ipsec_sad_entry_add);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPSEC_SAD_ENTRY_ADD_V2_REPLY + msg_id_base,
    .name = "ipsec_sad_entry_add_v2_reply",
    .handler = vl_api_ipsec_sad_entry_add_v2_reply_t_handler,
    .endian = vl_api_ipsec_sad_entry_add_v2_reply_t_endian,
    .format_fn = vl_api_ipsec_sad_entry_add_v2_reply_t_format,
    .size = sizeof(vl_api_ipsec_sad_entry_add_v2_reply_t),
    .traced = 1,
    .tojson = vl_api_ipsec_sad_entry_add_v2_reply_t_tojson,
    .fromjson = vl_api_ipsec_sad_entry_add_v2_reply_t_fromjson,
    .calc_size = vl_api_ipsec_sad_entry_add_v2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipsec_sad_entry_add_v2", api_ipsec_sad_entry_add_v2);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPSEC_SAD_ENTRY_DEL_REPLY + msg_id_base,
    .name = "ipsec_sad_entry_del_reply",
    .handler = vl_api_ipsec_sad_entry_del_reply_t_handler,
    .endian = vl_api_ipsec_sad_entry_del_reply_t_endian,
    .format_fn = vl_api_ipsec_sad_entry_del_reply_t_format,
    .size = sizeof(vl_api_ipsec_sad_entry_del_reply_t),
    .traced = 1,
    .tojson = vl_api_ipsec_sad_entry_del_reply_t_tojson,
    .fromjson = vl_api_ipsec_sad_entry_del_reply_t_fromjson,
    .calc_size = vl_api_ipsec_sad_entry_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipsec_sad_entry_del", api_ipsec_sad_entry_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPSEC_SAD_BIND_REPLY + msg_id_base,
    .name = "ipsec_sad_bind_reply",
    .handler = vl_api_ipsec_sad_bind_reply_t_handler,
    .endian = vl_api_ipsec_sad_bind_reply_t_endian,
    .format_fn = vl_api_ipsec_sad_bind_reply_t_format,
    .size = sizeof(vl_api_ipsec_sad_bind_reply_t),
    .traced = 1,
    .tojson = vl_api_ipsec_sad_bind_reply_t_tojson,
    .fromjson = vl_api_ipsec_sad_bind_reply_t_fromjson,
    .calc_size = vl_api_ipsec_sad_bind_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipsec_sad_bind", api_ipsec_sad_bind);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPSEC_SAD_UNBIND_REPLY + msg_id_base,
    .name = "ipsec_sad_unbind_reply",
    .handler = vl_api_ipsec_sad_unbind_reply_t_handler,
    .endian = vl_api_ipsec_sad_unbind_reply_t_endian,
    .format_fn = vl_api_ipsec_sad_unbind_reply_t_format,
    .size = sizeof(vl_api_ipsec_sad_unbind_reply_t),
    .traced = 1,
    .tojson = vl_api_ipsec_sad_unbind_reply_t_tojson,
    .fromjson = vl_api_ipsec_sad_unbind_reply_t_fromjson,
    .calc_size = vl_api_ipsec_sad_unbind_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipsec_sad_unbind", api_ipsec_sad_unbind);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPSEC_SAD_ENTRY_UPDATE_REPLY + msg_id_base,
    .name = "ipsec_sad_entry_update_reply",
    .handler = vl_api_ipsec_sad_entry_update_reply_t_handler,
    .endian = vl_api_ipsec_sad_entry_update_reply_t_endian,
    .format_fn = vl_api_ipsec_sad_entry_update_reply_t_format,
    .size = sizeof(vl_api_ipsec_sad_entry_update_reply_t),
    .traced = 1,
    .tojson = vl_api_ipsec_sad_entry_update_reply_t_tojson,
    .fromjson = vl_api_ipsec_sad_entry_update_reply_t_fromjson,
    .calc_size = vl_api_ipsec_sad_entry_update_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipsec_sad_entry_update", api_ipsec_sad_entry_update);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPSEC_TUNNEL_PROTECT_UPDATE_REPLY + msg_id_base,
    .name = "ipsec_tunnel_protect_update_reply",
    .handler = vl_api_ipsec_tunnel_protect_update_reply_t_handler,
    .endian = vl_api_ipsec_tunnel_protect_update_reply_t_endian,
    .format_fn = vl_api_ipsec_tunnel_protect_update_reply_t_format,
    .size = sizeof(vl_api_ipsec_tunnel_protect_update_reply_t),
    .traced = 1,
    .tojson = vl_api_ipsec_tunnel_protect_update_reply_t_tojson,
    .fromjson = vl_api_ipsec_tunnel_protect_update_reply_t_fromjson,
    .calc_size = vl_api_ipsec_tunnel_protect_update_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipsec_tunnel_protect_update", api_ipsec_tunnel_protect_update);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPSEC_TUNNEL_PROTECT_DEL_REPLY + msg_id_base,
    .name = "ipsec_tunnel_protect_del_reply",
    .handler = vl_api_ipsec_tunnel_protect_del_reply_t_handler,
    .endian = vl_api_ipsec_tunnel_protect_del_reply_t_endian,
    .format_fn = vl_api_ipsec_tunnel_protect_del_reply_t_format,
    .size = sizeof(vl_api_ipsec_tunnel_protect_del_reply_t),
    .traced = 1,
    .tojson = vl_api_ipsec_tunnel_protect_del_reply_t_tojson,
    .fromjson = vl_api_ipsec_tunnel_protect_del_reply_t_fromjson,
    .calc_size = vl_api_ipsec_tunnel_protect_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipsec_tunnel_protect_del", api_ipsec_tunnel_protect_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPSEC_TUNNEL_PROTECT_DETAILS + msg_id_base,
    .name = "ipsec_tunnel_protect_details",
    .handler = vl_api_ipsec_tunnel_protect_details_t_handler,
    .endian = vl_api_ipsec_tunnel_protect_details_t_endian,
    .format_fn = vl_api_ipsec_tunnel_protect_details_t_format,
    .size = sizeof(vl_api_ipsec_tunnel_protect_details_t),
    .traced = 1,
    .tojson = vl_api_ipsec_tunnel_protect_details_t_tojson,
    .fromjson = vl_api_ipsec_tunnel_protect_details_t_fromjson,
    .calc_size = vl_api_ipsec_tunnel_protect_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipsec_tunnel_protect_dump", api_ipsec_tunnel_protect_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPSEC_SPD_INTERFACE_DETAILS + msg_id_base,
    .name = "ipsec_spd_interface_details",
    .handler = vl_api_ipsec_spd_interface_details_t_handler,
    .endian = vl_api_ipsec_spd_interface_details_t_endian,
    .format_fn = vl_api_ipsec_spd_interface_details_t_format,
    .size = sizeof(vl_api_ipsec_spd_interface_details_t),
    .traced = 1,
    .tojson = vl_api_ipsec_spd_interface_details_t_tojson,
    .fromjson = vl_api_ipsec_spd_interface_details_t_fromjson,
    .calc_size = vl_api_ipsec_spd_interface_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipsec_spd_interface_dump", api_ipsec_spd_interface_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPSEC_ITF_CREATE_REPLY + msg_id_base,
    .name = "ipsec_itf_create_reply",
    .handler = vl_api_ipsec_itf_create_reply_t_handler,
    .endian = vl_api_ipsec_itf_create_reply_t_endian,
    .format_fn = vl_api_ipsec_itf_create_reply_t_format,
    .size = sizeof(vl_api_ipsec_itf_create_reply_t),
    .traced = 1,
    .tojson = vl_api_ipsec_itf_create_reply_t_tojson,
    .fromjson = vl_api_ipsec_itf_create_reply_t_fromjson,
    .calc_size = vl_api_ipsec_itf_create_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipsec_itf_create", api_ipsec_itf_create);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPSEC_ITF_DELETE_REPLY + msg_id_base,
    .name = "ipsec_itf_delete_reply",
    .handler = vl_api_ipsec_itf_delete_reply_t_handler,
    .endian = vl_api_ipsec_itf_delete_reply_t_endian,
    .format_fn = vl_api_ipsec_itf_delete_reply_t_format,
    .size = sizeof(vl_api_ipsec_itf_delete_reply_t),
    .traced = 1,
    .tojson = vl_api_ipsec_itf_delete_reply_t_tojson,
    .fromjson = vl_api_ipsec_itf_delete_reply_t_fromjson,
    .calc_size = vl_api_ipsec_itf_delete_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipsec_itf_delete", api_ipsec_itf_delete);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPSEC_ITF_DETAILS + msg_id_base,
    .name = "ipsec_itf_details",
    .handler = vl_api_ipsec_itf_details_t_handler,
    .endian = vl_api_ipsec_itf_details_t_endian,
    .format_fn = vl_api_ipsec_itf_details_t_format,
    .size = sizeof(vl_api_ipsec_itf_details_t),
    .traced = 1,
    .tojson = vl_api_ipsec_itf_details_t_tojson,
    .fromjson = vl_api_ipsec_itf_details_t_fromjson,
    .calc_size = vl_api_ipsec_itf_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipsec_itf_dump", api_ipsec_itf_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPSEC_SA_DETAILS + msg_id_base,
    .name = "ipsec_sa_details",
    .handler = vl_api_ipsec_sa_details_t_handler,
    .endian = vl_api_ipsec_sa_details_t_endian,
    .format_fn = vl_api_ipsec_sa_details_t_format,
    .size = sizeof(vl_api_ipsec_sa_details_t),
    .traced = 1,
    .tojson = vl_api_ipsec_sa_details_t_tojson,
    .fromjson = vl_api_ipsec_sa_details_t_fromjson,
    .calc_size = vl_api_ipsec_sa_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipsec_sa_dump", api_ipsec_sa_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPSEC_SA_V2_DETAILS + msg_id_base,
    .name = "ipsec_sa_v2_details",
    .handler = vl_api_ipsec_sa_v2_details_t_handler,
    .endian = vl_api_ipsec_sa_v2_details_t_endian,
    .format_fn = vl_api_ipsec_sa_v2_details_t_format,
    .size = sizeof(vl_api_ipsec_sa_v2_details_t),
    .traced = 1,
    .tojson = vl_api_ipsec_sa_v2_details_t_tojson,
    .fromjson = vl_api_ipsec_sa_v2_details_t_fromjson,
    .calc_size = vl_api_ipsec_sa_v2_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipsec_sa_v2_dump", api_ipsec_sa_v2_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPSEC_SA_V3_DETAILS + msg_id_base,
    .name = "ipsec_sa_v3_details",
    .handler = vl_api_ipsec_sa_v3_details_t_handler,
    .endian = vl_api_ipsec_sa_v3_details_t_endian,
    .format_fn = vl_api_ipsec_sa_v3_details_t_format,
    .size = sizeof(vl_api_ipsec_sa_v3_details_t),
    .traced = 1,
    .tojson = vl_api_ipsec_sa_v3_details_t_tojson,
    .fromjson = vl_api_ipsec_sa_v3_details_t_fromjson,
    .calc_size = vl_api_ipsec_sa_v3_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipsec_sa_v3_dump", api_ipsec_sa_v3_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPSEC_SA_V4_DETAILS + msg_id_base,
    .name = "ipsec_sa_v4_details",
    .handler = vl_api_ipsec_sa_v4_details_t_handler,
    .endian = vl_api_ipsec_sa_v4_details_t_endian,
    .format_fn = vl_api_ipsec_sa_v4_details_t_format,
    .size = sizeof(vl_api_ipsec_sa_v4_details_t),
    .traced = 1,
    .tojson = vl_api_ipsec_sa_v4_details_t_tojson,
    .fromjson = vl_api_ipsec_sa_v4_details_t_fromjson,
    .calc_size = vl_api_ipsec_sa_v4_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipsec_sa_v4_dump", api_ipsec_sa_v4_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPSEC_SA_V5_DETAILS + msg_id_base,
    .name = "ipsec_sa_v5_details",
    .handler = vl_api_ipsec_sa_v5_details_t_handler,
    .endian = vl_api_ipsec_sa_v5_details_t_endian,
    .format_fn = vl_api_ipsec_sa_v5_details_t_format,
    .size = sizeof(vl_api_ipsec_sa_v5_details_t),
    .traced = 1,
    .tojson = vl_api_ipsec_sa_v5_details_t_tojson,
    .fromjson = vl_api_ipsec_sa_v5_details_t_fromjson,
    .calc_size = vl_api_ipsec_sa_v5_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipsec_sa_v5_dump", api_ipsec_sa_v5_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPSEC_BACKEND_DETAILS + msg_id_base,
    .name = "ipsec_backend_details",
    .handler = vl_api_ipsec_backend_details_t_handler,
    .endian = vl_api_ipsec_backend_details_t_endian,
    .format_fn = vl_api_ipsec_backend_details_t_format,
    .size = sizeof(vl_api_ipsec_backend_details_t),
    .traced = 1,
    .tojson = vl_api_ipsec_backend_details_t_tojson,
    .fromjson = vl_api_ipsec_backend_details_t_fromjson,
    .calc_size = vl_api_ipsec_backend_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipsec_backend_dump", api_ipsec_backend_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPSEC_SELECT_BACKEND_REPLY + msg_id_base,
    .name = "ipsec_select_backend_reply",
    .handler = vl_api_ipsec_select_backend_reply_t_handler,
    .endian = vl_api_ipsec_select_backend_reply_t_endian,
    .format_fn = vl_api_ipsec_select_backend_reply_t_format,
    .size = sizeof(vl_api_ipsec_select_backend_reply_t),
    .traced = 1,
    .tojson = vl_api_ipsec_select_backend_reply_t_tojson,
    .fromjson = vl_api_ipsec_select_backend_reply_t_fromjson,
    .calc_size = vl_api_ipsec_select_backend_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipsec_select_backend", api_ipsec_select_backend);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPSEC_SET_ASYNC_MODE_REPLY + msg_id_base,
    .name = "ipsec_set_async_mode_reply",
    .handler = vl_api_ipsec_set_async_mode_reply_t_handler,
    .endian = vl_api_ipsec_set_async_mode_reply_t_endian,
    .format_fn = vl_api_ipsec_set_async_mode_reply_t_format,
    .size = sizeof(vl_api_ipsec_set_async_mode_reply_t),
    .traced = 1,
    .tojson = vl_api_ipsec_set_async_mode_reply_t_tojson,
    .fromjson = vl_api_ipsec_set_async_mode_reply_t_fromjson,
    .calc_size = vl_api_ipsec_set_async_mode_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipsec_set_async_mode", api_ipsec_set_async_mode);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   ipsec_test_main_t * mainp = &ipsec_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("ipsec_b648c199");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "ipsec plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
