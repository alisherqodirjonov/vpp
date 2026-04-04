#define vl_endianfun            /* define message structures */
#include "ikev2.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "ikev2.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "ikev2.api.h"
#undef vl_printfun

/* Generation not supported (vl_api_ikev2_plugin_get_version_reply_t_handler()) */
#ifndef VL_API_IKEV2_PLUGIN_SET_SLEEP_INTERVAL_REPLY_T_HANDLER
static void
vl_api_ikev2_plugin_set_sleep_interval_reply_t_handler (vl_api_ikev2_plugin_set_sleep_interval_reply_t * mp) {
   vat_main_t * vam = ikev2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_ikev2_get_sleep_interval_reply_t_handler()) */
/* Generation not supported (vl_api_ikev2_profile_details_t_handler()) */
/* Generation not supported (vl_api_ikev2_sa_details_t_handler()) */
/* Generation not supported (vl_api_ikev2_sa_v2_details_t_handler()) */
/* Generation not supported (vl_api_ikev2_sa_v3_details_t_handler()) */
/* Generation not supported (vl_api_ikev2_child_sa_details_t_handler()) */
/* Generation not supported (vl_api_ikev2_child_sa_v2_details_t_handler()) */
/* Generation not supported (vl_api_ikev2_nonce_get_reply_t_handler()) */
/* Generation not supported (vl_api_ikev2_traffic_selector_details_t_handler()) */
#ifndef VL_API_IKEV2_PROFILE_ADD_DEL_REPLY_T_HANDLER
static void
vl_api_ikev2_profile_add_del_reply_t_handler (vl_api_ikev2_profile_add_del_reply_t * mp) {
   vat_main_t * vam = ikev2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IKEV2_PROFILE_SET_AUTH_REPLY_T_HANDLER
static void
vl_api_ikev2_profile_set_auth_reply_t_handler (vl_api_ikev2_profile_set_auth_reply_t * mp) {
   vat_main_t * vam = ikev2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IKEV2_PROFILE_SET_ID_REPLY_T_HANDLER
static void
vl_api_ikev2_profile_set_id_reply_t_handler (vl_api_ikev2_profile_set_id_reply_t * mp) {
   vat_main_t * vam = ikev2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IKEV2_PROFILE_DISABLE_NATT_REPLY_T_HANDLER
static void
vl_api_ikev2_profile_disable_natt_reply_t_handler (vl_api_ikev2_profile_disable_natt_reply_t * mp) {
   vat_main_t * vam = ikev2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IKEV2_PROFILE_SET_TS_REPLY_T_HANDLER
static void
vl_api_ikev2_profile_set_ts_reply_t_handler (vl_api_ikev2_profile_set_ts_reply_t * mp) {
   vat_main_t * vam = ikev2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IKEV2_SET_LOCAL_KEY_REPLY_T_HANDLER
static void
vl_api_ikev2_set_local_key_reply_t_handler (vl_api_ikev2_set_local_key_reply_t * mp) {
   vat_main_t * vam = ikev2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IKEV2_SET_TUNNEL_INTERFACE_REPLY_T_HANDLER
static void
vl_api_ikev2_set_tunnel_interface_reply_t_handler (vl_api_ikev2_set_tunnel_interface_reply_t * mp) {
   vat_main_t * vam = ikev2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IKEV2_SET_RESPONDER_REPLY_T_HANDLER
static void
vl_api_ikev2_set_responder_reply_t_handler (vl_api_ikev2_set_responder_reply_t * mp) {
   vat_main_t * vam = ikev2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IKEV2_SET_RESPONDER_HOSTNAME_REPLY_T_HANDLER
static void
vl_api_ikev2_set_responder_hostname_reply_t_handler (vl_api_ikev2_set_responder_hostname_reply_t * mp) {
   vat_main_t * vam = ikev2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IKEV2_SET_IKE_TRANSFORMS_REPLY_T_HANDLER
static void
vl_api_ikev2_set_ike_transforms_reply_t_handler (vl_api_ikev2_set_ike_transforms_reply_t * mp) {
   vat_main_t * vam = ikev2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IKEV2_SET_ESP_TRANSFORMS_REPLY_T_HANDLER
static void
vl_api_ikev2_set_esp_transforms_reply_t_handler (vl_api_ikev2_set_esp_transforms_reply_t * mp) {
   vat_main_t * vam = ikev2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IKEV2_SET_SA_LIFETIME_REPLY_T_HANDLER
static void
vl_api_ikev2_set_sa_lifetime_reply_t_handler (vl_api_ikev2_set_sa_lifetime_reply_t * mp) {
   vat_main_t * vam = ikev2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IKEV2_INITIATE_SA_INIT_REPLY_T_HANDLER
static void
vl_api_ikev2_initiate_sa_init_reply_t_handler (vl_api_ikev2_initiate_sa_init_reply_t * mp) {
   vat_main_t * vam = ikev2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IKEV2_INITIATE_DEL_IKE_SA_REPLY_T_HANDLER
static void
vl_api_ikev2_initiate_del_ike_sa_reply_t_handler (vl_api_ikev2_initiate_del_ike_sa_reply_t * mp) {
   vat_main_t * vam = ikev2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IKEV2_INITIATE_DEL_CHILD_SA_REPLY_T_HANDLER
static void
vl_api_ikev2_initiate_del_child_sa_reply_t_handler (vl_api_ikev2_initiate_del_child_sa_reply_t * mp) {
   vat_main_t * vam = ikev2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IKEV2_INITIATE_REKEY_CHILD_SA_REPLY_T_HANDLER
static void
vl_api_ikev2_initiate_rekey_child_sa_reply_t_handler (vl_api_ikev2_initiate_rekey_child_sa_reply_t * mp) {
   vat_main_t * vam = ikev2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IKEV2_PROFILE_SET_UDP_ENCAP_REPLY_T_HANDLER
static void
vl_api_ikev2_profile_set_udp_encap_reply_t_handler (vl_api_ikev2_profile_set_udp_encap_reply_t * mp) {
   vat_main_t * vam = ikev2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IKEV2_PROFILE_SET_IPSEC_UDP_PORT_REPLY_T_HANDLER
static void
vl_api_ikev2_profile_set_ipsec_udp_port_reply_t_handler (vl_api_ikev2_profile_set_ipsec_udp_port_reply_t * mp) {
   vat_main_t * vam = ikev2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IKEV2_PROFILE_SET_LIVENESS_REPLY_T_HANDLER
static void
vl_api_ikev2_profile_set_liveness_reply_t_handler (vl_api_ikev2_profile_set_liveness_reply_t * mp) {
   vat_main_t * vam = ikev2_test_main.vat_main;
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
    .id = VL_API_IKEV2_PLUGIN_GET_VERSION_REPLY + msg_id_base,
    .name = "ikev2_plugin_get_version_reply",
    .handler = vl_api_ikev2_plugin_get_version_reply_t_handler,
    .endian = vl_api_ikev2_plugin_get_version_reply_t_endian,
    .format_fn = vl_api_ikev2_plugin_get_version_reply_t_format,
    .size = sizeof(vl_api_ikev2_plugin_get_version_reply_t),
    .traced = 1,
    .tojson = vl_api_ikev2_plugin_get_version_reply_t_tojson,
    .fromjson = vl_api_ikev2_plugin_get_version_reply_t_fromjson,
    .calc_size = vl_api_ikev2_plugin_get_version_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ikev2_plugin_get_version", api_ikev2_plugin_get_version);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IKEV2_PLUGIN_SET_SLEEP_INTERVAL_REPLY + msg_id_base,
    .name = "ikev2_plugin_set_sleep_interval_reply",
    .handler = vl_api_ikev2_plugin_set_sleep_interval_reply_t_handler,
    .endian = vl_api_ikev2_plugin_set_sleep_interval_reply_t_endian,
    .format_fn = vl_api_ikev2_plugin_set_sleep_interval_reply_t_format,
    .size = sizeof(vl_api_ikev2_plugin_set_sleep_interval_reply_t),
    .traced = 1,
    .tojson = vl_api_ikev2_plugin_set_sleep_interval_reply_t_tojson,
    .fromjson = vl_api_ikev2_plugin_set_sleep_interval_reply_t_fromjson,
    .calc_size = vl_api_ikev2_plugin_set_sleep_interval_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ikev2_plugin_set_sleep_interval", api_ikev2_plugin_set_sleep_interval);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IKEV2_GET_SLEEP_INTERVAL_REPLY + msg_id_base,
    .name = "ikev2_get_sleep_interval_reply",
    .handler = vl_api_ikev2_get_sleep_interval_reply_t_handler,
    .endian = vl_api_ikev2_get_sleep_interval_reply_t_endian,
    .format_fn = vl_api_ikev2_get_sleep_interval_reply_t_format,
    .size = sizeof(vl_api_ikev2_get_sleep_interval_reply_t),
    .traced = 1,
    .tojson = vl_api_ikev2_get_sleep_interval_reply_t_tojson,
    .fromjson = vl_api_ikev2_get_sleep_interval_reply_t_fromjson,
    .calc_size = vl_api_ikev2_get_sleep_interval_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ikev2_get_sleep_interval", api_ikev2_get_sleep_interval);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IKEV2_PROFILE_DETAILS + msg_id_base,
    .name = "ikev2_profile_details",
    .handler = vl_api_ikev2_profile_details_t_handler,
    .endian = vl_api_ikev2_profile_details_t_endian,
    .format_fn = vl_api_ikev2_profile_details_t_format,
    .size = sizeof(vl_api_ikev2_profile_details_t),
    .traced = 1,
    .tojson = vl_api_ikev2_profile_details_t_tojson,
    .fromjson = vl_api_ikev2_profile_details_t_fromjson,
    .calc_size = vl_api_ikev2_profile_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ikev2_profile_dump", api_ikev2_profile_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IKEV2_SA_DETAILS + msg_id_base,
    .name = "ikev2_sa_details",
    .handler = vl_api_ikev2_sa_details_t_handler,
    .endian = vl_api_ikev2_sa_details_t_endian,
    .format_fn = vl_api_ikev2_sa_details_t_format,
    .size = sizeof(vl_api_ikev2_sa_details_t),
    .traced = 1,
    .tojson = vl_api_ikev2_sa_details_t_tojson,
    .fromjson = vl_api_ikev2_sa_details_t_fromjson,
    .calc_size = vl_api_ikev2_sa_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ikev2_sa_dump", api_ikev2_sa_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IKEV2_SA_V2_DETAILS + msg_id_base,
    .name = "ikev2_sa_v2_details",
    .handler = vl_api_ikev2_sa_v2_details_t_handler,
    .endian = vl_api_ikev2_sa_v2_details_t_endian,
    .format_fn = vl_api_ikev2_sa_v2_details_t_format,
    .size = sizeof(vl_api_ikev2_sa_v2_details_t),
    .traced = 1,
    .tojson = vl_api_ikev2_sa_v2_details_t_tojson,
    .fromjson = vl_api_ikev2_sa_v2_details_t_fromjson,
    .calc_size = vl_api_ikev2_sa_v2_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ikev2_sa_v2_dump", api_ikev2_sa_v2_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IKEV2_SA_V3_DETAILS + msg_id_base,
    .name = "ikev2_sa_v3_details",
    .handler = vl_api_ikev2_sa_v3_details_t_handler,
    .endian = vl_api_ikev2_sa_v3_details_t_endian,
    .format_fn = vl_api_ikev2_sa_v3_details_t_format,
    .size = sizeof(vl_api_ikev2_sa_v3_details_t),
    .traced = 1,
    .tojson = vl_api_ikev2_sa_v3_details_t_tojson,
    .fromjson = vl_api_ikev2_sa_v3_details_t_fromjson,
    .calc_size = vl_api_ikev2_sa_v3_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ikev2_sa_v3_dump", api_ikev2_sa_v3_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IKEV2_CHILD_SA_DETAILS + msg_id_base,
    .name = "ikev2_child_sa_details",
    .handler = vl_api_ikev2_child_sa_details_t_handler,
    .endian = vl_api_ikev2_child_sa_details_t_endian,
    .format_fn = vl_api_ikev2_child_sa_details_t_format,
    .size = sizeof(vl_api_ikev2_child_sa_details_t),
    .traced = 1,
    .tojson = vl_api_ikev2_child_sa_details_t_tojson,
    .fromjson = vl_api_ikev2_child_sa_details_t_fromjson,
    .calc_size = vl_api_ikev2_child_sa_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ikev2_child_sa_dump", api_ikev2_child_sa_dump);
   hash_set_mem (vam->help_by_name, "ikev2_child_sa_dump", "sa_index <index>");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IKEV2_CHILD_SA_V2_DETAILS + msg_id_base,
    .name = "ikev2_child_sa_v2_details",
    .handler = vl_api_ikev2_child_sa_v2_details_t_handler,
    .endian = vl_api_ikev2_child_sa_v2_details_t_endian,
    .format_fn = vl_api_ikev2_child_sa_v2_details_t_format,
    .size = sizeof(vl_api_ikev2_child_sa_v2_details_t),
    .traced = 1,
    .tojson = vl_api_ikev2_child_sa_v2_details_t_tojson,
    .fromjson = vl_api_ikev2_child_sa_v2_details_t_fromjson,
    .calc_size = vl_api_ikev2_child_sa_v2_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ikev2_child_sa_v2_dump", api_ikev2_child_sa_v2_dump);
   hash_set_mem (vam->help_by_name, "ikev2_child_sa_v2_dump", "sa_index <index>");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IKEV2_NONCE_GET_REPLY + msg_id_base,
    .name = "ikev2_nonce_get_reply",
    .handler = vl_api_ikev2_nonce_get_reply_t_handler,
    .endian = vl_api_ikev2_nonce_get_reply_t_endian,
    .format_fn = vl_api_ikev2_nonce_get_reply_t_format,
    .size = sizeof(vl_api_ikev2_nonce_get_reply_t),
    .traced = 1,
    .tojson = vl_api_ikev2_nonce_get_reply_t_tojson,
    .fromjson = vl_api_ikev2_nonce_get_reply_t_fromjson,
    .calc_size = vl_api_ikev2_nonce_get_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ikev2_nonce_get", api_ikev2_nonce_get);
   hash_set_mem (vam->help_by_name, "ikev2_nonce_get", "initiator|responder sa_index <index>");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IKEV2_TRAFFIC_SELECTOR_DETAILS + msg_id_base,
    .name = "ikev2_traffic_selector_details",
    .handler = vl_api_ikev2_traffic_selector_details_t_handler,
    .endian = vl_api_ikev2_traffic_selector_details_t_endian,
    .format_fn = vl_api_ikev2_traffic_selector_details_t_format,
    .size = sizeof(vl_api_ikev2_traffic_selector_details_t),
    .traced = 1,
    .tojson = vl_api_ikev2_traffic_selector_details_t_tojson,
    .fromjson = vl_api_ikev2_traffic_selector_details_t_fromjson,
    .calc_size = vl_api_ikev2_traffic_selector_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ikev2_traffic_selector_dump", api_ikev2_traffic_selector_dump);
   hash_set_mem (vam->help_by_name, "ikev2_traffic_selector_dump", "initiator|responder sa_index <index> child_sa_index <index>");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IKEV2_PROFILE_ADD_DEL_REPLY + msg_id_base,
    .name = "ikev2_profile_add_del_reply",
    .handler = vl_api_ikev2_profile_add_del_reply_t_handler,
    .endian = vl_api_ikev2_profile_add_del_reply_t_endian,
    .format_fn = vl_api_ikev2_profile_add_del_reply_t_format,
    .size = sizeof(vl_api_ikev2_profile_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_ikev2_profile_add_del_reply_t_tojson,
    .fromjson = vl_api_ikev2_profile_add_del_reply_t_fromjson,
    .calc_size = vl_api_ikev2_profile_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ikev2_profile_add_del", api_ikev2_profile_add_del);
   hash_set_mem (vam->help_by_name, "ikev2_profile_add_del", "name <profile_name> [del]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IKEV2_PROFILE_SET_AUTH_REPLY + msg_id_base,
    .name = "ikev2_profile_set_auth_reply",
    .handler = vl_api_ikev2_profile_set_auth_reply_t_handler,
    .endian = vl_api_ikev2_profile_set_auth_reply_t_endian,
    .format_fn = vl_api_ikev2_profile_set_auth_reply_t_format,
    .size = sizeof(vl_api_ikev2_profile_set_auth_reply_t),
    .traced = 1,
    .tojson = vl_api_ikev2_profile_set_auth_reply_t_tojson,
    .fromjson = vl_api_ikev2_profile_set_auth_reply_t_fromjson,
    .calc_size = vl_api_ikev2_profile_set_auth_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ikev2_profile_set_auth", api_ikev2_profile_set_auth);
   hash_set_mem (vam->help_by_name, "ikev2_profile_set_auth", "name <profile_name> auth_method <method> (auth_data 0x<data> | auth_data <data>)");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IKEV2_PROFILE_SET_ID_REPLY + msg_id_base,
    .name = "ikev2_profile_set_id_reply",
    .handler = vl_api_ikev2_profile_set_id_reply_t_handler,
    .endian = vl_api_ikev2_profile_set_id_reply_t_endian,
    .format_fn = vl_api_ikev2_profile_set_id_reply_t_format,
    .size = sizeof(vl_api_ikev2_profile_set_id_reply_t),
    .traced = 1,
    .tojson = vl_api_ikev2_profile_set_id_reply_t_tojson,
    .fromjson = vl_api_ikev2_profile_set_id_reply_t_fromjson,
    .calc_size = vl_api_ikev2_profile_set_id_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ikev2_profile_set_id", api_ikev2_profile_set_id);
   hash_set_mem (vam->help_by_name, "ikev2_profile_set_id", "name <profile_name> id_type <type> (id_data 0x<data> | id_data <data>) (local|remote)");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IKEV2_PROFILE_DISABLE_NATT_REPLY + msg_id_base,
    .name = "ikev2_profile_disable_natt_reply",
    .handler = vl_api_ikev2_profile_disable_natt_reply_t_handler,
    .endian = vl_api_ikev2_profile_disable_natt_reply_t_endian,
    .format_fn = vl_api_ikev2_profile_disable_natt_reply_t_format,
    .size = sizeof(vl_api_ikev2_profile_disable_natt_reply_t),
    .traced = 1,
    .tojson = vl_api_ikev2_profile_disable_natt_reply_t_tojson,
    .fromjson = vl_api_ikev2_profile_disable_natt_reply_t_fromjson,
    .calc_size = vl_api_ikev2_profile_disable_natt_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ikev2_profile_disable_natt", api_ikev2_profile_disable_natt);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IKEV2_PROFILE_SET_TS_REPLY + msg_id_base,
    .name = "ikev2_profile_set_ts_reply",
    .handler = vl_api_ikev2_profile_set_ts_reply_t_handler,
    .endian = vl_api_ikev2_profile_set_ts_reply_t_endian,
    .format_fn = vl_api_ikev2_profile_set_ts_reply_t_format,
    .size = sizeof(vl_api_ikev2_profile_set_ts_reply_t),
    .traced = 1,
    .tojson = vl_api_ikev2_profile_set_ts_reply_t_tojson,
    .fromjson = vl_api_ikev2_profile_set_ts_reply_t_fromjson,
    .calc_size = vl_api_ikev2_profile_set_ts_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ikev2_profile_set_ts", api_ikev2_profile_set_ts);
   hash_set_mem (vam->help_by_name, "ikev2_profile_set_ts", "name <profile_name> protocol <proto> start_port <port> end_port <port> start_addr <ip> end_addr <ip> (local|remote)");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IKEV2_SET_LOCAL_KEY_REPLY + msg_id_base,
    .name = "ikev2_set_local_key_reply",
    .handler = vl_api_ikev2_set_local_key_reply_t_handler,
    .endian = vl_api_ikev2_set_local_key_reply_t_endian,
    .format_fn = vl_api_ikev2_set_local_key_reply_t_format,
    .size = sizeof(vl_api_ikev2_set_local_key_reply_t),
    .traced = 1,
    .tojson = vl_api_ikev2_set_local_key_reply_t_tojson,
    .fromjson = vl_api_ikev2_set_local_key_reply_t_fromjson,
    .calc_size = vl_api_ikev2_set_local_key_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ikev2_set_local_key", api_ikev2_set_local_key);
   hash_set_mem (vam->help_by_name, "ikev2_set_local_key", "file <absolute_file_path>");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IKEV2_SET_TUNNEL_INTERFACE_REPLY + msg_id_base,
    .name = "ikev2_set_tunnel_interface_reply",
    .handler = vl_api_ikev2_set_tunnel_interface_reply_t_handler,
    .endian = vl_api_ikev2_set_tunnel_interface_reply_t_endian,
    .format_fn = vl_api_ikev2_set_tunnel_interface_reply_t_format,
    .size = sizeof(vl_api_ikev2_set_tunnel_interface_reply_t),
    .traced = 1,
    .tojson = vl_api_ikev2_set_tunnel_interface_reply_t_tojson,
    .fromjson = vl_api_ikev2_set_tunnel_interface_reply_t_fromjson,
    .calc_size = vl_api_ikev2_set_tunnel_interface_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ikev2_set_tunnel_interface", api_ikev2_set_tunnel_interface);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IKEV2_SET_RESPONDER_REPLY + msg_id_base,
    .name = "ikev2_set_responder_reply",
    .handler = vl_api_ikev2_set_responder_reply_t_handler,
    .endian = vl_api_ikev2_set_responder_reply_t_endian,
    .format_fn = vl_api_ikev2_set_responder_reply_t_format,
    .size = sizeof(vl_api_ikev2_set_responder_reply_t),
    .traced = 1,
    .tojson = vl_api_ikev2_set_responder_reply_t_tojson,
    .fromjson = vl_api_ikev2_set_responder_reply_t_fromjson,
    .calc_size = vl_api_ikev2_set_responder_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ikev2_set_responder", api_ikev2_set_responder);
   hash_set_mem (vam->help_by_name, "ikev2_set_responder", "<profile_name> interface <interface> address <addr>");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IKEV2_SET_RESPONDER_HOSTNAME_REPLY + msg_id_base,
    .name = "ikev2_set_responder_hostname_reply",
    .handler = vl_api_ikev2_set_responder_hostname_reply_t_handler,
    .endian = vl_api_ikev2_set_responder_hostname_reply_t_endian,
    .format_fn = vl_api_ikev2_set_responder_hostname_reply_t_format,
    .size = sizeof(vl_api_ikev2_set_responder_hostname_reply_t),
    .traced = 1,
    .tojson = vl_api_ikev2_set_responder_hostname_reply_t_tojson,
    .fromjson = vl_api_ikev2_set_responder_hostname_reply_t_fromjson,
    .calc_size = vl_api_ikev2_set_responder_hostname_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ikev2_set_responder_hostname", api_ikev2_set_responder_hostname);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IKEV2_SET_IKE_TRANSFORMS_REPLY + msg_id_base,
    .name = "ikev2_set_ike_transforms_reply",
    .handler = vl_api_ikev2_set_ike_transforms_reply_t_handler,
    .endian = vl_api_ikev2_set_ike_transforms_reply_t_endian,
    .format_fn = vl_api_ikev2_set_ike_transforms_reply_t_format,
    .size = sizeof(vl_api_ikev2_set_ike_transforms_reply_t),
    .traced = 1,
    .tojson = vl_api_ikev2_set_ike_transforms_reply_t_tojson,
    .fromjson = vl_api_ikev2_set_ike_transforms_reply_t_fromjson,
    .calc_size = vl_api_ikev2_set_ike_transforms_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ikev2_set_ike_transforms", api_ikev2_set_ike_transforms);
   hash_set_mem (vam->help_by_name, "ikev2_set_ike_transforms", "<profile_name> <crypto alg> <key size> <integrity alg> <DH group>");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IKEV2_SET_ESP_TRANSFORMS_REPLY + msg_id_base,
    .name = "ikev2_set_esp_transforms_reply",
    .handler = vl_api_ikev2_set_esp_transforms_reply_t_handler,
    .endian = vl_api_ikev2_set_esp_transforms_reply_t_endian,
    .format_fn = vl_api_ikev2_set_esp_transforms_reply_t_format,
    .size = sizeof(vl_api_ikev2_set_esp_transforms_reply_t),
    .traced = 1,
    .tojson = vl_api_ikev2_set_esp_transforms_reply_t_tojson,
    .fromjson = vl_api_ikev2_set_esp_transforms_reply_t_fromjson,
    .calc_size = vl_api_ikev2_set_esp_transforms_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ikev2_set_esp_transforms", api_ikev2_set_esp_transforms);
   hash_set_mem (vam->help_by_name, "ikev2_set_esp_transforms", "<profile_name> <crypto alg> <key size> <integrity alg>");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IKEV2_SET_SA_LIFETIME_REPLY + msg_id_base,
    .name = "ikev2_set_sa_lifetime_reply",
    .handler = vl_api_ikev2_set_sa_lifetime_reply_t_handler,
    .endian = vl_api_ikev2_set_sa_lifetime_reply_t_endian,
    .format_fn = vl_api_ikev2_set_sa_lifetime_reply_t_format,
    .size = sizeof(vl_api_ikev2_set_sa_lifetime_reply_t),
    .traced = 1,
    .tojson = vl_api_ikev2_set_sa_lifetime_reply_t_tojson,
    .fromjson = vl_api_ikev2_set_sa_lifetime_reply_t_fromjson,
    .calc_size = vl_api_ikev2_set_sa_lifetime_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ikev2_set_sa_lifetime", api_ikev2_set_sa_lifetime);
   hash_set_mem (vam->help_by_name, "ikev2_set_sa_lifetime", "<profile_name> <seconds> <jitter> <handover> <max bytes>");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IKEV2_INITIATE_SA_INIT_REPLY + msg_id_base,
    .name = "ikev2_initiate_sa_init_reply",
    .handler = vl_api_ikev2_initiate_sa_init_reply_t_handler,
    .endian = vl_api_ikev2_initiate_sa_init_reply_t_endian,
    .format_fn = vl_api_ikev2_initiate_sa_init_reply_t_format,
    .size = sizeof(vl_api_ikev2_initiate_sa_init_reply_t),
    .traced = 1,
    .tojson = vl_api_ikev2_initiate_sa_init_reply_t_tojson,
    .fromjson = vl_api_ikev2_initiate_sa_init_reply_t_fromjson,
    .calc_size = vl_api_ikev2_initiate_sa_init_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ikev2_initiate_sa_init", api_ikev2_initiate_sa_init);
   hash_set_mem (vam->help_by_name, "ikev2_initiate_sa_init", "<profile_name>");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IKEV2_INITIATE_DEL_IKE_SA_REPLY + msg_id_base,
    .name = "ikev2_initiate_del_ike_sa_reply",
    .handler = vl_api_ikev2_initiate_del_ike_sa_reply_t_handler,
    .endian = vl_api_ikev2_initiate_del_ike_sa_reply_t_endian,
    .format_fn = vl_api_ikev2_initiate_del_ike_sa_reply_t_format,
    .size = sizeof(vl_api_ikev2_initiate_del_ike_sa_reply_t),
    .traced = 1,
    .tojson = vl_api_ikev2_initiate_del_ike_sa_reply_t_tojson,
    .fromjson = vl_api_ikev2_initiate_del_ike_sa_reply_t_fromjson,
    .calc_size = vl_api_ikev2_initiate_del_ike_sa_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ikev2_initiate_del_ike_sa", api_ikev2_initiate_del_ike_sa);
   hash_set_mem (vam->help_by_name, "ikev2_initiate_del_ike_sa", "<ispi>");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IKEV2_INITIATE_DEL_CHILD_SA_REPLY + msg_id_base,
    .name = "ikev2_initiate_del_child_sa_reply",
    .handler = vl_api_ikev2_initiate_del_child_sa_reply_t_handler,
    .endian = vl_api_ikev2_initiate_del_child_sa_reply_t_endian,
    .format_fn = vl_api_ikev2_initiate_del_child_sa_reply_t_format,
    .size = sizeof(vl_api_ikev2_initiate_del_child_sa_reply_t),
    .traced = 1,
    .tojson = vl_api_ikev2_initiate_del_child_sa_reply_t_tojson,
    .fromjson = vl_api_ikev2_initiate_del_child_sa_reply_t_fromjson,
    .calc_size = vl_api_ikev2_initiate_del_child_sa_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ikev2_initiate_del_child_sa", api_ikev2_initiate_del_child_sa);
   hash_set_mem (vam->help_by_name, "ikev2_initiate_del_child_sa", "<ispi>");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IKEV2_INITIATE_REKEY_CHILD_SA_REPLY + msg_id_base,
    .name = "ikev2_initiate_rekey_child_sa_reply",
    .handler = vl_api_ikev2_initiate_rekey_child_sa_reply_t_handler,
    .endian = vl_api_ikev2_initiate_rekey_child_sa_reply_t_endian,
    .format_fn = vl_api_ikev2_initiate_rekey_child_sa_reply_t_format,
    .size = sizeof(vl_api_ikev2_initiate_rekey_child_sa_reply_t),
    .traced = 1,
    .tojson = vl_api_ikev2_initiate_rekey_child_sa_reply_t_tojson,
    .fromjson = vl_api_ikev2_initiate_rekey_child_sa_reply_t_fromjson,
    .calc_size = vl_api_ikev2_initiate_rekey_child_sa_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ikev2_initiate_rekey_child_sa", api_ikev2_initiate_rekey_child_sa);
   hash_set_mem (vam->help_by_name, "ikev2_initiate_rekey_child_sa", "<ispi>");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IKEV2_PROFILE_SET_UDP_ENCAP_REPLY + msg_id_base,
    .name = "ikev2_profile_set_udp_encap_reply",
    .handler = vl_api_ikev2_profile_set_udp_encap_reply_t_handler,
    .endian = vl_api_ikev2_profile_set_udp_encap_reply_t_endian,
    .format_fn = vl_api_ikev2_profile_set_udp_encap_reply_t_format,
    .size = sizeof(vl_api_ikev2_profile_set_udp_encap_reply_t),
    .traced = 1,
    .tojson = vl_api_ikev2_profile_set_udp_encap_reply_t_tojson,
    .fromjson = vl_api_ikev2_profile_set_udp_encap_reply_t_fromjson,
    .calc_size = vl_api_ikev2_profile_set_udp_encap_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ikev2_profile_set_udp_encap", api_ikev2_profile_set_udp_encap);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IKEV2_PROFILE_SET_IPSEC_UDP_PORT_REPLY + msg_id_base,
    .name = "ikev2_profile_set_ipsec_udp_port_reply",
    .handler = vl_api_ikev2_profile_set_ipsec_udp_port_reply_t_handler,
    .endian = vl_api_ikev2_profile_set_ipsec_udp_port_reply_t_endian,
    .format_fn = vl_api_ikev2_profile_set_ipsec_udp_port_reply_t_format,
    .size = sizeof(vl_api_ikev2_profile_set_ipsec_udp_port_reply_t),
    .traced = 1,
    .tojson = vl_api_ikev2_profile_set_ipsec_udp_port_reply_t_tojson,
    .fromjson = vl_api_ikev2_profile_set_ipsec_udp_port_reply_t_fromjson,
    .calc_size = vl_api_ikev2_profile_set_ipsec_udp_port_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ikev2_profile_set_ipsec_udp_port", api_ikev2_profile_set_ipsec_udp_port);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IKEV2_PROFILE_SET_LIVENESS_REPLY + msg_id_base,
    .name = "ikev2_profile_set_liveness_reply",
    .handler = vl_api_ikev2_profile_set_liveness_reply_t_handler,
    .endian = vl_api_ikev2_profile_set_liveness_reply_t_endian,
    .format_fn = vl_api_ikev2_profile_set_liveness_reply_t_format,
    .size = sizeof(vl_api_ikev2_profile_set_liveness_reply_t),
    .traced = 1,
    .tojson = vl_api_ikev2_profile_set_liveness_reply_t_tojson,
    .fromjson = vl_api_ikev2_profile_set_liveness_reply_t_fromjson,
    .calc_size = vl_api_ikev2_profile_set_liveness_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ikev2_profile_set_liveness", api_ikev2_profile_set_liveness);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   ikev2_test_main_t * mainp = &ikev2_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("ikev2_14c94752");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "ikev2 plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
