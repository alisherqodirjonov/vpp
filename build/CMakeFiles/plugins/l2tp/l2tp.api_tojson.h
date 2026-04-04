/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ethernet/ethernet_types.api_tojson.h>
#include <vnet/ip/ip_types.api_tojson.h>
#ifndef included_l2tp_api_tojson_h
#define included_l2tp_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_l2t_lookup_key_t_tojson (vl_api_l2t_lookup_key_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("L2T_LOOKUP_KEY_API_SRC_ADDR");
    case 1:
        return cJSON_CreateString("L2T_LOOKUP_KEY_API_DST_ADDR");
    case 2:
        return cJSON_CreateString("L2T_LOOKUP_KEY_API_SESSION_ID");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_l2tpv3_create_tunnel_t_tojson (vl_api_l2tpv3_create_tunnel_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l2tpv3_create_tunnel");
    cJSON_AddStringToObject(o, "_crc", "15bed0c2");
    cJSON_AddItemToObject(o, "client_address", vl_api_address_t_tojson(&a->client_address));
    cJSON_AddItemToObject(o, "our_address", vl_api_address_t_tojson(&a->our_address));
    cJSON_AddNumberToObject(o, "local_session_id", a->local_session_id);
    cJSON_AddNumberToObject(o, "remote_session_id", a->remote_session_id);
    cJSON_AddNumberToObject(o, "local_cookie", a->local_cookie);
    cJSON_AddNumberToObject(o, "remote_cookie", a->remote_cookie);
    cJSON_AddBoolToObject(o, "l2_sublayer_present", a->l2_sublayer_present);
    cJSON_AddNumberToObject(o, "encap_vrf_id", a->encap_vrf_id);
    return o;
}
static inline cJSON *vl_api_l2tpv3_create_tunnel_reply_t_tojson (vl_api_l2tpv3_create_tunnel_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l2tpv3_create_tunnel_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_l2tpv3_set_tunnel_cookies_t_tojson (vl_api_l2tpv3_set_tunnel_cookies_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l2tpv3_set_tunnel_cookies");
    cJSON_AddStringToObject(o, "_crc", "b3f4faf7");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "new_local_cookie", a->new_local_cookie);
    cJSON_AddNumberToObject(o, "new_remote_cookie", a->new_remote_cookie);
    return o;
}
static inline cJSON *vl_api_l2tpv3_set_tunnel_cookies_reply_t_tojson (vl_api_l2tpv3_set_tunnel_cookies_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l2tpv3_set_tunnel_cookies_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sw_if_l2tpv3_tunnel_details_t_tojson (vl_api_sw_if_l2tpv3_tunnel_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_if_l2tpv3_tunnel_details");
    cJSON_AddStringToObject(o, "_crc", "50b88993");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddStringToObject(o, "interface_name", (char *)a->interface_name);
    cJSON_AddItemToObject(o, "client_address", vl_api_address_t_tojson(&a->client_address));
    cJSON_AddItemToObject(o, "our_address", vl_api_address_t_tojson(&a->our_address));
    cJSON_AddNumberToObject(o, "local_session_id", a->local_session_id);
    cJSON_AddNumberToObject(o, "remote_session_id", a->remote_session_id);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "local_cookie");
        for (i = 0; i < 2; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->local_cookie[i]));
        }
    }
    cJSON_AddNumberToObject(o, "remote_cookie", a->remote_cookie);
    cJSON_AddBoolToObject(o, "l2_sublayer_present", a->l2_sublayer_present);
    return o;
}
static inline cJSON *vl_api_sw_if_l2tpv3_tunnel_dump_t_tojson (vl_api_sw_if_l2tpv3_tunnel_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_if_l2tpv3_tunnel_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_l2tpv3_interface_enable_disable_t_tojson (vl_api_l2tpv3_interface_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l2tpv3_interface_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "3865946c");
    cJSON_AddBoolToObject(o, "enable_disable", a->enable_disable);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_l2tpv3_interface_enable_disable_reply_t_tojson (vl_api_l2tpv3_interface_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l2tpv3_interface_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_l2tpv3_set_lookup_key_t_tojson (vl_api_l2tpv3_set_lookup_key_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l2tpv3_set_lookup_key");
    cJSON_AddStringToObject(o, "_crc", "c9892c86");
    cJSON_AddItemToObject(o, "key", vl_api_l2t_lookup_key_t_tojson(a->key));
    return o;
}
static inline cJSON *vl_api_l2tpv3_set_lookup_key_reply_t_tojson (vl_api_l2tpv3_set_lookup_key_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l2tpv3_set_lookup_key_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
