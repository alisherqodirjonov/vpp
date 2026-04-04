/* Imported API files */
#include <ikev2/ikev2_types.api_tojson.h>
#include <vnet/ip/ip_types.api_tojson.h>
#include <vnet/interface_types.api_tojson.h>
#ifndef included_ikev2_api_tojson_h
#define included_ikev2_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_ikev2_plugin_get_version_t_tojson (vl_api_ikev2_plugin_get_version_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_plugin_get_version");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_ikev2_plugin_get_version_reply_t_tojson (vl_api_ikev2_plugin_get_version_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_plugin_get_version_reply");
    cJSON_AddStringToObject(o, "_crc", "9b32cf86");
    cJSON_AddNumberToObject(o, "major", a->major);
    cJSON_AddNumberToObject(o, "minor", a->minor);
    return o;
}
static inline cJSON *vl_api_ikev2_plugin_set_sleep_interval_t_tojson (vl_api_ikev2_plugin_set_sleep_interval_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_plugin_set_sleep_interval");
    cJSON_AddStringToObject(o, "_crc", "b7c096ae");
    cJSON_AddNumberToObject(o, "timeout", a->timeout);
    return o;
}
static inline cJSON *vl_api_ikev2_plugin_set_sleep_interval_reply_t_tojson (vl_api_ikev2_plugin_set_sleep_interval_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_plugin_set_sleep_interval_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ikev2_get_sleep_interval_t_tojson (vl_api_ikev2_get_sleep_interval_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_get_sleep_interval");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_ikev2_get_sleep_interval_reply_t_tojson (vl_api_ikev2_get_sleep_interval_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_get_sleep_interval_reply");
    cJSON_AddStringToObject(o, "_crc", "78ab91dc");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sleep_interval", a->sleep_interval);
    return o;
}
static inline cJSON *vl_api_ikev2_profile_dump_t_tojson (vl_api_ikev2_profile_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_profile_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_ikev2_profile_details_t_tojson (vl_api_ikev2_profile_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_profile_details");
    cJSON_AddStringToObject(o, "_crc", "670d01d9");
    cJSON_AddItemToObject(o, "profile", vl_api_ikev2_profile_t_tojson(&a->profile));
    return o;
}
static inline cJSON *vl_api_ikev2_sa_dump_t_tojson (vl_api_ikev2_sa_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_sa_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_ikev2_sa_v2_dump_t_tojson (vl_api_ikev2_sa_v2_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_sa_v2_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_ikev2_sa_v3_dump_t_tojson (vl_api_ikev2_sa_v3_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_sa_v3_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_ikev2_sa_details_t_tojson (vl_api_ikev2_sa_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_sa_details");
    cJSON_AddStringToObject(o, "_crc", "937c22d5");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddItemToObject(o, "sa", vl_api_ikev2_sa_t_tojson(&a->sa));
    return o;
}
static inline cJSON *vl_api_ikev2_sa_v2_details_t_tojson (vl_api_ikev2_sa_v2_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_sa_v2_details");
    cJSON_AddStringToObject(o, "_crc", "a616e604");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddItemToObject(o, "sa", vl_api_ikev2_sa_v2_t_tojson(&a->sa));
    return o;
}
static inline cJSON *vl_api_ikev2_sa_v3_details_t_tojson (vl_api_ikev2_sa_v3_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_sa_v3_details");
    cJSON_AddStringToObject(o, "_crc", "85c9a941");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddItemToObject(o, "sa", vl_api_ikev2_sa_v3_t_tojson(&a->sa));
    return o;
}
static inline cJSON *vl_api_ikev2_child_sa_dump_t_tojson (vl_api_ikev2_child_sa_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_child_sa_dump");
    cJSON_AddStringToObject(o, "_crc", "01eab609");
    cJSON_AddNumberToObject(o, "sa_index", a->sa_index);
    return o;
}
static inline cJSON *vl_api_ikev2_child_sa_details_t_tojson (vl_api_ikev2_child_sa_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_child_sa_details");
    cJSON_AddStringToObject(o, "_crc", "ff67741f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddItemToObject(o, "child_sa", vl_api_ikev2_child_sa_t_tojson(&a->child_sa));
    return o;
}
static inline cJSON *vl_api_ikev2_child_sa_v2_dump_t_tojson (vl_api_ikev2_child_sa_v2_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_child_sa_v2_dump");
    cJSON_AddStringToObject(o, "_crc", "01eab609");
    cJSON_AddNumberToObject(o, "sa_index", a->sa_index);
    return o;
}
static inline cJSON *vl_api_ikev2_child_sa_v2_details_t_tojson (vl_api_ikev2_child_sa_v2_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_child_sa_v2_details");
    cJSON_AddStringToObject(o, "_crc", "1db62aa2");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddItemToObject(o, "child_sa", vl_api_ikev2_child_sa_v2_t_tojson(&a->child_sa));
    return o;
}
static inline cJSON *vl_api_ikev2_nonce_get_t_tojson (vl_api_ikev2_nonce_get_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_nonce_get");
    cJSON_AddStringToObject(o, "_crc", "7fe9ad51");
    cJSON_AddBoolToObject(o, "is_initiator", a->is_initiator);
    cJSON_AddNumberToObject(o, "sa_index", a->sa_index);
    return o;
}
static inline cJSON *vl_api_ikev2_nonce_get_reply_t_tojson (vl_api_ikev2_nonce_get_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_nonce_get_reply");
    cJSON_AddStringToObject(o, "_crc", "1b37a342");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "data_len", a->data_len);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->nonce, a->data_len);
    cJSON_AddStringToObject(o, "nonce", s);
    vec_free(s);
    }
    return o;
}
static inline cJSON *vl_api_ikev2_traffic_selector_dump_t_tojson (vl_api_ikev2_traffic_selector_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_traffic_selector_dump");
    cJSON_AddStringToObject(o, "_crc", "a7385e33");
    cJSON_AddBoolToObject(o, "is_initiator", a->is_initiator);
    cJSON_AddNumberToObject(o, "sa_index", a->sa_index);
    cJSON_AddNumberToObject(o, "child_sa_index", a->child_sa_index);
    return o;
}
static inline cJSON *vl_api_ikev2_traffic_selector_details_t_tojson (vl_api_ikev2_traffic_selector_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_traffic_selector_details");
    cJSON_AddStringToObject(o, "_crc", "518cb06f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddItemToObject(o, "ts", vl_api_ikev2_ts_t_tojson(&a->ts));
    return o;
}
static inline cJSON *vl_api_ikev2_profile_add_del_t_tojson (vl_api_ikev2_profile_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_profile_add_del");
    cJSON_AddStringToObject(o, "_crc", "2c925b55");
    cJSON_AddStringToObject(o, "name", (char *)a->name);
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    return o;
}
static inline cJSON *vl_api_ikev2_profile_add_del_reply_t_tojson (vl_api_ikev2_profile_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_profile_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ikev2_profile_set_auth_t_tojson (vl_api_ikev2_profile_set_auth_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_profile_set_auth");
    cJSON_AddStringToObject(o, "_crc", "642c97cd");
    cJSON_AddStringToObject(o, "name", (char *)a->name);
    cJSON_AddNumberToObject(o, "auth_method", a->auth_method);
    cJSON_AddBoolToObject(o, "is_hex", a->is_hex);
    cJSON_AddNumberToObject(o, "data_len", a->data_len);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->data, a->data_len);
    cJSON_AddStringToObject(o, "data", s);
    vec_free(s);
    }
    return o;
}
static inline cJSON *vl_api_ikev2_profile_set_auth_reply_t_tojson (vl_api_ikev2_profile_set_auth_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_profile_set_auth_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ikev2_profile_set_id_t_tojson (vl_api_ikev2_profile_set_id_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_profile_set_id");
    cJSON_AddStringToObject(o, "_crc", "4d7e2418");
    cJSON_AddStringToObject(o, "name", (char *)a->name);
    cJSON_AddBoolToObject(o, "is_local", a->is_local);
    cJSON_AddNumberToObject(o, "id_type", a->id_type);
    cJSON_AddNumberToObject(o, "data_len", a->data_len);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->data, a->data_len);
    cJSON_AddStringToObject(o, "data", s);
    vec_free(s);
    }
    return o;
}
static inline cJSON *vl_api_ikev2_profile_set_id_reply_t_tojson (vl_api_ikev2_profile_set_id_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_profile_set_id_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ikev2_profile_disable_natt_t_tojson (vl_api_ikev2_profile_disable_natt_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_profile_disable_natt");
    cJSON_AddStringToObject(o, "_crc", "ebf79a66");
    cJSON_AddStringToObject(o, "name", (char *)a->name);
    return o;
}
static inline cJSON *vl_api_ikev2_profile_disable_natt_reply_t_tojson (vl_api_ikev2_profile_disable_natt_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_profile_disable_natt_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ikev2_profile_set_ts_t_tojson (vl_api_ikev2_profile_set_ts_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_profile_set_ts");
    cJSON_AddStringToObject(o, "_crc", "8eb8cfd1");
    cJSON_AddStringToObject(o, "name", (char *)a->name);
    cJSON_AddItemToObject(o, "ts", vl_api_ikev2_ts_t_tojson(&a->ts));
    return o;
}
static inline cJSON *vl_api_ikev2_profile_set_ts_reply_t_tojson (vl_api_ikev2_profile_set_ts_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_profile_set_ts_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ikev2_set_local_key_t_tojson (vl_api_ikev2_set_local_key_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_set_local_key");
    cJSON_AddStringToObject(o, "_crc", "799b69ec");
    cJSON_AddStringToObject(o, "key_file", (char *)a->key_file);
    return o;
}
static inline cJSON *vl_api_ikev2_set_local_key_reply_t_tojson (vl_api_ikev2_set_local_key_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_set_local_key_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ikev2_set_tunnel_interface_t_tojson (vl_api_ikev2_set_tunnel_interface_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_set_tunnel_interface");
    cJSON_AddStringToObject(o, "_crc", "ca67182c");
    cJSON_AddStringToObject(o, "name", (char *)a->name);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_ikev2_set_tunnel_interface_reply_t_tojson (vl_api_ikev2_set_tunnel_interface_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_set_tunnel_interface_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ikev2_set_responder_t_tojson (vl_api_ikev2_set_responder_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_set_responder");
    cJSON_AddStringToObject(o, "_crc", "a2055df1");
    cJSON_AddStringToObject(o, "name", (char *)a->name);
    cJSON_AddItemToObject(o, "responder", vl_api_ikev2_responder_t_tojson(&a->responder));
    return o;
}
static inline cJSON *vl_api_ikev2_set_responder_reply_t_tojson (vl_api_ikev2_set_responder_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_set_responder_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ikev2_set_responder_hostname_t_tojson (vl_api_ikev2_set_responder_hostname_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_set_responder_hostname");
    cJSON_AddStringToObject(o, "_crc", "350d6949");
    cJSON_AddStringToObject(o, "name", (char *)a->name);
    cJSON_AddStringToObject(o, "hostname", (char *)a->hostname);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_ikev2_set_responder_hostname_reply_t_tojson (vl_api_ikev2_set_responder_hostname_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_set_responder_hostname_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ikev2_set_ike_transforms_t_tojson (vl_api_ikev2_set_ike_transforms_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_set_ike_transforms");
    cJSON_AddStringToObject(o, "_crc", "076d7378");
    cJSON_AddStringToObject(o, "name", (char *)a->name);
    cJSON_AddItemToObject(o, "tr", vl_api_ikev2_ike_transforms_t_tojson(&a->tr));
    return o;
}
static inline cJSON *vl_api_ikev2_set_ike_transforms_reply_t_tojson (vl_api_ikev2_set_ike_transforms_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_set_ike_transforms_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ikev2_set_esp_transforms_t_tojson (vl_api_ikev2_set_esp_transforms_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_set_esp_transforms");
    cJSON_AddStringToObject(o, "_crc", "a63dc205");
    cJSON_AddStringToObject(o, "name", (char *)a->name);
    cJSON_AddItemToObject(o, "tr", vl_api_ikev2_esp_transforms_t_tojson(&a->tr));
    return o;
}
static inline cJSON *vl_api_ikev2_set_esp_transforms_reply_t_tojson (vl_api_ikev2_set_esp_transforms_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_set_esp_transforms_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ikev2_set_sa_lifetime_t_tojson (vl_api_ikev2_set_sa_lifetime_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_set_sa_lifetime");
    cJSON_AddStringToObject(o, "_crc", "7039feaa");
    cJSON_AddStringToObject(o, "name", (char *)a->name);
    cJSON_AddNumberToObject(o, "lifetime", a->lifetime);
    cJSON_AddNumberToObject(o, "lifetime_jitter", a->lifetime_jitter);
    cJSON_AddNumberToObject(o, "handover", a->handover);
    cJSON_AddNumberToObject(o, "lifetime_maxdata", a->lifetime_maxdata);
    return o;
}
static inline cJSON *vl_api_ikev2_set_sa_lifetime_reply_t_tojson (vl_api_ikev2_set_sa_lifetime_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_set_sa_lifetime_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ikev2_initiate_sa_init_t_tojson (vl_api_ikev2_initiate_sa_init_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_initiate_sa_init");
    cJSON_AddStringToObject(o, "_crc", "ebf79a66");
    cJSON_AddStringToObject(o, "name", (char *)a->name);
    return o;
}
static inline cJSON *vl_api_ikev2_initiate_sa_init_reply_t_tojson (vl_api_ikev2_initiate_sa_init_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_initiate_sa_init_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ikev2_initiate_del_ike_sa_t_tojson (vl_api_ikev2_initiate_del_ike_sa_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_initiate_del_ike_sa");
    cJSON_AddStringToObject(o, "_crc", "8d125bdd");
    cJSON_AddNumberToObject(o, "ispi", a->ispi);
    return o;
}
static inline cJSON *vl_api_ikev2_initiate_del_ike_sa_reply_t_tojson (vl_api_ikev2_initiate_del_ike_sa_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_initiate_del_ike_sa_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ikev2_initiate_del_child_sa_t_tojson (vl_api_ikev2_initiate_del_child_sa_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_initiate_del_child_sa");
    cJSON_AddStringToObject(o, "_crc", "7f004d2e");
    cJSON_AddNumberToObject(o, "ispi", a->ispi);
    return o;
}
static inline cJSON *vl_api_ikev2_initiate_del_child_sa_reply_t_tojson (vl_api_ikev2_initiate_del_child_sa_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_initiate_del_child_sa_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ikev2_initiate_rekey_child_sa_t_tojson (vl_api_ikev2_initiate_rekey_child_sa_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_initiate_rekey_child_sa");
    cJSON_AddStringToObject(o, "_crc", "7f004d2e");
    cJSON_AddNumberToObject(o, "ispi", a->ispi);
    return o;
}
static inline cJSON *vl_api_ikev2_initiate_rekey_child_sa_reply_t_tojson (vl_api_ikev2_initiate_rekey_child_sa_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_initiate_rekey_child_sa_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ikev2_profile_set_udp_encap_t_tojson (vl_api_ikev2_profile_set_udp_encap_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_profile_set_udp_encap");
    cJSON_AddStringToObject(o, "_crc", "ebf79a66");
    cJSON_AddStringToObject(o, "name", (char *)a->name);
    return o;
}
static inline cJSON *vl_api_ikev2_profile_set_udp_encap_reply_t_tojson (vl_api_ikev2_profile_set_udp_encap_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_profile_set_udp_encap_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ikev2_profile_set_ipsec_udp_port_t_tojson (vl_api_ikev2_profile_set_ipsec_udp_port_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_profile_set_ipsec_udp_port");
    cJSON_AddStringToObject(o, "_crc", "615ce758");
    cJSON_AddNumberToObject(o, "is_set", a->is_set);
    cJSON_AddNumberToObject(o, "port", a->port);
    cJSON_AddStringToObject(o, "name", (char *)a->name);
    return o;
}
static inline cJSON *vl_api_ikev2_profile_set_ipsec_udp_port_reply_t_tojson (vl_api_ikev2_profile_set_ipsec_udp_port_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_profile_set_ipsec_udp_port_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ikev2_profile_set_liveness_t_tojson (vl_api_ikev2_profile_set_liveness_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_profile_set_liveness");
    cJSON_AddStringToObject(o, "_crc", "6bdf4d65");
    cJSON_AddNumberToObject(o, "period", a->period);
    cJSON_AddNumberToObject(o, "max_retries", a->max_retries);
    return o;
}
static inline cJSON *vl_api_ikev2_profile_set_liveness_reply_t_tojson (vl_api_ikev2_profile_set_liveness_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ikev2_profile_set_liveness_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
