/* Imported API files */
#ifndef included_pot_api_tojson_h
#define included_pot_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_pot_profile_add_t_tojson (vl_api_pot_profile_add_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pot_profile_add");
    cJSON_AddStringToObject(o, "_crc", "ad5da3a3");
    cJSON_AddNumberToObject(o, "id", a->id);
    cJSON_AddNumberToObject(o, "validator", a->validator);
    cJSON_AddNumberToObject(o, "secret_key", a->secret_key);
    cJSON_AddNumberToObject(o, "secret_share", a->secret_share);
    cJSON_AddNumberToObject(o, "prime", a->prime);
    cJSON_AddNumberToObject(o, "max_bits", a->max_bits);
    cJSON_AddNumberToObject(o, "lpc", a->lpc);
    cJSON_AddNumberToObject(o, "polynomial_public", a->polynomial_public);
    vl_api_string_cJSON_AddToObject(o, "list_name", &a->list_name);
    return o;
}
static inline cJSON *vl_api_pot_profile_add_reply_t_tojson (vl_api_pot_profile_add_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pot_profile_add_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_pot_profile_activate_t_tojson (vl_api_pot_profile_activate_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pot_profile_activate");
    cJSON_AddStringToObject(o, "_crc", "0770af98");
    cJSON_AddNumberToObject(o, "id", a->id);
    vl_api_string_cJSON_AddToObject(o, "list_name", &a->list_name);
    return o;
}
static inline cJSON *vl_api_pot_profile_activate_reply_t_tojson (vl_api_pot_profile_activate_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pot_profile_activate_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_pot_profile_del_t_tojson (vl_api_pot_profile_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pot_profile_del");
    cJSON_AddStringToObject(o, "_crc", "cd63f53b");
    vl_api_string_cJSON_AddToObject(o, "list_name", &a->list_name);
    return o;
}
static inline cJSON *vl_api_pot_profile_del_reply_t_tojson (vl_api_pot_profile_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pot_profile_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_pot_profile_show_config_dump_t_tojson (vl_api_pot_profile_show_config_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pot_profile_show_config_dump");
    cJSON_AddStringToObject(o, "_crc", "005b7d59");
    cJSON_AddNumberToObject(o, "id", a->id);
    return o;
}
static inline cJSON *vl_api_pot_profile_show_config_details_t_tojson (vl_api_pot_profile_show_config_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pot_profile_show_config_details");
    cJSON_AddStringToObject(o, "_crc", "b7ce0618");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "id", a->id);
    cJSON_AddNumberToObject(o, "validator", a->validator);
    cJSON_AddNumberToObject(o, "secret_key", a->secret_key);
    cJSON_AddNumberToObject(o, "secret_share", a->secret_share);
    cJSON_AddNumberToObject(o, "prime", a->prime);
    cJSON_AddNumberToObject(o, "bit_mask", a->bit_mask);
    cJSON_AddNumberToObject(o, "lpc", a->lpc);
    cJSON_AddNumberToObject(o, "polynomial_public", a->polynomial_public);
    return o;
}
#endif
