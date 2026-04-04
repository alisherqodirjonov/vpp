/* Imported API files */
#ifndef included_auto_sdl_api_tojson_h
#define included_auto_sdl_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_auto_sdl_config_t_tojson (vl_api_auto_sdl_config_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "auto_sdl_config");
    cJSON_AddStringToObject(o, "_crc", "14f30db8");
    cJSON_AddNumberToObject(o, "threshold", a->threshold);
    cJSON_AddNumberToObject(o, "remove_timeout", a->remove_timeout);
    cJSON_AddBoolToObject(o, "enable", a->enable);
    return o;
}
static inline cJSON *vl_api_auto_sdl_config_reply_t_tojson (vl_api_auto_sdl_config_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "auto_sdl_config_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
