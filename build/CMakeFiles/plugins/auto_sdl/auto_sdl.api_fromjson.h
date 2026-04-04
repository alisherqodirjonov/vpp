/* Imported API files */
#ifndef included_auto_sdl_api_fromjson_h
#define included_auto_sdl_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_auto_sdl_config_t *vl_api_auto_sdl_config_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_auto_sdl_config_t);
    vl_api_auto_sdl_config_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "threshold");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->threshold);

    item = cJSON_GetObjectItem(o, "remove_timeout");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->remove_timeout);

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_auto_sdl_config_reply_t *vl_api_auto_sdl_config_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_auto_sdl_config_reply_t);
    vl_api_auto_sdl_config_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
