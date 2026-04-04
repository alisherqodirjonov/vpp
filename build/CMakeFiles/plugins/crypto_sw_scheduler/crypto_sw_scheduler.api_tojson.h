/* Imported API files */
#ifndef included_crypto_sw_scheduler_api_tojson_h
#define included_crypto_sw_scheduler_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_crypto_sw_scheduler_set_worker_t_tojson (vl_api_crypto_sw_scheduler_set_worker_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "crypto_sw_scheduler_set_worker");
    cJSON_AddStringToObject(o, "_crc", "b4274502");
    cJSON_AddNumberToObject(o, "worker_index", a->worker_index);
    cJSON_AddBoolToObject(o, "crypto_enable", a->crypto_enable);
    return o;
}
static inline cJSON *vl_api_crypto_sw_scheduler_set_worker_reply_t_tojson (vl_api_crypto_sw_scheduler_set_worker_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "crypto_sw_scheduler_set_worker_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
