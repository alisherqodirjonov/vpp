/* Imported API files */
#ifndef included_crypto_api_tojson_h
#define included_crypto_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_crypto_dispatch_mode_t_tojson (vl_api_crypto_dispatch_mode_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("CRYPTO_ASYNC_DISPATCH_POLLING");
    case 1:
        return cJSON_CreateString("CRYPTO_ASYNC_DISPATCH_INTERRUPT");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_crypto_op_class_type_t_tojson (vl_api_crypto_op_class_type_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("CRYPTO_API_OP_SIMPLE");
    case 1:
        return cJSON_CreateString("CRYPTO_API_OP_CHAINED");
    case 2:
        return cJSON_CreateString("CRYPTO_API_OP_BOTH");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_crypto_set_async_dispatch_t_tojson (vl_api_crypto_set_async_dispatch_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "crypto_set_async_dispatch");
    cJSON_AddStringToObject(o, "_crc", "5ca4adc0");
    cJSON_AddItemToObject(o, "mode", vl_api_crypto_dispatch_mode_t_tojson(a->mode));
    return o;
}
static inline cJSON *vl_api_crypto_set_async_dispatch_reply_t_tojson (vl_api_crypto_set_async_dispatch_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "crypto_set_async_dispatch_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_crypto_set_async_dispatch_v2_t_tojson (vl_api_crypto_set_async_dispatch_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "crypto_set_async_dispatch_v2");
    cJSON_AddStringToObject(o, "_crc", "667d2d54");
    cJSON_AddItemToObject(o, "mode", vl_api_crypto_dispatch_mode_t_tojson(a->mode));
    cJSON_AddBoolToObject(o, "adaptive", a->adaptive);
    return o;
}
static inline cJSON *vl_api_crypto_set_async_dispatch_v2_reply_t_tojson (vl_api_crypto_set_async_dispatch_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "crypto_set_async_dispatch_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_crypto_set_handler_t_tojson (vl_api_crypto_set_handler_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "crypto_set_handler");
    cJSON_AddStringToObject(o, "_crc", "ce9ad00d");
    cJSON_AddStringToObject(o, "alg_name", (char *)a->alg_name);
    cJSON_AddStringToObject(o, "engine", (char *)a->engine);
    cJSON_AddItemToObject(o, "oct", vl_api_crypto_op_class_type_t_tojson(a->oct));
    cJSON_AddNumberToObject(o, "is_async", a->is_async);
    return o;
}
static inline cJSON *vl_api_crypto_set_handler_reply_t_tojson (vl_api_crypto_set_handler_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "crypto_set_handler_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
