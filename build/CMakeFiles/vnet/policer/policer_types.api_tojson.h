/* Imported API files */
#ifndef included_policer_types_api_tojson_h
#define included_policer_types_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_sse2_qos_rate_type_t_tojson (vl_api_sse2_qos_rate_type_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("SSE2_QOS_RATE_API_KBPS");
    case 1:
        return cJSON_CreateString("SSE2_QOS_RATE_API_PPS");
    case 2:
        return cJSON_CreateString("SSE2_QOS_RATE_API_INVALID");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_sse2_qos_round_type_t_tojson (vl_api_sse2_qos_round_type_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("SSE2_QOS_ROUND_API_TO_CLOSEST");
    case 1:
        return cJSON_CreateString("SSE2_QOS_ROUND_API_TO_UP");
    case 2:
        return cJSON_CreateString("SSE2_QOS_ROUND_API_TO_DOWN");
    case 3:
        return cJSON_CreateString("SSE2_QOS_ROUND_API_INVALID");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_sse2_qos_policer_type_t_tojson (vl_api_sse2_qos_policer_type_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("SSE2_QOS_POLICER_TYPE_API_1R2C");
    case 1:
        return cJSON_CreateString("SSE2_QOS_POLICER_TYPE_API_1R3C_RFC_2697");
    case 2:
        return cJSON_CreateString("SSE2_QOS_POLICER_TYPE_API_2R3C_RFC_2698");
    case 3:
        return cJSON_CreateString("SSE2_QOS_POLICER_TYPE_API_2R3C_RFC_4115");
    case 4:
        return cJSON_CreateString("SSE2_QOS_POLICER_TYPE_API_2R3C_RFC_MEF5CF1");
    case 5:
        return cJSON_CreateString("SSE2_QOS_POLICER_TYPE_API_MAX");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_sse2_qos_action_type_t_tojson (vl_api_sse2_qos_action_type_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("SSE2_QOS_ACTION_API_DROP");
    case 1:
        return cJSON_CreateString("SSE2_QOS_ACTION_API_TRANSMIT");
    case 2:
        return cJSON_CreateString("SSE2_QOS_ACTION_API_MARK_AND_TRANSMIT");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_sse2_qos_action_t_tojson (vl_api_sse2_qos_action_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "type", vl_api_sse2_qos_action_type_t_tojson(a->type));
    cJSON_AddNumberToObject(o, "dscp", a->dscp);
    return o;
}
static inline cJSON *vl_api_policer_config_t_tojson (vl_api_policer_config_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "cir", a->cir);
    cJSON_AddNumberToObject(o, "eir", a->eir);
    cJSON_AddNumberToObject(o, "cb", a->cb);
    cJSON_AddNumberToObject(o, "eb", a->eb);
    cJSON_AddItemToObject(o, "rate_type", vl_api_sse2_qos_rate_type_t_tojson(a->rate_type));
    cJSON_AddItemToObject(o, "round_type", vl_api_sse2_qos_round_type_t_tojson(a->round_type));
    cJSON_AddItemToObject(o, "type", vl_api_sse2_qos_policer_type_t_tojson(a->type));
    cJSON_AddBoolToObject(o, "color_aware", a->color_aware);
    cJSON_AddItemToObject(o, "conform_action", vl_api_sse2_qos_action_t_tojson(&a->conform_action));
    cJSON_AddItemToObject(o, "exceed_action", vl_api_sse2_qos_action_t_tojson(&a->exceed_action));
    cJSON_AddItemToObject(o, "violate_action", vl_api_sse2_qos_action_t_tojson(&a->violate_action));
    return o;
}
#endif
