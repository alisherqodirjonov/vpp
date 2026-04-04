/* Imported API files */
#ifndef included_policer_types_api_fromjson_h
#define included_policer_types_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_sse2_qos_rate_type_t_fromjson(void **mp, int *len, cJSON *o, vl_api_sse2_qos_rate_type_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "SSE2_QOS_RATE_API_KBPS") == 0) {*a = 0; return 0;}
    if (strcmp(p, "SSE2_QOS_RATE_API_PPS") == 0) {*a = 1; return 0;}
    if (strcmp(p, "SSE2_QOS_RATE_API_INVALID") == 0) {*a = 2; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_sse2_qos_round_type_t_fromjson(void **mp, int *len, cJSON *o, vl_api_sse2_qos_round_type_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "SSE2_QOS_ROUND_API_TO_CLOSEST") == 0) {*a = 0; return 0;}
    if (strcmp(p, "SSE2_QOS_ROUND_API_TO_UP") == 0) {*a = 1; return 0;}
    if (strcmp(p, "SSE2_QOS_ROUND_API_TO_DOWN") == 0) {*a = 2; return 0;}
    if (strcmp(p, "SSE2_QOS_ROUND_API_INVALID") == 0) {*a = 3; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_sse2_qos_policer_type_t_fromjson(void **mp, int *len, cJSON *o, vl_api_sse2_qos_policer_type_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "SSE2_QOS_POLICER_TYPE_API_1R2C") == 0) {*a = 0; return 0;}
    if (strcmp(p, "SSE2_QOS_POLICER_TYPE_API_1R3C_RFC_2697") == 0) {*a = 1; return 0;}
    if (strcmp(p, "SSE2_QOS_POLICER_TYPE_API_2R3C_RFC_2698") == 0) {*a = 2; return 0;}
    if (strcmp(p, "SSE2_QOS_POLICER_TYPE_API_2R3C_RFC_4115") == 0) {*a = 3; return 0;}
    if (strcmp(p, "SSE2_QOS_POLICER_TYPE_API_2R3C_RFC_MEF5CF1") == 0) {*a = 4; return 0;}
    if (strcmp(p, "SSE2_QOS_POLICER_TYPE_API_MAX") == 0) {*a = 5; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_sse2_qos_action_type_t_fromjson(void **mp, int *len, cJSON *o, vl_api_sse2_qos_action_type_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "SSE2_QOS_ACTION_API_DROP") == 0) {*a = 0; return 0;}
    if (strcmp(p, "SSE2_QOS_ACTION_API_TRANSMIT") == 0) {*a = 1; return 0;}
    if (strcmp(p, "SSE2_QOS_ACTION_API_MARK_AND_TRANSMIT") == 0) {*a = 2; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_sse2_qos_action_t_fromjson (void **mp, int *len, cJSON *o, vl_api_sse2_qos_action_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "type");
    if (!item) goto error;
    if (vl_api_sse2_qos_action_type_t_fromjson(mp, len, item, &a->type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dscp");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->dscp);

    return 0;

  error:
    return -1;
}
static inline int vl_api_policer_config_t_fromjson (void **mp, int *len, cJSON *o, vl_api_policer_config_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "cir");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->cir);

    item = cJSON_GetObjectItem(o, "eir");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->eir);

    item = cJSON_GetObjectItem(o, "cb");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->cb);

    item = cJSON_GetObjectItem(o, "eb");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->eb);

    item = cJSON_GetObjectItem(o, "rate_type");
    if (!item) goto error;
    if (vl_api_sse2_qos_rate_type_t_fromjson(mp, len, item, &a->rate_type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "round_type");
    if (!item) goto error;
    if (vl_api_sse2_qos_round_type_t_fromjson(mp, len, item, &a->round_type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "type");
    if (!item) goto error;
    if (vl_api_sse2_qos_policer_type_t_fromjson(mp, len, item, &a->type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "color_aware");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->color_aware);

    item = cJSON_GetObjectItem(o, "conform_action");
    if (!item) goto error;
    if (vl_api_sse2_qos_action_t_fromjson(mp, len, item, &a->conform_action) < 0) goto error;

    item = cJSON_GetObjectItem(o, "exceed_action");
    if (!item) goto error;
    if (vl_api_sse2_qos_action_t_fromjson(mp, len, item, &a->exceed_action) < 0) goto error;

    item = cJSON_GetObjectItem(o, "violate_action");
    if (!item) goto error;
    if (vl_api_sse2_qos_action_t_fromjson(mp, len, item, &a->violate_action) < 0) goto error;

    return 0;

  error:
    return -1;
}
#endif
