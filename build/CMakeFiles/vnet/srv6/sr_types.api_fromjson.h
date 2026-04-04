/* Imported API files */
#ifndef included_sr_types_api_fromjson_h
#define included_sr_types_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_sr_policy_op_t_fromjson(void **mp, int *len, cJSON *o, vl_api_sr_policy_op_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "SR_POLICY_OP_API_NONE") == 0) {*a = 0; return 0;}
    if (strcmp(p, "SR_POLICY_OP_API_ADD") == 0) {*a = 1; return 0;}
    if (strcmp(p, "SR_POLICY_OP_API_DEL") == 0) {*a = 2; return 0;}
    if (strcmp(p, "SR_POLICY_OP_API_MOD") == 0) {*a = 3; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_sr_behavior_t_fromjson(void **mp, int *len, cJSON *o, vl_api_sr_behavior_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "SR_BEHAVIOR_API_END") == 0) {*a = 1; return 0;}
    if (strcmp(p, "SR_BEHAVIOR_API_X") == 0) {*a = 2; return 0;}
    if (strcmp(p, "SR_BEHAVIOR_API_T") == 0) {*a = 3; return 0;}
    if (strcmp(p, "SR_BEHAVIOR_API_D_FIRST") == 0) {*a = 4; return 0;}
    if (strcmp(p, "SR_BEHAVIOR_API_DX2") == 0) {*a = 5; return 0;}
    if (strcmp(p, "SR_BEHAVIOR_API_DX6") == 0) {*a = 6; return 0;}
    if (strcmp(p, "SR_BEHAVIOR_API_DX4") == 0) {*a = 7; return 0;}
    if (strcmp(p, "SR_BEHAVIOR_API_DT6") == 0) {*a = 8; return 0;}
    if (strcmp(p, "SR_BEHAVIOR_API_DT4") == 0) {*a = 9; return 0;}
    if (strcmp(p, "SR_BEHAVIOR_API_LAST") == 0) {*a = 10; return 0;}
    if (strcmp(p, "SR_BEHAVIOR_API_END_UN_PERF") == 0) {*a = 11; return 0;}
    if (strcmp(p, "SR_BEHAVIOR_API_END_UN") == 0) {*a = 12; return 0;}
    if (strcmp(p, "SR_BEHAVIOR_API_UA") == 0) {*a = 13; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_sr_steer_t_fromjson(void **mp, int *len, cJSON *o, vl_api_sr_steer_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "SR_STEER_API_L2") == 0) {*a = 2; return 0;}
    if (strcmp(p, "SR_STEER_API_IPV4") == 0) {*a = 4; return 0;}
    if (strcmp(p, "SR_STEER_API_IPV6") == 0) {*a = 6; return 0;}
    *a = 0;
    return -1;
}
#endif
