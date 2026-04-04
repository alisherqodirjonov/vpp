/* Imported API files */
#ifndef included_sr_types_api_tojson_h
#define included_sr_types_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_sr_policy_op_t_tojson (vl_api_sr_policy_op_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("SR_POLICY_OP_API_NONE");
    case 1:
        return cJSON_CreateString("SR_POLICY_OP_API_ADD");
    case 2:
        return cJSON_CreateString("SR_POLICY_OP_API_DEL");
    case 3:
        return cJSON_CreateString("SR_POLICY_OP_API_MOD");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_sr_behavior_t_tojson (vl_api_sr_behavior_t a) {
    switch(a) {
    case 1:
        return cJSON_CreateString("SR_BEHAVIOR_API_END");
    case 2:
        return cJSON_CreateString("SR_BEHAVIOR_API_X");
    case 3:
        return cJSON_CreateString("SR_BEHAVIOR_API_T");
    case 4:
        return cJSON_CreateString("SR_BEHAVIOR_API_D_FIRST");
    case 5:
        return cJSON_CreateString("SR_BEHAVIOR_API_DX2");
    case 6:
        return cJSON_CreateString("SR_BEHAVIOR_API_DX6");
    case 7:
        return cJSON_CreateString("SR_BEHAVIOR_API_DX4");
    case 8:
        return cJSON_CreateString("SR_BEHAVIOR_API_DT6");
    case 9:
        return cJSON_CreateString("SR_BEHAVIOR_API_DT4");
    case 10:
        return cJSON_CreateString("SR_BEHAVIOR_API_LAST");
    case 11:
        return cJSON_CreateString("SR_BEHAVIOR_API_END_UN_PERF");
    case 12:
        return cJSON_CreateString("SR_BEHAVIOR_API_END_UN");
    case 13:
        return cJSON_CreateString("SR_BEHAVIOR_API_UA");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_sr_steer_t_tojson (vl_api_sr_steer_t a) {
    switch(a) {
    case 2:
        return cJSON_CreateString("SR_STEER_API_L2");
    case 4:
        return cJSON_CreateString("SR_STEER_API_IPV4");
    case 6:
        return cJSON_CreateString("SR_STEER_API_IPV6");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
#endif
