#ifndef included_sr_types_api_types_h
#define included_sr_types_api_types_h
#define VL_API_SR_TYPES_API_VERSION_MAJOR 1
#define VL_API_SR_TYPES_API_VERSION_MINOR 0
#define VL_API_SR_TYPES_API_VERSION_PATCH 0
/* Imported API files */
typedef enum __attribute__((packed)) {
    SR_POLICY_OP_API_NONE = 0,
    SR_POLICY_OP_API_ADD = 1,
    SR_POLICY_OP_API_DEL = 2,
    SR_POLICY_OP_API_MOD = 3,
} vl_api_sr_policy_op_t;
STATIC_ASSERT(sizeof(vl_api_sr_policy_op_t) == sizeof(u8), "size of API enum sr_policy_op is wrong");
typedef enum __attribute__((packed)) {
    SR_BEHAVIOR_API_END = 1,
    SR_BEHAVIOR_API_X = 2,
    SR_BEHAVIOR_API_T = 3,
    SR_BEHAVIOR_API_D_FIRST = 4,
    SR_BEHAVIOR_API_DX2 = 5,
    SR_BEHAVIOR_API_DX6 = 6,
    SR_BEHAVIOR_API_DX4 = 7,
    SR_BEHAVIOR_API_DT6 = 8,
    SR_BEHAVIOR_API_DT4 = 9,
    SR_BEHAVIOR_API_LAST = 10,
    SR_BEHAVIOR_API_END_UN_PERF = 11,
    SR_BEHAVIOR_API_END_UN = 12,
    SR_BEHAVIOR_API_UA = 13,
} vl_api_sr_behavior_t;
STATIC_ASSERT(sizeof(vl_api_sr_behavior_t) == sizeof(u8), "size of API enum sr_behavior is wrong");
typedef enum __attribute__((packed)) {
    SR_STEER_API_L2 = 2,
    SR_STEER_API_IPV4 = 4,
    SR_STEER_API_IPV6 = 6,
} vl_api_sr_steer_t;
STATIC_ASSERT(sizeof(vl_api_sr_steer_t) == sizeof(u8), "size of API enum sr_steer is wrong");

#endif
