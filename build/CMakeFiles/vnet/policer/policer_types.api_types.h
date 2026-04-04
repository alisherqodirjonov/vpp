#ifndef included_policer_types_api_types_h
#define included_policer_types_api_types_h
#define VL_API_POLICER_TYPES_API_VERSION_MAJOR 1
#define VL_API_POLICER_TYPES_API_VERSION_MINOR 0
#define VL_API_POLICER_TYPES_API_VERSION_PATCH 0
/* Imported API files */
typedef enum __attribute__((packed)) {
    SSE2_QOS_RATE_API_KBPS = 0,
    SSE2_QOS_RATE_API_PPS = 1,
    SSE2_QOS_RATE_API_INVALID = 2,
} vl_api_sse2_qos_rate_type_t;
STATIC_ASSERT(sizeof(vl_api_sse2_qos_rate_type_t) == sizeof(u8), "size of API enum sse2_qos_rate_type is wrong");
typedef enum __attribute__((packed)) {
    SSE2_QOS_ROUND_API_TO_CLOSEST = 0,
    SSE2_QOS_ROUND_API_TO_UP = 1,
    SSE2_QOS_ROUND_API_TO_DOWN = 2,
    SSE2_QOS_ROUND_API_INVALID = 3,
} vl_api_sse2_qos_round_type_t;
STATIC_ASSERT(sizeof(vl_api_sse2_qos_round_type_t) == sizeof(u8), "size of API enum sse2_qos_round_type is wrong");
typedef enum __attribute__((packed)) {
    SSE2_QOS_POLICER_TYPE_API_1R2C = 0,
    SSE2_QOS_POLICER_TYPE_API_1R3C_RFC_2697 = 1,
    SSE2_QOS_POLICER_TYPE_API_2R3C_RFC_2698 = 2,
    SSE2_QOS_POLICER_TYPE_API_2R3C_RFC_4115 = 3,
    SSE2_QOS_POLICER_TYPE_API_2R3C_RFC_MEF5CF1 = 4,
    SSE2_QOS_POLICER_TYPE_API_MAX = 5,
} vl_api_sse2_qos_policer_type_t;
STATIC_ASSERT(sizeof(vl_api_sse2_qos_policer_type_t) == sizeof(u8), "size of API enum sse2_qos_policer_type is wrong");
typedef enum __attribute__((packed)) {
    SSE2_QOS_ACTION_API_DROP = 0,
    SSE2_QOS_ACTION_API_TRANSMIT = 1,
    SSE2_QOS_ACTION_API_MARK_AND_TRANSMIT = 2,
} vl_api_sse2_qos_action_type_t;
STATIC_ASSERT(sizeof(vl_api_sse2_qos_action_type_t) == sizeof(u8), "size of API enum sse2_qos_action_type is wrong");
typedef struct __attribute__ ((packed)) _vl_api_sse2_qos_action {
    vl_api_sse2_qos_action_type_t type;
    u8 dscp;
} vl_api_sse2_qos_action_t;
#define VL_API_SSE2_QOS_ACTION_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_policer_config {
    u32 cir;
    u32 eir;
    u64 cb;
    u64 eb;
    vl_api_sse2_qos_rate_type_t rate_type;
    vl_api_sse2_qos_round_type_t round_type;
    vl_api_sse2_qos_policer_type_t type;
    bool color_aware;
    vl_api_sse2_qos_action_t conform_action;
    vl_api_sse2_qos_action_t exceed_action;
    vl_api_sse2_qos_action_t violate_action;
} vl_api_policer_config_t;
#define VL_API_POLICER_CONFIG_IS_CONSTANT_SIZE (1)


#endif
