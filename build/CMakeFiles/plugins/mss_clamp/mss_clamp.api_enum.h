#ifndef included_mss_clamp_api_enum_h
#define included_mss_clamp_api_enum_h
typedef enum {
   VL_API_MSS_CLAMP_ENABLE_DISABLE,
   VL_API_MSS_CLAMP_ENABLE_DISABLE_REPLY,
   VL_API_MSS_CLAMP_GET,
   VL_API_MSS_CLAMP_GET_REPLY,
   VL_API_MSS_CLAMP_DETAILS,
   VL_MSG_MSS_CLAMP_LAST
} vl_api_mss_clamp_enum_t;
typedef enum {
   MSS_CLAMP_ERROR_CLAMPED,
   MSS_CLAMP_N_ERROR
} vl_counter_mss_clamp_enum_t;
extern vlib_error_desc_t mss_clamp_error_counters[];
#endif
