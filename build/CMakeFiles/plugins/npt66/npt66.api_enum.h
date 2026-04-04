#ifndef included_npt66_api_enum_h
#define included_npt66_api_enum_h
typedef enum {
   VL_API_NPT66_BINDING_ADD_DEL,
   VL_API_NPT66_BINDING_ADD_DEL_REPLY,
   VL_MSG_NPT66_LAST
} vl_api_npt66_enum_t;
typedef enum {
   NPT66_ERROR_RX,
   NPT66_ERROR_TX,
   NPT66_ERROR_TRANSLATION,
   NPT66_ERROR_ICMP6_CHECKSUM,
   NPT66_ERROR_ICMP6_TRUNCATED,
   NPT66_N_ERROR
} vl_counter_npt66_enum_t;
extern vlib_error_desc_t npt66_error_counters[];
#endif
