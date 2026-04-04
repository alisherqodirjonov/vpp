#ifndef included_syslog_api_enum_h
#define included_syslog_api_enum_h
typedef enum {
   VL_API_SYSLOG_SET_SENDER,
   VL_API_SYSLOG_SET_SENDER_REPLY,
   VL_API_SYSLOG_GET_SENDER,
   VL_API_SYSLOG_GET_SENDER_REPLY,
   VL_API_SYSLOG_SET_FILTER,
   VL_API_SYSLOG_SET_FILTER_REPLY,
   VL_API_SYSLOG_GET_FILTER,
   VL_API_SYSLOG_GET_FILTER_REPLY,
   VL_MSG_SYSLOG_LAST
} vl_api_syslog_enum_t;
#endif
