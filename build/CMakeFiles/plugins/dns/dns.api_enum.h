#ifndef included_dns_api_enum_h
#define included_dns_api_enum_h
typedef enum {
   VL_API_DNS_ENABLE_DISABLE,
   VL_API_DNS_ENABLE_DISABLE_REPLY,
   VL_API_DNS_NAME_SERVER_ADD_DEL,
   VL_API_DNS_NAME_SERVER_ADD_DEL_REPLY,
   VL_API_DNS_RESOLVE_NAME,
   VL_API_DNS_RESOLVE_NAME_REPLY,
   VL_API_DNS_RESOLVE_IP,
   VL_API_DNS_RESOLVE_IP_REPLY,
   VL_MSG_DNS_LAST
} vl_api_dns_enum_t;
#endif
