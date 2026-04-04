#ifndef included_udp_api_enum_h
#define included_udp_api_enum_h
typedef enum {
   VL_API_UDP_ENCAP_ADD,
   VL_API_UDP_ENCAP_ADD_REPLY,
   VL_API_UDP_ENCAP_DEL,
   VL_API_UDP_ENCAP_DEL_REPLY,
   VL_API_UDP_ENCAP_DUMP,
   VL_API_UDP_ENCAP_DETAILS,
   VL_API_UDP_DECAP_ADD_DEL,
   VL_API_UDP_DECAP_ADD_DEL_REPLY,
   VL_MSG_UDP_LAST
} vl_api_udp_enum_t;
#endif
