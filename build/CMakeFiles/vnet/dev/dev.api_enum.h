#ifndef included_dev_api_enum_h
#define included_dev_api_enum_h
typedef enum {
   VL_API_DEV_ATTACH,
   VL_API_DEV_ATTACH_REPLY,
   VL_API_DEV_DETACH,
   VL_API_DEV_DETACH_REPLY,
   VL_API_DEV_CREATE_PORT_IF,
   VL_API_DEV_CREATE_PORT_IF_REPLY,
   VL_API_DEV_REMOVE_PORT_IF,
   VL_API_DEV_REMOVE_PORT_IF_REPLY,
   VL_MSG_DEV_LAST
} vl_api_dev_enum_t;
#endif
