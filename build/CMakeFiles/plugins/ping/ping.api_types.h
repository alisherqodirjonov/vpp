#ifndef included_ping_api_types_h
#define included_ping_api_types_h
#define VL_API_PING_API_VERSION_MAJOR 0
#define VL_API_PING_API_VERSION_MINOR 1
#define VL_API_PING_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/interface_types.api_types.h>
#include <vnet/ip/ip_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_want_ping_finished_events {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_address_t address;
    u32 repeat;
    f64 interval;
} vl_api_want_ping_finished_events_t;
#define VL_API_WANT_PING_FINISHED_EVENTS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_want_ping_finished_events_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_want_ping_finished_events_reply_t;
#define VL_API_WANT_PING_FINISHED_EVENTS_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ping_finished_event {
    u16 _vl_msg_id;
    u32 client_index;
    u32 request_count;
    u32 reply_count;
} vl_api_ping_finished_event_t;
#define VL_API_PING_FINISHED_EVENT_IS_CONSTANT_SIZE (1)

#define VL_API_WANT_PING_FINISHED_EVENTS_CRC "want_ping_finished_events_e79ee58b"
#define VL_API_WANT_PING_FINISHED_EVENTS_REPLY_CRC "want_ping_finished_events_reply_e8d4e804"
#define VL_API_PING_FINISHED_EVENT_CRC "ping_finished_event_397ccf72"

#endif
