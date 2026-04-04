#ifndef included_selog_api_types_h
#define included_selog_api_types_h
/* Imported API files */
typedef struct __attribute__ ((packed)) _vl_api_selog_get_shm {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_selog_get_shm_t;
#define VL_API_SELOG_GET_SHM_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_selog_get_shm_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_selog_get_shm_reply_t;
#define VL_API_SELOG_GET_SHM_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_selog_get_string_table {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_selog_get_string_table_t;
#define VL_API_SELOG_GET_STRING_TABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_selog_get_string_table_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_string_t s;
} vl_api_selog_get_string_table_reply_t;
#define VL_API_SELOG_GET_STRING_TABLE_REPLY_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_selog_track_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_selog_track_dump_t;
#define VL_API_SELOG_TRACK_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_selog_track_details {
    u16 _vl_msg_id;
    u32 context;
    u32 index;
    vl_api_string_t name;
} vl_api_selog_track_details_t;
#define VL_API_SELOG_TRACK_DETAILS_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_selog_event_type_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_selog_event_type_dump_t;
#define VL_API_SELOG_EVENT_TYPE_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_selog_event_type_details {
    u16 _vl_msg_id;
    u32 context;
    u32 index;
    u8 fmt_args[32];
    vl_api_string_t fmt;
} vl_api_selog_event_type_details_t;
#define VL_API_SELOG_EVENT_TYPE_DETAILS_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_selog_event_type_string_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 event_type_index;
} vl_api_selog_event_type_string_dump_t;
#define VL_API_SELOG_EVENT_TYPE_STRING_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_selog_event_type_string_details {
    u16 _vl_msg_id;
    u32 context;
    u32 index;
    vl_api_string_t s;
} vl_api_selog_event_type_string_details_t;
#define VL_API_SELOG_EVENT_TYPE_STRING_DETAILS_IS_CONSTANT_SIZE (0)

#define VL_API_SELOG_GET_SHM_CRC "selog_get_shm_51077d14"
#define VL_API_SELOG_GET_SHM_REPLY_CRC "selog_get_shm_reply_e8d4e804"
#define VL_API_SELOG_GET_STRING_TABLE_CRC "selog_get_string_table_51077d14"
#define VL_API_SELOG_GET_STRING_TABLE_REPLY_CRC "selog_get_string_table_reply_17fc26aa"
#define VL_API_SELOG_TRACK_DUMP_CRC "selog_track_dump_51077d14"
#define VL_API_SELOG_TRACK_DETAILS_CRC "selog_track_details_33dce766"
#define VL_API_SELOG_EVENT_TYPE_DUMP_CRC "selog_event_type_dump_51077d14"
#define VL_API_SELOG_EVENT_TYPE_DETAILS_CRC "selog_event_type_details_745bca80"
#define VL_API_SELOG_EVENT_TYPE_STRING_DUMP_CRC "selog_event_type_string_dump_6a7f2680"
#define VL_API_SELOG_EVENT_TYPE_STRING_DETAILS_CRC "selog_event_type_string_details_3718921d"

#endif
