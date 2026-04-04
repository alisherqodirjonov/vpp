#ifndef included_bpf_trace_filter_api_types_h
#define included_bpf_trace_filter_api_types_h
#define VL_API_BPF_TRACE_FILTER_API_VERSION_MAJOR 0
#define VL_API_BPF_TRACE_FILTER_API_VERSION_MINOR 1
#define VL_API_BPF_TRACE_FILTER_API_VERSION_PATCH 0
/* Imported API files */
typedef struct __attribute__ ((packed)) _vl_api_bpf_trace_filter_set {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_string_t filter;
} vl_api_bpf_trace_filter_set_t;
#define VL_API_BPF_TRACE_FILTER_SET_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_bpf_trace_filter_set_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_bpf_trace_filter_set_reply_t;
#define VL_API_BPF_TRACE_FILTER_SET_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_bpf_trace_filter_set_v2 {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    bool optimize;
    vl_api_string_t filter;
} vl_api_bpf_trace_filter_set_v2_t;
#define VL_API_BPF_TRACE_FILTER_SET_V2_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_bpf_trace_filter_set_v2_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_bpf_trace_filter_set_v2_reply_t;
#define VL_API_BPF_TRACE_FILTER_SET_V2_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_BPF_TRACE_FILTER_SET_CRC "bpf_trace_filter_set_3171346e"
#define VL_API_BPF_TRACE_FILTER_SET_REPLY_CRC "bpf_trace_filter_set_reply_e8d4e804"
#define VL_API_BPF_TRACE_FILTER_SET_V2_CRC "bpf_trace_filter_set_v2_5615acbf"
#define VL_API_BPF_TRACE_FILTER_SET_V2_REPLY_CRC "bpf_trace_filter_set_v2_reply_e8d4e804"

#endif
