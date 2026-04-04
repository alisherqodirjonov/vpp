#ifndef included_bpf_trace_filter_api_enum_h
#define included_bpf_trace_filter_api_enum_h
typedef enum {
   VL_API_BPF_TRACE_FILTER_SET,
   VL_API_BPF_TRACE_FILTER_SET_REPLY,
   VL_API_BPF_TRACE_FILTER_SET_V2,
   VL_API_BPF_TRACE_FILTER_SET_V2_REPLY,
   VL_MSG_BPF_TRACE_FILTER_LAST
} vl_api_bpf_trace_filter_enum_t;
#endif
