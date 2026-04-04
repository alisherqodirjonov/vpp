#ifndef included_graph_api_types_h
#define included_graph_api_types_h
#define VL_API_GRAPH_API_VERSION_MAJOR 1
#define VL_API_GRAPH_API_VERSION_MINOR 0
#define VL_API_GRAPH_API_VERSION_PATCH 0
/* Imported API files */
typedef enum {
    NODE_FLAG_FRAME_NO_FREE_AFTER_DISPATCH = 1,
    NODE_FLAG_IS_OUTPUT = 2,
    NODE_FLAG_IS_DROP = 4,
    NODE_FLAG_IS_PUNT = 8,
    NODE_FLAG_IS_HANDOFF = 16,
    NODE_FLAG_TRACE = 32,
    NODE_FLAG_SWITCH_FROM_INTERRUPT_TO_POLLING_MODE = 64,
    NODE_FLAG_SWITCH_FROM_POLLING_TO_INTERRUPT_MODE = 128,
    NODE_FLAG_TRACE_SUPPORTED = 256,
} vl_api_node_flag_t;
typedef struct __attribute__ ((packed)) _vl_api_graph_node_get {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 cursor;
    u32 index;
    u8 name[64];
    vl_api_node_flag_t flags;
    bool want_arcs;
} vl_api_graph_node_get_t;
#define VL_API_GRAPH_NODE_GET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_graph_node_get_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 cursor;
} vl_api_graph_node_get_reply_t;
#define VL_API_GRAPH_NODE_GET_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_graph_node_details {
    u16 _vl_msg_id;
    u32 context;
    u32 index;
    u8 name[64];
    vl_api_node_flag_t flags;
    u32 n_arcs;
    u32 arcs_out[0];
} vl_api_graph_node_details_t;
#define VL_API_GRAPH_NODE_DETAILS_IS_CONSTANT_SIZE (0)

#define VL_API_GRAPH_NODE_GET_CRC "graph_node_get_39c8792e"
#define VL_API_GRAPH_NODE_GET_REPLY_CRC "graph_node_get_reply_53b48f5d"
#define VL_API_GRAPH_NODE_DETAILS_CRC "graph_node_details_ac762018"

#endif
