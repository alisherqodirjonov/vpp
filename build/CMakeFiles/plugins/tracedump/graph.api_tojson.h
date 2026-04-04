/* Imported API files */
#ifndef included_graph_api_tojson_h
#define included_graph_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_node_flag_t_tojson (vl_api_node_flag_t a) {
    switch(a) {
    case 1:
        return cJSON_CreateString("NODE_FLAG_FRAME_NO_FREE_AFTER_DISPATCH");
    case 2:
        return cJSON_CreateString("NODE_FLAG_IS_OUTPUT");
    case 4:
        return cJSON_CreateString("NODE_FLAG_IS_DROP");
    case 8:
        return cJSON_CreateString("NODE_FLAG_IS_PUNT");
    case 16:
        return cJSON_CreateString("NODE_FLAG_IS_HANDOFF");
    case 32:
        return cJSON_CreateString("NODE_FLAG_TRACE");
    case 64:
        return cJSON_CreateString("NODE_FLAG_SWITCH_FROM_INTERRUPT_TO_POLLING_MODE");
    case 128:
        return cJSON_CreateString("NODE_FLAG_SWITCH_FROM_POLLING_TO_INTERRUPT_MODE");
    case 256:
        return cJSON_CreateString("NODE_FLAG_TRACE_SUPPORTED");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_graph_node_get_t_tojson (vl_api_graph_node_get_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "graph_node_get");
    cJSON_AddStringToObject(o, "_crc", "39c8792e");
    cJSON_AddNumberToObject(o, "cursor", a->cursor);
    cJSON_AddNumberToObject(o, "index", a->index);
    cJSON_AddStringToObject(o, "name", (char *)a->name);
    cJSON_AddItemToObject(o, "flags", vl_api_node_flag_t_tojson(a->flags));
    cJSON_AddBoolToObject(o, "want_arcs", a->want_arcs);
    return o;
}
static inline cJSON *vl_api_graph_node_get_reply_t_tojson (vl_api_graph_node_get_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "graph_node_get_reply");
    cJSON_AddStringToObject(o, "_crc", "53b48f5d");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "cursor", a->cursor);
    return o;
}
static inline cJSON *vl_api_graph_node_details_t_tojson (vl_api_graph_node_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "graph_node_details");
    cJSON_AddStringToObject(o, "_crc", "ac762018");
    cJSON_AddNumberToObject(o, "index", a->index);
    cJSON_AddStringToObject(o, "name", (char *)a->name);
    cJSON_AddItemToObject(o, "flags", vl_api_node_flag_t_tojson(a->flags));
    cJSON_AddNumberToObject(o, "n_arcs", a->n_arcs);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "arcs_out");
        for (i = 0; i < a->n_arcs; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->arcs_out[i]));
        }
    }
    return o;
}
#endif
