/* Imported API files */
#ifndef included_graph_api_fromjson_h
#define included_graph_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_node_flag_t_fromjson(void **mp, int *len, cJSON *o, vl_api_node_flag_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "NODE_FLAG_FRAME_NO_FREE_AFTER_DISPATCH") == 0) {*a = 1; return 0;}
    if (strcmp(p, "NODE_FLAG_IS_OUTPUT") == 0) {*a = 2; return 0;}
    if (strcmp(p, "NODE_FLAG_IS_DROP") == 0) {*a = 4; return 0;}
    if (strcmp(p, "NODE_FLAG_IS_PUNT") == 0) {*a = 8; return 0;}
    if (strcmp(p, "NODE_FLAG_IS_HANDOFF") == 0) {*a = 16; return 0;}
    if (strcmp(p, "NODE_FLAG_TRACE") == 0) {*a = 32; return 0;}
    if (strcmp(p, "NODE_FLAG_SWITCH_FROM_INTERRUPT_TO_POLLING_MODE") == 0) {*a = 64; return 0;}
    if (strcmp(p, "NODE_FLAG_SWITCH_FROM_POLLING_TO_INTERRUPT_MODE") == 0) {*a = 128; return 0;}
    if (strcmp(p, "NODE_FLAG_TRACE_SUPPORTED") == 0) {*a = 256; return 0;}
    *a = 0;
    return -1;
}
static inline vl_api_graph_node_get_t *vl_api_graph_node_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_graph_node_get_t);
    vl_api_graph_node_get_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "cursor");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->cursor);

    item = cJSON_GetObjectItem(o, "index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->index);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    strncpy_s((char *)a->name, sizeof(a->name), cJSON_GetStringValue(item), sizeof(a->name) - 1);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_node_flag_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "want_arcs");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->want_arcs);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_graph_node_get_reply_t *vl_api_graph_node_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_graph_node_get_reply_t);
    vl_api_graph_node_get_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "cursor");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->cursor);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_graph_node_details_t *vl_api_graph_node_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_graph_node_details_t);
    vl_api_graph_node_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->index);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    strncpy_s((char *)a->name, sizeof(a->name), cJSON_GetStringValue(item), sizeof(a->name) - 1);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_node_flag_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "arcs_out");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "arcs_out");
        int size = cJSON_GetArraySize(array);
        a->n_arcs = size;
        a = cJSON_realloc(a, l + sizeof(u32) * size);
        u32 *d = (void *)a + l;
        l += sizeof(u32) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_u32_fromjson(e, &d[i]);
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
