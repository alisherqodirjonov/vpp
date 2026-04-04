/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#ifndef included_flowprobe_api_fromjson_h
#define included_flowprobe_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_flowprobe_which_flags_t_fromjson(void **mp, int *len, cJSON *o, vl_api_flowprobe_which_flags_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "FLOWPROBE_WHICH_FLAG_IP4") == 0) {*a = 1; return 0;}
    if (strcmp(p, "FLOWPROBE_WHICH_FLAG_L2") == 0) {*a = 2; return 0;}
    if (strcmp(p, "FLOWPROBE_WHICH_FLAG_IP6") == 0) {*a = 4; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_flowprobe_which_t_fromjson(void **mp, int *len, cJSON *o, vl_api_flowprobe_which_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "FLOWPROBE_WHICH_IP4") == 0) {*a = 0; return 0;}
    if (strcmp(p, "FLOWPROBE_WHICH_IP6") == 0) {*a = 1; return 0;}
    if (strcmp(p, "FLOWPROBE_WHICH_L2") == 0) {*a = 2; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_flowprobe_record_flags_t_fromjson(void **mp, int *len, cJSON *o, vl_api_flowprobe_record_flags_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "FLOWPROBE_RECORD_FLAG_L2") == 0) {*a = 1; return 0;}
    if (strcmp(p, "FLOWPROBE_RECORD_FLAG_L3") == 0) {*a = 2; return 0;}
    if (strcmp(p, "FLOWPROBE_RECORD_FLAG_L4") == 0) {*a = 4; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_flowprobe_direction_t_fromjson(void **mp, int *len, cJSON *o, vl_api_flowprobe_direction_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "FLOWPROBE_DIRECTION_RX") == 0) {*a = 0; return 0;}
    if (strcmp(p, "FLOWPROBE_DIRECTION_TX") == 0) {*a = 1; return 0;}
    if (strcmp(p, "FLOWPROBE_DIRECTION_BOTH") == 0) {*a = 2; return 0;}
    *a = 0;
    return -1;
}
static inline vl_api_flowprobe_tx_interface_add_del_t *vl_api_flowprobe_tx_interface_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_flowprobe_tx_interface_add_del_t);
    vl_api_flowprobe_tx_interface_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "which");
    if (!item) goto error;
    if (vl_api_flowprobe_which_flags_t_fromjson((void **)&a, &l, item, &a->which) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_flowprobe_tx_interface_add_del_reply_t *vl_api_flowprobe_tx_interface_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_flowprobe_tx_interface_add_del_reply_t);
    vl_api_flowprobe_tx_interface_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_flowprobe_interface_add_del_t *vl_api_flowprobe_interface_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_flowprobe_interface_add_del_t);
    vl_api_flowprobe_interface_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "which");
    if (!item) goto error;
    if (vl_api_flowprobe_which_t_fromjson((void **)&a, &l, item, &a->which) < 0) goto error;

    item = cJSON_GetObjectItem(o, "direction");
    if (!item) goto error;
    if (vl_api_flowprobe_direction_t_fromjson((void **)&a, &l, item, &a->direction) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_flowprobe_interface_add_del_reply_t *vl_api_flowprobe_interface_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_flowprobe_interface_add_del_reply_t);
    vl_api_flowprobe_interface_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_flowprobe_interface_dump_t *vl_api_flowprobe_interface_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_flowprobe_interface_dump_t);
    vl_api_flowprobe_interface_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_flowprobe_interface_details_t *vl_api_flowprobe_interface_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_flowprobe_interface_details_t);
    vl_api_flowprobe_interface_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "which");
    if (!item) goto error;
    if (vl_api_flowprobe_which_t_fromjson((void **)&a, &l, item, &a->which) < 0) goto error;

    item = cJSON_GetObjectItem(o, "direction");
    if (!item) goto error;
    if (vl_api_flowprobe_direction_t_fromjson((void **)&a, &l, item, &a->direction) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_flowprobe_params_t *vl_api_flowprobe_params_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_flowprobe_params_t);
    vl_api_flowprobe_params_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "record_flags");
    if (!item) goto error;
    if (vl_api_flowprobe_record_flags_t_fromjson((void **)&a, &l, item, &a->record_flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "active_timer");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->active_timer);

    item = cJSON_GetObjectItem(o, "passive_timer");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->passive_timer);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_flowprobe_params_reply_t *vl_api_flowprobe_params_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_flowprobe_params_reply_t);
    vl_api_flowprobe_params_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_flowprobe_set_params_t *vl_api_flowprobe_set_params_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_flowprobe_set_params_t);
    vl_api_flowprobe_set_params_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "record_flags");
    if (!item) goto error;
    if (vl_api_flowprobe_record_flags_t_fromjson((void **)&a, &l, item, &a->record_flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "active_timer");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->active_timer);

    item = cJSON_GetObjectItem(o, "passive_timer");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->passive_timer);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_flowprobe_set_params_reply_t *vl_api_flowprobe_set_params_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_flowprobe_set_params_reply_t);
    vl_api_flowprobe_set_params_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_flowprobe_get_params_t *vl_api_flowprobe_get_params_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_flowprobe_get_params_t);
    vl_api_flowprobe_get_params_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_flowprobe_get_params_reply_t *vl_api_flowprobe_get_params_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_flowprobe_get_params_reply_t);
    vl_api_flowprobe_get_params_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "record_flags");
    if (!item) goto error;
    if (vl_api_flowprobe_record_flags_t_fromjson((void **)&a, &l, item, &a->record_flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "active_timer");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->active_timer);

    item = cJSON_GetObjectItem(o, "passive_timer");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->passive_timer);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
