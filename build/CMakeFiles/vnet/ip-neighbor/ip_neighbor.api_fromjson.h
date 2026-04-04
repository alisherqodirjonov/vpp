/* Imported API files */
#include <vnet/ip/ip_types.api_fromjson.h>
#include <vnet/ethernet/ethernet_types.api_fromjson.h>
#include <vnet/interface_types.api_fromjson.h>
#ifndef included_ip_neighbor_api_fromjson_h
#define included_ip_neighbor_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_ip_neighbor_flags_t_fromjson(void **mp, int *len, cJSON *o, vl_api_ip_neighbor_flags_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "IP_API_NEIGHBOR_FLAG_NONE") == 0) {*a = 0; return 0;}
    if (strcmp(p, "IP_API_NEIGHBOR_FLAG_STATIC") == 0) {*a = 1; return 0;}
    if (strcmp(p, "IP_API_NEIGHBOR_FLAG_NO_FIB_ENTRY") == 0) {*a = 2; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_ip_neighbor_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ip_neighbor_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson(mp, len, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_ip_neighbor_flags_t_fromjson(mp, len, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "mac_address");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson(mp, len, item, &a->mac_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ip_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->ip_address) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_ip_neighbor_event_flags_t_fromjson(void **mp, int *len, cJSON *o, vl_api_ip_neighbor_event_flags_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "IP_NEIGHBOR_API_EVENT_FLAG_ADDED") == 0) {*a = 1; return 0;}
    if (strcmp(p, "IP_NEIGHBOR_API_EVENT_FLAG_REMOVED") == 0) {*a = 2; return 0;}
    *a = 0;
    return -1;
}
static inline vl_api_ip_neighbor_add_del_t *vl_api_ip_neighbor_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_neighbor_add_del_t);
    vl_api_ip_neighbor_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "neighbor");
    if (!item) goto error;
    if (vl_api_ip_neighbor_t_fromjson((void **)&a, &l, item, &a->neighbor) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_neighbor_add_del_reply_t *vl_api_ip_neighbor_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_neighbor_add_del_reply_t);
    vl_api_ip_neighbor_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "stats_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->stats_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_neighbor_dump_t *vl_api_ip_neighbor_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_neighbor_dump_t);
    vl_api_ip_neighbor_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "af");
    if (!item) goto error;
    if (vl_api_address_family_t_fromjson((void **)&a, &l, item, &a->af) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_neighbor_details_t *vl_api_ip_neighbor_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_neighbor_details_t);
    vl_api_ip_neighbor_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "age");
    if (!item) goto error;
    vl_api_f64_fromjson(item, &a->age);

    item = cJSON_GetObjectItem(o, "neighbor");
    if (!item) goto error;
    if (vl_api_ip_neighbor_t_fromjson((void **)&a, &l, item, &a->neighbor) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_neighbor_config_t *vl_api_ip_neighbor_config_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_neighbor_config_t);
    vl_api_ip_neighbor_config_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "af");
    if (!item) goto error;
    if (vl_api_address_family_t_fromjson((void **)&a, &l, item, &a->af) < 0) goto error;

    item = cJSON_GetObjectItem(o, "max_number");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->max_number);

    item = cJSON_GetObjectItem(o, "max_age");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->max_age);

    item = cJSON_GetObjectItem(o, "recycle");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->recycle);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_neighbor_config_reply_t *vl_api_ip_neighbor_config_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_neighbor_config_reply_t);
    vl_api_ip_neighbor_config_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_neighbor_config_get_t *vl_api_ip_neighbor_config_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_neighbor_config_get_t);
    vl_api_ip_neighbor_config_get_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "af");
    if (!item) goto error;
    if (vl_api_address_family_t_fromjson((void **)&a, &l, item, &a->af) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_neighbor_config_get_reply_t *vl_api_ip_neighbor_config_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_neighbor_config_get_reply_t);
    vl_api_ip_neighbor_config_get_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "af");
    if (!item) goto error;
    if (vl_api_address_family_t_fromjson((void **)&a, &l, item, &a->af) < 0) goto error;

    item = cJSON_GetObjectItem(o, "max_number");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->max_number);

    item = cJSON_GetObjectItem(o, "max_age");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->max_age);

    item = cJSON_GetObjectItem(o, "recycle");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->recycle);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_neighbor_replace_begin_t *vl_api_ip_neighbor_replace_begin_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_neighbor_replace_begin_t);
    vl_api_ip_neighbor_replace_begin_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_ip_neighbor_replace_begin_reply_t *vl_api_ip_neighbor_replace_begin_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_neighbor_replace_begin_reply_t);
    vl_api_ip_neighbor_replace_begin_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_neighbor_replace_end_t *vl_api_ip_neighbor_replace_end_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_neighbor_replace_end_t);
    vl_api_ip_neighbor_replace_end_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_ip_neighbor_replace_end_reply_t *vl_api_ip_neighbor_replace_end_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_neighbor_replace_end_reply_t);
    vl_api_ip_neighbor_replace_end_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_neighbor_flush_t *vl_api_ip_neighbor_flush_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_neighbor_flush_t);
    vl_api_ip_neighbor_flush_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "af");
    if (!item) goto error;
    if (vl_api_address_family_t_fromjson((void **)&a, &l, item, &a->af) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_neighbor_flush_reply_t *vl_api_ip_neighbor_flush_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_neighbor_flush_reply_t);
    vl_api_ip_neighbor_flush_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_want_ip_neighbor_events_t *vl_api_want_ip_neighbor_events_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_want_ip_neighbor_events_t);
    vl_api_want_ip_neighbor_events_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable);

    item = cJSON_GetObjectItem(o, "pid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->pid);

    item = cJSON_GetObjectItem(o, "ip");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->ip) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_want_ip_neighbor_events_reply_t *vl_api_want_ip_neighbor_events_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_want_ip_neighbor_events_reply_t);
    vl_api_want_ip_neighbor_events_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_neighbor_event_t *vl_api_ip_neighbor_event_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_neighbor_event_t);
    vl_api_ip_neighbor_event_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "pid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->pid);

    item = cJSON_GetObjectItem(o, "neighbor");
    if (!item) goto error;
    if (vl_api_ip_neighbor_t_fromjson((void **)&a, &l, item, &a->neighbor) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_want_ip_neighbor_events_v2_t *vl_api_want_ip_neighbor_events_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_want_ip_neighbor_events_v2_t);
    vl_api_want_ip_neighbor_events_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable);

    item = cJSON_GetObjectItem(o, "pid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->pid);

    item = cJSON_GetObjectItem(o, "ip");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->ip) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_want_ip_neighbor_events_v2_reply_t *vl_api_want_ip_neighbor_events_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_want_ip_neighbor_events_v2_reply_t);
    vl_api_want_ip_neighbor_events_v2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_neighbor_event_v2_t *vl_api_ip_neighbor_event_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_neighbor_event_v2_t);
    vl_api_ip_neighbor_event_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "pid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->pid);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_ip_neighbor_event_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "neighbor");
    if (!item) goto error;
    if (vl_api_ip_neighbor_t_fromjson((void **)&a, &l, item, &a->neighbor) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
