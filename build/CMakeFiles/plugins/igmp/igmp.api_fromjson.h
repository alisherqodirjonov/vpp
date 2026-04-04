/* Imported API files */
#include <vnet/ip/ip_types.api_fromjson.h>
#include <vnet/interface_types.api_fromjson.h>
#ifndef included_igmp_api_fromjson_h
#define included_igmp_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_filter_mode_t_fromjson(void **mp, int *len, cJSON *o, vl_api_filter_mode_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "EXCLUDE") == 0) {*a = 0; return 0;}
    if (strcmp(p, "INCLUDE") == 0) {*a = 1; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_igmp_group_t_fromjson (void **mp, int *len, cJSON *o, vl_api_igmp_group_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "filter");
    if (!item) goto error;
    if (vl_api_filter_mode_t_fromjson(mp, len, item, &a->filter) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson(mp, len, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "gaddr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson(mp, len, item, &a->gaddr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "saddrs");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "saddrs");
        int size = cJSON_GetArraySize(array);
        a->n_srcs = size;
        *mp = cJSON_realloc(*mp, *len + sizeof(vl_api_ip4_address_t) * size);
        vl_api_ip4_address_t *d = (void *)*mp + *len;
        *len += sizeof(vl_api_ip4_address_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_ip4_address_t_fromjson(mp, len, e, &d[i]) < 0) goto error; 
        }
    }

    return 0;

  error:
    return -1;
}
static inline int vl_api_group_prefix_type_t_fromjson(void **mp, int *len, cJSON *o, vl_api_group_prefix_type_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "ASM") == 0) {*a = 0; return 0;}
    if (strcmp(p, "SSM") == 0) {*a = 1; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_group_prefix_t_fromjson (void **mp, int *len, cJSON *o, vl_api_group_prefix_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "type");
    if (!item) goto error;
    if (vl_api_group_prefix_type_t_fromjson(mp, len, item, &a->type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "prefix");
    if (!item) goto error;
    if (vl_api_prefix_t_fromjson(mp, len, item, &a->prefix) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline vl_api_igmp_listen_t *vl_api_igmp_listen_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_igmp_listen_t);
    vl_api_igmp_listen_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "group");
    if (!item) goto error;
    if (vl_api_igmp_group_t_fromjson((void **)&a, &l, item, &a->group) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_igmp_listen_reply_t *vl_api_igmp_listen_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_igmp_listen_reply_t);
    vl_api_igmp_listen_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_igmp_enable_disable_t *vl_api_igmp_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_igmp_enable_disable_t);
    vl_api_igmp_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable);

    item = cJSON_GetObjectItem(o, "mode");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->mode);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_igmp_enable_disable_reply_t *vl_api_igmp_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_igmp_enable_disable_reply_t);
    vl_api_igmp_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_igmp_proxy_device_add_del_t *vl_api_igmp_proxy_device_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_igmp_proxy_device_add_del_t);
    vl_api_igmp_proxy_device_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "add");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->add);

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_igmp_proxy_device_add_del_reply_t *vl_api_igmp_proxy_device_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_igmp_proxy_device_add_del_reply_t);
    vl_api_igmp_proxy_device_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_igmp_proxy_device_add_del_interface_t *vl_api_igmp_proxy_device_add_del_interface_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_igmp_proxy_device_add_del_interface_t);
    vl_api_igmp_proxy_device_add_del_interface_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->add);

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_igmp_proxy_device_add_del_interface_reply_t *vl_api_igmp_proxy_device_add_del_interface_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_igmp_proxy_device_add_del_interface_reply_t);
    vl_api_igmp_proxy_device_add_del_interface_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_igmp_dump_t *vl_api_igmp_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_igmp_dump_t);
    vl_api_igmp_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_igmp_details_t *vl_api_igmp_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_igmp_details_t);
    vl_api_igmp_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "saddr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->saddr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "gaddr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->gaddr) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_igmp_clear_interface_t *vl_api_igmp_clear_interface_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_igmp_clear_interface_t);
    vl_api_igmp_clear_interface_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_igmp_clear_interface_reply_t *vl_api_igmp_clear_interface_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_igmp_clear_interface_reply_t);
    vl_api_igmp_clear_interface_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_want_igmp_events_t *vl_api_want_igmp_events_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_want_igmp_events_t);
    vl_api_want_igmp_events_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->enable);

    item = cJSON_GetObjectItem(o, "pid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->pid);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_want_igmp_events_reply_t *vl_api_want_igmp_events_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_want_igmp_events_reply_t);
    vl_api_want_igmp_events_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_igmp_event_t *vl_api_igmp_event_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_igmp_event_t);
    vl_api_igmp_event_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "filter");
    if (!item) goto error;
    if (vl_api_filter_mode_t_fromjson((void **)&a, &l, item, &a->filter) < 0) goto error;

    item = cJSON_GetObjectItem(o, "saddr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->saddr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "gaddr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->gaddr) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_igmp_group_prefix_set_t *vl_api_igmp_group_prefix_set_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_igmp_group_prefix_set_t);
    vl_api_igmp_group_prefix_set_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "gp");
    if (!item) goto error;
    if (vl_api_group_prefix_t_fromjson((void **)&a, &l, item, &a->gp) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_igmp_group_prefix_set_reply_t *vl_api_igmp_group_prefix_set_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_igmp_group_prefix_set_reply_t);
    vl_api_igmp_group_prefix_set_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_igmp_group_prefix_dump_t *vl_api_igmp_group_prefix_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_igmp_group_prefix_dump_t);
    vl_api_igmp_group_prefix_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_igmp_group_prefix_details_t *vl_api_igmp_group_prefix_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_igmp_group_prefix_details_t);
    vl_api_igmp_group_prefix_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "gp");
    if (!item) goto error;
    if (vl_api_group_prefix_t_fromjson((void **)&a, &l, item, &a->gp) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
