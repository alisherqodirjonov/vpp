/* Imported API files */
#include <vnet/ip/ip_types.api_fromjson.h>
#ifndef included_syslog_api_fromjson_h
#define included_syslog_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_syslog_severity_t_fromjson(void **mp, int *len, cJSON *o, vl_api_syslog_severity_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "SYSLOG_API_SEVERITY_EMERG") == 0) {*a = 0; return 0;}
    if (strcmp(p, "SYSLOG_API_SEVERITY_ALERT") == 0) {*a = 1; return 0;}
    if (strcmp(p, "SYSLOG_API_SEVERITY_CRIT") == 0) {*a = 2; return 0;}
    if (strcmp(p, "SYSLOG_API_SEVERITY_ERR") == 0) {*a = 3; return 0;}
    if (strcmp(p, "SYSLOG_API_SEVERITY_WARN") == 0) {*a = 4; return 0;}
    if (strcmp(p, "SYSLOG_API_SEVERITY_NOTICE") == 0) {*a = 5; return 0;}
    if (strcmp(p, "SYSLOG_API_SEVERITY_INFO") == 0) {*a = 6; return 0;}
    if (strcmp(p, "SYSLOG_API_SEVERITY_DBG") == 0) {*a = 7; return 0;}
    *a = 0;
    return -1;
}
static inline vl_api_syslog_set_sender_t *vl_api_syslog_set_sender_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_syslog_set_sender_t);
    vl_api_syslog_set_sender_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "src_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->src_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "collector_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->collector_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "collector_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->collector_port);

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    item = cJSON_GetObjectItem(o, "max_msg_size");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->max_msg_size);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_syslog_set_sender_reply_t *vl_api_syslog_set_sender_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_syslog_set_sender_reply_t);
    vl_api_syslog_set_sender_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_syslog_get_sender_t *vl_api_syslog_get_sender_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_syslog_get_sender_t);
    vl_api_syslog_get_sender_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_syslog_get_sender_reply_t *vl_api_syslog_get_sender_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_syslog_get_sender_reply_t);
    vl_api_syslog_get_sender_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "src_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->src_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "collector_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->collector_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "collector_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->collector_port);

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    item = cJSON_GetObjectItem(o, "max_msg_size");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->max_msg_size);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_syslog_set_filter_t *vl_api_syslog_set_filter_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_syslog_set_filter_t);
    vl_api_syslog_set_filter_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "severity");
    if (!item) goto error;
    if (vl_api_syslog_severity_t_fromjson((void **)&a, &l, item, &a->severity) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_syslog_set_filter_reply_t *vl_api_syslog_set_filter_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_syslog_set_filter_reply_t);
    vl_api_syslog_set_filter_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_syslog_get_filter_t *vl_api_syslog_get_filter_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_syslog_get_filter_t);
    vl_api_syslog_get_filter_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_syslog_get_filter_reply_t *vl_api_syslog_get_filter_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_syslog_get_filter_reply_t);
    vl_api_syslog_get_filter_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "severity");
    if (!item) goto error;
    if (vl_api_syslog_severity_t_fromjson((void **)&a, &l, item, &a->severity) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
