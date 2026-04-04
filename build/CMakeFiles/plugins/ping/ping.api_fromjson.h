/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/ip/ip_types.api_fromjson.h>
#ifndef included_ping_api_fromjson_h
#define included_ping_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_want_ping_finished_events_t *vl_api_want_ping_finished_events_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_want_ping_finished_events_t);
    vl_api_want_ping_finished_events_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "repeat");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->repeat);

    item = cJSON_GetObjectItem(o, "interval");
    if (!item) goto error;
    vl_api_f64_fromjson(item, &a->interval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_want_ping_finished_events_reply_t *vl_api_want_ping_finished_events_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_want_ping_finished_events_reply_t);
    vl_api_want_ping_finished_events_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ping_finished_event_t *vl_api_ping_finished_event_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ping_finished_event_t);
    vl_api_ping_finished_event_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "request_count");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->request_count);

    item = cJSON_GetObjectItem(o, "reply_count");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->reply_count);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
