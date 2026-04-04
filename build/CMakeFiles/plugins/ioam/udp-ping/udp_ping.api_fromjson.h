/* Imported API files */
#include <vnet/ip/ip_types.api_fromjson.h>
#ifndef included_udp_ping_api_fromjson_h
#define included_udp_ping_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_udp_ping_add_del_t *vl_api_udp_ping_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_udp_ping_add_del_t);
    vl_api_udp_ping_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "src_ip_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->src_ip_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dst_ip_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->dst_ip_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "start_src_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->start_src_port);

    item = cJSON_GetObjectItem(o, "end_src_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->end_src_port);

    item = cJSON_GetObjectItem(o, "start_dst_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->start_dst_port);

    item = cJSON_GetObjectItem(o, "end_dst_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->end_dst_port);

    item = cJSON_GetObjectItem(o, "interval");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->interval);

    item = cJSON_GetObjectItem(o, "dis");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->dis);

    item = cJSON_GetObjectItem(o, "fault_det");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->fault_det);

    item = cJSON_GetObjectItem(o, "reserve");
    if (!item) goto error;
    if (u8string_fromjson2(o, "reserve", a->reserve) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_udp_ping_add_del_reply_t *vl_api_udp_ping_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_udp_ping_add_del_reply_t);
    vl_api_udp_ping_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_udp_ping_export_t *vl_api_udp_ping_export_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_udp_ping_export_t);
    vl_api_udp_ping_export_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_udp_ping_export_reply_t *vl_api_udp_ping_export_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_udp_ping_export_reply_t);
    vl_api_udp_ping_export_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
