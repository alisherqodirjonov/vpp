/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#ifndef included_sr_pt_api_fromjson_h
#define included_sr_pt_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_sr_pt_iface_dump_t *vl_api_sr_pt_iface_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_pt_iface_dump_t);
    vl_api_sr_pt_iface_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_sr_pt_iface_details_t *vl_api_sr_pt_iface_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_pt_iface_details_t);
    vl_api_sr_pt_iface_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->id);

    item = cJSON_GetObjectItem(o, "ingress_load");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->ingress_load);

    item = cJSON_GetObjectItem(o, "egress_load");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->egress_load);

    item = cJSON_GetObjectItem(o, "tts_template");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->tts_template);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_pt_iface_add_t *vl_api_sr_pt_iface_add_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_pt_iface_add_t);
    vl_api_sr_pt_iface_add_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->id);

    item = cJSON_GetObjectItem(o, "ingress_load");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->ingress_load);

    item = cJSON_GetObjectItem(o, "egress_load");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->egress_load);

    item = cJSON_GetObjectItem(o, "tts_template");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->tts_template);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_pt_iface_add_reply_t *vl_api_sr_pt_iface_add_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_pt_iface_add_reply_t);
    vl_api_sr_pt_iface_add_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_pt_iface_del_t *vl_api_sr_pt_iface_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_pt_iface_del_t);
    vl_api_sr_pt_iface_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_pt_iface_del_reply_t *vl_api_sr_pt_iface_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_pt_iface_del_reply_t);
    vl_api_sr_pt_iface_del_reply_t *a = cJSON_malloc(l);

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
