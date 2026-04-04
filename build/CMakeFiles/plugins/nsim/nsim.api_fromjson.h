/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#ifndef included_nsim_api_fromjson_h
#define included_nsim_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_nsim_cross_connect_enable_disable_t *vl_api_nsim_cross_connect_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nsim_cross_connect_enable_disable_t);
    vl_api_nsim_cross_connect_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "enable_disable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable_disable);

    item = cJSON_GetObjectItem(o, "sw_if_index0");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index0) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index1");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index1) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nsim_cross_connect_enable_disable_reply_t *vl_api_nsim_cross_connect_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nsim_cross_connect_enable_disable_reply_t);
    vl_api_nsim_cross_connect_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nsim_output_feature_enable_disable_t *vl_api_nsim_output_feature_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nsim_output_feature_enable_disable_t);
    vl_api_nsim_output_feature_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "enable_disable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable_disable);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nsim_output_feature_enable_disable_reply_t *vl_api_nsim_output_feature_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nsim_output_feature_enable_disable_reply_t);
    vl_api_nsim_output_feature_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nsim_configure_t *vl_api_nsim_configure_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nsim_configure_t);
    vl_api_nsim_configure_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "delay_in_usec");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->delay_in_usec);

    item = cJSON_GetObjectItem(o, "average_packet_size");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->average_packet_size);

    item = cJSON_GetObjectItem(o, "bandwidth_in_bits_per_second");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->bandwidth_in_bits_per_second);

    item = cJSON_GetObjectItem(o, "packets_per_drop");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->packets_per_drop);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nsim_configure_reply_t *vl_api_nsim_configure_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nsim_configure_reply_t);
    vl_api_nsim_configure_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nsim_configure2_t *vl_api_nsim_configure2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nsim_configure2_t);
    vl_api_nsim_configure2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "delay_in_usec");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->delay_in_usec);

    item = cJSON_GetObjectItem(o, "average_packet_size");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->average_packet_size);

    item = cJSON_GetObjectItem(o, "bandwidth_in_bits_per_second");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->bandwidth_in_bits_per_second);

    item = cJSON_GetObjectItem(o, "packets_per_drop");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->packets_per_drop);

    item = cJSON_GetObjectItem(o, "packets_per_reorder");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->packets_per_reorder);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nsim_configure2_reply_t *vl_api_nsim_configure2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nsim_configure2_reply_t);
    vl_api_nsim_configure2_reply_t *a = cJSON_malloc(l);

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
