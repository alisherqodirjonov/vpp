/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/policer/policer_types.api_fromjson.h>
#ifndef included_policer_api_fromjson_h
#define included_policer_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_policer_bind_t *vl_api_policer_bind_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_policer_bind_t);
    vl_api_policer_bind_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    strncpy_s((char *)a->name, sizeof(a->name), cJSON_GetStringValue(item), sizeof(a->name) - 1);

    item = cJSON_GetObjectItem(o, "worker_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->worker_index);

    item = cJSON_GetObjectItem(o, "bind_enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->bind_enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_policer_bind_reply_t *vl_api_policer_bind_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_policer_bind_reply_t);
    vl_api_policer_bind_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_policer_bind_v2_t *vl_api_policer_bind_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_policer_bind_v2_t);
    vl_api_policer_bind_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "policer_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->policer_index);

    item = cJSON_GetObjectItem(o, "worker_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->worker_index);

    item = cJSON_GetObjectItem(o, "bind_enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->bind_enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_policer_bind_v2_reply_t *vl_api_policer_bind_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_policer_bind_v2_reply_t);
    vl_api_policer_bind_v2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_policer_input_t *vl_api_policer_input_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_policer_input_t);
    vl_api_policer_input_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    strncpy_s((char *)a->name, sizeof(a->name), cJSON_GetStringValue(item), sizeof(a->name) - 1);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "apply");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->apply);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_policer_input_reply_t *vl_api_policer_input_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_policer_input_reply_t);
    vl_api_policer_input_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_policer_input_v2_t *vl_api_policer_input_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_policer_input_v2_t);
    vl_api_policer_input_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "policer_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->policer_index);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "apply");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->apply);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_policer_input_v2_reply_t *vl_api_policer_input_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_policer_input_v2_reply_t);
    vl_api_policer_input_v2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_policer_output_t *vl_api_policer_output_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_policer_output_t);
    vl_api_policer_output_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    strncpy_s((char *)a->name, sizeof(a->name), cJSON_GetStringValue(item), sizeof(a->name) - 1);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "apply");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->apply);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_policer_output_reply_t *vl_api_policer_output_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_policer_output_reply_t);
    vl_api_policer_output_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_policer_output_v2_t *vl_api_policer_output_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_policer_output_v2_t);
    vl_api_policer_output_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "policer_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->policer_index);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "apply");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->apply);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_policer_output_v2_reply_t *vl_api_policer_output_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_policer_output_v2_reply_t);
    vl_api_policer_output_v2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_policer_add_del_t *vl_api_policer_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_policer_add_del_t);
    vl_api_policer_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    strncpy_s((char *)a->name, sizeof(a->name), cJSON_GetStringValue(item), sizeof(a->name) - 1);

    item = cJSON_GetObjectItem(o, "cir");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->cir);

    item = cJSON_GetObjectItem(o, "eir");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->eir);

    item = cJSON_GetObjectItem(o, "cb");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->cb);

    item = cJSON_GetObjectItem(o, "eb");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->eb);

    item = cJSON_GetObjectItem(o, "rate_type");
    if (!item) goto error;
    if (vl_api_sse2_qos_rate_type_t_fromjson((void **)&a, &l, item, &a->rate_type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "round_type");
    if (!item) goto error;
    if (vl_api_sse2_qos_round_type_t_fromjson((void **)&a, &l, item, &a->round_type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "type");
    if (!item) goto error;
    if (vl_api_sse2_qos_policer_type_t_fromjson((void **)&a, &l, item, &a->type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "color_aware");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->color_aware);

    item = cJSON_GetObjectItem(o, "conform_action");
    if (!item) goto error;
    if (vl_api_sse2_qos_action_t_fromjson((void **)&a, &l, item, &a->conform_action) < 0) goto error;

    item = cJSON_GetObjectItem(o, "exceed_action");
    if (!item) goto error;
    if (vl_api_sse2_qos_action_t_fromjson((void **)&a, &l, item, &a->exceed_action) < 0) goto error;

    item = cJSON_GetObjectItem(o, "violate_action");
    if (!item) goto error;
    if (vl_api_sse2_qos_action_t_fromjson((void **)&a, &l, item, &a->violate_action) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_policer_add_t *vl_api_policer_add_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_policer_add_t);
    vl_api_policer_add_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    strncpy_s((char *)a->name, sizeof(a->name), cJSON_GetStringValue(item), sizeof(a->name) - 1);

    item = cJSON_GetObjectItem(o, "infos");
    if (!item) goto error;
    if (vl_api_policer_config_t_fromjson((void **)&a, &l, item, &a->infos) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_policer_del_t *vl_api_policer_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_policer_del_t);
    vl_api_policer_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "policer_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->policer_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_policer_del_reply_t *vl_api_policer_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_policer_del_reply_t);
    vl_api_policer_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_policer_update_t *vl_api_policer_update_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_policer_update_t);
    vl_api_policer_update_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "policer_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->policer_index);

    item = cJSON_GetObjectItem(o, "infos");
    if (!item) goto error;
    if (vl_api_policer_config_t_fromjson((void **)&a, &l, item, &a->infos) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_policer_update_reply_t *vl_api_policer_update_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_policer_update_reply_t);
    vl_api_policer_update_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_policer_reset_t *vl_api_policer_reset_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_policer_reset_t);
    vl_api_policer_reset_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "policer_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->policer_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_policer_reset_reply_t *vl_api_policer_reset_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_policer_reset_reply_t);
    vl_api_policer_reset_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_policer_add_del_reply_t *vl_api_policer_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_policer_add_del_reply_t);
    vl_api_policer_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "policer_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->policer_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_policer_add_reply_t *vl_api_policer_add_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_policer_add_reply_t);
    vl_api_policer_add_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "policer_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->policer_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_policer_dump_t *vl_api_policer_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_policer_dump_t);
    vl_api_policer_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "match_name_valid");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->match_name_valid);

    item = cJSON_GetObjectItem(o, "match_name");
    if (!item) goto error;
    strncpy_s((char *)a->match_name, sizeof(a->match_name), cJSON_GetStringValue(item), sizeof(a->match_name) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_policer_dump_v2_t *vl_api_policer_dump_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_policer_dump_v2_t);
    vl_api_policer_dump_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "policer_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->policer_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_policer_details_t *vl_api_policer_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_policer_details_t);
    vl_api_policer_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    strncpy_s((char *)a->name, sizeof(a->name), cJSON_GetStringValue(item), sizeof(a->name) - 1);

    item = cJSON_GetObjectItem(o, "cir");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->cir);

    item = cJSON_GetObjectItem(o, "eir");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->eir);

    item = cJSON_GetObjectItem(o, "cb");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->cb);

    item = cJSON_GetObjectItem(o, "eb");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->eb);

    item = cJSON_GetObjectItem(o, "rate_type");
    if (!item) goto error;
    if (vl_api_sse2_qos_rate_type_t_fromjson((void **)&a, &l, item, &a->rate_type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "round_type");
    if (!item) goto error;
    if (vl_api_sse2_qos_round_type_t_fromjson((void **)&a, &l, item, &a->round_type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "type");
    if (!item) goto error;
    if (vl_api_sse2_qos_policer_type_t_fromjson((void **)&a, &l, item, &a->type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "conform_action");
    if (!item) goto error;
    if (vl_api_sse2_qos_action_t_fromjson((void **)&a, &l, item, &a->conform_action) < 0) goto error;

    item = cJSON_GetObjectItem(o, "exceed_action");
    if (!item) goto error;
    if (vl_api_sse2_qos_action_t_fromjson((void **)&a, &l, item, &a->exceed_action) < 0) goto error;

    item = cJSON_GetObjectItem(o, "violate_action");
    if (!item) goto error;
    if (vl_api_sse2_qos_action_t_fromjson((void **)&a, &l, item, &a->violate_action) < 0) goto error;

    item = cJSON_GetObjectItem(o, "single_rate");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->single_rate);

    item = cJSON_GetObjectItem(o, "color_aware");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->color_aware);

    item = cJSON_GetObjectItem(o, "scale");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->scale);

    item = cJSON_GetObjectItem(o, "cir_tokens_per_period");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->cir_tokens_per_period);

    item = cJSON_GetObjectItem(o, "pir_tokens_per_period");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->pir_tokens_per_period);

    item = cJSON_GetObjectItem(o, "current_limit");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->current_limit);

    item = cJSON_GetObjectItem(o, "current_bucket");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->current_bucket);

    item = cJSON_GetObjectItem(o, "extended_limit");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->extended_limit);

    item = cJSON_GetObjectItem(o, "extended_bucket");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->extended_bucket);

    item = cJSON_GetObjectItem(o, "last_update_time");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->last_update_time);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
