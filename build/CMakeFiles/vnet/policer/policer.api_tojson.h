/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/policer/policer_types.api_tojson.h>
#ifndef included_policer_api_tojson_h
#define included_policer_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_policer_bind_t_tojson (vl_api_policer_bind_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "policer_bind");
    cJSON_AddStringToObject(o, "_crc", "dcf516f9");
    cJSON_AddStringToObject(o, "name", (char *)a->name);
    cJSON_AddNumberToObject(o, "worker_index", a->worker_index);
    cJSON_AddBoolToObject(o, "bind_enable", a->bind_enable);
    return o;
}
static inline cJSON *vl_api_policer_bind_reply_t_tojson (vl_api_policer_bind_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "policer_bind_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_policer_bind_v2_t_tojson (vl_api_policer_bind_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "policer_bind_v2");
    cJSON_AddStringToObject(o, "_crc", "f87bd3c0");
    cJSON_AddNumberToObject(o, "policer_index", a->policer_index);
    cJSON_AddNumberToObject(o, "worker_index", a->worker_index);
    cJSON_AddBoolToObject(o, "bind_enable", a->bind_enable);
    return o;
}
static inline cJSON *vl_api_policer_bind_v2_reply_t_tojson (vl_api_policer_bind_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "policer_bind_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_policer_input_t_tojson (vl_api_policer_input_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "policer_input");
    cJSON_AddStringToObject(o, "_crc", "233f0ef5");
    cJSON_AddStringToObject(o, "name", (char *)a->name);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "apply", a->apply);
    return o;
}
static inline cJSON *vl_api_policer_input_reply_t_tojson (vl_api_policer_input_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "policer_input_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_policer_input_v2_t_tojson (vl_api_policer_input_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "policer_input_v2");
    cJSON_AddStringToObject(o, "_crc", "8388eb84");
    cJSON_AddNumberToObject(o, "policer_index", a->policer_index);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "apply", a->apply);
    return o;
}
static inline cJSON *vl_api_policer_input_v2_reply_t_tojson (vl_api_policer_input_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "policer_input_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_policer_output_t_tojson (vl_api_policer_output_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "policer_output");
    cJSON_AddStringToObject(o, "_crc", "233f0ef5");
    cJSON_AddStringToObject(o, "name", (char *)a->name);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "apply", a->apply);
    return o;
}
static inline cJSON *vl_api_policer_output_reply_t_tojson (vl_api_policer_output_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "policer_output_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_policer_output_v2_t_tojson (vl_api_policer_output_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "policer_output_v2");
    cJSON_AddStringToObject(o, "_crc", "8388eb84");
    cJSON_AddNumberToObject(o, "policer_index", a->policer_index);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "apply", a->apply);
    return o;
}
static inline cJSON *vl_api_policer_output_v2_reply_t_tojson (vl_api_policer_output_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "policer_output_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_policer_add_del_t_tojson (vl_api_policer_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "policer_add_del");
    cJSON_AddStringToObject(o, "_crc", "2b31dd38");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddStringToObject(o, "name", (char *)a->name);
    cJSON_AddNumberToObject(o, "cir", a->cir);
    cJSON_AddNumberToObject(o, "eir", a->eir);
    cJSON_AddNumberToObject(o, "cb", a->cb);
    cJSON_AddNumberToObject(o, "eb", a->eb);
    cJSON_AddItemToObject(o, "rate_type", vl_api_sse2_qos_rate_type_t_tojson(a->rate_type));
    cJSON_AddItemToObject(o, "round_type", vl_api_sse2_qos_round_type_t_tojson(a->round_type));
    cJSON_AddItemToObject(o, "type", vl_api_sse2_qos_policer_type_t_tojson(a->type));
    cJSON_AddBoolToObject(o, "color_aware", a->color_aware);
    cJSON_AddItemToObject(o, "conform_action", vl_api_sse2_qos_action_t_tojson(&a->conform_action));
    cJSON_AddItemToObject(o, "exceed_action", vl_api_sse2_qos_action_t_tojson(&a->exceed_action));
    cJSON_AddItemToObject(o, "violate_action", vl_api_sse2_qos_action_t_tojson(&a->violate_action));
    return o;
}
static inline cJSON *vl_api_policer_add_t_tojson (vl_api_policer_add_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "policer_add");
    cJSON_AddStringToObject(o, "_crc", "4d949e35");
    cJSON_AddStringToObject(o, "name", (char *)a->name);
    cJSON_AddItemToObject(o, "infos", vl_api_policer_config_t_tojson(&a->infos));
    return o;
}
static inline cJSON *vl_api_policer_del_t_tojson (vl_api_policer_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "policer_del");
    cJSON_AddStringToObject(o, "_crc", "7ff7912e");
    cJSON_AddNumberToObject(o, "policer_index", a->policer_index);
    return o;
}
static inline cJSON *vl_api_policer_del_reply_t_tojson (vl_api_policer_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "policer_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_policer_update_t_tojson (vl_api_policer_update_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "policer_update");
    cJSON_AddStringToObject(o, "_crc", "fd039ef0");
    cJSON_AddNumberToObject(o, "policer_index", a->policer_index);
    cJSON_AddItemToObject(o, "infos", vl_api_policer_config_t_tojson(&a->infos));
    return o;
}
static inline cJSON *vl_api_policer_update_reply_t_tojson (vl_api_policer_update_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "policer_update_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_policer_reset_t_tojson (vl_api_policer_reset_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "policer_reset");
    cJSON_AddStringToObject(o, "_crc", "7ff7912e");
    cJSON_AddNumberToObject(o, "policer_index", a->policer_index);
    return o;
}
static inline cJSON *vl_api_policer_reset_reply_t_tojson (vl_api_policer_reset_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "policer_reset_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_policer_add_del_reply_t_tojson (vl_api_policer_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "policer_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "a177cef2");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "policer_index", a->policer_index);
    return o;
}
static inline cJSON *vl_api_policer_add_reply_t_tojson (vl_api_policer_add_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "policer_add_reply");
    cJSON_AddStringToObject(o, "_crc", "a177cef2");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "policer_index", a->policer_index);
    return o;
}
static inline cJSON *vl_api_policer_dump_t_tojson (vl_api_policer_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "policer_dump");
    cJSON_AddStringToObject(o, "_crc", "35f1ae0f");
    cJSON_AddBoolToObject(o, "match_name_valid", a->match_name_valid);
    cJSON_AddStringToObject(o, "match_name", (char *)a->match_name);
    return o;
}
static inline cJSON *vl_api_policer_dump_v2_t_tojson (vl_api_policer_dump_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "policer_dump_v2");
    cJSON_AddStringToObject(o, "_crc", "7ff7912e");
    cJSON_AddNumberToObject(o, "policer_index", a->policer_index);
    return o;
}
static inline cJSON *vl_api_policer_details_t_tojson (vl_api_policer_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "policer_details");
    cJSON_AddStringToObject(o, "_crc", "72d0e248");
    cJSON_AddStringToObject(o, "name", (char *)a->name);
    cJSON_AddNumberToObject(o, "cir", a->cir);
    cJSON_AddNumberToObject(o, "eir", a->eir);
    cJSON_AddNumberToObject(o, "cb", a->cb);
    cJSON_AddNumberToObject(o, "eb", a->eb);
    cJSON_AddItemToObject(o, "rate_type", vl_api_sse2_qos_rate_type_t_tojson(a->rate_type));
    cJSON_AddItemToObject(o, "round_type", vl_api_sse2_qos_round_type_t_tojson(a->round_type));
    cJSON_AddItemToObject(o, "type", vl_api_sse2_qos_policer_type_t_tojson(a->type));
    cJSON_AddItemToObject(o, "conform_action", vl_api_sse2_qos_action_t_tojson(&a->conform_action));
    cJSON_AddItemToObject(o, "exceed_action", vl_api_sse2_qos_action_t_tojson(&a->exceed_action));
    cJSON_AddItemToObject(o, "violate_action", vl_api_sse2_qos_action_t_tojson(&a->violate_action));
    cJSON_AddBoolToObject(o, "single_rate", a->single_rate);
    cJSON_AddBoolToObject(o, "color_aware", a->color_aware);
    cJSON_AddNumberToObject(o, "scale", a->scale);
    cJSON_AddNumberToObject(o, "cir_tokens_per_period", a->cir_tokens_per_period);
    cJSON_AddNumberToObject(o, "pir_tokens_per_period", a->pir_tokens_per_period);
    cJSON_AddNumberToObject(o, "current_limit", a->current_limit);
    cJSON_AddNumberToObject(o, "current_bucket", a->current_bucket);
    cJSON_AddNumberToObject(o, "extended_limit", a->extended_limit);
    cJSON_AddNumberToObject(o, "extended_bucket", a->extended_bucket);
    cJSON_AddNumberToObject(o, "last_update_time", a->last_update_time);
    return o;
}
#endif
