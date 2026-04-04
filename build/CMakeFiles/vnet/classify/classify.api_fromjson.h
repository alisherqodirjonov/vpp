/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#ifndef included_classify_api_fromjson_h
#define included_classify_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_classify_action_t_fromjson(void **mp, int *len, cJSON *o, vl_api_classify_action_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "CLASSIFY_API_ACTION_NONE") == 0) {*a = 0; return 0;}
    if (strcmp(p, "CLASSIFY_API_ACTION_SET_IP4_FIB_INDEX") == 0) {*a = 1; return 0;}
    if (strcmp(p, "CLASSIFY_API_ACTION_SET_IP6_FIB_INDEX") == 0) {*a = 2; return 0;}
    if (strcmp(p, "CLASSIFY_API_ACTION_SET_METADATA") == 0) {*a = 3; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_policer_classify_table_t_fromjson(void **mp, int *len, cJSON *o, vl_api_policer_classify_table_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "POLICER_CLASSIFY_API_TABLE_IP4") == 0) {*a = 0; return 0;}
    if (strcmp(p, "POLICER_CLASSIFY_API_TABLE_IP6") == 0) {*a = 1; return 0;}
    if (strcmp(p, "POLICER_CLASSIFY_API_TABLE_L2") == 0) {*a = 2; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_flow_classify_table_t_fromjson(void **mp, int *len, cJSON *o, vl_api_flow_classify_table_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "FLOW_CLASSIFY_API_TABLE_IP4") == 0) {*a = 0; return 0;}
    if (strcmp(p, "FLOW_CLASSIFY_API_TABLE_IP6") == 0) {*a = 1; return 0;}
    *a = 0;
    return -1;
}
static inline vl_api_classify_add_del_table_t *vl_api_classify_add_del_table_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_classify_add_del_table_t);
    vl_api_classify_add_del_table_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "del_chain");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->del_chain);

    item = cJSON_GetObjectItem(o, "table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_index);

    item = cJSON_GetObjectItem(o, "nbuckets");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->nbuckets);

    item = cJSON_GetObjectItem(o, "memory_size");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->memory_size);

    item = cJSON_GetObjectItem(o, "skip_n_vectors");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->skip_n_vectors);

    item = cJSON_GetObjectItem(o, "match_n_vectors");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->match_n_vectors);

    item = cJSON_GetObjectItem(o, "next_table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->next_table_index);

    item = cJSON_GetObjectItem(o, "miss_next_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->miss_next_index);

    item = cJSON_GetObjectItem(o, "current_data_flag");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->current_data_flag);

    item = cJSON_GetObjectItem(o, "current_data_offset");
    if (!item) goto error;
    vl_api_i16_fromjson(item, &a->current_data_offset);

    item = cJSON_GetObjectItem(o, "mask");
    if (!item) goto error;
    s = u8string_fromjson(o, "mask");
    if (!s) goto error;
    a->mask_len = vec_len(s);
    a = cJSON_realloc(a, l + vec_len(s));
    clib_memcpy((void *)a + l, s, vec_len(s));
    l += vec_len(s);
    vec_free(s);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_classify_add_del_table_reply_t *vl_api_classify_add_del_table_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_classify_add_del_table_reply_t);
    vl_api_classify_add_del_table_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "new_table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->new_table_index);

    item = cJSON_GetObjectItem(o, "skip_n_vectors");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->skip_n_vectors);

    item = cJSON_GetObjectItem(o, "match_n_vectors");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->match_n_vectors);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_classify_add_del_session_t *vl_api_classify_add_del_session_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_classify_add_del_session_t);
    vl_api_classify_add_del_session_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_index);

    item = cJSON_GetObjectItem(o, "hit_next_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->hit_next_index);

    item = cJSON_GetObjectItem(o, "opaque_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->opaque_index);

    item = cJSON_GetObjectItem(o, "advance");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->advance);

    item = cJSON_GetObjectItem(o, "action");
    if (!item) goto error;
    if (vl_api_classify_action_t_fromjson((void **)&a, &l, item, &a->action) < 0) goto error;

    item = cJSON_GetObjectItem(o, "metadata");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->metadata);

    item = cJSON_GetObjectItem(o, "match");
    if (!item) goto error;
    s = u8string_fromjson(o, "match");
    if (!s) goto error;
    a->match_len = vec_len(s);
    a = cJSON_realloc(a, l + vec_len(s));
    clib_memcpy((void *)a + l, s, vec_len(s));
    l += vec_len(s);
    vec_free(s);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_classify_add_del_session_reply_t *vl_api_classify_add_del_session_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_classify_add_del_session_reply_t);
    vl_api_classify_add_del_session_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_policer_classify_set_interface_t *vl_api_policer_classify_set_interface_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_policer_classify_set_interface_t);
    vl_api_policer_classify_set_interface_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ip4_table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ip4_table_index);

    item = cJSON_GetObjectItem(o, "ip6_table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ip6_table_index);

    item = cJSON_GetObjectItem(o, "l2_table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->l2_table_index);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_policer_classify_set_interface_reply_t *vl_api_policer_classify_set_interface_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_policer_classify_set_interface_reply_t);
    vl_api_policer_classify_set_interface_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_policer_classify_dump_t *vl_api_policer_classify_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_policer_classify_dump_t);
    vl_api_policer_classify_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "type");
    if (!item) goto error;
    if (vl_api_policer_classify_table_t_fromjson((void **)&a, &l, item, &a->type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_policer_classify_details_t *vl_api_policer_classify_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_policer_classify_details_t);
    vl_api_policer_classify_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_classify_table_ids_t *vl_api_classify_table_ids_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_classify_table_ids_t);
    vl_api_classify_table_ids_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_classify_table_ids_reply_t *vl_api_classify_table_ids_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_classify_table_ids_reply_t);
    vl_api_classify_table_ids_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "ids");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "ids");
        int size = cJSON_GetArraySize(array);
        a->count = size;
        a = cJSON_realloc(a, l + sizeof(u32) * size);
        u32 *d = (void *)a + l;
        l += sizeof(u32) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_u32_fromjson(e, &d[i]);
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_classify_table_by_interface_t *vl_api_classify_table_by_interface_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_classify_table_by_interface_t);
    vl_api_classify_table_by_interface_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_classify_table_by_interface_reply_t *vl_api_classify_table_by_interface_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_classify_table_by_interface_reply_t);
    vl_api_classify_table_by_interface_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "l2_table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->l2_table_id);

    item = cJSON_GetObjectItem(o, "ip4_table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ip4_table_id);

    item = cJSON_GetObjectItem(o, "ip6_table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ip6_table_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_classify_table_info_t *vl_api_classify_table_info_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_classify_table_info_t);
    vl_api_classify_table_info_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_classify_table_info_reply_t *vl_api_classify_table_info_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_classify_table_info_reply_t);
    vl_api_classify_table_info_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_id);

    item = cJSON_GetObjectItem(o, "nbuckets");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->nbuckets);

    item = cJSON_GetObjectItem(o, "match_n_vectors");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->match_n_vectors);

    item = cJSON_GetObjectItem(o, "skip_n_vectors");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->skip_n_vectors);

    item = cJSON_GetObjectItem(o, "active_sessions");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->active_sessions);

    item = cJSON_GetObjectItem(o, "next_table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->next_table_index);

    item = cJSON_GetObjectItem(o, "miss_next_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->miss_next_index);

    item = cJSON_GetObjectItem(o, "mask");
    if (!item) goto error;
    s = u8string_fromjson(o, "mask");
    if (!s) goto error;
    a->mask_length = vec_len(s);
    a = cJSON_realloc(a, l + vec_len(s));
    clib_memcpy((void *)a + l, s, vec_len(s));
    l += vec_len(s);
    vec_free(s);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_classify_session_dump_t *vl_api_classify_session_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_classify_session_dump_t);
    vl_api_classify_session_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_classify_session_details_t *vl_api_classify_session_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_classify_session_details_t);
    vl_api_classify_session_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_id);

    item = cJSON_GetObjectItem(o, "hit_next_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->hit_next_index);

    item = cJSON_GetObjectItem(o, "advance");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->advance);

    item = cJSON_GetObjectItem(o, "opaque_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->opaque_index);

    item = cJSON_GetObjectItem(o, "match");
    if (!item) goto error;
    s = u8string_fromjson(o, "match");
    if (!s) goto error;
    a->match_length = vec_len(s);
    a = cJSON_realloc(a, l + vec_len(s));
    clib_memcpy((void *)a + l, s, vec_len(s));
    l += vec_len(s);
    vec_free(s);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_flow_classify_set_interface_t *vl_api_flow_classify_set_interface_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_flow_classify_set_interface_t);
    vl_api_flow_classify_set_interface_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ip4_table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ip4_table_index);

    item = cJSON_GetObjectItem(o, "ip6_table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ip6_table_index);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_flow_classify_set_interface_reply_t *vl_api_flow_classify_set_interface_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_flow_classify_set_interface_reply_t);
    vl_api_flow_classify_set_interface_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_flow_classify_dump_t *vl_api_flow_classify_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_flow_classify_dump_t);
    vl_api_flow_classify_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "type");
    if (!item) goto error;
    if (vl_api_flow_classify_table_t_fromjson((void **)&a, &l, item, &a->type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_flow_classify_details_t *vl_api_flow_classify_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_flow_classify_details_t);
    vl_api_flow_classify_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_classify_set_interface_ip_table_t *vl_api_classify_set_interface_ip_table_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_classify_set_interface_ip_table_t);
    vl_api_classify_set_interface_ip_table_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_ipv6");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_ipv6);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_classify_set_interface_ip_table_reply_t *vl_api_classify_set_interface_ip_table_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_classify_set_interface_ip_table_reply_t);
    vl_api_classify_set_interface_ip_table_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_classify_set_interface_l2_tables_t *vl_api_classify_set_interface_l2_tables_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_classify_set_interface_l2_tables_t);
    vl_api_classify_set_interface_l2_tables_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ip4_table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ip4_table_index);

    item = cJSON_GetObjectItem(o, "ip6_table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ip6_table_index);

    item = cJSON_GetObjectItem(o, "other_table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->other_table_index);

    item = cJSON_GetObjectItem(o, "is_input");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_input);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_classify_set_interface_l2_tables_reply_t *vl_api_classify_set_interface_l2_tables_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_classify_set_interface_l2_tables_reply_t);
    vl_api_classify_set_interface_l2_tables_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_input_acl_set_interface_t *vl_api_input_acl_set_interface_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_input_acl_set_interface_t);
    vl_api_input_acl_set_interface_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ip4_table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ip4_table_index);

    item = cJSON_GetObjectItem(o, "ip6_table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ip6_table_index);

    item = cJSON_GetObjectItem(o, "l2_table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->l2_table_index);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_input_acl_set_interface_reply_t *vl_api_input_acl_set_interface_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_input_acl_set_interface_reply_t);
    vl_api_input_acl_set_interface_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_punt_acl_add_del_t *vl_api_punt_acl_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_punt_acl_add_del_t);
    vl_api_punt_acl_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "ip4_table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ip4_table_index);

    item = cJSON_GetObjectItem(o, "ip6_table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ip6_table_index);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_punt_acl_add_del_reply_t *vl_api_punt_acl_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_punt_acl_add_del_reply_t);
    vl_api_punt_acl_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_punt_acl_get_t *vl_api_punt_acl_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_punt_acl_get_t);
    vl_api_punt_acl_get_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_punt_acl_get_reply_t *vl_api_punt_acl_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_punt_acl_get_reply_t);
    vl_api_punt_acl_get_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "ip4_table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ip4_table_index);

    item = cJSON_GetObjectItem(o, "ip6_table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ip6_table_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_output_acl_set_interface_t *vl_api_output_acl_set_interface_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_output_acl_set_interface_t);
    vl_api_output_acl_set_interface_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ip4_table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ip4_table_index);

    item = cJSON_GetObjectItem(o, "ip6_table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ip6_table_index);

    item = cJSON_GetObjectItem(o, "l2_table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->l2_table_index);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_output_acl_set_interface_reply_t *vl_api_output_acl_set_interface_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_output_acl_set_interface_reply_t);
    vl_api_output_acl_set_interface_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_classify_pcap_lookup_table_t *vl_api_classify_pcap_lookup_table_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_classify_pcap_lookup_table_t);
    vl_api_classify_pcap_lookup_table_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "skip_n_vectors");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->skip_n_vectors);

    item = cJSON_GetObjectItem(o, "match_n_vectors");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->match_n_vectors);

    item = cJSON_GetObjectItem(o, "mask");
    if (!item) goto error;
    s = u8string_fromjson(o, "mask");
    if (!s) goto error;
    a->mask_len = vec_len(s);
    a = cJSON_realloc(a, l + vec_len(s));
    clib_memcpy((void *)a + l, s, vec_len(s));
    l += vec_len(s);
    vec_free(s);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_classify_pcap_lookup_table_reply_t *vl_api_classify_pcap_lookup_table_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_classify_pcap_lookup_table_reply_t);
    vl_api_classify_pcap_lookup_table_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_classify_pcap_set_table_t *vl_api_classify_pcap_set_table_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_classify_pcap_set_table_t);
    vl_api_classify_pcap_set_table_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_index);

    item = cJSON_GetObjectItem(o, "sort_masks");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->sort_masks);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_classify_pcap_set_table_reply_t *vl_api_classify_pcap_set_table_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_classify_pcap_set_table_reply_t);
    vl_api_classify_pcap_set_table_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_classify_pcap_get_tables_t *vl_api_classify_pcap_get_tables_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_classify_pcap_get_tables_t);
    vl_api_classify_pcap_get_tables_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_classify_pcap_get_tables_reply_t *vl_api_classify_pcap_get_tables_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_classify_pcap_get_tables_reply_t);
    vl_api_classify_pcap_get_tables_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "indices");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "indices");
        int size = cJSON_GetArraySize(array);
        a->count = size;
        a = cJSON_realloc(a, l + sizeof(u32) * size);
        u32 *d = (void *)a + l;
        l += sizeof(u32) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_u32_fromjson(e, &d[i]);
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_classify_trace_lookup_table_t *vl_api_classify_trace_lookup_table_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_classify_trace_lookup_table_t);
    vl_api_classify_trace_lookup_table_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "skip_n_vectors");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->skip_n_vectors);

    item = cJSON_GetObjectItem(o, "match_n_vectors");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->match_n_vectors);

    item = cJSON_GetObjectItem(o, "mask");
    if (!item) goto error;
    s = u8string_fromjson(o, "mask");
    if (!s) goto error;
    a->mask_len = vec_len(s);
    a = cJSON_realloc(a, l + vec_len(s));
    clib_memcpy((void *)a + l, s, vec_len(s));
    l += vec_len(s);
    vec_free(s);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_classify_trace_lookup_table_reply_t *vl_api_classify_trace_lookup_table_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_classify_trace_lookup_table_reply_t);
    vl_api_classify_trace_lookup_table_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_classify_trace_set_table_t *vl_api_classify_trace_set_table_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_classify_trace_set_table_t);
    vl_api_classify_trace_set_table_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_index);

    item = cJSON_GetObjectItem(o, "sort_masks");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->sort_masks);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_classify_trace_set_table_reply_t *vl_api_classify_trace_set_table_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_classify_trace_set_table_reply_t);
    vl_api_classify_trace_set_table_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_classify_trace_get_tables_t *vl_api_classify_trace_get_tables_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_classify_trace_get_tables_t);
    vl_api_classify_trace_get_tables_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_classify_trace_get_tables_reply_t *vl_api_classify_trace_get_tables_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_classify_trace_get_tables_reply_t);
    vl_api_classify_trace_get_tables_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "indices");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "indices");
        int size = cJSON_GetArraySize(array);
        a->count = size;
        a = cJSON_realloc(a, l + sizeof(u32) * size);
        u32 *d = (void *)a + l;
        l += sizeof(u32) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_u32_fromjson(e, &d[i]);
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
