/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <lisp/lisp-cp/lisp_types.api_fromjson.h>
#ifndef included_lisp_api_fromjson_h
#define included_lisp_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_lisp_locator_set_filter_t_fromjson(void **mp, int *len, cJSON *o, vl_api_lisp_locator_set_filter_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "LISP_LOCATOR_SET_FILTER_API_ALL") == 0) {*a = 0; return 0;}
    if (strcmp(p, "LISP_LOCATOR_SET_FILTER_API_LOCAL") == 0) {*a = 1; return 0;}
    if (strcmp(p, "LISP_LOCATOR_SET_FILTER_API_REMOTE") == 0) {*a = 2; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_lisp_adjacency_t_fromjson (void **mp, int *len, cJSON *o, vl_api_lisp_adjacency_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "reid");
    if (!item) goto error;
    if (vl_api_eid_t_fromjson(mp, len, item, &a->reid) < 0) goto error;

    item = cJSON_GetObjectItem(o, "leid");
    if (!item) goto error;
    if (vl_api_eid_t_fromjson(mp, len, item, &a->leid) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline vl_api_lisp_add_del_locator_set_t *vl_api_lisp_add_del_locator_set_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_add_del_locator_set_t);
    vl_api_lisp_add_del_locator_set_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "locator_set_name");
    if (!item) goto error;
    strncpy_s((char *)a->locator_set_name, sizeof(a->locator_set_name), cJSON_GetStringValue(item), sizeof(a->locator_set_name) - 1);

    item = cJSON_GetObjectItem(o, "locators");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "locators");
        int size = cJSON_GetArraySize(array);
        a->locator_num = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_local_locator_t) * size);
        vl_api_local_locator_t *d = (void *)a + l;
        l += sizeof(vl_api_local_locator_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_local_locator_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_add_del_locator_set_reply_t *vl_api_lisp_add_del_locator_set_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_add_del_locator_set_reply_t);
    vl_api_lisp_add_del_locator_set_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "ls_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ls_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_add_del_locator_t *vl_api_lisp_add_del_locator_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_add_del_locator_t);
    vl_api_lisp_add_del_locator_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "locator_set_name");
    if (!item) goto error;
    strncpy_s((char *)a->locator_set_name, sizeof(a->locator_set_name), cJSON_GetStringValue(item), sizeof(a->locator_set_name) - 1);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "priority");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->priority);

    item = cJSON_GetObjectItem(o, "weight");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->weight);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_add_del_locator_reply_t *vl_api_lisp_add_del_locator_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_add_del_locator_reply_t);
    vl_api_lisp_add_del_locator_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_add_del_local_eid_t *vl_api_lisp_add_del_local_eid_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_add_del_local_eid_t);
    vl_api_lisp_add_del_local_eid_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "eid");
    if (!item) goto error;
    if (vl_api_eid_t_fromjson((void **)&a, &l, item, &a->eid) < 0) goto error;

    item = cJSON_GetObjectItem(o, "locator_set_name");
    if (!item) goto error;
    strncpy_s((char *)a->locator_set_name, sizeof(a->locator_set_name), cJSON_GetStringValue(item), sizeof(a->locator_set_name) - 1);

    item = cJSON_GetObjectItem(o, "vni");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vni);

    item = cJSON_GetObjectItem(o, "key");
    if (!item) goto error;
    if (vl_api_hmac_key_t_fromjson((void **)&a, &l, item, &a->key) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_add_del_local_eid_reply_t *vl_api_lisp_add_del_local_eid_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_add_del_local_eid_reply_t);
    vl_api_lisp_add_del_local_eid_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_add_del_map_server_t *vl_api_lisp_add_del_map_server_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_add_del_map_server_t);
    vl_api_lisp_add_del_map_server_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "ip_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->ip_address) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_add_del_map_server_reply_t *vl_api_lisp_add_del_map_server_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_add_del_map_server_reply_t);
    vl_api_lisp_add_del_map_server_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_add_del_map_resolver_t *vl_api_lisp_add_del_map_resolver_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_add_del_map_resolver_t);
    vl_api_lisp_add_del_map_resolver_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "ip_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->ip_address) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_add_del_map_resolver_reply_t *vl_api_lisp_add_del_map_resolver_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_add_del_map_resolver_reply_t);
    vl_api_lisp_add_del_map_resolver_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_enable_disable_t *vl_api_lisp_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_enable_disable_t);
    vl_api_lisp_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_enable_disable_reply_t *vl_api_lisp_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_enable_disable_reply_t);
    vl_api_lisp_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_pitr_set_locator_set_t *vl_api_lisp_pitr_set_locator_set_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_pitr_set_locator_set_t);
    vl_api_lisp_pitr_set_locator_set_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "ls_name");
    if (!item) goto error;
    strncpy_s((char *)a->ls_name, sizeof(a->ls_name), cJSON_GetStringValue(item), sizeof(a->ls_name) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_pitr_set_locator_set_reply_t *vl_api_lisp_pitr_set_locator_set_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_pitr_set_locator_set_reply_t);
    vl_api_lisp_pitr_set_locator_set_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_use_petr_t *vl_api_lisp_use_petr_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_use_petr_t);
    vl_api_lisp_use_petr_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "ip_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->ip_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_use_petr_reply_t *vl_api_lisp_use_petr_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_use_petr_reply_t);
    vl_api_lisp_use_petr_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_show_lisp_use_petr_t *vl_api_show_lisp_use_petr_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_lisp_use_petr_t);
    vl_api_show_lisp_use_petr_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_show_lisp_use_petr_reply_t *vl_api_show_lisp_use_petr_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_lisp_use_petr_reply_t);
    vl_api_show_lisp_use_petr_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "is_petr_enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_petr_enable);

    item = cJSON_GetObjectItem(o, "ip_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->ip_address) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_show_lisp_rloc_probe_state_t *vl_api_show_lisp_rloc_probe_state_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_lisp_rloc_probe_state_t);
    vl_api_show_lisp_rloc_probe_state_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_show_lisp_rloc_probe_state_reply_t *vl_api_show_lisp_rloc_probe_state_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_lisp_rloc_probe_state_reply_t);
    vl_api_show_lisp_rloc_probe_state_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "is_enabled");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_enabled);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_rloc_probe_enable_disable_t *vl_api_lisp_rloc_probe_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_rloc_probe_enable_disable_t);
    vl_api_lisp_rloc_probe_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_rloc_probe_enable_disable_reply_t *vl_api_lisp_rloc_probe_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_rloc_probe_enable_disable_reply_t);
    vl_api_lisp_rloc_probe_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_map_register_enable_disable_t *vl_api_lisp_map_register_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_map_register_enable_disable_t);
    vl_api_lisp_map_register_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_map_register_enable_disable_reply_t *vl_api_lisp_map_register_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_map_register_enable_disable_reply_t);
    vl_api_lisp_map_register_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_show_lisp_map_register_state_t *vl_api_show_lisp_map_register_state_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_lisp_map_register_state_t);
    vl_api_show_lisp_map_register_state_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_show_lisp_map_register_state_reply_t *vl_api_show_lisp_map_register_state_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_lisp_map_register_state_reply_t);
    vl_api_show_lisp_map_register_state_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "is_enabled");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_enabled);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_map_request_mode_t *vl_api_lisp_map_request_mode_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_map_request_mode_t);
    vl_api_lisp_map_request_mode_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_src_dst");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_src_dst);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_map_request_mode_reply_t *vl_api_lisp_map_request_mode_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_map_request_mode_reply_t);
    vl_api_lisp_map_request_mode_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_show_lisp_map_request_mode_t *vl_api_show_lisp_map_request_mode_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_lisp_map_request_mode_t);
    vl_api_show_lisp_map_request_mode_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_show_lisp_map_request_mode_reply_t *vl_api_show_lisp_map_request_mode_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_lisp_map_request_mode_reply_t);
    vl_api_show_lisp_map_request_mode_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "is_src_dst");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_src_dst);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_add_del_remote_mapping_t *vl_api_lisp_add_del_remote_mapping_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_add_del_remote_mapping_t);
    vl_api_lisp_add_del_remote_mapping_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "is_src_dst");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_src_dst);

    item = cJSON_GetObjectItem(o, "del_all");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->del_all);

    item = cJSON_GetObjectItem(o, "vni");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vni);

    item = cJSON_GetObjectItem(o, "action");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->action);

    item = cJSON_GetObjectItem(o, "deid");
    if (!item) goto error;
    if (vl_api_eid_t_fromjson((void **)&a, &l, item, &a->deid) < 0) goto error;

    item = cJSON_GetObjectItem(o, "seid");
    if (!item) goto error;
    if (vl_api_eid_t_fromjson((void **)&a, &l, item, &a->seid) < 0) goto error;

    item = cJSON_GetObjectItem(o, "rlocs");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "rlocs");
        int size = cJSON_GetArraySize(array);
        a->rloc_num = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_remote_locator_t) * size);
        vl_api_remote_locator_t *d = (void *)a + l;
        l += sizeof(vl_api_remote_locator_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_remote_locator_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_add_del_remote_mapping_reply_t *vl_api_lisp_add_del_remote_mapping_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_add_del_remote_mapping_reply_t);
    vl_api_lisp_add_del_remote_mapping_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_add_del_adjacency_t *vl_api_lisp_add_del_adjacency_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_add_del_adjacency_t);
    vl_api_lisp_add_del_adjacency_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "vni");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vni);

    item = cJSON_GetObjectItem(o, "reid");
    if (!item) goto error;
    if (vl_api_eid_t_fromjson((void **)&a, &l, item, &a->reid) < 0) goto error;

    item = cJSON_GetObjectItem(o, "leid");
    if (!item) goto error;
    if (vl_api_eid_t_fromjson((void **)&a, &l, item, &a->leid) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_add_del_adjacency_reply_t *vl_api_lisp_add_del_adjacency_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_add_del_adjacency_reply_t);
    vl_api_lisp_add_del_adjacency_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_add_del_map_request_itr_rlocs_t *vl_api_lisp_add_del_map_request_itr_rlocs_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_add_del_map_request_itr_rlocs_t);
    vl_api_lisp_add_del_map_request_itr_rlocs_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "locator_set_name");
    if (!item) goto error;
    strncpy_s((char *)a->locator_set_name, sizeof(a->locator_set_name), cJSON_GetStringValue(item), sizeof(a->locator_set_name) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_add_del_map_request_itr_rlocs_reply_t *vl_api_lisp_add_del_map_request_itr_rlocs_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_add_del_map_request_itr_rlocs_reply_t);
    vl_api_lisp_add_del_map_request_itr_rlocs_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_eid_table_add_del_map_t *vl_api_lisp_eid_table_add_del_map_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_eid_table_add_del_map_t);
    vl_api_lisp_eid_table_add_del_map_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "vni");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vni);

    item = cJSON_GetObjectItem(o, "dp_table");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->dp_table);

    item = cJSON_GetObjectItem(o, "is_l2");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_l2);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_eid_table_add_del_map_reply_t *vl_api_lisp_eid_table_add_del_map_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_eid_table_add_del_map_reply_t);
    vl_api_lisp_eid_table_add_del_map_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_locator_dump_t *vl_api_lisp_locator_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_locator_dump_t);
    vl_api_lisp_locator_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "ls_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ls_index);

    item = cJSON_GetObjectItem(o, "ls_name");
    if (!item) goto error;
    strncpy_s((char *)a->ls_name, sizeof(a->ls_name), cJSON_GetStringValue(item), sizeof(a->ls_name) - 1);

    item = cJSON_GetObjectItem(o, "is_index_set");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->is_index_set);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_locator_details_t *vl_api_lisp_locator_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_locator_details_t);
    vl_api_lisp_locator_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "local");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->local);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ip_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->ip_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "priority");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->priority);

    item = cJSON_GetObjectItem(o, "weight");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->weight);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_locator_set_details_t *vl_api_lisp_locator_set_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_locator_set_details_t);
    vl_api_lisp_locator_set_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "ls_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ls_index);

    item = cJSON_GetObjectItem(o, "ls_name");
    if (!item) goto error;
    strncpy_s((char *)a->ls_name, sizeof(a->ls_name), cJSON_GetStringValue(item), sizeof(a->ls_name) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_locator_set_dump_t *vl_api_lisp_locator_set_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_locator_set_dump_t);
    vl_api_lisp_locator_set_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "filter");
    if (!item) goto error;
    if (vl_api_lisp_locator_set_filter_t_fromjson((void **)&a, &l, item, &a->filter) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_eid_table_details_t *vl_api_lisp_eid_table_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_eid_table_details_t);
    vl_api_lisp_eid_table_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "locator_set_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->locator_set_index);

    item = cJSON_GetObjectItem(o, "action");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->action);

    item = cJSON_GetObjectItem(o, "is_local");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_local);

    item = cJSON_GetObjectItem(o, "is_src_dst");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_src_dst);

    item = cJSON_GetObjectItem(o, "vni");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vni);

    item = cJSON_GetObjectItem(o, "deid");
    if (!item) goto error;
    if (vl_api_eid_t_fromjson((void **)&a, &l, item, &a->deid) < 0) goto error;

    item = cJSON_GetObjectItem(o, "seid");
    if (!item) goto error;
    if (vl_api_eid_t_fromjson((void **)&a, &l, item, &a->seid) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ttl");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ttl);

    item = cJSON_GetObjectItem(o, "authoritative");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->authoritative);

    item = cJSON_GetObjectItem(o, "key");
    if (!item) goto error;
    if (vl_api_hmac_key_t_fromjson((void **)&a, &l, item, &a->key) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_eid_table_dump_t *vl_api_lisp_eid_table_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_eid_table_dump_t);
    vl_api_lisp_eid_table_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "eid_set");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->eid_set);

    item = cJSON_GetObjectItem(o, "prefix_length");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->prefix_length);

    item = cJSON_GetObjectItem(o, "vni");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vni);

    item = cJSON_GetObjectItem(o, "eid");
    if (!item) goto error;
    if (vl_api_eid_t_fromjson((void **)&a, &l, item, &a->eid) < 0) goto error;

    item = cJSON_GetObjectItem(o, "filter");
    if (!item) goto error;
    if (vl_api_lisp_locator_set_filter_t_fromjson((void **)&a, &l, item, &a->filter) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_adjacencies_get_reply_t *vl_api_lisp_adjacencies_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_adjacencies_get_reply_t);
    vl_api_lisp_adjacencies_get_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "adjacencies");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "adjacencies");
        int size = cJSON_GetArraySize(array);
        a->count = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_lisp_adjacency_t) * size);
        vl_api_lisp_adjacency_t *d = (void *)a + l;
        l += sizeof(vl_api_lisp_adjacency_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_lisp_adjacency_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_adjacencies_get_t *vl_api_lisp_adjacencies_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_adjacencies_get_t);
    vl_api_lisp_adjacencies_get_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "vni");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vni);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_eid_table_map_details_t *vl_api_lisp_eid_table_map_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_eid_table_map_details_t);
    vl_api_lisp_eid_table_map_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "vni");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vni);

    item = cJSON_GetObjectItem(o, "dp_table");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->dp_table);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_eid_table_map_dump_t *vl_api_lisp_eid_table_map_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_eid_table_map_dump_t);
    vl_api_lisp_eid_table_map_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_l2");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_l2);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_eid_table_vni_dump_t *vl_api_lisp_eid_table_vni_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_eid_table_vni_dump_t);
    vl_api_lisp_eid_table_vni_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_lisp_eid_table_vni_details_t *vl_api_lisp_eid_table_vni_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_eid_table_vni_details_t);
    vl_api_lisp_eid_table_vni_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "vni");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vni);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_map_resolver_details_t *vl_api_lisp_map_resolver_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_map_resolver_details_t);
    vl_api_lisp_map_resolver_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "ip_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->ip_address) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_map_resolver_dump_t *vl_api_lisp_map_resolver_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_map_resolver_dump_t);
    vl_api_lisp_map_resolver_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_lisp_map_server_details_t *vl_api_lisp_map_server_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_map_server_details_t);
    vl_api_lisp_map_server_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "ip_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->ip_address) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_map_server_dump_t *vl_api_lisp_map_server_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_map_server_dump_t);
    vl_api_lisp_map_server_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_show_lisp_status_t *vl_api_show_lisp_status_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_lisp_status_t);
    vl_api_show_lisp_status_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_show_lisp_status_reply_t *vl_api_show_lisp_status_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_lisp_status_reply_t);
    vl_api_show_lisp_status_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "is_lisp_enabled");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_lisp_enabled);

    item = cJSON_GetObjectItem(o, "is_gpe_enabled");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_gpe_enabled);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lisp_get_map_request_itr_rlocs_t *vl_api_lisp_get_map_request_itr_rlocs_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_get_map_request_itr_rlocs_t);
    vl_api_lisp_get_map_request_itr_rlocs_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_lisp_get_map_request_itr_rlocs_reply_t *vl_api_lisp_get_map_request_itr_rlocs_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lisp_get_map_request_itr_rlocs_reply_t);
    vl_api_lisp_get_map_request_itr_rlocs_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "locator_set_name");
    if (!item) goto error;
    strncpy_s((char *)a->locator_set_name, sizeof(a->locator_set_name), cJSON_GetStringValue(item), sizeof(a->locator_set_name) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_show_lisp_pitr_t *vl_api_show_lisp_pitr_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_lisp_pitr_t);
    vl_api_show_lisp_pitr_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_show_lisp_pitr_reply_t *vl_api_show_lisp_pitr_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_lisp_pitr_reply_t);
    vl_api_show_lisp_pitr_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "is_enabled");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_enabled);

    item = cJSON_GetObjectItem(o, "locator_set_name");
    if (!item) goto error;
    strncpy_s((char *)a->locator_set_name, sizeof(a->locator_set_name), cJSON_GetStringValue(item), sizeof(a->locator_set_name) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
