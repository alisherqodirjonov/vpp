/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <lisp/lisp-cp/lisp_types.api_fromjson.h>
#ifndef included_one_api_fromjson_h
#define included_one_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_one_map_mode_t_fromjson(void **mp, int *len, cJSON *o, vl_api_one_map_mode_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "ONE_MAP_MODE_API_DST_ONLY") == 0) {*a = 0; return 0;}
    if (strcmp(p, "ONE_MAP_MODE_API_SRC_DST") == 0) {*a = 1; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_one_l2_arp_entry_t_fromjson (void **mp, int *len, cJSON *o, vl_api_one_l2_arp_entry_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "mac");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson(mp, len, item, &a->mac) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ip4");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson(mp, len, item, &a->ip4) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_one_ndp_entry_t_fromjson (void **mp, int *len, cJSON *o, vl_api_one_ndp_entry_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "mac");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson(mp, len, item, &a->mac) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ip6");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson(mp, len, item, &a->ip6) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_one_filter_t_fromjson(void **mp, int *len, cJSON *o, vl_api_one_filter_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "ONE_FILTER_API_ALL") == 0) {*a = 0; return 0;}
    if (strcmp(p, "ONE_FILTER_API_LOCAL") == 0) {*a = 1; return 0;}
    if (strcmp(p, "ONE_FILTER_API_REMOTE") == 0) {*a = 2; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_one_adjacency_t_fromjson (void **mp, int *len, cJSON *o, vl_api_one_adjacency_t *a) {
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
static inline vl_api_one_add_del_locator_set_t *vl_api_one_add_del_locator_set_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_add_del_locator_set_t);
    vl_api_one_add_del_locator_set_t *a = cJSON_malloc(l);

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
static inline vl_api_one_add_del_locator_set_reply_t *vl_api_one_add_del_locator_set_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_add_del_locator_set_reply_t);
    vl_api_one_add_del_locator_set_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_one_add_del_locator_t *vl_api_one_add_del_locator_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_add_del_locator_t);
    vl_api_one_add_del_locator_t *a = cJSON_malloc(l);

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
static inline vl_api_one_add_del_locator_reply_t *vl_api_one_add_del_locator_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_add_del_locator_reply_t);
    vl_api_one_add_del_locator_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_add_del_local_eid_t *vl_api_one_add_del_local_eid_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_add_del_local_eid_t);
    vl_api_one_add_del_local_eid_t *a = cJSON_malloc(l);

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
static inline vl_api_one_add_del_local_eid_reply_t *vl_api_one_add_del_local_eid_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_add_del_local_eid_reply_t);
    vl_api_one_add_del_local_eid_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_map_register_set_ttl_t *vl_api_one_map_register_set_ttl_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_map_register_set_ttl_t);
    vl_api_one_map_register_set_ttl_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "ttl");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ttl);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_map_register_set_ttl_reply_t *vl_api_one_map_register_set_ttl_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_map_register_set_ttl_reply_t);
    vl_api_one_map_register_set_ttl_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_show_one_map_register_ttl_t *vl_api_show_one_map_register_ttl_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_one_map_register_ttl_t);
    vl_api_show_one_map_register_ttl_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_show_one_map_register_ttl_reply_t *vl_api_show_one_map_register_ttl_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_one_map_register_ttl_reply_t);
    vl_api_show_one_map_register_ttl_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "ttl");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ttl);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_add_del_map_server_t *vl_api_one_add_del_map_server_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_add_del_map_server_t);
    vl_api_one_add_del_map_server_t *a = cJSON_malloc(l);

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
static inline vl_api_one_add_del_map_server_reply_t *vl_api_one_add_del_map_server_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_add_del_map_server_reply_t);
    vl_api_one_add_del_map_server_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_add_del_map_resolver_t *vl_api_one_add_del_map_resolver_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_add_del_map_resolver_t);
    vl_api_one_add_del_map_resolver_t *a = cJSON_malloc(l);

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
static inline vl_api_one_add_del_map_resolver_reply_t *vl_api_one_add_del_map_resolver_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_add_del_map_resolver_reply_t);
    vl_api_one_add_del_map_resolver_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_enable_disable_t *vl_api_one_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_enable_disable_t);
    vl_api_one_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_enable_disable_reply_t *vl_api_one_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_enable_disable_reply_t);
    vl_api_one_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_nsh_set_locator_set_t *vl_api_one_nsh_set_locator_set_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_nsh_set_locator_set_t);
    vl_api_one_nsh_set_locator_set_t *a = cJSON_malloc(l);

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
static inline vl_api_one_nsh_set_locator_set_reply_t *vl_api_one_nsh_set_locator_set_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_nsh_set_locator_set_reply_t);
    vl_api_one_nsh_set_locator_set_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_pitr_set_locator_set_t *vl_api_one_pitr_set_locator_set_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_pitr_set_locator_set_t);
    vl_api_one_pitr_set_locator_set_t *a = cJSON_malloc(l);

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
static inline vl_api_one_pitr_set_locator_set_reply_t *vl_api_one_pitr_set_locator_set_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_pitr_set_locator_set_reply_t);
    vl_api_one_pitr_set_locator_set_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_use_petr_t *vl_api_one_use_petr_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_use_petr_t);
    vl_api_one_use_petr_t *a = cJSON_malloc(l);

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
static inline vl_api_one_use_petr_reply_t *vl_api_one_use_petr_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_use_petr_reply_t);
    vl_api_one_use_petr_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_show_one_use_petr_t *vl_api_show_one_use_petr_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_one_use_petr_t);
    vl_api_show_one_use_petr_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_show_one_use_petr_reply_t *vl_api_show_one_use_petr_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_one_use_petr_reply_t);
    vl_api_show_one_use_petr_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "status");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->status);

    item = cJSON_GetObjectItem(o, "ip_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->ip_address) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_show_one_rloc_probe_state_t *vl_api_show_one_rloc_probe_state_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_one_rloc_probe_state_t);
    vl_api_show_one_rloc_probe_state_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_show_one_rloc_probe_state_reply_t *vl_api_show_one_rloc_probe_state_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_one_rloc_probe_state_reply_t);
    vl_api_show_one_rloc_probe_state_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "is_enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_rloc_probe_enable_disable_t *vl_api_one_rloc_probe_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_rloc_probe_enable_disable_t);
    vl_api_one_rloc_probe_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_rloc_probe_enable_disable_reply_t *vl_api_one_rloc_probe_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_rloc_probe_enable_disable_reply_t);
    vl_api_one_rloc_probe_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_map_register_enable_disable_t *vl_api_one_map_register_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_map_register_enable_disable_t);
    vl_api_one_map_register_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_map_register_enable_disable_reply_t *vl_api_one_map_register_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_map_register_enable_disable_reply_t);
    vl_api_one_map_register_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_show_one_map_register_state_t *vl_api_show_one_map_register_state_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_one_map_register_state_t);
    vl_api_show_one_map_register_state_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_show_one_map_register_state_reply_t *vl_api_show_one_map_register_state_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_one_map_register_state_reply_t);
    vl_api_show_one_map_register_state_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "is_enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_map_request_mode_t *vl_api_one_map_request_mode_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_map_request_mode_t);
    vl_api_one_map_request_mode_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "mode");
    if (!item) goto error;
    if (vl_api_one_map_mode_t_fromjson((void **)&a, &l, item, &a->mode) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_map_request_mode_reply_t *vl_api_one_map_request_mode_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_map_request_mode_reply_t);
    vl_api_one_map_request_mode_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_show_one_map_request_mode_t *vl_api_show_one_map_request_mode_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_one_map_request_mode_t);
    vl_api_show_one_map_request_mode_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_show_one_map_request_mode_reply_t *vl_api_show_one_map_request_mode_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_one_map_request_mode_reply_t);
    vl_api_show_one_map_request_mode_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "mode");
    if (!item) goto error;
    if (vl_api_one_map_mode_t_fromjson((void **)&a, &l, item, &a->mode) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_add_del_remote_mapping_t *vl_api_one_add_del_remote_mapping_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_add_del_remote_mapping_t);
    vl_api_one_add_del_remote_mapping_t *a = cJSON_malloc(l);

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
static inline vl_api_one_add_del_remote_mapping_reply_t *vl_api_one_add_del_remote_mapping_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_add_del_remote_mapping_reply_t);
    vl_api_one_add_del_remote_mapping_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_add_del_l2_arp_entry_t *vl_api_one_add_del_l2_arp_entry_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_add_del_l2_arp_entry_t);
    vl_api_one_add_del_l2_arp_entry_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "bd");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bd);

    item = cJSON_GetObjectItem(o, "entry");
    if (!item) goto error;
    if (vl_api_one_l2_arp_entry_t_fromjson((void **)&a, &l, item, &a->entry) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_add_del_l2_arp_entry_reply_t *vl_api_one_add_del_l2_arp_entry_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_add_del_l2_arp_entry_reply_t);
    vl_api_one_add_del_l2_arp_entry_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_l2_arp_entries_get_t *vl_api_one_l2_arp_entries_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_l2_arp_entries_get_t);
    vl_api_one_l2_arp_entries_get_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bd");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bd);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_l2_arp_entries_get_reply_t *vl_api_one_l2_arp_entries_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_l2_arp_entries_get_reply_t);
    vl_api_one_l2_arp_entries_get_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "entries");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "entries");
        int size = cJSON_GetArraySize(array);
        a->count = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_one_l2_arp_entry_t) * size);
        vl_api_one_l2_arp_entry_t *d = (void *)a + l;
        l += sizeof(vl_api_one_l2_arp_entry_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_one_l2_arp_entry_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_add_del_ndp_entry_t *vl_api_one_add_del_ndp_entry_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_add_del_ndp_entry_t);
    vl_api_one_add_del_ndp_entry_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "bd");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bd);

    item = cJSON_GetObjectItem(o, "entry");
    if (!item) goto error;
    if (vl_api_one_ndp_entry_t_fromjson((void **)&a, &l, item, &a->entry) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_add_del_ndp_entry_reply_t *vl_api_one_add_del_ndp_entry_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_add_del_ndp_entry_reply_t);
    vl_api_one_add_del_ndp_entry_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_ndp_entries_get_t *vl_api_one_ndp_entries_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_ndp_entries_get_t);
    vl_api_one_ndp_entries_get_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bd");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bd);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_ndp_entries_get_reply_t *vl_api_one_ndp_entries_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_ndp_entries_get_reply_t);
    vl_api_one_ndp_entries_get_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "entries");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "entries");
        int size = cJSON_GetArraySize(array);
        a->count = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_one_ndp_entry_t) * size);
        vl_api_one_ndp_entry_t *d = (void *)a + l;
        l += sizeof(vl_api_one_ndp_entry_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_one_ndp_entry_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_set_transport_protocol_t *vl_api_one_set_transport_protocol_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_set_transport_protocol_t);
    vl_api_one_set_transport_protocol_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->protocol);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_set_transport_protocol_reply_t *vl_api_one_set_transport_protocol_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_set_transport_protocol_reply_t);
    vl_api_one_set_transport_protocol_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_get_transport_protocol_t *vl_api_one_get_transport_protocol_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_get_transport_protocol_t);
    vl_api_one_get_transport_protocol_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_one_get_transport_protocol_reply_t *vl_api_one_get_transport_protocol_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_get_transport_protocol_reply_t);
    vl_api_one_get_transport_protocol_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->protocol);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_ndp_bd_get_t *vl_api_one_ndp_bd_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_ndp_bd_get_t);
    vl_api_one_ndp_bd_get_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_one_ndp_bd_get_reply_t *vl_api_one_ndp_bd_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_ndp_bd_get_reply_t);
    vl_api_one_ndp_bd_get_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "bridge_domains");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "bridge_domains");
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
static inline vl_api_one_l2_arp_bd_get_t *vl_api_one_l2_arp_bd_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_l2_arp_bd_get_t);
    vl_api_one_l2_arp_bd_get_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_one_l2_arp_bd_get_reply_t *vl_api_one_l2_arp_bd_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_l2_arp_bd_get_reply_t);
    vl_api_one_l2_arp_bd_get_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "bridge_domains");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "bridge_domains");
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
static inline vl_api_one_add_del_adjacency_t *vl_api_one_add_del_adjacency_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_add_del_adjacency_t);
    vl_api_one_add_del_adjacency_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->is_add);

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
static inline vl_api_one_add_del_adjacency_reply_t *vl_api_one_add_del_adjacency_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_add_del_adjacency_reply_t);
    vl_api_one_add_del_adjacency_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_add_del_map_request_itr_rlocs_t *vl_api_one_add_del_map_request_itr_rlocs_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_add_del_map_request_itr_rlocs_t);
    vl_api_one_add_del_map_request_itr_rlocs_t *a = cJSON_malloc(l);

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
static inline vl_api_one_add_del_map_request_itr_rlocs_reply_t *vl_api_one_add_del_map_request_itr_rlocs_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_add_del_map_request_itr_rlocs_reply_t);
    vl_api_one_add_del_map_request_itr_rlocs_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_eid_table_add_del_map_t *vl_api_one_eid_table_add_del_map_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_eid_table_add_del_map_t);
    vl_api_one_eid_table_add_del_map_t *a = cJSON_malloc(l);

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
static inline vl_api_one_eid_table_add_del_map_reply_t *vl_api_one_eid_table_add_del_map_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_eid_table_add_del_map_reply_t);
    vl_api_one_eid_table_add_del_map_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_locator_dump_t *vl_api_one_locator_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_locator_dump_t);
    vl_api_one_locator_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "ls_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ls_index);

    item = cJSON_GetObjectItem(o, "ls_name");
    if (!item) goto error;
    strncpy_s((char *)a->ls_name, sizeof(a->ls_name), cJSON_GetStringValue(item), sizeof(a->ls_name) - 1);

    item = cJSON_GetObjectItem(o, "is_index_set");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_index_set);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_locator_details_t *vl_api_one_locator_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_locator_details_t);
    vl_api_one_locator_details_t *a = cJSON_malloc(l);

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
static inline vl_api_one_locator_set_details_t *vl_api_one_locator_set_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_locator_set_details_t);
    vl_api_one_locator_set_details_t *a = cJSON_malloc(l);

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
static inline vl_api_one_locator_set_dump_t *vl_api_one_locator_set_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_locator_set_dump_t);
    vl_api_one_locator_set_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "filter");
    if (!item) goto error;
    if (vl_api_one_filter_t_fromjson((void **)&a, &l, item, &a->filter) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_eid_table_details_t *vl_api_one_eid_table_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_eid_table_details_t);
    vl_api_one_eid_table_details_t *a = cJSON_malloc(l);

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
static inline vl_api_one_eid_table_dump_t *vl_api_one_eid_table_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_eid_table_dump_t);
    vl_api_one_eid_table_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "eid_set");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->eid_set);

    item = cJSON_GetObjectItem(o, "vni");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vni);

    item = cJSON_GetObjectItem(o, "eid");
    if (!item) goto error;
    if (vl_api_eid_t_fromjson((void **)&a, &l, item, &a->eid) < 0) goto error;

    item = cJSON_GetObjectItem(o, "filter");
    if (!item) goto error;
    if (vl_api_one_filter_t_fromjson((void **)&a, &l, item, &a->filter) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_adjacencies_get_reply_t *vl_api_one_adjacencies_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_adjacencies_get_reply_t);
    vl_api_one_adjacencies_get_reply_t *a = cJSON_malloc(l);

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
        a = cJSON_realloc(a, l + sizeof(vl_api_one_adjacency_t) * size);
        vl_api_one_adjacency_t *d = (void *)a + l;
        l += sizeof(vl_api_one_adjacency_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_one_adjacency_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_adjacencies_get_t *vl_api_one_adjacencies_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_adjacencies_get_t);
    vl_api_one_adjacencies_get_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "vni");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vni);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_eid_table_map_details_t *vl_api_one_eid_table_map_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_eid_table_map_details_t);
    vl_api_one_eid_table_map_details_t *a = cJSON_malloc(l);

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
static inline vl_api_one_eid_table_map_dump_t *vl_api_one_eid_table_map_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_eid_table_map_dump_t);
    vl_api_one_eid_table_map_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_l2");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_l2);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_eid_table_vni_dump_t *vl_api_one_eid_table_vni_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_eid_table_vni_dump_t);
    vl_api_one_eid_table_vni_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_one_eid_table_vni_details_t *vl_api_one_eid_table_vni_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_eid_table_vni_details_t);
    vl_api_one_eid_table_vni_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "vni");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vni);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_map_resolver_details_t *vl_api_one_map_resolver_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_map_resolver_details_t);
    vl_api_one_map_resolver_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "ip_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->ip_address) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_map_resolver_dump_t *vl_api_one_map_resolver_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_map_resolver_dump_t);
    vl_api_one_map_resolver_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_one_map_server_details_t *vl_api_one_map_server_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_map_server_details_t);
    vl_api_one_map_server_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "ip_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->ip_address) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_map_server_dump_t *vl_api_one_map_server_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_map_server_dump_t);
    vl_api_one_map_server_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_show_one_status_t *vl_api_show_one_status_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_one_status_t);
    vl_api_show_one_status_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_show_one_status_reply_t *vl_api_show_one_status_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_one_status_reply_t);
    vl_api_show_one_status_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "feature_status");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->feature_status);

    item = cJSON_GetObjectItem(o, "gpe_status");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->gpe_status);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_get_map_request_itr_rlocs_t *vl_api_one_get_map_request_itr_rlocs_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_get_map_request_itr_rlocs_t);
    vl_api_one_get_map_request_itr_rlocs_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_one_get_map_request_itr_rlocs_reply_t *vl_api_one_get_map_request_itr_rlocs_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_get_map_request_itr_rlocs_reply_t);
    vl_api_one_get_map_request_itr_rlocs_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_show_one_nsh_mapping_t *vl_api_show_one_nsh_mapping_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_one_nsh_mapping_t);
    vl_api_show_one_nsh_mapping_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_show_one_nsh_mapping_reply_t *vl_api_show_one_nsh_mapping_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_one_nsh_mapping_reply_t);
    vl_api_show_one_nsh_mapping_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "is_set");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_set);

    item = cJSON_GetObjectItem(o, "locator_set_name");
    if (!item) goto error;
    strncpy_s((char *)a->locator_set_name, sizeof(a->locator_set_name), cJSON_GetStringValue(item), sizeof(a->locator_set_name) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_show_one_pitr_t *vl_api_show_one_pitr_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_one_pitr_t);
    vl_api_show_one_pitr_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_show_one_pitr_reply_t *vl_api_show_one_pitr_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_one_pitr_reply_t);
    vl_api_show_one_pitr_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "status");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->status);

    item = cJSON_GetObjectItem(o, "locator_set_name");
    if (!item) goto error;
    strncpy_s((char *)a->locator_set_name, sizeof(a->locator_set_name), cJSON_GetStringValue(item), sizeof(a->locator_set_name) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_stats_dump_t *vl_api_one_stats_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_stats_dump_t);
    vl_api_one_stats_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_one_stats_details_t *vl_api_one_stats_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_stats_details_t);
    vl_api_one_stats_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "vni");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vni);

    item = cJSON_GetObjectItem(o, "deid");
    if (!item) goto error;
    if (vl_api_eid_t_fromjson((void **)&a, &l, item, &a->deid) < 0) goto error;

    item = cJSON_GetObjectItem(o, "seid");
    if (!item) goto error;
    if (vl_api_eid_t_fromjson((void **)&a, &l, item, &a->seid) < 0) goto error;

    item = cJSON_GetObjectItem(o, "rloc");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->rloc) < 0) goto error;

    item = cJSON_GetObjectItem(o, "lloc");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->lloc) < 0) goto error;

    item = cJSON_GetObjectItem(o, "pkt_count");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->pkt_count);

    item = cJSON_GetObjectItem(o, "bytes");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bytes);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_stats_flush_t *vl_api_one_stats_flush_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_stats_flush_t);
    vl_api_one_stats_flush_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_one_stats_flush_reply_t *vl_api_one_stats_flush_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_stats_flush_reply_t);
    vl_api_one_stats_flush_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_stats_enable_disable_t *vl_api_one_stats_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_stats_enable_disable_t);
    vl_api_one_stats_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_stats_enable_disable_reply_t *vl_api_one_stats_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_stats_enable_disable_reply_t);
    vl_api_one_stats_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_show_one_stats_enable_disable_t *vl_api_show_one_stats_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_one_stats_enable_disable_t);
    vl_api_show_one_stats_enable_disable_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_show_one_stats_enable_disable_reply_t *vl_api_show_one_stats_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_one_stats_enable_disable_reply_t);
    vl_api_show_one_stats_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "is_enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_map_register_fallback_threshold_t *vl_api_one_map_register_fallback_threshold_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_map_register_fallback_threshold_t);
    vl_api_one_map_register_fallback_threshold_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "value");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->value);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_map_register_fallback_threshold_reply_t *vl_api_one_map_register_fallback_threshold_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_map_register_fallback_threshold_reply_t);
    vl_api_one_map_register_fallback_threshold_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_show_one_map_register_fallback_threshold_t *vl_api_show_one_map_register_fallback_threshold_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_one_map_register_fallback_threshold_t);
    vl_api_show_one_map_register_fallback_threshold_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_show_one_map_register_fallback_threshold_reply_t *vl_api_show_one_map_register_fallback_threshold_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_one_map_register_fallback_threshold_reply_t);
    vl_api_show_one_map_register_fallback_threshold_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "value");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->value);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_enable_disable_xtr_mode_t *vl_api_one_enable_disable_xtr_mode_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_enable_disable_xtr_mode_t);
    vl_api_one_enable_disable_xtr_mode_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_enable_disable_xtr_mode_reply_t *vl_api_one_enable_disable_xtr_mode_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_enable_disable_xtr_mode_reply_t);
    vl_api_one_enable_disable_xtr_mode_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_show_xtr_mode_t *vl_api_one_show_xtr_mode_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_show_xtr_mode_t);
    vl_api_one_show_xtr_mode_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_one_show_xtr_mode_reply_t *vl_api_one_show_xtr_mode_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_show_xtr_mode_reply_t);
    vl_api_one_show_xtr_mode_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "is_enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_enable_disable_petr_mode_t *vl_api_one_enable_disable_petr_mode_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_enable_disable_petr_mode_t);
    vl_api_one_enable_disable_petr_mode_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_enable_disable_petr_mode_reply_t *vl_api_one_enable_disable_petr_mode_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_enable_disable_petr_mode_reply_t);
    vl_api_one_enable_disable_petr_mode_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_show_petr_mode_t *vl_api_one_show_petr_mode_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_show_petr_mode_t);
    vl_api_one_show_petr_mode_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_one_show_petr_mode_reply_t *vl_api_one_show_petr_mode_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_show_petr_mode_reply_t);
    vl_api_one_show_petr_mode_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "is_enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_enable_disable_pitr_mode_t *vl_api_one_enable_disable_pitr_mode_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_enable_disable_pitr_mode_t);
    vl_api_one_enable_disable_pitr_mode_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_enable_disable_pitr_mode_reply_t *vl_api_one_enable_disable_pitr_mode_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_enable_disable_pitr_mode_reply_t);
    vl_api_one_enable_disable_pitr_mode_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_one_show_pitr_mode_t *vl_api_one_show_pitr_mode_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_show_pitr_mode_t);
    vl_api_one_show_pitr_mode_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_one_show_pitr_mode_reply_t *vl_api_one_show_pitr_mode_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_one_show_pitr_mode_reply_t);
    vl_api_one_show_pitr_mode_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "is_enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
