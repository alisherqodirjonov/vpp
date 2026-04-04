/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <lisp/lisp-cp/lisp_types.api_fromjson.h>
#ifndef included_lisp_gpe_api_fromjson_h
#define included_lisp_gpe_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_gpe_locator_t_fromjson (void **mp, int *len, cJSON *o, vl_api_gpe_locator_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "weight");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->weight);

    item = cJSON_GetObjectItem(o, "addr");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->addr) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_gpe_fwd_entry_t_fromjson (void **mp, int *len, cJSON *o, vl_api_gpe_fwd_entry_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "fwd_entry_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->fwd_entry_index);

    item = cJSON_GetObjectItem(o, "dp_table");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->dp_table);

    item = cJSON_GetObjectItem(o, "leid");
    if (!item) goto error;
    if (vl_api_eid_t_fromjson(mp, len, item, &a->leid) < 0) goto error;

    item = cJSON_GetObjectItem(o, "reid");
    if (!item) goto error;
    if (vl_api_eid_t_fromjson(mp, len, item, &a->reid) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vni");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vni);

    item = cJSON_GetObjectItem(o, "action");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->action);

    return 0;

  error:
    return -1;
}
static inline int vl_api_gpe_native_fwd_rpath_t_fromjson (void **mp, int *len, cJSON *o, vl_api_gpe_native_fwd_rpath_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "fib_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->fib_index);

    item = cJSON_GetObjectItem(o, "nh_sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson(mp, len, item, &a->nh_sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "nh_addr");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->nh_addr) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline vl_api_gpe_add_del_fwd_entry_t *vl_api_gpe_add_del_fwd_entry_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gpe_add_del_fwd_entry_t);
    vl_api_gpe_add_del_fwd_entry_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "rmt_eid");
    if (!item) goto error;
    if (vl_api_eid_t_fromjson((void **)&a, &l, item, &a->rmt_eid) < 0) goto error;

    item = cJSON_GetObjectItem(o, "lcl_eid");
    if (!item) goto error;
    if (vl_api_eid_t_fromjson((void **)&a, &l, item, &a->lcl_eid) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vni");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vni);

    item = cJSON_GetObjectItem(o, "dp_table");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->dp_table);

    item = cJSON_GetObjectItem(o, "action");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->action);

    item = cJSON_GetObjectItem(o, "locs");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "locs");
        int size = cJSON_GetArraySize(array);
        a->loc_num = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_gpe_locator_t) * size);
        vl_api_gpe_locator_t *d = (void *)a + l;
        l += sizeof(vl_api_gpe_locator_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_gpe_locator_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_gpe_add_del_fwd_entry_reply_t *vl_api_gpe_add_del_fwd_entry_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gpe_add_del_fwd_entry_reply_t);
    vl_api_gpe_add_del_fwd_entry_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "fwd_entry_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->fwd_entry_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_gpe_enable_disable_t *vl_api_gpe_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gpe_enable_disable_t);
    vl_api_gpe_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_gpe_enable_disable_reply_t *vl_api_gpe_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gpe_enable_disable_reply_t);
    vl_api_gpe_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_gpe_add_del_iface_t *vl_api_gpe_add_del_iface_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gpe_add_del_iface_t);
    vl_api_gpe_add_del_iface_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "is_l2");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_l2);

    item = cJSON_GetObjectItem(o, "dp_table");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->dp_table);

    item = cJSON_GetObjectItem(o, "vni");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vni);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_gpe_add_del_iface_reply_t *vl_api_gpe_add_del_iface_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gpe_add_del_iface_reply_t);
    vl_api_gpe_add_del_iface_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_gpe_fwd_entry_vnis_get_t *vl_api_gpe_fwd_entry_vnis_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gpe_fwd_entry_vnis_get_t);
    vl_api_gpe_fwd_entry_vnis_get_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_gpe_fwd_entry_vnis_get_reply_t *vl_api_gpe_fwd_entry_vnis_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gpe_fwd_entry_vnis_get_reply_t);
    vl_api_gpe_fwd_entry_vnis_get_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "vnis");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "vnis");
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
static inline vl_api_gpe_fwd_entries_get_t *vl_api_gpe_fwd_entries_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gpe_fwd_entries_get_t);
    vl_api_gpe_fwd_entries_get_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "vni");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vni);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_gpe_fwd_entries_get_reply_t *vl_api_gpe_fwd_entries_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gpe_fwd_entries_get_reply_t);
    vl_api_gpe_fwd_entries_get_reply_t *a = cJSON_malloc(l);

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
        a = cJSON_realloc(a, l + sizeof(vl_api_gpe_fwd_entry_t) * size);
        vl_api_gpe_fwd_entry_t *d = (void *)a + l;
        l += sizeof(vl_api_gpe_fwd_entry_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_gpe_fwd_entry_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_gpe_fwd_entry_path_dump_t *vl_api_gpe_fwd_entry_path_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gpe_fwd_entry_path_dump_t);
    vl_api_gpe_fwd_entry_path_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "fwd_entry_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->fwd_entry_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_gpe_fwd_entry_path_details_t *vl_api_gpe_fwd_entry_path_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gpe_fwd_entry_path_details_t);
    vl_api_gpe_fwd_entry_path_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "lcl_loc");
    if (!item) goto error;
    if (vl_api_gpe_locator_t_fromjson((void **)&a, &l, item, &a->lcl_loc) < 0) goto error;

    item = cJSON_GetObjectItem(o, "rmt_loc");
    if (!item) goto error;
    if (vl_api_gpe_locator_t_fromjson((void **)&a, &l, item, &a->rmt_loc) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_gpe_set_encap_mode_t *vl_api_gpe_set_encap_mode_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gpe_set_encap_mode_t);
    vl_api_gpe_set_encap_mode_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_vxlan");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_vxlan);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_gpe_set_encap_mode_reply_t *vl_api_gpe_set_encap_mode_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gpe_set_encap_mode_reply_t);
    vl_api_gpe_set_encap_mode_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_gpe_get_encap_mode_t *vl_api_gpe_get_encap_mode_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gpe_get_encap_mode_t);
    vl_api_gpe_get_encap_mode_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_gpe_get_encap_mode_reply_t *vl_api_gpe_get_encap_mode_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gpe_get_encap_mode_reply_t);
    vl_api_gpe_get_encap_mode_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "encap_mode");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->encap_mode);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_gpe_add_del_native_fwd_rpath_t *vl_api_gpe_add_del_native_fwd_rpath_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gpe_add_del_native_fwd_rpath_t);
    vl_api_gpe_add_del_native_fwd_rpath_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_id);

    item = cJSON_GetObjectItem(o, "nh_sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->nh_sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "nh_addr");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->nh_addr) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_gpe_add_del_native_fwd_rpath_reply_t *vl_api_gpe_add_del_native_fwd_rpath_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gpe_add_del_native_fwd_rpath_reply_t);
    vl_api_gpe_add_del_native_fwd_rpath_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_gpe_native_fwd_rpaths_get_t *vl_api_gpe_native_fwd_rpaths_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gpe_native_fwd_rpaths_get_t);
    vl_api_gpe_native_fwd_rpaths_get_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_ip4");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_ip4);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_gpe_native_fwd_rpaths_get_reply_t *vl_api_gpe_native_fwd_rpaths_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gpe_native_fwd_rpaths_get_reply_t);
    vl_api_gpe_native_fwd_rpaths_get_reply_t *a = cJSON_malloc(l);

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
        a = cJSON_realloc(a, l + sizeof(vl_api_gpe_native_fwd_rpath_t) * size);
        vl_api_gpe_native_fwd_rpath_t *d = (void *)a + l;
        l += sizeof(vl_api_gpe_native_fwd_rpath_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_gpe_native_fwd_rpath_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
