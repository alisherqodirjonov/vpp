/* Imported API files */
#include <vnet/fib/fib_types.api_fromjson.h>
#ifndef included_bier_api_fromjson_h
#define included_bier_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_bier_table_id_t_fromjson (void **mp, int *len, cJSON *o, vl_api_bier_table_id_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "bt_set");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->bt_set);

    item = cJSON_GetObjectItem(o, "bt_sub_domain");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->bt_sub_domain);

    item = cJSON_GetObjectItem(o, "bt_hdr_len_id");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->bt_hdr_len_id);

    return 0;

  error:
    return -1;
}
static inline int vl_api_bier_route_t_fromjson (void **mp, int *len, cJSON *o, vl_api_bier_route_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "br_bp");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->br_bp);

    item = cJSON_GetObjectItem(o, "br_tbl_id");
    if (!item) goto error;
    if (vl_api_bier_table_id_t_fromjson(mp, len, item, &a->br_tbl_id) < 0) goto error;

    item = cJSON_GetObjectItem(o, "br_paths");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "br_paths");
        int size = cJSON_GetArraySize(array);
        a->br_n_paths = size;
        *mp = cJSON_realloc(*mp, *len + sizeof(vl_api_fib_path_t) * size);
        vl_api_fib_path_t *d = (void *)*mp + *len;
        *len += sizeof(vl_api_fib_path_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_fib_path_t_fromjson(mp, len, e, &d[i]) < 0) goto error; 
        }
    }

    return 0;

  error:
    return -1;
}
static inline vl_api_bier_table_add_del_t *vl_api_bier_table_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bier_table_add_del_t);
    vl_api_bier_table_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bt_tbl_id");
    if (!item) goto error;
    if (vl_api_bier_table_id_t_fromjson((void **)&a, &l, item, &a->bt_tbl_id) < 0) goto error;

    item = cJSON_GetObjectItem(o, "bt_label");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bt_label);

    item = cJSON_GetObjectItem(o, "bt_is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->bt_is_add);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bier_table_add_del_reply_t *vl_api_bier_table_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bier_table_add_del_reply_t);
    vl_api_bier_table_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bier_table_dump_t *vl_api_bier_table_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bier_table_dump_t);
    vl_api_bier_table_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_bier_table_details_t *vl_api_bier_table_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bier_table_details_t);
    vl_api_bier_table_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bt_label");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bt_label);

    item = cJSON_GetObjectItem(o, "bt_tbl_id");
    if (!item) goto error;
    if (vl_api_bier_table_id_t_fromjson((void **)&a, &l, item, &a->bt_tbl_id) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bier_route_add_del_t *vl_api_bier_route_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bier_route_add_del_t);
    vl_api_bier_route_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "br_is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->br_is_add);

    item = cJSON_GetObjectItem(o, "br_is_replace");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->br_is_replace);

    item = cJSON_GetObjectItem(o, "br_route");
    if (!item) goto error;
    if (vl_api_bier_route_t_fromjson((void **)&a, &l, item, &a->br_route) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bier_route_add_del_reply_t *vl_api_bier_route_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bier_route_add_del_reply_t);
    vl_api_bier_route_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bier_route_dump_t *vl_api_bier_route_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bier_route_dump_t);
    vl_api_bier_route_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "br_tbl_id");
    if (!item) goto error;
    if (vl_api_bier_table_id_t_fromjson((void **)&a, &l, item, &a->br_tbl_id) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bier_route_details_t *vl_api_bier_route_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bier_route_details_t);
    vl_api_bier_route_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "br_route");
    if (!item) goto error;
    if (vl_api_bier_route_t_fromjson((void **)&a, &l, item, &a->br_route) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bier_imp_add_t *vl_api_bier_imp_add_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bier_imp_add_t);
    vl_api_bier_imp_add_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bi_tbl_id");
    if (!item) goto error;
    if (vl_api_bier_table_id_t_fromjson((void **)&a, &l, item, &a->bi_tbl_id) < 0) goto error;

    item = cJSON_GetObjectItem(o, "bi_src");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->bi_src);

    item = cJSON_GetObjectItem(o, "bi_bytes");
    if (!item) goto error;
    s = u8string_fromjson(o, "bi_bytes");
    if (!s) goto error;
    a->bi_n_bytes = vec_len(s);
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
static inline vl_api_bier_imp_add_reply_t *vl_api_bier_imp_add_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bier_imp_add_reply_t);
    vl_api_bier_imp_add_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "bi_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bi_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bier_imp_del_t *vl_api_bier_imp_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bier_imp_del_t);
    vl_api_bier_imp_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bi_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bi_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bier_imp_del_reply_t *vl_api_bier_imp_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bier_imp_del_reply_t);
    vl_api_bier_imp_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bier_imp_dump_t *vl_api_bier_imp_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bier_imp_dump_t);
    vl_api_bier_imp_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_bier_imp_details_t *vl_api_bier_imp_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bier_imp_details_t);
    vl_api_bier_imp_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bi_tbl_id");
    if (!item) goto error;
    if (vl_api_bier_table_id_t_fromjson((void **)&a, &l, item, &a->bi_tbl_id) < 0) goto error;

    item = cJSON_GetObjectItem(o, "bi_src");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->bi_src);

    item = cJSON_GetObjectItem(o, "bi_bytes");
    if (!item) goto error;
    s = u8string_fromjson(o, "bi_bytes");
    if (!s) goto error;
    a->bi_n_bytes = vec_len(s);
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
static inline vl_api_bier_disp_table_add_del_t *vl_api_bier_disp_table_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bier_disp_table_add_del_t);
    vl_api_bier_disp_table_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bdt_tbl_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bdt_tbl_id);

    item = cJSON_GetObjectItem(o, "bdt_is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->bdt_is_add);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bier_disp_table_add_del_reply_t *vl_api_bier_disp_table_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bier_disp_table_add_del_reply_t);
    vl_api_bier_disp_table_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bier_disp_table_dump_t *vl_api_bier_disp_table_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bier_disp_table_dump_t);
    vl_api_bier_disp_table_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_bier_disp_table_details_t *vl_api_bier_disp_table_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bier_disp_table_details_t);
    vl_api_bier_disp_table_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bdt_tbl_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bdt_tbl_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bier_disp_entry_add_del_t *vl_api_bier_disp_entry_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bier_disp_entry_add_del_t);
    vl_api_bier_disp_entry_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bde_bp");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->bde_bp);

    item = cJSON_GetObjectItem(o, "bde_tbl_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bde_tbl_id);

    item = cJSON_GetObjectItem(o, "bde_is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->bde_is_add);

    item = cJSON_GetObjectItem(o, "bde_payload_proto");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->bde_payload_proto);

    item = cJSON_GetObjectItem(o, "bde_paths");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "bde_paths");
        int size = cJSON_GetArraySize(array);
        a->bde_n_paths = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_fib_path_t) * size);
        vl_api_fib_path_t *d = (void *)a + l;
        l += sizeof(vl_api_fib_path_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_fib_path_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bier_disp_entry_add_del_reply_t *vl_api_bier_disp_entry_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bier_disp_entry_add_del_reply_t);
    vl_api_bier_disp_entry_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bier_disp_entry_dump_t *vl_api_bier_disp_entry_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bier_disp_entry_dump_t);
    vl_api_bier_disp_entry_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bde_tbl_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bde_tbl_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bier_disp_entry_details_t *vl_api_bier_disp_entry_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bier_disp_entry_details_t);
    vl_api_bier_disp_entry_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bde_bp");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->bde_bp);

    item = cJSON_GetObjectItem(o, "bde_tbl_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bde_tbl_id);

    item = cJSON_GetObjectItem(o, "bde_is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->bde_is_add);

    item = cJSON_GetObjectItem(o, "bde_payload_proto");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->bde_payload_proto);

    item = cJSON_GetObjectItem(o, "bde_paths");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "bde_paths");
        int size = cJSON_GetArraySize(array);
        a->bde_n_paths = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_fib_path_t) * size);
        vl_api_fib_path_t *d = (void *)a + l;
        l += sizeof(vl_api_fib_path_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_fib_path_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
