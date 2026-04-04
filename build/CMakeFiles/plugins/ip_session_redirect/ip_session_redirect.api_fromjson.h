/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/fib/fib_types.api_fromjson.h>
#ifndef included_ip_session_redirect_api_fromjson_h
#define included_ip_session_redirect_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_ip_session_redirect_add_t *vl_api_ip_session_redirect_add_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_session_redirect_add_t);
    vl_api_ip_session_redirect_add_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_index);

    item = cJSON_GetObjectItem(o, "match_len");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->match_len);

    item = cJSON_GetObjectItem(o, "match");
    if (!item) goto error;
    if (u8string_fromjson2(o, "match", a->match) < 0) goto error;

    item = cJSON_GetObjectItem(o, "opaque_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->opaque_index);

    item = cJSON_GetObjectItem(o, "is_punt");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_punt);

    item = cJSON_GetObjectItem(o, "paths");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "paths");
        int size = cJSON_GetArraySize(array);
        a->n_paths = size;
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
static inline vl_api_ip_session_redirect_add_reply_t *vl_api_ip_session_redirect_add_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_session_redirect_add_reply_t);
    vl_api_ip_session_redirect_add_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_session_redirect_add_v2_t *vl_api_ip_session_redirect_add_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_session_redirect_add_v2_t);
    vl_api_ip_session_redirect_add_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_index);

    item = cJSON_GetObjectItem(o, "opaque_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->opaque_index);

    item = cJSON_GetObjectItem(o, "proto");
    if (!item) goto error;
    if (vl_api_fib_path_nh_proto_t_fromjson((void **)&a, &l, item, &a->proto) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_punt");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_punt);

    item = cJSON_GetObjectItem(o, "match_len");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->match_len);

    item = cJSON_GetObjectItem(o, "match");
    if (!item) goto error;
    if (u8string_fromjson2(o, "match", a->match) < 0) goto error;

    item = cJSON_GetObjectItem(o, "paths");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "paths");
        int size = cJSON_GetArraySize(array);
        a->n_paths = size;
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
static inline vl_api_ip_session_redirect_add_v2_reply_t *vl_api_ip_session_redirect_add_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_session_redirect_add_v2_reply_t);
    vl_api_ip_session_redirect_add_v2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_session_redirect_del_t *vl_api_ip_session_redirect_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_session_redirect_del_t);
    vl_api_ip_session_redirect_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_index);

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
static inline vl_api_ip_session_redirect_del_reply_t *vl_api_ip_session_redirect_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_session_redirect_del_reply_t);
    vl_api_ip_session_redirect_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_session_redirect_dump_t *vl_api_ip_session_redirect_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_session_redirect_dump_t);
    vl_api_ip_session_redirect_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip_session_redirect_details_t *vl_api_ip_session_redirect_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip_session_redirect_details_t);
    vl_api_ip_session_redirect_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_index);

    item = cJSON_GetObjectItem(o, "opaque_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->opaque_index);

    item = cJSON_GetObjectItem(o, "is_punt");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_punt);

    item = cJSON_GetObjectItem(o, "is_ip6");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_ip6);

    item = cJSON_GetObjectItem(o, "match_length");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->match_length);

    item = cJSON_GetObjectItem(o, "match");
    if (!item) goto error;
    if (u8string_fromjson2(o, "match", a->match) < 0) goto error;

    item = cJSON_GetObjectItem(o, "paths");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "paths");
        int size = cJSON_GetArraySize(array);
        a->n_paths = size;
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
