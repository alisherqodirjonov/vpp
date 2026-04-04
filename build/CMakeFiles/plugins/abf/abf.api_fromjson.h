/* Imported API files */
#include <vnet/ip/ip_types.api_fromjson.h>
#include <vnet/fib/fib_types.api_fromjson.h>
#include <vnet/interface_types.api_fromjson.h>
#ifndef included_abf_api_fromjson_h
#define included_abf_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_abf_policy_t_fromjson (void **mp, int *len, cJSON *o, vl_api_abf_policy_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "policy_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->policy_id);

    item = cJSON_GetObjectItem(o, "acl_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->acl_index);

    item = cJSON_GetObjectItem(o, "paths");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "paths");
        int size = cJSON_GetArraySize(array);
        a->n_paths = size;
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
static inline int vl_api_abf_itf_attach_t_fromjson (void **mp, int *len, cJSON *o, vl_api_abf_itf_attach_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "policy_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->policy_id);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson(mp, len, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "priority");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->priority);

    item = cJSON_GetObjectItem(o, "is_ipv6");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_ipv6);

    return 0;

  error:
    return -1;
}
static inline vl_api_abf_plugin_get_version_t *vl_api_abf_plugin_get_version_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_abf_plugin_get_version_t);
    vl_api_abf_plugin_get_version_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_abf_plugin_get_version_reply_t *vl_api_abf_plugin_get_version_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_abf_plugin_get_version_reply_t);
    vl_api_abf_plugin_get_version_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "major");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->major);

    item = cJSON_GetObjectItem(o, "minor");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->minor);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_abf_policy_add_del_t *vl_api_abf_policy_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_abf_policy_add_del_t);
    vl_api_abf_policy_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "policy");
    if (!item) goto error;
    if (vl_api_abf_policy_t_fromjson((void **)&a, &l, item, &a->policy) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_abf_policy_add_del_reply_t *vl_api_abf_policy_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_abf_policy_add_del_reply_t);
    vl_api_abf_policy_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_abf_policy_details_t *vl_api_abf_policy_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_abf_policy_details_t);
    vl_api_abf_policy_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "policy");
    if (!item) goto error;
    if (vl_api_abf_policy_t_fromjson((void **)&a, &l, item, &a->policy) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_abf_policy_dump_t *vl_api_abf_policy_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_abf_policy_dump_t);
    vl_api_abf_policy_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_abf_itf_attach_add_del_t *vl_api_abf_itf_attach_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_abf_itf_attach_add_del_t);
    vl_api_abf_itf_attach_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "attach");
    if (!item) goto error;
    if (vl_api_abf_itf_attach_t_fromjson((void **)&a, &l, item, &a->attach) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_abf_itf_attach_add_del_reply_t *vl_api_abf_itf_attach_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_abf_itf_attach_add_del_reply_t);
    vl_api_abf_itf_attach_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_abf_itf_attach_details_t *vl_api_abf_itf_attach_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_abf_itf_attach_details_t);
    vl_api_abf_itf_attach_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "attach");
    if (!item) goto error;
    if (vl_api_abf_itf_attach_t_fromjson((void **)&a, &l, item, &a->attach) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_abf_itf_attach_dump_t *vl_api_abf_itf_attach_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_abf_itf_attach_dump_t);
    vl_api_abf_itf_attach_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
#endif
