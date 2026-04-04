/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/ip/ip_types.api_fromjson.h>
#ifndef included_npt66_api_fromjson_h
#define included_npt66_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_npt66_binding_add_del_t *vl_api_npt66_binding_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_npt66_binding_add_del_t);
    vl_api_npt66_binding_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "internal");
    if (!item) goto error;
    if (vl_api_ip6_prefix_t_fromjson((void **)&a, &l, item, &a->internal) < 0) goto error;

    item = cJSON_GetObjectItem(o, "external");
    if (!item) goto error;
    if (vl_api_ip6_prefix_t_fromjson((void **)&a, &l, item, &a->external) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_npt66_binding_add_del_reply_t *vl_api_npt66_binding_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_npt66_binding_add_del_reply_t);
    vl_api_npt66_binding_add_del_reply_t *a = cJSON_malloc(l);

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
