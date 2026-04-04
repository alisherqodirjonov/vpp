/* Imported API files */
#include <vnet/fib/fib_types.api_fromjson.h>
#ifndef included_fib_api_fromjson_h
#define included_fib_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_fib_source_t_fromjson (void **mp, int *len, cJSON *o, vl_api_fib_source_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "priority");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->priority);

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->id);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    strncpy_s((char *)a->name, sizeof(a->name), cJSON_GetStringValue(item), sizeof(a->name) - 1);

    return 0;

  error:
    return -1;
}
static inline vl_api_fib_source_add_t *vl_api_fib_source_add_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_fib_source_add_t);
    vl_api_fib_source_add_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "src");
    if (!item) goto error;
    if (vl_api_fib_source_t_fromjson((void **)&a, &l, item, &a->src) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_fib_source_add_reply_t *vl_api_fib_source_add_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_fib_source_add_reply_t);
    vl_api_fib_source_add_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_fib_source_dump_t *vl_api_fib_source_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_fib_source_dump_t);
    vl_api_fib_source_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_fib_source_details_t *vl_api_fib_source_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_fib_source_details_t);
    vl_api_fib_source_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "src");
    if (!item) goto error;
    if (vl_api_fib_source_t_fromjson((void **)&a, &l, item, &a->src) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
