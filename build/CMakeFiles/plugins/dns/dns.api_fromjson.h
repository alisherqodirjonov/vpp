/* Imported API files */
#ifndef included_dns_api_fromjson_h
#define included_dns_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_dns_enable_disable_t *vl_api_dns_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dns_enable_disable_t);
    vl_api_dns_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dns_enable_disable_reply_t *vl_api_dns_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dns_enable_disable_reply_t);
    vl_api_dns_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dns_name_server_add_del_t *vl_api_dns_name_server_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dns_name_server_add_del_t);
    vl_api_dns_name_server_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_ip6");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->is_ip6);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "server_address");
    if (!item) goto error;
    if (u8string_fromjson2(o, "server_address", a->server_address) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dns_name_server_add_del_reply_t *vl_api_dns_name_server_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dns_name_server_add_del_reply_t);
    vl_api_dns_name_server_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dns_resolve_name_t *vl_api_dns_resolve_name_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dns_resolve_name_t);
    vl_api_dns_resolve_name_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    if (u8string_fromjson2(o, "name", a->name) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dns_resolve_name_reply_t *vl_api_dns_resolve_name_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dns_resolve_name_reply_t);
    vl_api_dns_resolve_name_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "ip4_set");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->ip4_set);

    item = cJSON_GetObjectItem(o, "ip6_set");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->ip6_set);

    item = cJSON_GetObjectItem(o, "ip4_address");
    if (!item) goto error;
    if (u8string_fromjson2(o, "ip4_address", a->ip4_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ip6_address");
    if (!item) goto error;
    if (u8string_fromjson2(o, "ip6_address", a->ip6_address) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dns_resolve_ip_t *vl_api_dns_resolve_ip_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dns_resolve_ip_t);
    vl_api_dns_resolve_ip_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_ip6");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->is_ip6);

    item = cJSON_GetObjectItem(o, "address");
    if (!item) goto error;
    if (u8string_fromjson2(o, "address", a->address) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dns_resolve_ip_reply_t *vl_api_dns_resolve_ip_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dns_resolve_ip_reply_t);
    vl_api_dns_resolve_ip_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    if (u8string_fromjson2(o, "name", a->name) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
