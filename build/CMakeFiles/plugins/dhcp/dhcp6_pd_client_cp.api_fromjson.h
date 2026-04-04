/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/ip/ip_types.api_fromjson.h>
#ifndef included_dhcp6_pd_client_cp_api_fromjson_h
#define included_dhcp6_pd_client_cp_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_dhcp6_pd_client_enable_disable_t *vl_api_dhcp6_pd_client_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dhcp6_pd_client_enable_disable_t);
    vl_api_dhcp6_pd_client_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "prefix_group");
    if (!item) goto error;
    strncpy_s((char *)a->prefix_group, sizeof(a->prefix_group), cJSON_GetStringValue(item), sizeof(a->prefix_group) - 1);

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dhcp6_pd_client_enable_disable_reply_t *vl_api_dhcp6_pd_client_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dhcp6_pd_client_enable_disable_reply_t);
    vl_api_dhcp6_pd_client_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip6_add_del_address_using_prefix_t *vl_api_ip6_add_del_address_using_prefix_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip6_add_del_address_using_prefix_t);
    vl_api_ip6_add_del_address_using_prefix_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "prefix_group");
    if (!item) goto error;
    strncpy_s((char *)a->prefix_group, sizeof(a->prefix_group), cJSON_GetStringValue(item), sizeof(a->prefix_group) - 1);

    item = cJSON_GetObjectItem(o, "address_with_prefix");
    if (!item) goto error;
    if (vl_api_ip6_address_with_prefix_t_fromjson((void **)&a, &l, item, &a->address_with_prefix) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip6_add_del_address_using_prefix_reply_t *vl_api_ip6_add_del_address_using_prefix_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip6_add_del_address_using_prefix_reply_t);
    vl_api_ip6_add_del_address_using_prefix_reply_t *a = cJSON_malloc(l);

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
