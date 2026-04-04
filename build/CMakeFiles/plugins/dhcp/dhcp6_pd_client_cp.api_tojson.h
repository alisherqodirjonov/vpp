/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ip/ip_types.api_tojson.h>
#ifndef included_dhcp6_pd_client_cp_api_tojson_h
#define included_dhcp6_pd_client_cp_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_dhcp6_pd_client_enable_disable_t_tojson (vl_api_dhcp6_pd_client_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dhcp6_pd_client_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "a75a0772");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddStringToObject(o, "prefix_group", (char *)a->prefix_group);
    cJSON_AddBoolToObject(o, "enable", a->enable);
    return o;
}
static inline cJSON *vl_api_dhcp6_pd_client_enable_disable_reply_t_tojson (vl_api_dhcp6_pd_client_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dhcp6_pd_client_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ip6_add_del_address_using_prefix_t_tojson (vl_api_ip6_add_del_address_using_prefix_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip6_add_del_address_using_prefix");
    cJSON_AddStringToObject(o, "_crc", "3982f30a");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddStringToObject(o, "prefix_group", (char *)a->prefix_group);
    cJSON_AddItemToObject(o, "address_with_prefix", vl_api_ip6_address_with_prefix_t_tojson(&a->address_with_prefix));
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    return o;
}
static inline cJSON *vl_api_ip6_add_del_address_using_prefix_reply_t_tojson (vl_api_ip6_add_del_address_using_prefix_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip6_add_del_address_using_prefix_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
