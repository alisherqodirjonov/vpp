/* Imported API files */
#include <vnet/ip/ip_types.api_tojson.h>
#include <vnet/fib/fib_types.api_tojson.h>
#include <vnet/interface_types.api_tojson.h>
#ifndef included_abf_api_tojson_h
#define included_abf_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_abf_policy_t_tojson (vl_api_abf_policy_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "policy_id", a->policy_id);
    cJSON_AddNumberToObject(o, "acl_index", a->acl_index);
    cJSON_AddNumberToObject(o, "n_paths", a->n_paths);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "paths");
        for (i = 0; i < a->n_paths; i++) {
            cJSON_AddItemToArray(array, vl_api_fib_path_t_tojson(&a->paths[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_abf_itf_attach_t_tojson (vl_api_abf_itf_attach_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "policy_id", a->policy_id);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "priority", a->priority);
    cJSON_AddBoolToObject(o, "is_ipv6", a->is_ipv6);
    return o;
}
static inline cJSON *vl_api_abf_plugin_get_version_t_tojson (vl_api_abf_plugin_get_version_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "abf_plugin_get_version");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_abf_plugin_get_version_reply_t_tojson (vl_api_abf_plugin_get_version_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "abf_plugin_get_version_reply");
    cJSON_AddStringToObject(o, "_crc", "9b32cf86");
    cJSON_AddNumberToObject(o, "major", a->major);
    cJSON_AddNumberToObject(o, "minor", a->minor);
    return o;
}
static inline cJSON *vl_api_abf_policy_add_del_t_tojson (vl_api_abf_policy_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "abf_policy_add_del");
    cJSON_AddStringToObject(o, "_crc", "c6131197");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "policy", vl_api_abf_policy_t_tojson(&a->policy));
    return o;
}
static inline cJSON *vl_api_abf_policy_add_del_reply_t_tojson (vl_api_abf_policy_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "abf_policy_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_abf_policy_details_t_tojson (vl_api_abf_policy_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "abf_policy_details");
    cJSON_AddStringToObject(o, "_crc", "b7487fa4");
    cJSON_AddItemToObject(o, "policy", vl_api_abf_policy_t_tojson(&a->policy));
    return o;
}
static inline cJSON *vl_api_abf_policy_dump_t_tojson (vl_api_abf_policy_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "abf_policy_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_abf_itf_attach_add_del_t_tojson (vl_api_abf_itf_attach_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "abf_itf_attach_add_del");
    cJSON_AddStringToObject(o, "_crc", "25c8621b");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "attach", vl_api_abf_itf_attach_t_tojson(&a->attach));
    return o;
}
static inline cJSON *vl_api_abf_itf_attach_add_del_reply_t_tojson (vl_api_abf_itf_attach_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "abf_itf_attach_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_abf_itf_attach_details_t_tojson (vl_api_abf_itf_attach_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "abf_itf_attach_details");
    cJSON_AddStringToObject(o, "_crc", "7819523e");
    cJSON_AddItemToObject(o, "attach", vl_api_abf_itf_attach_t_tojson(&a->attach));
    return o;
}
static inline cJSON *vl_api_abf_itf_attach_dump_t_tojson (vl_api_abf_itf_attach_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "abf_itf_attach_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
#endif
