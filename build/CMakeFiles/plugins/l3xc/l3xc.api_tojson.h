/* Imported API files */
#include <vnet/fib/fib_types.api_tojson.h>
#include <vnet/interface_types.api_tojson.h>
#ifndef included_l3xc_api_tojson_h
#define included_l3xc_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_l3xc_t_tojson (vl_api_l3xc_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "is_ip6", a->is_ip6);
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
static inline cJSON *vl_api_l3xc_plugin_get_version_t_tojson (vl_api_l3xc_plugin_get_version_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l3xc_plugin_get_version");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_l3xc_plugin_get_version_reply_t_tojson (vl_api_l3xc_plugin_get_version_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l3xc_plugin_get_version_reply");
    cJSON_AddStringToObject(o, "_crc", "9b32cf86");
    cJSON_AddNumberToObject(o, "major", a->major);
    cJSON_AddNumberToObject(o, "minor", a->minor);
    return o;
}
static inline cJSON *vl_api_l3xc_update_t_tojson (vl_api_l3xc_update_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l3xc_update");
    cJSON_AddStringToObject(o, "_crc", "e96aabdf");
    cJSON_AddItemToObject(o, "l3xc", vl_api_l3xc_t_tojson(&a->l3xc));
    return o;
}
static inline cJSON *vl_api_l3xc_update_reply_t_tojson (vl_api_l3xc_update_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l3xc_update_reply");
    cJSON_AddStringToObject(o, "_crc", "1992deab");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "stats_index", a->stats_index);
    return o;
}
static inline cJSON *vl_api_l3xc_del_t_tojson (vl_api_l3xc_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l3xc_del");
    cJSON_AddStringToObject(o, "_crc", "e7dbef91");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "is_ip6", a->is_ip6);
    return o;
}
static inline cJSON *vl_api_l3xc_del_reply_t_tojson (vl_api_l3xc_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l3xc_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_l3xc_dump_t_tojson (vl_api_l3xc_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l3xc_dump");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_l3xc_details_t_tojson (vl_api_l3xc_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l3xc_details");
    cJSON_AddStringToObject(o, "_crc", "bc5bf852");
    cJSON_AddItemToObject(o, "l3xc", vl_api_l3xc_t_tojson(&a->l3xc));
    return o;
}
#endif
