/* Imported API files */
#include <vnet/ethernet/ethernet_types.api_tojson.h>
#include <vnet/interface_types.api_tojson.h>
#ifndef included_mactime_api_tojson_h
#define included_mactime_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_time_range_t_tojson (vl_api_time_range_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "start", a->start);
    cJSON_AddNumberToObject(o, "end", a->end);
    return o;
}
static inline cJSON *vl_api_mactime_time_range_t_tojson (vl_api_mactime_time_range_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "start", a->start);
    cJSON_AddNumberToObject(o, "end", a->end);
    return o;
}
static inline cJSON *vl_api_mactime_enable_disable_t_tojson (vl_api_mactime_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "mactime_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "3865946c");
    cJSON_AddBoolToObject(o, "enable_disable", a->enable_disable);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_mactime_enable_disable_reply_t_tojson (vl_api_mactime_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "mactime_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_mactime_add_del_range_t_tojson (vl_api_mactime_add_del_range_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "mactime_add_del_range");
    cJSON_AddStringToObject(o, "_crc", "cb56e877");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddBoolToObject(o, "drop", a->drop);
    cJSON_AddBoolToObject(o, "allow", a->allow);
    cJSON_AddNumberToObject(o, "allow_quota", a->allow_quota);
    cJSON_AddBoolToObject(o, "no_udp_10001", a->no_udp_10001);
    cJSON_AddNumberToObject(o, "data_quota", a->data_quota);
    cJSON_AddItemToObject(o, "mac_address", vl_api_mac_address_t_tojson(&a->mac_address));
    cJSON_AddStringToObject(o, "device_name", (char *)a->device_name);
    cJSON_AddNumberToObject(o, "count", a->count);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "ranges");
        for (i = 0; i < a->count; i++) {
            cJSON_AddItemToArray(array, vl_api_time_range_t_tojson(&a->ranges[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_mactime_add_del_range_reply_t_tojson (vl_api_mactime_add_del_range_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "mactime_add_del_range_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_mactime_dump_t_tojson (vl_api_mactime_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "mactime_dump");
    cJSON_AddStringToObject(o, "_crc", "8f454e23");
    cJSON_AddNumberToObject(o, "my_table_epoch", a->my_table_epoch);
    return o;
}
static inline cJSON *vl_api_mactime_details_t_tojson (vl_api_mactime_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "mactime_details");
    cJSON_AddStringToObject(o, "_crc", "da25b13a");
    cJSON_AddNumberToObject(o, "pool_index", a->pool_index);
    cJSON_AddItemToObject(o, "mac_address", vl_api_mac_address_t_tojson(&a->mac_address));
    cJSON_AddNumberToObject(o, "data_quota", a->data_quota);
    cJSON_AddNumberToObject(o, "data_used_in_range", a->data_used_in_range);
    cJSON_AddNumberToObject(o, "flags", a->flags);
    cJSON_AddStringToObject(o, "device_name", (char *)a->device_name);
    cJSON_AddNumberToObject(o, "nranges", a->nranges);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "ranges");
        for (i = 0; i < a->nranges; i++) {
            cJSON_AddItemToArray(array, vl_api_mactime_time_range_t_tojson(&a->ranges[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_mactime_dump_reply_t_tojson (vl_api_mactime_dump_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "mactime_dump_reply");
    cJSON_AddStringToObject(o, "_crc", "49bcc753");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "table_epoch", a->table_epoch);
    return o;
}
#endif
