/* Imported API files */
#include <vnet/ip/ip_types.api_tojson.h>
#include <vnet/interface_types.api_tojson.h>
#ifndef included_teib_api_tojson_h
#define included_teib_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_teib_entry_t_tojson (vl_api_teib_entry_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "peer", vl_api_address_t_tojson(&a->peer));
    cJSON_AddItemToObject(o, "nh", vl_api_address_t_tojson(&a->nh));
    cJSON_AddNumberToObject(o, "nh_table_id", a->nh_table_id);
    return o;
}
static inline cJSON *vl_api_teib_entry_add_del_t_tojson (vl_api_teib_entry_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "teib_entry_add_del");
    cJSON_AddStringToObject(o, "_crc", "8016cfd2");
    cJSON_AddNumberToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "entry", vl_api_teib_entry_t_tojson(&a->entry));
    return o;
}
static inline cJSON *vl_api_teib_entry_add_del_reply_t_tojson (vl_api_teib_entry_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "teib_entry_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_teib_dump_t_tojson (vl_api_teib_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "teib_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_teib_details_t_tojson (vl_api_teib_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "teib_details");
    cJSON_AddStringToObject(o, "_crc", "981ee1a1");
    cJSON_AddItemToObject(o, "entry", vl_api_teib_entry_t_tojson(&a->entry));
    return o;
}
#endif
