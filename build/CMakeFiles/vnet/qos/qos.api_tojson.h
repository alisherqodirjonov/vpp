/* Imported API files */
#include <vnet/ip/ip_types.api_tojson.h>
#include <vnet/interface_types.api_tojson.h>
#ifndef included_qos_api_tojson_h
#define included_qos_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_qos_source_t_tojson (vl_api_qos_source_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("QOS_API_SOURCE_EXT");
    case 1:
        return cJSON_CreateString("QOS_API_SOURCE_VLAN");
    case 2:
        return cJSON_CreateString("QOS_API_SOURCE_MPLS");
    case 3:
        return cJSON_CreateString("QOS_API_SOURCE_IP");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_qos_store_t_tojson (vl_api_qos_store_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "input_source", vl_api_qos_source_t_tojson(a->input_source));
    cJSON_AddNumberToObject(o, "value", a->value);
    return o;
}
static inline cJSON *vl_api_qos_record_t_tojson (vl_api_qos_record_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "input_source", vl_api_qos_source_t_tojson(a->input_source));
    return o;
}
static inline cJSON *vl_api_qos_egress_map_row_t_tojson (vl_api_qos_egress_map_row_t *a) {
    cJSON *o = cJSON_CreateObject();
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->outputs, 256);
    cJSON_AddStringToObject(o, "outputs", s);
    vec_free(s);
    }
    return o;
}
static inline cJSON *vl_api_qos_egress_map_t_tojson (vl_api_qos_egress_map_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "id", a->id);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "rows");
        for (i = 0; i < 4; i++) {
            cJSON_AddItemToArray(array, vl_api_qos_egress_map_row_t_tojson(&a->rows[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_qos_mark_t_tojson (vl_api_qos_mark_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "map_id", a->map_id);
    cJSON_AddItemToObject(o, "output_source", vl_api_qos_source_t_tojson(a->output_source));
    return o;
}
static inline cJSON *vl_api_qos_store_enable_disable_t_tojson (vl_api_qos_store_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "qos_store_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "f3abcc8b");
    cJSON_AddBoolToObject(o, "enable", a->enable);
    cJSON_AddItemToObject(o, "store", vl_api_qos_store_t_tojson(&a->store));
    return o;
}
static inline cJSON *vl_api_qos_store_enable_disable_reply_t_tojson (vl_api_qos_store_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "qos_store_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_qos_store_dump_t_tojson (vl_api_qos_store_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "qos_store_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_qos_store_details_t_tojson (vl_api_qos_store_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "qos_store_details");
    cJSON_AddStringToObject(o, "_crc", "3ee0aad7");
    cJSON_AddItemToObject(o, "store", vl_api_qos_store_t_tojson(&a->store));
    return o;
}
static inline cJSON *vl_api_qos_record_enable_disable_t_tojson (vl_api_qos_record_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "qos_record_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "2f1a4a38");
    cJSON_AddBoolToObject(o, "enable", a->enable);
    cJSON_AddItemToObject(o, "record", vl_api_qos_record_t_tojson(&a->record));
    return o;
}
static inline cJSON *vl_api_qos_record_enable_disable_reply_t_tojson (vl_api_qos_record_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "qos_record_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_qos_record_dump_t_tojson (vl_api_qos_record_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "qos_record_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_qos_record_details_t_tojson (vl_api_qos_record_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "qos_record_details");
    cJSON_AddStringToObject(o, "_crc", "a425d4d3");
    cJSON_AddItemToObject(o, "record", vl_api_qos_record_t_tojson(&a->record));
    return o;
}
static inline cJSON *vl_api_qos_egress_map_update_t_tojson (vl_api_qos_egress_map_update_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "qos_egress_map_update");
    cJSON_AddStringToObject(o, "_crc", "6d1c065f");
    cJSON_AddItemToObject(o, "map", vl_api_qos_egress_map_t_tojson(&a->map));
    return o;
}
static inline cJSON *vl_api_qos_egress_map_update_reply_t_tojson (vl_api_qos_egress_map_update_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "qos_egress_map_update_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_qos_egress_map_delete_t_tojson (vl_api_qos_egress_map_delete_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "qos_egress_map_delete");
    cJSON_AddStringToObject(o, "_crc", "3a91bde5");
    cJSON_AddNumberToObject(o, "id", a->id);
    return o;
}
static inline cJSON *vl_api_qos_egress_map_delete_reply_t_tojson (vl_api_qos_egress_map_delete_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "qos_egress_map_delete_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_qos_egress_map_dump_t_tojson (vl_api_qos_egress_map_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "qos_egress_map_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_qos_egress_map_details_t_tojson (vl_api_qos_egress_map_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "qos_egress_map_details");
    cJSON_AddStringToObject(o, "_crc", "46c5653c");
    cJSON_AddItemToObject(o, "map", vl_api_qos_egress_map_t_tojson(&a->map));
    return o;
}
static inline cJSON *vl_api_qos_mark_enable_disable_t_tojson (vl_api_qos_mark_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "qos_mark_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "1a010f74");
    cJSON_AddBoolToObject(o, "enable", a->enable);
    cJSON_AddItemToObject(o, "mark", vl_api_qos_mark_t_tojson(&a->mark));
    return o;
}
static inline cJSON *vl_api_qos_mark_enable_disable_reply_t_tojson (vl_api_qos_mark_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "qos_mark_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_qos_mark_dump_t_tojson (vl_api_qos_mark_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "qos_mark_dump");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_qos_mark_details_t_tojson (vl_api_qos_mark_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "qos_mark_details");
    cJSON_AddStringToObject(o, "_crc", "89fe81a9");
    cJSON_AddItemToObject(o, "mark", vl_api_qos_mark_t_tojson(&a->mark));
    return o;
}
static inline cJSON *vl_api_qos_mark_details_reply_t_tojson (vl_api_qos_mark_details_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "qos_mark_details_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
