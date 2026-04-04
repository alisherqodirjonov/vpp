/* Imported API files */
#include <vnet/ip/ip_types.api_tojson.h>
#ifndef included_ipfix_export_api_tojson_h
#define included_ipfix_export_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_set_ipfix_exporter_t_tojson (vl_api_set_ipfix_exporter_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "set_ipfix_exporter");
    cJSON_AddStringToObject(o, "_crc", "5530c8a0");
    cJSON_AddItemToObject(o, "collector_address", vl_api_address_t_tojson(&a->collector_address));
    cJSON_AddNumberToObject(o, "collector_port", a->collector_port);
    cJSON_AddItemToObject(o, "src_address", vl_api_address_t_tojson(&a->src_address));
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    cJSON_AddNumberToObject(o, "path_mtu", a->path_mtu);
    cJSON_AddNumberToObject(o, "template_interval", a->template_interval);
    cJSON_AddBoolToObject(o, "udp_checksum", a->udp_checksum);
    return o;
}
static inline cJSON *vl_api_set_ipfix_exporter_reply_t_tojson (vl_api_set_ipfix_exporter_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "set_ipfix_exporter_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ipfix_exporter_dump_t_tojson (vl_api_ipfix_exporter_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipfix_exporter_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_ipfix_exporter_details_t_tojson (vl_api_ipfix_exporter_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipfix_exporter_details");
    cJSON_AddStringToObject(o, "_crc", "0dedbfe4");
    cJSON_AddItemToObject(o, "collector_address", vl_api_address_t_tojson(&a->collector_address));
    cJSON_AddNumberToObject(o, "collector_port", a->collector_port);
    cJSON_AddItemToObject(o, "src_address", vl_api_address_t_tojson(&a->src_address));
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    cJSON_AddNumberToObject(o, "path_mtu", a->path_mtu);
    cJSON_AddNumberToObject(o, "template_interval", a->template_interval);
    cJSON_AddBoolToObject(o, "udp_checksum", a->udp_checksum);
    return o;
}
static inline cJSON *vl_api_ipfix_exporter_create_delete_t_tojson (vl_api_ipfix_exporter_create_delete_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipfix_exporter_create_delete");
    cJSON_AddStringToObject(o, "_crc", "0753a768");
    cJSON_AddBoolToObject(o, "is_create", a->is_create);
    cJSON_AddItemToObject(o, "collector_address", vl_api_address_t_tojson(&a->collector_address));
    cJSON_AddNumberToObject(o, "collector_port", a->collector_port);
    cJSON_AddItemToObject(o, "src_address", vl_api_address_t_tojson(&a->src_address));
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    cJSON_AddNumberToObject(o, "path_mtu", a->path_mtu);
    cJSON_AddNumberToObject(o, "template_interval", a->template_interval);
    cJSON_AddBoolToObject(o, "udp_checksum", a->udp_checksum);
    return o;
}
static inline cJSON *vl_api_ipfix_exporter_create_delete_reply_t_tojson (vl_api_ipfix_exporter_create_delete_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipfix_exporter_create_delete_reply");
    cJSON_AddStringToObject(o, "_crc", "9ffac24b");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "stat_index", a->stat_index);
    return o;
}
static inline cJSON *vl_api_ipfix_all_exporter_get_t_tojson (vl_api_ipfix_all_exporter_get_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipfix_all_exporter_get");
    cJSON_AddStringToObject(o, "_crc", "f75ba505");
    cJSON_AddNumberToObject(o, "cursor", a->cursor);
    return o;
}
static inline cJSON *vl_api_ipfix_all_exporter_get_reply_t_tojson (vl_api_ipfix_all_exporter_get_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipfix_all_exporter_get_reply");
    cJSON_AddStringToObject(o, "_crc", "53b48f5d");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "cursor", a->cursor);
    return o;
}
static inline cJSON *vl_api_ipfix_all_exporter_details_t_tojson (vl_api_ipfix_all_exporter_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipfix_all_exporter_details");
    cJSON_AddStringToObject(o, "_crc", "0dedbfe4");
    cJSON_AddItemToObject(o, "collector_address", vl_api_address_t_tojson(&a->collector_address));
    cJSON_AddNumberToObject(o, "collector_port", a->collector_port);
    cJSON_AddItemToObject(o, "src_address", vl_api_address_t_tojson(&a->src_address));
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    cJSON_AddNumberToObject(o, "path_mtu", a->path_mtu);
    cJSON_AddNumberToObject(o, "template_interval", a->template_interval);
    cJSON_AddBoolToObject(o, "udp_checksum", a->udp_checksum);
    return o;
}
static inline cJSON *vl_api_set_ipfix_classify_stream_t_tojson (vl_api_set_ipfix_classify_stream_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "set_ipfix_classify_stream");
    cJSON_AddStringToObject(o, "_crc", "c9cbe053");
    cJSON_AddNumberToObject(o, "domain_id", a->domain_id);
    cJSON_AddNumberToObject(o, "src_port", a->src_port);
    return o;
}
static inline cJSON *vl_api_set_ipfix_classify_stream_reply_t_tojson (vl_api_set_ipfix_classify_stream_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "set_ipfix_classify_stream_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ipfix_classify_stream_dump_t_tojson (vl_api_ipfix_classify_stream_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipfix_classify_stream_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_ipfix_classify_stream_details_t_tojson (vl_api_ipfix_classify_stream_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipfix_classify_stream_details");
    cJSON_AddStringToObject(o, "_crc", "2903539d");
    cJSON_AddNumberToObject(o, "domain_id", a->domain_id);
    cJSON_AddNumberToObject(o, "src_port", a->src_port);
    return o;
}
static inline cJSON *vl_api_ipfix_classify_table_add_del_t_tojson (vl_api_ipfix_classify_table_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipfix_classify_table_add_del");
    cJSON_AddStringToObject(o, "_crc", "3e449bb9");
    cJSON_AddNumberToObject(o, "table_id", a->table_id);
    cJSON_AddItemToObject(o, "ip_version", vl_api_address_family_t_tojson(a->ip_version));
    cJSON_AddItemToObject(o, "transport_protocol", vl_api_ip_proto_t_tojson(a->transport_protocol));
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    return o;
}
static inline cJSON *vl_api_ipfix_classify_table_add_del_reply_t_tojson (vl_api_ipfix_classify_table_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipfix_classify_table_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ipfix_classify_table_dump_t_tojson (vl_api_ipfix_classify_table_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipfix_classify_table_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_ipfix_classify_table_details_t_tojson (vl_api_ipfix_classify_table_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipfix_classify_table_details");
    cJSON_AddStringToObject(o, "_crc", "1af8c28c");
    cJSON_AddNumberToObject(o, "table_id", a->table_id);
    cJSON_AddItemToObject(o, "ip_version", vl_api_address_family_t_tojson(a->ip_version));
    cJSON_AddItemToObject(o, "transport_protocol", vl_api_ip_proto_t_tojson(a->transport_protocol));
    return o;
}
static inline cJSON *vl_api_ipfix_flush_t_tojson (vl_api_ipfix_flush_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipfix_flush");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_ipfix_flush_reply_t_tojson (vl_api_ipfix_flush_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipfix_flush_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
