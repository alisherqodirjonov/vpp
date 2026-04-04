/* Imported API files */
#include <vnet/ip/ip_types.api_fromjson.h>
#ifndef included_ipfix_export_api_fromjson_h
#define included_ipfix_export_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_set_ipfix_exporter_t *vl_api_set_ipfix_exporter_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_set_ipfix_exporter_t);
    vl_api_set_ipfix_exporter_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "collector_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->collector_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "collector_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->collector_port);

    item = cJSON_GetObjectItem(o, "src_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->src_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    item = cJSON_GetObjectItem(o, "path_mtu");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->path_mtu);

    item = cJSON_GetObjectItem(o, "template_interval");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->template_interval);

    item = cJSON_GetObjectItem(o, "udp_checksum");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->udp_checksum);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_set_ipfix_exporter_reply_t *vl_api_set_ipfix_exporter_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_set_ipfix_exporter_reply_t);
    vl_api_set_ipfix_exporter_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipfix_exporter_dump_t *vl_api_ipfix_exporter_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipfix_exporter_dump_t);
    vl_api_ipfix_exporter_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_ipfix_exporter_details_t *vl_api_ipfix_exporter_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipfix_exporter_details_t);
    vl_api_ipfix_exporter_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "collector_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->collector_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "collector_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->collector_port);

    item = cJSON_GetObjectItem(o, "src_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->src_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    item = cJSON_GetObjectItem(o, "path_mtu");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->path_mtu);

    item = cJSON_GetObjectItem(o, "template_interval");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->template_interval);

    item = cJSON_GetObjectItem(o, "udp_checksum");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->udp_checksum);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipfix_exporter_create_delete_t *vl_api_ipfix_exporter_create_delete_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipfix_exporter_create_delete_t);
    vl_api_ipfix_exporter_create_delete_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_create");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_create);

    item = cJSON_GetObjectItem(o, "collector_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->collector_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "collector_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->collector_port);

    item = cJSON_GetObjectItem(o, "src_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->src_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    item = cJSON_GetObjectItem(o, "path_mtu");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->path_mtu);

    item = cJSON_GetObjectItem(o, "template_interval");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->template_interval);

    item = cJSON_GetObjectItem(o, "udp_checksum");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->udp_checksum);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipfix_exporter_create_delete_reply_t *vl_api_ipfix_exporter_create_delete_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipfix_exporter_create_delete_reply_t);
    vl_api_ipfix_exporter_create_delete_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "stat_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->stat_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipfix_all_exporter_get_t *vl_api_ipfix_all_exporter_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipfix_all_exporter_get_t);
    vl_api_ipfix_all_exporter_get_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "cursor");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->cursor);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipfix_all_exporter_get_reply_t *vl_api_ipfix_all_exporter_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipfix_all_exporter_get_reply_t);
    vl_api_ipfix_all_exporter_get_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "cursor");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->cursor);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipfix_all_exporter_details_t *vl_api_ipfix_all_exporter_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipfix_all_exporter_details_t);
    vl_api_ipfix_all_exporter_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "collector_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->collector_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "collector_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->collector_port);

    item = cJSON_GetObjectItem(o, "src_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->src_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    item = cJSON_GetObjectItem(o, "path_mtu");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->path_mtu);

    item = cJSON_GetObjectItem(o, "template_interval");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->template_interval);

    item = cJSON_GetObjectItem(o, "udp_checksum");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->udp_checksum);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_set_ipfix_classify_stream_t *vl_api_set_ipfix_classify_stream_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_set_ipfix_classify_stream_t);
    vl_api_set_ipfix_classify_stream_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "domain_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->domain_id);

    item = cJSON_GetObjectItem(o, "src_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->src_port);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_set_ipfix_classify_stream_reply_t *vl_api_set_ipfix_classify_stream_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_set_ipfix_classify_stream_reply_t);
    vl_api_set_ipfix_classify_stream_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipfix_classify_stream_dump_t *vl_api_ipfix_classify_stream_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipfix_classify_stream_dump_t);
    vl_api_ipfix_classify_stream_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_ipfix_classify_stream_details_t *vl_api_ipfix_classify_stream_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipfix_classify_stream_details_t);
    vl_api_ipfix_classify_stream_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "domain_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->domain_id);

    item = cJSON_GetObjectItem(o, "src_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->src_port);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipfix_classify_table_add_del_t *vl_api_ipfix_classify_table_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipfix_classify_table_add_del_t);
    vl_api_ipfix_classify_table_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_id);

    item = cJSON_GetObjectItem(o, "ip_version");
    if (!item) goto error;
    if (vl_api_address_family_t_fromjson((void **)&a, &l, item, &a->ip_version) < 0) goto error;

    item = cJSON_GetObjectItem(o, "transport_protocol");
    if (!item) goto error;
    if (vl_api_ip_proto_t_fromjson((void **)&a, &l, item, &a->transport_protocol) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipfix_classify_table_add_del_reply_t *vl_api_ipfix_classify_table_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipfix_classify_table_add_del_reply_t);
    vl_api_ipfix_classify_table_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipfix_classify_table_dump_t *vl_api_ipfix_classify_table_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipfix_classify_table_dump_t);
    vl_api_ipfix_classify_table_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_ipfix_classify_table_details_t *vl_api_ipfix_classify_table_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipfix_classify_table_details_t);
    vl_api_ipfix_classify_table_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_id);

    item = cJSON_GetObjectItem(o, "ip_version");
    if (!item) goto error;
    if (vl_api_address_family_t_fromjson((void **)&a, &l, item, &a->ip_version) < 0) goto error;

    item = cJSON_GetObjectItem(o, "transport_protocol");
    if (!item) goto error;
    if (vl_api_ip_proto_t_fromjson((void **)&a, &l, item, &a->transport_protocol) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ipfix_flush_t *vl_api_ipfix_flush_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipfix_flush_t);
    vl_api_ipfix_flush_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_ipfix_flush_reply_t *vl_api_ipfix_flush_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ipfix_flush_reply_t);
    vl_api_ipfix_flush_reply_t *a = cJSON_malloc(l);

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
