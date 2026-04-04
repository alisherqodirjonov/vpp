/* Imported API files */
#include <vnet/ip/ip_types.api_tojson.h>
#include <vnet/interface_types.api_tojson.h>
#include <nat/lib/nat_types.api_tojson.h>
#ifndef included_nat64_api_tojson_h
#define included_nat64_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_nat64_plugin_enable_disable_t_tojson (vl_api_nat64_plugin_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat64_plugin_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "45948b90");
    cJSON_AddNumberToObject(o, "bib_buckets", a->bib_buckets);
    cJSON_AddNumberToObject(o, "bib_memory_size", a->bib_memory_size);
    cJSON_AddNumberToObject(o, "st_buckets", a->st_buckets);
    cJSON_AddNumberToObject(o, "st_memory_size", a->st_memory_size);
    cJSON_AddBoolToObject(o, "enable", a->enable);
    return o;
}
static inline cJSON *vl_api_nat64_plugin_enable_disable_reply_t_tojson (vl_api_nat64_plugin_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat64_plugin_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat64_set_timeouts_t_tojson (vl_api_nat64_set_timeouts_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat64_set_timeouts");
    cJSON_AddStringToObject(o, "_crc", "d4746b16");
    cJSON_AddNumberToObject(o, "udp", a->udp);
    cJSON_AddNumberToObject(o, "tcp_established", a->tcp_established);
    cJSON_AddNumberToObject(o, "tcp_transitory", a->tcp_transitory);
    cJSON_AddNumberToObject(o, "icmp", a->icmp);
    return o;
}
static inline cJSON *vl_api_nat64_set_timeouts_reply_t_tojson (vl_api_nat64_set_timeouts_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat64_set_timeouts_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat64_get_timeouts_t_tojson (vl_api_nat64_get_timeouts_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat64_get_timeouts");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_nat64_get_timeouts_reply_t_tojson (vl_api_nat64_get_timeouts_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat64_get_timeouts_reply");
    cJSON_AddStringToObject(o, "_crc", "3c4df4e1");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "udp", a->udp);
    cJSON_AddNumberToObject(o, "tcp_established", a->tcp_established);
    cJSON_AddNumberToObject(o, "tcp_transitory", a->tcp_transitory);
    cJSON_AddNumberToObject(o, "icmp", a->icmp);
    return o;
}
static inline cJSON *vl_api_nat64_add_del_pool_addr_range_t_tojson (vl_api_nat64_add_del_pool_addr_range_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat64_add_del_pool_addr_range");
    cJSON_AddStringToObject(o, "_crc", "a3b944e3");
    cJSON_AddItemToObject(o, "start_addr", vl_api_ip4_address_t_tojson(&a->start_addr));
    cJSON_AddItemToObject(o, "end_addr", vl_api_ip4_address_t_tojson(&a->end_addr));
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    return o;
}
static inline cJSON *vl_api_nat64_add_del_pool_addr_range_reply_t_tojson (vl_api_nat64_add_del_pool_addr_range_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat64_add_del_pool_addr_range_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat64_pool_addr_dump_t_tojson (vl_api_nat64_pool_addr_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat64_pool_addr_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_nat64_pool_addr_details_t_tojson (vl_api_nat64_pool_addr_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat64_pool_addr_details");
    cJSON_AddStringToObject(o, "_crc", "9bb99cdb");
    cJSON_AddItemToObject(o, "address", vl_api_ip4_address_t_tojson(&a->address));
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    return o;
}
static inline cJSON *vl_api_nat64_add_del_interface_t_tojson (vl_api_nat64_add_del_interface_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat64_add_del_interface");
    cJSON_AddStringToObject(o, "_crc", "f3699b83");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "flags", vl_api_nat_config_flags_t_tojson(a->flags));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_nat64_add_del_interface_reply_t_tojson (vl_api_nat64_add_del_interface_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat64_add_del_interface_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat64_interface_dump_t_tojson (vl_api_nat64_interface_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat64_interface_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_nat64_interface_details_t_tojson (vl_api_nat64_interface_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat64_interface_details");
    cJSON_AddStringToObject(o, "_crc", "5d286289");
    cJSON_AddItemToObject(o, "flags", vl_api_nat_config_flags_t_tojson(a->flags));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_nat64_add_del_static_bib_t_tojson (vl_api_nat64_add_del_static_bib_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat64_add_del_static_bib");
    cJSON_AddStringToObject(o, "_crc", "1c404de5");
    cJSON_AddItemToObject(o, "i_addr", vl_api_ip6_address_t_tojson(&a->i_addr));
    cJSON_AddItemToObject(o, "o_addr", vl_api_ip4_address_t_tojson(&a->o_addr));
    cJSON_AddNumberToObject(o, "i_port", a->i_port);
    cJSON_AddNumberToObject(o, "o_port", a->o_port);
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    cJSON_AddNumberToObject(o, "proto", a->proto);
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    return o;
}
static inline cJSON *vl_api_nat64_add_del_static_bib_reply_t_tojson (vl_api_nat64_add_del_static_bib_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat64_add_del_static_bib_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat64_bib_dump_t_tojson (vl_api_nat64_bib_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat64_bib_dump");
    cJSON_AddStringToObject(o, "_crc", "cfcb6b75");
    cJSON_AddNumberToObject(o, "proto", a->proto);
    return o;
}
static inline cJSON *vl_api_nat64_bib_details_t_tojson (vl_api_nat64_bib_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat64_bib_details");
    cJSON_AddStringToObject(o, "_crc", "43bc3ddf");
    cJSON_AddItemToObject(o, "i_addr", vl_api_ip6_address_t_tojson(&a->i_addr));
    cJSON_AddItemToObject(o, "o_addr", vl_api_ip4_address_t_tojson(&a->o_addr));
    cJSON_AddNumberToObject(o, "i_port", a->i_port);
    cJSON_AddNumberToObject(o, "o_port", a->o_port);
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    cJSON_AddNumberToObject(o, "proto", a->proto);
    cJSON_AddItemToObject(o, "flags", vl_api_nat_config_flags_t_tojson(a->flags));
    cJSON_AddNumberToObject(o, "ses_num", a->ses_num);
    return o;
}
static inline cJSON *vl_api_nat64_st_dump_t_tojson (vl_api_nat64_st_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat64_st_dump");
    cJSON_AddStringToObject(o, "_crc", "cfcb6b75");
    cJSON_AddNumberToObject(o, "proto", a->proto);
    return o;
}
static inline cJSON *vl_api_nat64_st_details_t_tojson (vl_api_nat64_st_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat64_st_details");
    cJSON_AddStringToObject(o, "_crc", "dd3361ed");
    cJSON_AddItemToObject(o, "il_addr", vl_api_ip6_address_t_tojson(&a->il_addr));
    cJSON_AddItemToObject(o, "ol_addr", vl_api_ip4_address_t_tojson(&a->ol_addr));
    cJSON_AddNumberToObject(o, "il_port", a->il_port);
    cJSON_AddNumberToObject(o, "ol_port", a->ol_port);
    cJSON_AddItemToObject(o, "ir_addr", vl_api_ip6_address_t_tojson(&a->ir_addr));
    cJSON_AddItemToObject(o, "or_addr", vl_api_ip4_address_t_tojson(&a->or_addr));
    cJSON_AddNumberToObject(o, "r_port", a->r_port);
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    cJSON_AddNumberToObject(o, "proto", a->proto);
    return o;
}
static inline cJSON *vl_api_nat64_add_del_prefix_t_tojson (vl_api_nat64_add_del_prefix_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat64_add_del_prefix");
    cJSON_AddStringToObject(o, "_crc", "727b2f4c");
    cJSON_AddItemToObject(o, "prefix", vl_api_ip6_prefix_t_tojson(&a->prefix));
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    return o;
}
static inline cJSON *vl_api_nat64_add_del_prefix_reply_t_tojson (vl_api_nat64_add_del_prefix_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat64_add_del_prefix_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat64_prefix_dump_t_tojson (vl_api_nat64_prefix_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat64_prefix_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_nat64_prefix_details_t_tojson (vl_api_nat64_prefix_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat64_prefix_details");
    cJSON_AddStringToObject(o, "_crc", "20568de3");
    cJSON_AddItemToObject(o, "prefix", vl_api_ip6_prefix_t_tojson(&a->prefix));
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    return o;
}
static inline cJSON *vl_api_nat64_add_del_interface_addr_t_tojson (vl_api_nat64_add_del_interface_addr_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat64_add_del_interface_addr");
    cJSON_AddStringToObject(o, "_crc", "47d6e753");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_nat64_add_del_interface_addr_reply_t_tojson (vl_api_nat64_add_del_interface_addr_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat64_add_del_interface_addr_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
