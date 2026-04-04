/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/fib/fib_types.api_tojson.h>
#include <vnet/ethernet/ethernet_types.api_tojson.h>
#include <vnet/mfib/mfib_types.api_tojson.h>
#include <vnet/interface_types.api_tojson.h>
#ifndef included_ip_api_tojson_h
#define included_ip_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_ip_table_t_tojson (vl_api_ip_table_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "table_id", a->table_id);
    cJSON_AddBoolToObject(o, "is_ip6", a->is_ip6);
    cJSON_AddStringToObject(o, "name", (char *)a->name);
    return o;
}
static inline cJSON *vl_api_ip_route_t_tojson (vl_api_ip_route_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "table_id", a->table_id);
    cJSON_AddNumberToObject(o, "stats_index", a->stats_index);
    cJSON_AddItemToObject(o, "prefix", vl_api_prefix_t_tojson(&a->prefix));
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
static inline cJSON *vl_api_ip_route_v2_t_tojson (vl_api_ip_route_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "table_id", a->table_id);
    cJSON_AddNumberToObject(o, "stats_index", a->stats_index);
    cJSON_AddItemToObject(o, "prefix", vl_api_prefix_t_tojson(&a->prefix));
    cJSON_AddNumberToObject(o, "n_paths", a->n_paths);
    cJSON_AddNumberToObject(o, "src", a->src);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "paths");
        for (i = 0; i < a->n_paths; i++) {
            cJSON_AddItemToArray(array, vl_api_fib_path_t_tojson(&a->paths[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_ip_flow_hash_config_t_tojson (vl_api_ip_flow_hash_config_t a) {
    cJSON *array = cJSON_CreateArray();
    if (a & IP_API_FLOW_HASH_SRC_IP)
       cJSON_AddItemToArray(array, cJSON_CreateString("IP_API_FLOW_HASH_SRC_IP"));
    if (a & IP_API_FLOW_HASH_DST_IP)
       cJSON_AddItemToArray(array, cJSON_CreateString("IP_API_FLOW_HASH_DST_IP"));
    if (a & IP_API_FLOW_HASH_SRC_PORT)
       cJSON_AddItemToArray(array, cJSON_CreateString("IP_API_FLOW_HASH_SRC_PORT"));
    if (a & IP_API_FLOW_HASH_DST_PORT)
       cJSON_AddItemToArray(array, cJSON_CreateString("IP_API_FLOW_HASH_DST_PORT"));
    if (a & IP_API_FLOW_HASH_PROTO)
       cJSON_AddItemToArray(array, cJSON_CreateString("IP_API_FLOW_HASH_PROTO"));
    if (a & IP_API_FLOW_HASH_REVERSE)
       cJSON_AddItemToArray(array, cJSON_CreateString("IP_API_FLOW_HASH_REVERSE"));
    if (a & IP_API_FLOW_HASH_SYMETRIC)
       cJSON_AddItemToArray(array, cJSON_CreateString("IP_API_FLOW_HASH_SYMETRIC"));
    if (a & IP_API_FLOW_HASH_FLOW_LABEL)
       cJSON_AddItemToArray(array, cJSON_CreateString("IP_API_FLOW_HASH_FLOW_LABEL"));
    return array;
}
static inline cJSON *vl_api_ip_flow_hash_config_v2_t_tojson (vl_api_ip_flow_hash_config_v2_t a) {
    cJSON *array = cJSON_CreateArray();
    if (a & IP_API_V2_FLOW_HASH_SRC_IP)
       cJSON_AddItemToArray(array, cJSON_CreateString("IP_API_V2_FLOW_HASH_SRC_IP"));
    if (a & IP_API_V2_FLOW_HASH_DST_IP)
       cJSON_AddItemToArray(array, cJSON_CreateString("IP_API_V2_FLOW_HASH_DST_IP"));
    if (a & IP_API_V2_FLOW_HASH_SRC_PORT)
       cJSON_AddItemToArray(array, cJSON_CreateString("IP_API_V2_FLOW_HASH_SRC_PORT"));
    if (a & IP_API_V2_FLOW_HASH_DST_PORT)
       cJSON_AddItemToArray(array, cJSON_CreateString("IP_API_V2_FLOW_HASH_DST_PORT"));
    if (a & IP_API_V2_FLOW_HASH_PROTO)
       cJSON_AddItemToArray(array, cJSON_CreateString("IP_API_V2_FLOW_HASH_PROTO"));
    if (a & IP_API_V2_FLOW_HASH_REVERSE)
       cJSON_AddItemToArray(array, cJSON_CreateString("IP_API_V2_FLOW_HASH_REVERSE"));
    if (a & IP_API_V2_FLOW_HASH_SYMETRIC)
       cJSON_AddItemToArray(array, cJSON_CreateString("IP_API_V2_FLOW_HASH_SYMETRIC"));
    if (a & IP_API_V2_FLOW_HASH_FLOW_LABEL)
       cJSON_AddItemToArray(array, cJSON_CreateString("IP_API_V2_FLOW_HASH_FLOW_LABEL"));
    if (a & IP_API_V2_FLOW_HASH_GTPV1_TEID)
       cJSON_AddItemToArray(array, cJSON_CreateString("IP_API_V2_FLOW_HASH_GTPV1_TEID"));
    return array;
}
static inline cJSON *vl_api_ip_mroute_t_tojson (vl_api_ip_mroute_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "table_id", a->table_id);
    cJSON_AddItemToObject(o, "entry_flags", vl_api_mfib_entry_flags_t_tojson(a->entry_flags));
    cJSON_AddNumberToObject(o, "rpf_id", a->rpf_id);
    cJSON_AddItemToObject(o, "prefix", vl_api_mprefix_t_tojson(&a->prefix));
    cJSON_AddNumberToObject(o, "n_paths", a->n_paths);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "paths");
        for (i = 0; i < a->n_paths; i++) {
            cJSON_AddItemToArray(array, vl_api_mfib_path_t_tojson(&a->paths[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_punt_redirect_t_tojson (vl_api_punt_redirect_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "rx_sw_if_index", a->rx_sw_if_index);
    cJSON_AddNumberToObject(o, "tx_sw_if_index", a->tx_sw_if_index);
    cJSON_AddItemToObject(o, "nh", vl_api_address_t_tojson(&a->nh));
    return o;
}
static inline cJSON *vl_api_punt_redirect_v2_t_tojson (vl_api_punt_redirect_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "rx_sw_if_index", a->rx_sw_if_index);
    cJSON_AddItemToObject(o, "af", vl_api_address_family_t_tojson(a->af));
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
static inline cJSON *vl_api_ip_reass_type_t_tojson (vl_api_ip_reass_type_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("IP_REASS_TYPE_FULL");
    case 1:
        return cJSON_CreateString("IP_REASS_TYPE_SHALLOW_VIRTUAL");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_ip_path_mtu_t_tojson (vl_api_ip_path_mtu_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "table_id", a->table_id);
    cJSON_AddItemToObject(o, "nh", vl_api_address_t_tojson(&a->nh));
    cJSON_AddNumberToObject(o, "path_mtu", a->path_mtu);
    return o;
}
static inline cJSON *vl_api_ip_table_add_del_t_tojson (vl_api_ip_table_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_table_add_del");
    cJSON_AddStringToObject(o, "_crc", "0ffdaec0");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "table", vl_api_ip_table_t_tojson(&a->table));
    return o;
}
static inline cJSON *vl_api_ip_table_add_del_reply_t_tojson (vl_api_ip_table_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_table_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ip_table_add_del_v2_t_tojson (vl_api_ip_table_add_del_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_table_add_del_v2");
    cJSON_AddStringToObject(o, "_crc", "14e5081f");
    cJSON_AddItemToObject(o, "table", vl_api_ip_table_t_tojson(&a->table));
    cJSON_AddBoolToObject(o, "create_mfib", a->create_mfib);
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    return o;
}
static inline cJSON *vl_api_ip_table_add_del_v2_reply_t_tojson (vl_api_ip_table_add_del_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_table_add_del_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ip_table_allocate_t_tojson (vl_api_ip_table_allocate_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_table_allocate");
    cJSON_AddStringToObject(o, "_crc", "b9d2e09e");
    cJSON_AddItemToObject(o, "table", vl_api_ip_table_t_tojson(&a->table));
    return o;
}
static inline cJSON *vl_api_ip_table_allocate_reply_t_tojson (vl_api_ip_table_allocate_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_table_allocate_reply");
    cJSON_AddStringToObject(o, "_crc", "1728303a");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddItemToObject(o, "table", vl_api_ip_table_t_tojson(&a->table));
    return o;
}
static inline cJSON *vl_api_ip_table_dump_t_tojson (vl_api_ip_table_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_table_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_ip_table_replace_begin_t_tojson (vl_api_ip_table_replace_begin_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_table_replace_begin");
    cJSON_AddStringToObject(o, "_crc", "b9d2e09e");
    cJSON_AddItemToObject(o, "table", vl_api_ip_table_t_tojson(&a->table));
    return o;
}
static inline cJSON *vl_api_ip_table_replace_begin_reply_t_tojson (vl_api_ip_table_replace_begin_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_table_replace_begin_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ip_table_replace_end_t_tojson (vl_api_ip_table_replace_end_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_table_replace_end");
    cJSON_AddStringToObject(o, "_crc", "b9d2e09e");
    cJSON_AddItemToObject(o, "table", vl_api_ip_table_t_tojson(&a->table));
    return o;
}
static inline cJSON *vl_api_ip_table_replace_end_reply_t_tojson (vl_api_ip_table_replace_end_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_table_replace_end_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ip_table_flush_t_tojson (vl_api_ip_table_flush_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_table_flush");
    cJSON_AddStringToObject(o, "_crc", "b9d2e09e");
    cJSON_AddItemToObject(o, "table", vl_api_ip_table_t_tojson(&a->table));
    return o;
}
static inline cJSON *vl_api_ip_table_flush_reply_t_tojson (vl_api_ip_table_flush_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_table_flush_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ip_table_details_t_tojson (vl_api_ip_table_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_table_details");
    cJSON_AddStringToObject(o, "_crc", "c79fca0f");
    cJSON_AddItemToObject(o, "table", vl_api_ip_table_t_tojson(&a->table));
    return o;
}
static inline cJSON *vl_api_ip_route_add_del_t_tojson (vl_api_ip_route_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_route_add_del");
    cJSON_AddStringToObject(o, "_crc", "b8ecfe0d");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddBoolToObject(o, "is_multipath", a->is_multipath);
    cJSON_AddItemToObject(o, "route", vl_api_ip_route_t_tojson(&a->route));
    return o;
}
static inline cJSON *vl_api_ip_route_add_del_v2_t_tojson (vl_api_ip_route_add_del_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_route_add_del_v2");
    cJSON_AddStringToObject(o, "_crc", "521ef330");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddBoolToObject(o, "is_multipath", a->is_multipath);
    cJSON_AddItemToObject(o, "route", vl_api_ip_route_v2_t_tojson(&a->route));
    return o;
}
static inline cJSON *vl_api_ip_route_add_del_reply_t_tojson (vl_api_ip_route_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_route_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "1992deab");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "stats_index", a->stats_index);
    return o;
}
static inline cJSON *vl_api_ip_route_add_del_v2_reply_t_tojson (vl_api_ip_route_add_del_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_route_add_del_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "1992deab");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "stats_index", a->stats_index);
    return o;
}
static inline cJSON *vl_api_ip_route_dump_t_tojson (vl_api_ip_route_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_route_dump");
    cJSON_AddStringToObject(o, "_crc", "b9d2e09e");
    cJSON_AddItemToObject(o, "table", vl_api_ip_table_t_tojson(&a->table));
    return o;
}
static inline cJSON *vl_api_ip_route_v2_dump_t_tojson (vl_api_ip_route_v2_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_route_v2_dump");
    cJSON_AddStringToObject(o, "_crc", "d16f72e6");
    cJSON_AddNumberToObject(o, "src", a->src);
    cJSON_AddItemToObject(o, "table", vl_api_ip_table_t_tojson(&a->table));
    return o;
}
static inline cJSON *vl_api_ip_route_details_t_tojson (vl_api_ip_route_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_route_details");
    cJSON_AddStringToObject(o, "_crc", "bda8f315");
    cJSON_AddItemToObject(o, "route", vl_api_ip_route_t_tojson(&a->route));
    return o;
}
static inline cJSON *vl_api_ip_route_v2_details_t_tojson (vl_api_ip_route_v2_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_route_v2_details");
    cJSON_AddStringToObject(o, "_crc", "b09aa6c0");
    cJSON_AddItemToObject(o, "route", vl_api_ip_route_v2_t_tojson(&a->route));
    return o;
}
static inline cJSON *vl_api_ip_route_lookup_t_tojson (vl_api_ip_route_lookup_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_route_lookup");
    cJSON_AddStringToObject(o, "_crc", "710d6471");
    cJSON_AddNumberToObject(o, "table_id", a->table_id);
    cJSON_AddNumberToObject(o, "exact", a->exact);
    cJSON_AddItemToObject(o, "prefix", vl_api_prefix_t_tojson(&a->prefix));
    return o;
}
static inline cJSON *vl_api_ip_route_lookup_v2_t_tojson (vl_api_ip_route_lookup_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_route_lookup_v2");
    cJSON_AddStringToObject(o, "_crc", "710d6471");
    cJSON_AddNumberToObject(o, "table_id", a->table_id);
    cJSON_AddNumberToObject(o, "exact", a->exact);
    cJSON_AddItemToObject(o, "prefix", vl_api_prefix_t_tojson(&a->prefix));
    return o;
}
static inline cJSON *vl_api_ip_route_lookup_reply_t_tojson (vl_api_ip_route_lookup_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_route_lookup_reply");
    cJSON_AddStringToObject(o, "_crc", "5d8febcb");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddItemToObject(o, "route", vl_api_ip_route_t_tojson(&a->route));
    return o;
}
static inline cJSON *vl_api_ip_route_lookup_v2_reply_t_tojson (vl_api_ip_route_lookup_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_route_lookup_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "84cc9e03");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddItemToObject(o, "route", vl_api_ip_route_v2_t_tojson(&a->route));
    return o;
}
static inline cJSON *vl_api_set_ip_flow_hash_t_tojson (vl_api_set_ip_flow_hash_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "set_ip_flow_hash");
    cJSON_AddStringToObject(o, "_crc", "084ee09e");
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    cJSON_AddBoolToObject(o, "is_ipv6", a->is_ipv6);
    cJSON_AddBoolToObject(o, "src", a->src);
    cJSON_AddBoolToObject(o, "dst", a->dst);
    cJSON_AddBoolToObject(o, "sport", a->sport);
    cJSON_AddBoolToObject(o, "dport", a->dport);
    cJSON_AddBoolToObject(o, "proto", a->proto);
    cJSON_AddBoolToObject(o, "reverse", a->reverse);
    cJSON_AddBoolToObject(o, "symmetric", a->symmetric);
    return o;
}
static inline cJSON *vl_api_set_ip_flow_hash_reply_t_tojson (vl_api_set_ip_flow_hash_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "set_ip_flow_hash_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_set_ip_flow_hash_v2_t_tojson (vl_api_set_ip_flow_hash_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "set_ip_flow_hash_v2");
    cJSON_AddStringToObject(o, "_crc", "6d132100");
    cJSON_AddNumberToObject(o, "table_id", a->table_id);
    cJSON_AddItemToObject(o, "af", vl_api_address_family_t_tojson(a->af));
    cJSON_AddItemToObject(o, "flow_hash_config", vl_api_ip_flow_hash_config_t_tojson(a->flow_hash_config));
    return o;
}
static inline cJSON *vl_api_set_ip_flow_hash_v2_reply_t_tojson (vl_api_set_ip_flow_hash_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "set_ip_flow_hash_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_set_ip_flow_hash_v3_t_tojson (vl_api_set_ip_flow_hash_v3_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "set_ip_flow_hash_v3");
    cJSON_AddStringToObject(o, "_crc", "b7876e07");
    cJSON_AddNumberToObject(o, "table_id", a->table_id);
    cJSON_AddItemToObject(o, "af", vl_api_address_family_t_tojson(a->af));
    cJSON_AddItemToObject(o, "flow_hash_config", vl_api_ip_flow_hash_config_v2_t_tojson(a->flow_hash_config));
    return o;
}
static inline cJSON *vl_api_set_ip_flow_hash_v3_reply_t_tojson (vl_api_set_ip_flow_hash_v3_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "set_ip_flow_hash_v3_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_set_ip_flow_hash_router_id_t_tojson (vl_api_set_ip_flow_hash_router_id_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "set_ip_flow_hash_router_id");
    cJSON_AddStringToObject(o, "_crc", "03e4f48e");
    cJSON_AddNumberToObject(o, "router_id", a->router_id);
    return o;
}
static inline cJSON *vl_api_set_ip_flow_hash_router_id_reply_t_tojson (vl_api_set_ip_flow_hash_router_id_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "set_ip_flow_hash_router_id_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sw_interface_ip6_enable_disable_t_tojson (vl_api_sw_interface_ip6_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_ip6_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "ae6cfcfb");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "enable", a->enable);
    return o;
}
static inline cJSON *vl_api_sw_interface_ip6_enable_disable_reply_t_tojson (vl_api_sw_interface_ip6_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_ip6_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sw_interface_ip4_enable_disable_t_tojson (vl_api_sw_interface_ip4_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_ip4_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "ae6cfcfb");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "enable", a->enable);
    return o;
}
static inline cJSON *vl_api_sw_interface_ip4_enable_disable_reply_t_tojson (vl_api_sw_interface_ip4_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_ip4_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ip_mtable_dump_t_tojson (vl_api_ip_mtable_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_mtable_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_ip_mtable_details_t_tojson (vl_api_ip_mtable_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_mtable_details");
    cJSON_AddStringToObject(o, "_crc", "b9d2e09e");
    cJSON_AddItemToObject(o, "table", vl_api_ip_table_t_tojson(&a->table));
    return o;
}
static inline cJSON *vl_api_ip_mroute_add_del_t_tojson (vl_api_ip_mroute_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_mroute_add_del");
    cJSON_AddStringToObject(o, "_crc", "0dd7e790");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddBoolToObject(o, "is_multipath", a->is_multipath);
    cJSON_AddItemToObject(o, "route", vl_api_ip_mroute_t_tojson(&a->route));
    return o;
}
static inline cJSON *vl_api_ip_mroute_add_del_reply_t_tojson (vl_api_ip_mroute_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_mroute_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "1992deab");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "stats_index", a->stats_index);
    return o;
}
static inline cJSON *vl_api_ip_mroute_dump_t_tojson (vl_api_ip_mroute_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_mroute_dump");
    cJSON_AddStringToObject(o, "_crc", "b9d2e09e");
    cJSON_AddItemToObject(o, "table", vl_api_ip_table_t_tojson(&a->table));
    return o;
}
static inline cJSON *vl_api_ip_mroute_details_t_tojson (vl_api_ip_mroute_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_mroute_details");
    cJSON_AddStringToObject(o, "_crc", "c5cb23fc");
    cJSON_AddItemToObject(o, "route", vl_api_ip_mroute_t_tojson(&a->route));
    return o;
}
static inline cJSON *vl_api_ip_address_details_t_tojson (vl_api_ip_address_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_address_details");
    cJSON_AddStringToObject(o, "_crc", "ee29b797");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "prefix", vl_api_address_with_prefix_t_tojson(&a->prefix));
    return o;
}
static inline cJSON *vl_api_ip_address_dump_t_tojson (vl_api_ip_address_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_address_dump");
    cJSON_AddStringToObject(o, "_crc", "2d033de4");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "is_ipv6", a->is_ipv6);
    return o;
}
static inline cJSON *vl_api_ip_unnumbered_details_t_tojson (vl_api_ip_unnumbered_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_unnumbered_details");
    cJSON_AddStringToObject(o, "_crc", "cc59bd42");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "ip_sw_if_index", a->ip_sw_if_index);
    return o;
}
static inline cJSON *vl_api_ip_unnumbered_dump_t_tojson (vl_api_ip_unnumbered_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_unnumbered_dump");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_ip_details_t_tojson (vl_api_ip_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_details");
    cJSON_AddStringToObject(o, "_crc", "eb152d07");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "is_ipv6", a->is_ipv6);
    return o;
}
static inline cJSON *vl_api_ip_dump_t_tojson (vl_api_ip_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_dump");
    cJSON_AddStringToObject(o, "_crc", "98d231ca");
    cJSON_AddBoolToObject(o, "is_ipv6", a->is_ipv6);
    return o;
}
static inline cJSON *vl_api_mfib_signal_dump_t_tojson (vl_api_mfib_signal_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "mfib_signal_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_mfib_signal_details_t_tojson (vl_api_mfib_signal_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "mfib_signal_details");
    cJSON_AddStringToObject(o, "_crc", "6f4a4cfb");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "table_id", a->table_id);
    cJSON_AddItemToObject(o, "prefix", vl_api_mprefix_t_tojson(&a->prefix));
    cJSON_AddNumberToObject(o, "ip_packet_len", a->ip_packet_len);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->ip_packet_data, 256);
    cJSON_AddStringToObject(o, "ip_packet_data", s);
    vec_free(s);
    }
    return o;
}
static inline cJSON *vl_api_ip_punt_police_t_tojson (vl_api_ip_punt_police_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_punt_police");
    cJSON_AddStringToObject(o, "_crc", "db867cea");
    cJSON_AddNumberToObject(o, "policer_index", a->policer_index);
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddBoolToObject(o, "is_ip6", a->is_ip6);
    return o;
}
static inline cJSON *vl_api_ip_punt_police_reply_t_tojson (vl_api_ip_punt_police_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_punt_police_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ip_punt_redirect_t_tojson (vl_api_ip_punt_redirect_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_punt_redirect");
    cJSON_AddStringToObject(o, "_crc", "6580f635");
    cJSON_AddItemToObject(o, "punt", vl_api_punt_redirect_t_tojson(&a->punt));
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    return o;
}
static inline cJSON *vl_api_ip_punt_redirect_reply_t_tojson (vl_api_ip_punt_redirect_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_punt_redirect_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ip_punt_redirect_dump_t_tojson (vl_api_ip_punt_redirect_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_punt_redirect_dump");
    cJSON_AddStringToObject(o, "_crc", "2d033de4");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "is_ipv6", a->is_ipv6);
    return o;
}
static inline cJSON *vl_api_ip_punt_redirect_details_t_tojson (vl_api_ip_punt_redirect_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_punt_redirect_details");
    cJSON_AddStringToObject(o, "_crc", "2cef63e7");
    cJSON_AddItemToObject(o, "punt", vl_api_punt_redirect_t_tojson(&a->punt));
    return o;
}
static inline cJSON *vl_api_add_del_ip_punt_redirect_v2_t_tojson (vl_api_add_del_ip_punt_redirect_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "add_del_ip_punt_redirect_v2");
    cJSON_AddStringToObject(o, "_crc", "9e804227");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "punt", vl_api_punt_redirect_v2_t_tojson(&a->punt));
    return o;
}
static inline cJSON *vl_api_add_del_ip_punt_redirect_v2_reply_t_tojson (vl_api_add_del_ip_punt_redirect_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "add_del_ip_punt_redirect_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ip_punt_redirect_v2_dump_t_tojson (vl_api_ip_punt_redirect_v2_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_punt_redirect_v2_dump");
    cJSON_AddStringToObject(o, "_crc", "d817a484");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "af", vl_api_address_family_t_tojson(a->af));
    return o;
}
static inline cJSON *vl_api_ip_punt_redirect_v2_details_t_tojson (vl_api_ip_punt_redirect_v2_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_punt_redirect_v2_details");
    cJSON_AddStringToObject(o, "_crc", "7ba42e1d");
    cJSON_AddItemToObject(o, "punt", vl_api_punt_redirect_v2_t_tojson(&a->punt));
    return o;
}
static inline cJSON *vl_api_ip_container_proxy_add_del_t_tojson (vl_api_ip_container_proxy_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_container_proxy_add_del");
    cJSON_AddStringToObject(o, "_crc", "7df1dff1");
    cJSON_AddItemToObject(o, "pfx", vl_api_prefix_t_tojson(&a->pfx));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    return o;
}
static inline cJSON *vl_api_ip_container_proxy_add_del_reply_t_tojson (vl_api_ip_container_proxy_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_container_proxy_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ip_container_proxy_dump_t_tojson (vl_api_ip_container_proxy_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_container_proxy_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_ip_container_proxy_details_t_tojson (vl_api_ip_container_proxy_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_container_proxy_details");
    cJSON_AddStringToObject(o, "_crc", "a8085523");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "prefix", vl_api_prefix_t_tojson(&a->prefix));
    return o;
}
static inline cJSON *vl_api_ip_source_and_port_range_check_add_del_t_tojson (vl_api_ip_source_and_port_range_check_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_source_and_port_range_check_add_del");
    cJSON_AddStringToObject(o, "_crc", "92a067e3");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "prefix", vl_api_prefix_t_tojson(&a->prefix));
    cJSON_AddNumberToObject(o, "number_of_ranges", a->number_of_ranges);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "low_ports");
        for (i = 0; i < 32; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->low_ports[i]));
        }
    }
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "high_ports");
        for (i = 0; i < 32; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->high_ports[i]));
        }
    }
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    return o;
}
static inline cJSON *vl_api_ip_source_and_port_range_check_add_del_reply_t_tojson (vl_api_ip_source_and_port_range_check_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_source_and_port_range_check_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ip_source_and_port_range_check_interface_add_del_t_tojson (vl_api_ip_source_and_port_range_check_interface_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_source_and_port_range_check_interface_add_del");
    cJSON_AddStringToObject(o, "_crc", "e1ba8987");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "tcp_in_vrf_id", a->tcp_in_vrf_id);
    cJSON_AddNumberToObject(o, "tcp_out_vrf_id", a->tcp_out_vrf_id);
    cJSON_AddNumberToObject(o, "udp_in_vrf_id", a->udp_in_vrf_id);
    cJSON_AddNumberToObject(o, "udp_out_vrf_id", a->udp_out_vrf_id);
    return o;
}
static inline cJSON *vl_api_ip_source_and_port_range_check_interface_add_del_reply_t_tojson (vl_api_ip_source_and_port_range_check_interface_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_source_and_port_range_check_interface_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sw_interface_ip6_set_link_local_address_t_tojson (vl_api_sw_interface_ip6_set_link_local_address_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_ip6_set_link_local_address");
    cJSON_AddStringToObject(o, "_crc", "1c10f15f");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "ip", vl_api_ip6_address_t_tojson(&a->ip));
    return o;
}
static inline cJSON *vl_api_sw_interface_ip6_set_link_local_address_reply_t_tojson (vl_api_sw_interface_ip6_set_link_local_address_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_ip6_set_link_local_address_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sw_interface_ip6_get_link_local_address_t_tojson (vl_api_sw_interface_ip6_get_link_local_address_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_ip6_get_link_local_address");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_sw_interface_ip6_get_link_local_address_reply_t_tojson (vl_api_sw_interface_ip6_get_link_local_address_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_ip6_get_link_local_address_reply");
    cJSON_AddStringToObject(o, "_crc", "d16b7130");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddItemToObject(o, "ip", vl_api_ip6_address_t_tojson(&a->ip));
    return o;
}
static inline cJSON *vl_api_ioam_enable_t_tojson (vl_api_ioam_enable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ioam_enable");
    cJSON_AddStringToObject(o, "_crc", "51ccd868");
    cJSON_AddNumberToObject(o, "id", a->id);
    cJSON_AddBoolToObject(o, "seqno", a->seqno);
    cJSON_AddBoolToObject(o, "analyse", a->analyse);
    cJSON_AddBoolToObject(o, "pot_enable", a->pot_enable);
    cJSON_AddBoolToObject(o, "trace_enable", a->trace_enable);
    cJSON_AddNumberToObject(o, "node_id", a->node_id);
    return o;
}
static inline cJSON *vl_api_ioam_enable_reply_t_tojson (vl_api_ioam_enable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ioam_enable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ioam_disable_t_tojson (vl_api_ioam_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ioam_disable");
    cJSON_AddStringToObject(o, "_crc", "6b16a45e");
    cJSON_AddNumberToObject(o, "id", a->id);
    return o;
}
static inline cJSON *vl_api_ioam_disable_reply_t_tojson (vl_api_ioam_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ioam_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ip_reassembly_set_t_tojson (vl_api_ip_reassembly_set_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_reassembly_set");
    cJSON_AddStringToObject(o, "_crc", "16467d25");
    cJSON_AddNumberToObject(o, "timeout_ms", a->timeout_ms);
    cJSON_AddNumberToObject(o, "max_reassemblies", a->max_reassemblies);
    cJSON_AddNumberToObject(o, "max_reassembly_length", a->max_reassembly_length);
    cJSON_AddNumberToObject(o, "expire_walk_interval_ms", a->expire_walk_interval_ms);
    cJSON_AddBoolToObject(o, "is_ip6", a->is_ip6);
    cJSON_AddItemToObject(o, "type", vl_api_ip_reass_type_t_tojson(a->type));
    return o;
}
static inline cJSON *vl_api_ip_reassembly_set_reply_t_tojson (vl_api_ip_reassembly_set_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_reassembly_set_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ip_reassembly_get_t_tojson (vl_api_ip_reassembly_get_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_reassembly_get");
    cJSON_AddStringToObject(o, "_crc", "ea13ff63");
    cJSON_AddBoolToObject(o, "is_ip6", a->is_ip6);
    cJSON_AddItemToObject(o, "type", vl_api_ip_reass_type_t_tojson(a->type));
    return o;
}
static inline cJSON *vl_api_ip_reassembly_get_reply_t_tojson (vl_api_ip_reassembly_get_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_reassembly_get_reply");
    cJSON_AddStringToObject(o, "_crc", "d5eb8d34");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "timeout_ms", a->timeout_ms);
    cJSON_AddNumberToObject(o, "max_reassemblies", a->max_reassemblies);
    cJSON_AddNumberToObject(o, "max_reassembly_length", a->max_reassembly_length);
    cJSON_AddNumberToObject(o, "expire_walk_interval_ms", a->expire_walk_interval_ms);
    cJSON_AddBoolToObject(o, "is_ip6", a->is_ip6);
    return o;
}
static inline cJSON *vl_api_ip_reassembly_enable_disable_t_tojson (vl_api_ip_reassembly_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_reassembly_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "eb77968d");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "enable_ip4", a->enable_ip4);
    cJSON_AddBoolToObject(o, "enable_ip6", a->enable_ip6);
    cJSON_AddItemToObject(o, "type", vl_api_ip_reass_type_t_tojson(a->type));
    return o;
}
static inline cJSON *vl_api_ip_reassembly_enable_disable_reply_t_tojson (vl_api_ip_reassembly_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_reassembly_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ip_local_reass_enable_disable_t_tojson (vl_api_ip_local_reass_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_local_reass_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "34e2ccc4");
    cJSON_AddBoolToObject(o, "enable_ip4", a->enable_ip4);
    cJSON_AddBoolToObject(o, "enable_ip6", a->enable_ip6);
    return o;
}
static inline cJSON *vl_api_ip_local_reass_enable_disable_reply_t_tojson (vl_api_ip_local_reass_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_local_reass_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ip_local_reass_get_t_tojson (vl_api_ip_local_reass_get_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_local_reass_get");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_ip_local_reass_get_reply_t_tojson (vl_api_ip_local_reass_get_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_local_reass_get_reply");
    cJSON_AddStringToObject(o, "_crc", "3e93a702");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddBoolToObject(o, "ip4_is_enabled", a->ip4_is_enabled);
    cJSON_AddBoolToObject(o, "ip6_is_enabled", a->ip6_is_enabled);
    return o;
}
static inline cJSON *vl_api_ip_path_mtu_update_t_tojson (vl_api_ip_path_mtu_update_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_path_mtu_update");
    cJSON_AddStringToObject(o, "_crc", "10bbe5cb");
    cJSON_AddItemToObject(o, "pmtu", vl_api_ip_path_mtu_t_tojson(&a->pmtu));
    return o;
}
static inline cJSON *vl_api_ip_path_mtu_update_reply_t_tojson (vl_api_ip_path_mtu_update_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_path_mtu_update_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ip_path_mtu_get_t_tojson (vl_api_ip_path_mtu_get_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_path_mtu_get");
    cJSON_AddStringToObject(o, "_crc", "f75ba505");
    cJSON_AddNumberToObject(o, "cursor", a->cursor);
    return o;
}
static inline cJSON *vl_api_ip_path_mtu_get_reply_t_tojson (vl_api_ip_path_mtu_get_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_path_mtu_get_reply");
    cJSON_AddStringToObject(o, "_crc", "53b48f5d");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "cursor", a->cursor);
    return o;
}
static inline cJSON *vl_api_ip_path_mtu_details_t_tojson (vl_api_ip_path_mtu_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_path_mtu_details");
    cJSON_AddStringToObject(o, "_crc", "ac9539a7");
    cJSON_AddItemToObject(o, "pmtu", vl_api_ip_path_mtu_t_tojson(&a->pmtu));
    return o;
}
static inline cJSON *vl_api_ip_path_mtu_replace_begin_t_tojson (vl_api_ip_path_mtu_replace_begin_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_path_mtu_replace_begin");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_ip_path_mtu_replace_begin_reply_t_tojson (vl_api_ip_path_mtu_replace_begin_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_path_mtu_replace_begin_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ip_path_mtu_replace_end_t_tojson (vl_api_ip_path_mtu_replace_end_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_path_mtu_replace_end");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_ip_path_mtu_replace_end_reply_t_tojson (vl_api_ip_path_mtu_replace_end_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_path_mtu_replace_end_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
