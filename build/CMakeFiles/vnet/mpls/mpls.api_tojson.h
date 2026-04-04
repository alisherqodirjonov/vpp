/* Imported API files */
#include <vnet/fib/fib_types.api_tojson.h>
#include <vnet/ip/ip_types.api_tojson.h>
#include <vnet/interface_types.api_tojson.h>
#ifndef included_mpls_api_tojson_h
#define included_mpls_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_mpls_tunnel_t_tojson (vl_api_mpls_tunnel_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "mt_sw_if_index", a->mt_sw_if_index);
    cJSON_AddNumberToObject(o, "mt_tunnel_index", a->mt_tunnel_index);
    cJSON_AddBoolToObject(o, "mt_l2_only", a->mt_l2_only);
    cJSON_AddBoolToObject(o, "mt_is_multicast", a->mt_is_multicast);
    cJSON_AddStringToObject(o, "mt_tag", (char *)a->mt_tag);
    cJSON_AddNumberToObject(o, "mt_n_paths", a->mt_n_paths);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "mt_paths");
        for (i = 0; i < a->mt_n_paths; i++) {
            cJSON_AddItemToArray(array, vl_api_fib_path_t_tojson(&a->mt_paths[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_mpls_table_t_tojson (vl_api_mpls_table_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "mt_table_id", a->mt_table_id);
    cJSON_AddStringToObject(o, "mt_name", (char *)a->mt_name);
    return o;
}
static inline cJSON *vl_api_mpls_route_t_tojson (vl_api_mpls_route_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "mr_table_id", a->mr_table_id);
    cJSON_AddNumberToObject(o, "mr_label", a->mr_label);
    cJSON_AddNumberToObject(o, "mr_eos", a->mr_eos);
    cJSON_AddNumberToObject(o, "mr_eos_proto", a->mr_eos_proto);
    cJSON_AddBoolToObject(o, "mr_is_multicast", a->mr_is_multicast);
    cJSON_AddNumberToObject(o, "mr_n_paths", a->mr_n_paths);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "mr_paths");
        for (i = 0; i < a->mr_n_paths; i++) {
            cJSON_AddItemToArray(array, vl_api_fib_path_t_tojson(&a->mr_paths[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_mpls_ip_bind_unbind_t_tojson (vl_api_mpls_ip_bind_unbind_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "mpls_ip_bind_unbind");
    cJSON_AddStringToObject(o, "_crc", "c7533b32");
    cJSON_AddNumberToObject(o, "mb_mpls_table_id", a->mb_mpls_table_id);
    cJSON_AddNumberToObject(o, "mb_label", a->mb_label);
    cJSON_AddNumberToObject(o, "mb_ip_table_id", a->mb_ip_table_id);
    cJSON_AddBoolToObject(o, "mb_is_bind", a->mb_is_bind);
    cJSON_AddItemToObject(o, "mb_prefix", vl_api_prefix_t_tojson(&a->mb_prefix));
    return o;
}
static inline cJSON *vl_api_mpls_ip_bind_unbind_reply_t_tojson (vl_api_mpls_ip_bind_unbind_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "mpls_ip_bind_unbind_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_mpls_tunnel_add_del_t_tojson (vl_api_mpls_tunnel_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "mpls_tunnel_add_del");
    cJSON_AddStringToObject(o, "_crc", "44350ac1");
    cJSON_AddBoolToObject(o, "mt_is_add", a->mt_is_add);
    cJSON_AddItemToObject(o, "mt_tunnel", vl_api_mpls_tunnel_t_tojson(&a->mt_tunnel));
    return o;
}
static inline cJSON *vl_api_mpls_tunnel_add_del_reply_t_tojson (vl_api_mpls_tunnel_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "mpls_tunnel_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "afb01472");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "tunnel_index", a->tunnel_index);
    return o;
}
static inline cJSON *vl_api_mpls_tunnel_dump_t_tojson (vl_api_mpls_tunnel_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "mpls_tunnel_dump");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_mpls_tunnel_details_t_tojson (vl_api_mpls_tunnel_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "mpls_tunnel_details");
    cJSON_AddStringToObject(o, "_crc", "57118ae3");
    cJSON_AddItemToObject(o, "mt_tunnel", vl_api_mpls_tunnel_t_tojson(&a->mt_tunnel));
    return o;
}
static inline cJSON *vl_api_mpls_interface_dump_t_tojson (vl_api_mpls_interface_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "mpls_interface_dump");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_mpls_interface_details_t_tojson (vl_api_mpls_interface_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "mpls_interface_details");
    cJSON_AddStringToObject(o, "_crc", "0b45011c");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_mpls_table_add_del_t_tojson (vl_api_mpls_table_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "mpls_table_add_del");
    cJSON_AddStringToObject(o, "_crc", "57817512");
    cJSON_AddBoolToObject(o, "mt_is_add", a->mt_is_add);
    cJSON_AddItemToObject(o, "mt_table", vl_api_mpls_table_t_tojson(&a->mt_table));
    return o;
}
static inline cJSON *vl_api_mpls_table_add_del_reply_t_tojson (vl_api_mpls_table_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "mpls_table_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_mpls_table_dump_t_tojson (vl_api_mpls_table_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "mpls_table_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_mpls_table_details_t_tojson (vl_api_mpls_table_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "mpls_table_details");
    cJSON_AddStringToObject(o, "_crc", "f03ecdc8");
    cJSON_AddItemToObject(o, "mt_table", vl_api_mpls_table_t_tojson(&a->mt_table));
    return o;
}
static inline cJSON *vl_api_mpls_route_add_del_t_tojson (vl_api_mpls_route_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "mpls_route_add_del");
    cJSON_AddStringToObject(o, "_crc", "8e1d1e07");
    cJSON_AddBoolToObject(o, "mr_is_add", a->mr_is_add);
    cJSON_AddBoolToObject(o, "mr_is_multipath", a->mr_is_multipath);
    cJSON_AddItemToObject(o, "mr_route", vl_api_mpls_route_t_tojson(&a->mr_route));
    return o;
}
static inline cJSON *vl_api_mpls_route_add_del_reply_t_tojson (vl_api_mpls_route_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "mpls_route_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "1992deab");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "stats_index", a->stats_index);
    return o;
}
static inline cJSON *vl_api_mpls_route_dump_t_tojson (vl_api_mpls_route_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "mpls_route_dump");
    cJSON_AddStringToObject(o, "_crc", "935fdefa");
    cJSON_AddItemToObject(o, "table", vl_api_mpls_table_t_tojson(&a->table));
    return o;
}
static inline cJSON *vl_api_mpls_route_details_t_tojson (vl_api_mpls_route_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "mpls_route_details");
    cJSON_AddStringToObject(o, "_crc", "9b5043dc");
    cJSON_AddItemToObject(o, "mr_route", vl_api_mpls_route_t_tojson(&a->mr_route));
    return o;
}
static inline cJSON *vl_api_sw_interface_set_mpls_enable_t_tojson (vl_api_sw_interface_set_mpls_enable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_mpls_enable");
    cJSON_AddStringToObject(o, "_crc", "ae6cfcfb");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "enable", a->enable);
    return o;
}
static inline cJSON *vl_api_sw_interface_set_mpls_enable_reply_t_tojson (vl_api_sw_interface_set_mpls_enable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_mpls_enable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
