/* Imported API files */
#include <vnet/ip/ip_types.api_tojson.h>
#include <vnet/fib/fib_types.api_tojson.h>
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ip/ip.api_tojson.h>
#ifndef included_cnat_api_tojson_h
#define included_cnat_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_cnat_translation_flags_t_tojson (vl_api_cnat_translation_flags_t a) {
    switch(a) {
    case 1:
        return cJSON_CreateString("CNAT_TRANSLATION_ALLOC_PORT");
    case 4:
        return cJSON_CreateString("CNAT_TRANSLATION_NO_RETURN_SESSION");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_cnat_endpoint_tuple_flags_t_tojson (vl_api_cnat_endpoint_tuple_flags_t a) {
    switch(a) {
    case 1:
        return cJSON_CreateString("CNAT_EPT_NO_NAT");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_cnat_lb_type_t_tojson (vl_api_cnat_lb_type_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("CNAT_LB_TYPE_DEFAULT");
    case 1:
        return cJSON_CreateString("CNAT_LB_TYPE_MAGLEV");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_cnat_endpoint_t_tojson (vl_api_cnat_endpoint_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "addr", vl_api_address_t_tojson(&a->addr));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "if_af", vl_api_address_family_t_tojson(a->if_af));
    cJSON_AddNumberToObject(o, "port", a->port);
    return o;
}
static inline cJSON *vl_api_cnat_endpoint_tuple_t_tojson (vl_api_cnat_endpoint_tuple_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "dst_ep", vl_api_cnat_endpoint_t_tojson(&a->dst_ep));
    cJSON_AddItemToObject(o, "src_ep", vl_api_cnat_endpoint_t_tojson(&a->src_ep));
    cJSON_AddNumberToObject(o, "flags", a->flags);
    return o;
}
static inline cJSON *vl_api_cnat_translation_t_tojson (vl_api_cnat_translation_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "vip", vl_api_cnat_endpoint_t_tojson(&a->vip));
    cJSON_AddNumberToObject(o, "id", a->id);
    cJSON_AddItemToObject(o, "ip_proto", vl_api_ip_proto_t_tojson(a->ip_proto));
    cJSON_AddNumberToObject(o, "is_real_ip", a->is_real_ip);
    cJSON_AddNumberToObject(o, "flags", a->flags);
    cJSON_AddItemToObject(o, "lb_type", vl_api_cnat_lb_type_t_tojson(a->lb_type));
    cJSON_AddNumberToObject(o, "n_paths", a->n_paths);
    cJSON_AddItemToObject(o, "flow_hash_config", vl_api_ip_flow_hash_config_v2_t_tojson(a->flow_hash_config));
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "paths");
        for (i = 0; i < a->n_paths; i++) {
            cJSON_AddItemToArray(array, vl_api_cnat_endpoint_tuple_t_tojson(&a->paths[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_cnat_session_t_tojson (vl_api_cnat_session_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "src", vl_api_cnat_endpoint_t_tojson(&a->src));
    cJSON_AddItemToObject(o, "dst", vl_api_cnat_endpoint_t_tojson(&a->dst));
    cJSON_AddItemToObject(o, "new", vl_api_cnat_endpoint_t_tojson(&a->new));
    cJSON_AddItemToObject(o, "ip_proto", vl_api_ip_proto_t_tojson(a->ip_proto));
    cJSON_AddNumberToObject(o, "location", a->location);
    cJSON_AddNumberToObject(o, "timestamp", a->timestamp);
    return o;
}
static inline cJSON *vl_api_cnat_snat_policy_table_t_tojson (vl_api_cnat_snat_policy_table_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("CNAT_POLICY_INCLUDE_V4");
    case 1:
        return cJSON_CreateString("CNAT_POLICY_INCLUDE_V6");
    case 2:
        return cJSON_CreateString("CNAT_POLICY_POD");
    case 3:
        return cJSON_CreateString("CNAT_POLICY_HOST");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_cnat_snat_policies_t_tojson (vl_api_cnat_snat_policies_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("CNAT_POLICY_NONE");
    case 1:
        return cJSON_CreateString("CNAT_POLICY_IF_PFX");
    case 2:
        return cJSON_CreateString("CNAT_POLICY_K8S");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_cnat_translation_update_t_tojson (vl_api_cnat_translation_update_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "cnat_translation_update");
    cJSON_AddStringToObject(o, "_crc", "f8d40bc5");
    cJSON_AddItemToObject(o, "translation", vl_api_cnat_translation_t_tojson(&a->translation));
    return o;
}
static inline cJSON *vl_api_cnat_translation_update_reply_t_tojson (vl_api_cnat_translation_update_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "cnat_translation_update_reply");
    cJSON_AddStringToObject(o, "_crc", "e2fc8294");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "id", a->id);
    return o;
}
static inline cJSON *vl_api_cnat_translation_del_t_tojson (vl_api_cnat_translation_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "cnat_translation_del");
    cJSON_AddStringToObject(o, "_crc", "3a91bde5");
    cJSON_AddNumberToObject(o, "id", a->id);
    return o;
}
static inline cJSON *vl_api_cnat_translation_del_reply_t_tojson (vl_api_cnat_translation_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "cnat_translation_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_cnat_translation_details_t_tojson (vl_api_cnat_translation_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "cnat_translation_details");
    cJSON_AddStringToObject(o, "_crc", "1a5140b7");
    cJSON_AddItemToObject(o, "translation", vl_api_cnat_translation_t_tojson(&a->translation));
    return o;
}
static inline cJSON *vl_api_cnat_translation_dump_t_tojson (vl_api_cnat_translation_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "cnat_translation_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_cnat_session_purge_t_tojson (vl_api_cnat_session_purge_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "cnat_session_purge");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_cnat_session_purge_reply_t_tojson (vl_api_cnat_session_purge_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "cnat_session_purge_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_cnat_session_details_t_tojson (vl_api_cnat_session_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "cnat_session_details");
    cJSON_AddStringToObject(o, "_crc", "7e5017c7");
    cJSON_AddItemToObject(o, "session", vl_api_cnat_session_t_tojson(&a->session));
    return o;
}
static inline cJSON *vl_api_cnat_session_dump_t_tojson (vl_api_cnat_session_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "cnat_session_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_cnat_set_snat_addresses_t_tojson (vl_api_cnat_set_snat_addresses_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "cnat_set_snat_addresses");
    cJSON_AddStringToObject(o, "_crc", "d997e96c");
    cJSON_AddItemToObject(o, "snat_ip4", vl_api_ip4_address_t_tojson(&a->snat_ip4));
    cJSON_AddItemToObject(o, "snat_ip6", vl_api_ip6_address_t_tojson(&a->snat_ip6));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_cnat_set_snat_addresses_reply_t_tojson (vl_api_cnat_set_snat_addresses_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "cnat_set_snat_addresses_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_cnat_get_snat_addresses_t_tojson (vl_api_cnat_get_snat_addresses_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "cnat_get_snat_addresses");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_cnat_get_snat_addresses_reply_t_tojson (vl_api_cnat_get_snat_addresses_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "cnat_get_snat_addresses_reply");
    cJSON_AddStringToObject(o, "_crc", "879513c1");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "id", a->id);
    cJSON_AddItemToObject(o, "snat_ip4", vl_api_ip4_address_t_tojson(&a->snat_ip4));
    cJSON_AddItemToObject(o, "snat_ip6", vl_api_ip6_address_t_tojson(&a->snat_ip6));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_cnat_snat_policy_add_del_exclude_pfx_t_tojson (vl_api_cnat_snat_policy_add_del_exclude_pfx_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "cnat_snat_policy_add_del_exclude_pfx");
    cJSON_AddStringToObject(o, "_crc", "e26dd79a");
    cJSON_AddNumberToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "prefix", vl_api_prefix_t_tojson(&a->prefix));
    return o;
}
static inline cJSON *vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t_tojson (vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "cnat_snat_policy_add_del_exclude_pfx_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_cnat_snat_policy_add_del_if_t_tojson (vl_api_cnat_snat_policy_add_del_if_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "cnat_snat_policy_add_del_if");
    cJSON_AddStringToObject(o, "_crc", "4ebb8d02");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "table", vl_api_cnat_snat_policy_table_t_tojson(a->table));
    return o;
}
static inline cJSON *vl_api_cnat_snat_policy_add_del_if_reply_t_tojson (vl_api_cnat_snat_policy_add_del_if_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "cnat_snat_policy_add_del_if_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_cnat_set_snat_policy_t_tojson (vl_api_cnat_set_snat_policy_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "cnat_set_snat_policy");
    cJSON_AddStringToObject(o, "_crc", "d3e6eaf4");
    cJSON_AddItemToObject(o, "policy", vl_api_cnat_snat_policies_t_tojson(a->policy));
    return o;
}
static inline cJSON *vl_api_cnat_set_snat_policy_reply_t_tojson (vl_api_cnat_set_snat_policy_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "cnat_set_snat_policy_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
