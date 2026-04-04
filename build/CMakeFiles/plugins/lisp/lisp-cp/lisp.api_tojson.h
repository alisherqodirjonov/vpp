/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <lisp/lisp-cp/lisp_types.api_tojson.h>
#ifndef included_lisp_api_tojson_h
#define included_lisp_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_lisp_locator_set_filter_t_tojson (vl_api_lisp_locator_set_filter_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("LISP_LOCATOR_SET_FILTER_API_ALL");
    case 1:
        return cJSON_CreateString("LISP_LOCATOR_SET_FILTER_API_LOCAL");
    case 2:
        return cJSON_CreateString("LISP_LOCATOR_SET_FILTER_API_REMOTE");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_lisp_adjacency_t_tojson (vl_api_lisp_adjacency_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "reid", vl_api_eid_t_tojson(&a->reid));
    cJSON_AddItemToObject(o, "leid", vl_api_eid_t_tojson(&a->leid));
    return o;
}
static inline cJSON *vl_api_lisp_add_del_locator_set_t_tojson (vl_api_lisp_add_del_locator_set_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_add_del_locator_set");
    cJSON_AddStringToObject(o, "_crc", "6fcd6471");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddStringToObject(o, "locator_set_name", (char *)a->locator_set_name);
    cJSON_AddNumberToObject(o, "locator_num", a->locator_num);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "locators");
        for (i = 0; i < a->locator_num; i++) {
            cJSON_AddItemToArray(array, vl_api_local_locator_t_tojson(&a->locators[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_lisp_add_del_locator_set_reply_t_tojson (vl_api_lisp_add_del_locator_set_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_add_del_locator_set_reply");
    cJSON_AddStringToObject(o, "_crc", "b6666db4");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "ls_index", a->ls_index);
    return o;
}
static inline cJSON *vl_api_lisp_add_del_locator_t_tojson (vl_api_lisp_add_del_locator_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_add_del_locator");
    cJSON_AddStringToObject(o, "_crc", "af4d8f13");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddStringToObject(o, "locator_set_name", (char *)a->locator_set_name);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "priority", a->priority);
    cJSON_AddNumberToObject(o, "weight", a->weight);
    return o;
}
static inline cJSON *vl_api_lisp_add_del_locator_reply_t_tojson (vl_api_lisp_add_del_locator_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_add_del_locator_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_lisp_add_del_local_eid_t_tojson (vl_api_lisp_add_del_local_eid_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_add_del_local_eid");
    cJSON_AddStringToObject(o, "_crc", "4e5a83a2");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "eid", vl_api_eid_t_tojson(&a->eid));
    cJSON_AddStringToObject(o, "locator_set_name", (char *)a->locator_set_name);
    cJSON_AddNumberToObject(o, "vni", a->vni);
    cJSON_AddItemToObject(o, "key", vl_api_hmac_key_t_tojson(&a->key));
    return o;
}
static inline cJSON *vl_api_lisp_add_del_local_eid_reply_t_tojson (vl_api_lisp_add_del_local_eid_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_add_del_local_eid_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_lisp_add_del_map_server_t_tojson (vl_api_lisp_add_del_map_server_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_add_del_map_server");
    cJSON_AddStringToObject(o, "_crc", "ce19e32d");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "ip_address", vl_api_address_t_tojson(&a->ip_address));
    return o;
}
static inline cJSON *vl_api_lisp_add_del_map_server_reply_t_tojson (vl_api_lisp_add_del_map_server_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_add_del_map_server_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_lisp_add_del_map_resolver_t_tojson (vl_api_lisp_add_del_map_resolver_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_add_del_map_resolver");
    cJSON_AddStringToObject(o, "_crc", "ce19e32d");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "ip_address", vl_api_address_t_tojson(&a->ip_address));
    return o;
}
static inline cJSON *vl_api_lisp_add_del_map_resolver_reply_t_tojson (vl_api_lisp_add_del_map_resolver_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_add_del_map_resolver_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_lisp_enable_disable_t_tojson (vl_api_lisp_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "c264d7bf");
    cJSON_AddBoolToObject(o, "is_enable", a->is_enable);
    return o;
}
static inline cJSON *vl_api_lisp_enable_disable_reply_t_tojson (vl_api_lisp_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_lisp_pitr_set_locator_set_t_tojson (vl_api_lisp_pitr_set_locator_set_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_pitr_set_locator_set");
    cJSON_AddStringToObject(o, "_crc", "486e2b76");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddStringToObject(o, "ls_name", (char *)a->ls_name);
    return o;
}
static inline cJSON *vl_api_lisp_pitr_set_locator_set_reply_t_tojson (vl_api_lisp_pitr_set_locator_set_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_pitr_set_locator_set_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_lisp_use_petr_t_tojson (vl_api_lisp_use_petr_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_use_petr");
    cJSON_AddStringToObject(o, "_crc", "d87dbad9");
    cJSON_AddItemToObject(o, "ip_address", vl_api_address_t_tojson(&a->ip_address));
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    return o;
}
static inline cJSON *vl_api_lisp_use_petr_reply_t_tojson (vl_api_lisp_use_petr_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_use_petr_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_show_lisp_use_petr_t_tojson (vl_api_show_lisp_use_petr_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "show_lisp_use_petr");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_show_lisp_use_petr_reply_t_tojson (vl_api_show_lisp_use_petr_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "show_lisp_use_petr_reply");
    cJSON_AddStringToObject(o, "_crc", "22b9a4b0");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddBoolToObject(o, "is_petr_enable", a->is_petr_enable);
    cJSON_AddItemToObject(o, "ip_address", vl_api_address_t_tojson(&a->ip_address));
    return o;
}
static inline cJSON *vl_api_show_lisp_rloc_probe_state_t_tojson (vl_api_show_lisp_rloc_probe_state_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "show_lisp_rloc_probe_state");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_show_lisp_rloc_probe_state_reply_t_tojson (vl_api_show_lisp_rloc_probe_state_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "show_lisp_rloc_probe_state_reply");
    cJSON_AddStringToObject(o, "_crc", "e33a377b");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddBoolToObject(o, "is_enabled", a->is_enabled);
    return o;
}
static inline cJSON *vl_api_lisp_rloc_probe_enable_disable_t_tojson (vl_api_lisp_rloc_probe_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_rloc_probe_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "c264d7bf");
    cJSON_AddBoolToObject(o, "is_enable", a->is_enable);
    return o;
}
static inline cJSON *vl_api_lisp_rloc_probe_enable_disable_reply_t_tojson (vl_api_lisp_rloc_probe_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_rloc_probe_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_lisp_map_register_enable_disable_t_tojson (vl_api_lisp_map_register_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_map_register_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "c264d7bf");
    cJSON_AddBoolToObject(o, "is_enable", a->is_enable);
    return o;
}
static inline cJSON *vl_api_lisp_map_register_enable_disable_reply_t_tojson (vl_api_lisp_map_register_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_map_register_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_show_lisp_map_register_state_t_tojson (vl_api_show_lisp_map_register_state_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "show_lisp_map_register_state");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_show_lisp_map_register_state_reply_t_tojson (vl_api_show_lisp_map_register_state_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "show_lisp_map_register_state_reply");
    cJSON_AddStringToObject(o, "_crc", "e33a377b");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddBoolToObject(o, "is_enabled", a->is_enabled);
    return o;
}
static inline cJSON *vl_api_lisp_map_request_mode_t_tojson (vl_api_lisp_map_request_mode_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_map_request_mode");
    cJSON_AddStringToObject(o, "_crc", "f43c26ae");
    cJSON_AddBoolToObject(o, "is_src_dst", a->is_src_dst);
    return o;
}
static inline cJSON *vl_api_lisp_map_request_mode_reply_t_tojson (vl_api_lisp_map_request_mode_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_map_request_mode_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_show_lisp_map_request_mode_t_tojson (vl_api_show_lisp_map_request_mode_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "show_lisp_map_request_mode");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_show_lisp_map_request_mode_reply_t_tojson (vl_api_show_lisp_map_request_mode_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "show_lisp_map_request_mode_reply");
    cJSON_AddStringToObject(o, "_crc", "5b05038e");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddBoolToObject(o, "is_src_dst", a->is_src_dst);
    return o;
}
static inline cJSON *vl_api_lisp_add_del_remote_mapping_t_tojson (vl_api_lisp_add_del_remote_mapping_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_add_del_remote_mapping");
    cJSON_AddStringToObject(o, "_crc", "6d5c789e");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddBoolToObject(o, "is_src_dst", a->is_src_dst);
    cJSON_AddBoolToObject(o, "del_all", a->del_all);
    cJSON_AddNumberToObject(o, "vni", a->vni);
    cJSON_AddNumberToObject(o, "action", a->action);
    cJSON_AddItemToObject(o, "deid", vl_api_eid_t_tojson(&a->deid));
    cJSON_AddItemToObject(o, "seid", vl_api_eid_t_tojson(&a->seid));
    cJSON_AddNumberToObject(o, "rloc_num", a->rloc_num);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "rlocs");
        for (i = 0; i < a->rloc_num; i++) {
            cJSON_AddItemToArray(array, vl_api_remote_locator_t_tojson(&a->rlocs[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_lisp_add_del_remote_mapping_reply_t_tojson (vl_api_lisp_add_del_remote_mapping_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_add_del_remote_mapping_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_lisp_add_del_adjacency_t_tojson (vl_api_lisp_add_del_adjacency_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_add_del_adjacency");
    cJSON_AddStringToObject(o, "_crc", "2ce0e6f6");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddNumberToObject(o, "vni", a->vni);
    cJSON_AddItemToObject(o, "reid", vl_api_eid_t_tojson(&a->reid));
    cJSON_AddItemToObject(o, "leid", vl_api_eid_t_tojson(&a->leid));
    return o;
}
static inline cJSON *vl_api_lisp_add_del_adjacency_reply_t_tojson (vl_api_lisp_add_del_adjacency_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_add_del_adjacency_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_lisp_add_del_map_request_itr_rlocs_t_tojson (vl_api_lisp_add_del_map_request_itr_rlocs_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_add_del_map_request_itr_rlocs");
    cJSON_AddStringToObject(o, "_crc", "6be88e45");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddStringToObject(o, "locator_set_name", (char *)a->locator_set_name);
    return o;
}
static inline cJSON *vl_api_lisp_add_del_map_request_itr_rlocs_reply_t_tojson (vl_api_lisp_add_del_map_request_itr_rlocs_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_add_del_map_request_itr_rlocs_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_lisp_eid_table_add_del_map_t_tojson (vl_api_lisp_eid_table_add_del_map_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_eid_table_add_del_map");
    cJSON_AddStringToObject(o, "_crc", "9481416b");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddNumberToObject(o, "vni", a->vni);
    cJSON_AddNumberToObject(o, "dp_table", a->dp_table);
    cJSON_AddBoolToObject(o, "is_l2", a->is_l2);
    return o;
}
static inline cJSON *vl_api_lisp_eid_table_add_del_map_reply_t_tojson (vl_api_lisp_eid_table_add_del_map_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_eid_table_add_del_map_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_lisp_locator_dump_t_tojson (vl_api_lisp_locator_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_locator_dump");
    cJSON_AddStringToObject(o, "_crc", "b954fad7");
    cJSON_AddNumberToObject(o, "ls_index", a->ls_index);
    cJSON_AddStringToObject(o, "ls_name", (char *)a->ls_name);
    cJSON_AddNumberToObject(o, "is_index_set", a->is_index_set);
    return o;
}
static inline cJSON *vl_api_lisp_locator_details_t_tojson (vl_api_lisp_locator_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_locator_details");
    cJSON_AddStringToObject(o, "_crc", "2c620ffe");
    cJSON_AddNumberToObject(o, "local", a->local);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "ip_address", vl_api_address_t_tojson(&a->ip_address));
    cJSON_AddNumberToObject(o, "priority", a->priority);
    cJSON_AddNumberToObject(o, "weight", a->weight);
    return o;
}
static inline cJSON *vl_api_lisp_locator_set_details_t_tojson (vl_api_lisp_locator_set_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_locator_set_details");
    cJSON_AddStringToObject(o, "_crc", "5b33a105");
    cJSON_AddNumberToObject(o, "ls_index", a->ls_index);
    cJSON_AddStringToObject(o, "ls_name", (char *)a->ls_name);
    return o;
}
static inline cJSON *vl_api_lisp_locator_set_dump_t_tojson (vl_api_lisp_locator_set_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_locator_set_dump");
    cJSON_AddStringToObject(o, "_crc", "c2cb5922");
    cJSON_AddItemToObject(o, "filter", vl_api_lisp_locator_set_filter_t_tojson(a->filter));
    return o;
}
static inline cJSON *vl_api_lisp_eid_table_details_t_tojson (vl_api_lisp_eid_table_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_eid_table_details");
    cJSON_AddStringToObject(o, "_crc", "1c29f792");
    cJSON_AddNumberToObject(o, "locator_set_index", a->locator_set_index);
    cJSON_AddNumberToObject(o, "action", a->action);
    cJSON_AddBoolToObject(o, "is_local", a->is_local);
    cJSON_AddBoolToObject(o, "is_src_dst", a->is_src_dst);
    cJSON_AddNumberToObject(o, "vni", a->vni);
    cJSON_AddItemToObject(o, "deid", vl_api_eid_t_tojson(&a->deid));
    cJSON_AddItemToObject(o, "seid", vl_api_eid_t_tojson(&a->seid));
    cJSON_AddNumberToObject(o, "ttl", a->ttl);
    cJSON_AddNumberToObject(o, "authoritative", a->authoritative);
    cJSON_AddItemToObject(o, "key", vl_api_hmac_key_t_tojson(&a->key));
    return o;
}
static inline cJSON *vl_api_lisp_eid_table_dump_t_tojson (vl_api_lisp_eid_table_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_eid_table_dump");
    cJSON_AddStringToObject(o, "_crc", "629468b5");
    cJSON_AddNumberToObject(o, "eid_set", a->eid_set);
    cJSON_AddNumberToObject(o, "prefix_length", a->prefix_length);
    cJSON_AddNumberToObject(o, "vni", a->vni);
    cJSON_AddItemToObject(o, "eid", vl_api_eid_t_tojson(&a->eid));
    cJSON_AddItemToObject(o, "filter", vl_api_lisp_locator_set_filter_t_tojson(a->filter));
    return o;
}
static inline cJSON *vl_api_lisp_adjacencies_get_reply_t_tojson (vl_api_lisp_adjacencies_get_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_adjacencies_get_reply");
    cJSON_AddStringToObject(o, "_crc", "807257bf");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "count", a->count);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "adjacencies");
        for (i = 0; i < a->count; i++) {
            cJSON_AddItemToArray(array, vl_api_lisp_adjacency_t_tojson(&a->adjacencies[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_lisp_adjacencies_get_t_tojson (vl_api_lisp_adjacencies_get_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_adjacencies_get");
    cJSON_AddStringToObject(o, "_crc", "8d1f2fe9");
    cJSON_AddNumberToObject(o, "vni", a->vni);
    return o;
}
static inline cJSON *vl_api_lisp_eid_table_map_details_t_tojson (vl_api_lisp_eid_table_map_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_eid_table_map_details");
    cJSON_AddStringToObject(o, "_crc", "0b6859e2");
    cJSON_AddNumberToObject(o, "vni", a->vni);
    cJSON_AddNumberToObject(o, "dp_table", a->dp_table);
    return o;
}
static inline cJSON *vl_api_lisp_eid_table_map_dump_t_tojson (vl_api_lisp_eid_table_map_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_eid_table_map_dump");
    cJSON_AddStringToObject(o, "_crc", "d6cf0c3d");
    cJSON_AddBoolToObject(o, "is_l2", a->is_l2);
    return o;
}
static inline cJSON *vl_api_lisp_eid_table_vni_dump_t_tojson (vl_api_lisp_eid_table_vni_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_eid_table_vni_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_lisp_eid_table_vni_details_t_tojson (vl_api_lisp_eid_table_vni_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_eid_table_vni_details");
    cJSON_AddStringToObject(o, "_crc", "64abc01e");
    cJSON_AddNumberToObject(o, "vni", a->vni);
    return o;
}
static inline cJSON *vl_api_lisp_map_resolver_details_t_tojson (vl_api_lisp_map_resolver_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_map_resolver_details");
    cJSON_AddStringToObject(o, "_crc", "3e78fc57");
    cJSON_AddItemToObject(o, "ip_address", vl_api_address_t_tojson(&a->ip_address));
    return o;
}
static inline cJSON *vl_api_lisp_map_resolver_dump_t_tojson (vl_api_lisp_map_resolver_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_map_resolver_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_lisp_map_server_details_t_tojson (vl_api_lisp_map_server_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_map_server_details");
    cJSON_AddStringToObject(o, "_crc", "3e78fc57");
    cJSON_AddItemToObject(o, "ip_address", vl_api_address_t_tojson(&a->ip_address));
    return o;
}
static inline cJSON *vl_api_lisp_map_server_dump_t_tojson (vl_api_lisp_map_server_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_map_server_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_show_lisp_status_t_tojson (vl_api_show_lisp_status_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "show_lisp_status");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_show_lisp_status_reply_t_tojson (vl_api_show_lisp_status_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "show_lisp_status_reply");
    cJSON_AddStringToObject(o, "_crc", "9e8f10c0");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddBoolToObject(o, "is_lisp_enabled", a->is_lisp_enabled);
    cJSON_AddBoolToObject(o, "is_gpe_enabled", a->is_gpe_enabled);
    return o;
}
static inline cJSON *vl_api_lisp_get_map_request_itr_rlocs_t_tojson (vl_api_lisp_get_map_request_itr_rlocs_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_get_map_request_itr_rlocs");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_lisp_get_map_request_itr_rlocs_reply_t_tojson (vl_api_lisp_get_map_request_itr_rlocs_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lisp_get_map_request_itr_rlocs_reply");
    cJSON_AddStringToObject(o, "_crc", "76580f3a");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddStringToObject(o, "locator_set_name", (char *)a->locator_set_name);
    return o;
}
static inline cJSON *vl_api_show_lisp_pitr_t_tojson (vl_api_show_lisp_pitr_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "show_lisp_pitr");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_show_lisp_pitr_reply_t_tojson (vl_api_show_lisp_pitr_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "show_lisp_pitr_reply");
    cJSON_AddStringToObject(o, "_crc", "27aa69b1");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddBoolToObject(o, "is_enabled", a->is_enabled);
    cJSON_AddStringToObject(o, "locator_set_name", (char *)a->locator_set_name);
    return o;
}
#endif
