/* Imported API files */
#include <acl/acl_types.api_tojson.h>
#include <vnet/interface_types.api_tojson.h>
#ifndef included_acl_api_tojson_h
#define included_acl_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_acl_plugin_get_version_t_tojson (vl_api_acl_plugin_get_version_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "acl_plugin_get_version");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_acl_plugin_get_version_reply_t_tojson (vl_api_acl_plugin_get_version_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "acl_plugin_get_version_reply");
    cJSON_AddStringToObject(o, "_crc", "9b32cf86");
    cJSON_AddNumberToObject(o, "major", a->major);
    cJSON_AddNumberToObject(o, "minor", a->minor);
    return o;
}
static inline cJSON *vl_api_acl_plugin_control_ping_t_tojson (vl_api_acl_plugin_control_ping_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "acl_plugin_control_ping");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_acl_plugin_control_ping_reply_t_tojson (vl_api_acl_plugin_control_ping_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "acl_plugin_control_ping_reply");
    cJSON_AddStringToObject(o, "_crc", "f6b0b8ca");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "vpe_pid", a->vpe_pid);
    return o;
}
static inline cJSON *vl_api_acl_plugin_get_conn_table_max_entries_t_tojson (vl_api_acl_plugin_get_conn_table_max_entries_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "acl_plugin_get_conn_table_max_entries");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_acl_plugin_get_conn_table_max_entries_reply_t_tojson (vl_api_acl_plugin_get_conn_table_max_entries_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "acl_plugin_get_conn_table_max_entries_reply");
    cJSON_AddStringToObject(o, "_crc", "7a096d3d");
    cJSON_AddNumberToObject(o, "conn_table_max_entries", a->conn_table_max_entries);
    return o;
}
static inline cJSON *vl_api_acl_add_replace_t_tojson (vl_api_acl_add_replace_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "acl_add_replace");
    cJSON_AddStringToObject(o, "_crc", "ee5c2f18");
    cJSON_AddNumberToObject(o, "acl_index", a->acl_index);
    cJSON_AddStringToObject(o, "tag", (char *)a->tag);
    cJSON_AddNumberToObject(o, "count", a->count);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "r");
        for (i = 0; i < a->count; i++) {
            cJSON_AddItemToArray(array, vl_api_acl_rule_t_tojson(&a->r[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_acl_add_replace_reply_t_tojson (vl_api_acl_add_replace_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "acl_add_replace_reply");
    cJSON_AddStringToObject(o, "_crc", "ac407b0c");
    cJSON_AddNumberToObject(o, "acl_index", a->acl_index);
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_acl_del_t_tojson (vl_api_acl_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "acl_del");
    cJSON_AddStringToObject(o, "_crc", "ef34fea4");
    cJSON_AddNumberToObject(o, "acl_index", a->acl_index);
    return o;
}
static inline cJSON *vl_api_acl_del_reply_t_tojson (vl_api_acl_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "acl_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_acl_interface_add_del_t_tojson (vl_api_acl_interface_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "acl_interface_add_del");
    cJSON_AddStringToObject(o, "_crc", "4b54bebd");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddBoolToObject(o, "is_input", a->is_input);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "acl_index", a->acl_index);
    return o;
}
static inline cJSON *vl_api_acl_interface_add_del_reply_t_tojson (vl_api_acl_interface_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "acl_interface_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_acl_interface_set_acl_list_t_tojson (vl_api_acl_interface_set_acl_list_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "acl_interface_set_acl_list");
    cJSON_AddStringToObject(o, "_crc", "473982bd");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "count", a->count);
    cJSON_AddNumberToObject(o, "n_input", a->n_input);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "acls");
        for (i = 0; i < a->count; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->acls[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_acl_interface_set_acl_list_reply_t_tojson (vl_api_acl_interface_set_acl_list_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "acl_interface_set_acl_list_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_acl_dump_t_tojson (vl_api_acl_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "acl_dump");
    cJSON_AddStringToObject(o, "_crc", "ef34fea4");
    cJSON_AddNumberToObject(o, "acl_index", a->acl_index);
    return o;
}
static inline cJSON *vl_api_acl_details_t_tojson (vl_api_acl_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "acl_details");
    cJSON_AddStringToObject(o, "_crc", "95babae0");
    cJSON_AddNumberToObject(o, "acl_index", a->acl_index);
    cJSON_AddStringToObject(o, "tag", (char *)a->tag);
    cJSON_AddNumberToObject(o, "count", a->count);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "r");
        for (i = 0; i < a->count; i++) {
            cJSON_AddItemToArray(array, vl_api_acl_rule_t_tojson(&a->r[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_acl_interface_list_dump_t_tojson (vl_api_acl_interface_list_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "acl_interface_list_dump");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_acl_interface_list_details_t_tojson (vl_api_acl_interface_list_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "acl_interface_list_details");
    cJSON_AddStringToObject(o, "_crc", "e695d256");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "count", a->count);
    cJSON_AddNumberToObject(o, "n_input", a->n_input);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "acls");
        for (i = 0; i < a->count; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->acls[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_macip_acl_add_t_tojson (vl_api_macip_acl_add_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "macip_acl_add");
    cJSON_AddStringToObject(o, "_crc", "ce6fbad0");
    cJSON_AddStringToObject(o, "tag", (char *)a->tag);
    cJSON_AddNumberToObject(o, "count", a->count);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "r");
        for (i = 0; i < a->count; i++) {
            cJSON_AddItemToArray(array, vl_api_macip_acl_rule_t_tojson(&a->r[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_macip_acl_add_reply_t_tojson (vl_api_macip_acl_add_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "macip_acl_add_reply");
    cJSON_AddStringToObject(o, "_crc", "ac407b0c");
    cJSON_AddNumberToObject(o, "acl_index", a->acl_index);
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_macip_acl_add_replace_t_tojson (vl_api_macip_acl_add_replace_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "macip_acl_add_replace");
    cJSON_AddStringToObject(o, "_crc", "2a461dd4");
    cJSON_AddNumberToObject(o, "acl_index", a->acl_index);
    cJSON_AddStringToObject(o, "tag", (char *)a->tag);
    cJSON_AddNumberToObject(o, "count", a->count);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "r");
        for (i = 0; i < a->count; i++) {
            cJSON_AddItemToArray(array, vl_api_macip_acl_rule_t_tojson(&a->r[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_macip_acl_add_replace_reply_t_tojson (vl_api_macip_acl_add_replace_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "macip_acl_add_replace_reply");
    cJSON_AddStringToObject(o, "_crc", "ac407b0c");
    cJSON_AddNumberToObject(o, "acl_index", a->acl_index);
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_macip_acl_del_t_tojson (vl_api_macip_acl_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "macip_acl_del");
    cJSON_AddStringToObject(o, "_crc", "ef34fea4");
    cJSON_AddNumberToObject(o, "acl_index", a->acl_index);
    return o;
}
static inline cJSON *vl_api_macip_acl_del_reply_t_tojson (vl_api_macip_acl_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "macip_acl_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_macip_acl_interface_add_del_t_tojson (vl_api_macip_acl_interface_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "macip_acl_interface_add_del");
    cJSON_AddStringToObject(o, "_crc", "4b8690b1");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "acl_index", a->acl_index);
    return o;
}
static inline cJSON *vl_api_macip_acl_interface_add_del_reply_t_tojson (vl_api_macip_acl_interface_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "macip_acl_interface_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_macip_acl_dump_t_tojson (vl_api_macip_acl_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "macip_acl_dump");
    cJSON_AddStringToObject(o, "_crc", "ef34fea4");
    cJSON_AddNumberToObject(o, "acl_index", a->acl_index);
    return o;
}
static inline cJSON *vl_api_macip_acl_details_t_tojson (vl_api_macip_acl_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "macip_acl_details");
    cJSON_AddStringToObject(o, "_crc", "27135b59");
    cJSON_AddNumberToObject(o, "acl_index", a->acl_index);
    cJSON_AddStringToObject(o, "tag", (char *)a->tag);
    cJSON_AddNumberToObject(o, "count", a->count);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "r");
        for (i = 0; i < a->count; i++) {
            cJSON_AddItemToArray(array, vl_api_macip_acl_rule_t_tojson(&a->r[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_macip_acl_interface_get_t_tojson (vl_api_macip_acl_interface_get_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "macip_acl_interface_get");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_macip_acl_interface_get_reply_t_tojson (vl_api_macip_acl_interface_get_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "macip_acl_interface_get_reply");
    cJSON_AddStringToObject(o, "_crc", "accf9b05");
    cJSON_AddNumberToObject(o, "count", a->count);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "acls");
        for (i = 0; i < a->count; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->acls[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_macip_acl_interface_list_dump_t_tojson (vl_api_macip_acl_interface_list_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "macip_acl_interface_list_dump");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_macip_acl_interface_list_details_t_tojson (vl_api_macip_acl_interface_list_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "macip_acl_interface_list_details");
    cJSON_AddStringToObject(o, "_crc", "a0c5d56d");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "count", a->count);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "acls");
        for (i = 0; i < a->count; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->acls[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_acl_interface_set_etype_whitelist_t_tojson (vl_api_acl_interface_set_etype_whitelist_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "acl_interface_set_etype_whitelist");
    cJSON_AddStringToObject(o, "_crc", "3f5c2d2d");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "count", a->count);
    cJSON_AddNumberToObject(o, "n_input", a->n_input);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "whitelist");
        for (i = 0; i < a->count; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->whitelist[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_acl_interface_set_etype_whitelist_reply_t_tojson (vl_api_acl_interface_set_etype_whitelist_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "acl_interface_set_etype_whitelist_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_acl_interface_etype_whitelist_dump_t_tojson (vl_api_acl_interface_etype_whitelist_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "acl_interface_etype_whitelist_dump");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_acl_interface_etype_whitelist_details_t_tojson (vl_api_acl_interface_etype_whitelist_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "acl_interface_etype_whitelist_details");
    cJSON_AddStringToObject(o, "_crc", "cc2bfded");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "count", a->count);
    cJSON_AddNumberToObject(o, "n_input", a->n_input);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "whitelist");
        for (i = 0; i < a->count; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->whitelist[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_acl_stats_intf_counters_enable_t_tojson (vl_api_acl_stats_intf_counters_enable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "acl_stats_intf_counters_enable");
    cJSON_AddStringToObject(o, "_crc", "b3e225d2");
    cJSON_AddBoolToObject(o, "enable", a->enable);
    return o;
}
static inline cJSON *vl_api_acl_stats_intf_counters_enable_reply_t_tojson (vl_api_acl_stats_intf_counters_enable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "acl_stats_intf_counters_enable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_acl_plugin_use_hash_lookup_set_t_tojson (vl_api_acl_plugin_use_hash_lookup_set_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "acl_plugin_use_hash_lookup_set");
    cJSON_AddStringToObject(o, "_crc", "b3e225d2");
    cJSON_AddBoolToObject(o, "enable", a->enable);
    return o;
}
static inline cJSON *vl_api_acl_plugin_use_hash_lookup_set_reply_t_tojson (vl_api_acl_plugin_use_hash_lookup_set_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "acl_plugin_use_hash_lookup_set_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_acl_plugin_use_hash_lookup_get_t_tojson (vl_api_acl_plugin_use_hash_lookup_get_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "acl_plugin_use_hash_lookup_get");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_acl_plugin_use_hash_lookup_get_reply_t_tojson (vl_api_acl_plugin_use_hash_lookup_get_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "acl_plugin_use_hash_lookup_get_reply");
    cJSON_AddStringToObject(o, "_crc", "5392ad31");
    cJSON_AddBoolToObject(o, "enable", a->enable);
    return o;
}
#endif
