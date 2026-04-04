/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#ifndef included_classify_api_tojson_h
#define included_classify_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_classify_action_t_tojson (vl_api_classify_action_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("CLASSIFY_API_ACTION_NONE");
    case 1:
        return cJSON_CreateString("CLASSIFY_API_ACTION_SET_IP4_FIB_INDEX");
    case 2:
        return cJSON_CreateString("CLASSIFY_API_ACTION_SET_IP6_FIB_INDEX");
    case 3:
        return cJSON_CreateString("CLASSIFY_API_ACTION_SET_METADATA");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_policer_classify_table_t_tojson (vl_api_policer_classify_table_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("POLICER_CLASSIFY_API_TABLE_IP4");
    case 1:
        return cJSON_CreateString("POLICER_CLASSIFY_API_TABLE_IP6");
    case 2:
        return cJSON_CreateString("POLICER_CLASSIFY_API_TABLE_L2");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_flow_classify_table_t_tojson (vl_api_flow_classify_table_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("FLOW_CLASSIFY_API_TABLE_IP4");
    case 1:
        return cJSON_CreateString("FLOW_CLASSIFY_API_TABLE_IP6");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_classify_add_del_table_t_tojson (vl_api_classify_add_del_table_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "classify_add_del_table");
    cJSON_AddStringToObject(o, "_crc", "6849e39e");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddBoolToObject(o, "del_chain", a->del_chain);
    cJSON_AddNumberToObject(o, "table_index", a->table_index);
    cJSON_AddNumberToObject(o, "nbuckets", a->nbuckets);
    cJSON_AddNumberToObject(o, "memory_size", a->memory_size);
    cJSON_AddNumberToObject(o, "skip_n_vectors", a->skip_n_vectors);
    cJSON_AddNumberToObject(o, "match_n_vectors", a->match_n_vectors);
    cJSON_AddNumberToObject(o, "next_table_index", a->next_table_index);
    cJSON_AddNumberToObject(o, "miss_next_index", a->miss_next_index);
    cJSON_AddNumberToObject(o, "current_data_flag", a->current_data_flag);
    cJSON_AddNumberToObject(o, "current_data_offset", a->current_data_offset);
    cJSON_AddNumberToObject(o, "mask_len", a->mask_len);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->mask, a->mask_len);
    cJSON_AddStringToObject(o, "mask", s);
    vec_free(s);
    }
    return o;
}
static inline cJSON *vl_api_classify_add_del_table_reply_t_tojson (vl_api_classify_add_del_table_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "classify_add_del_table_reply");
    cJSON_AddStringToObject(o, "_crc", "05486349");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "new_table_index", a->new_table_index);
    cJSON_AddNumberToObject(o, "skip_n_vectors", a->skip_n_vectors);
    cJSON_AddNumberToObject(o, "match_n_vectors", a->match_n_vectors);
    return o;
}
static inline cJSON *vl_api_classify_add_del_session_t_tojson (vl_api_classify_add_del_session_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "classify_add_del_session");
    cJSON_AddStringToObject(o, "_crc", "f20879f0");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddNumberToObject(o, "table_index", a->table_index);
    cJSON_AddNumberToObject(o, "hit_next_index", a->hit_next_index);
    cJSON_AddNumberToObject(o, "opaque_index", a->opaque_index);
    cJSON_AddNumberToObject(o, "advance", a->advance);
    cJSON_AddItemToObject(o, "action", vl_api_classify_action_t_tojson(a->action));
    cJSON_AddNumberToObject(o, "metadata", a->metadata);
    cJSON_AddNumberToObject(o, "match_len", a->match_len);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->match, a->match_len);
    cJSON_AddStringToObject(o, "match", s);
    vec_free(s);
    }
    return o;
}
static inline cJSON *vl_api_classify_add_del_session_reply_t_tojson (vl_api_classify_add_del_session_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "classify_add_del_session_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_policer_classify_set_interface_t_tojson (vl_api_policer_classify_set_interface_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "policer_classify_set_interface");
    cJSON_AddStringToObject(o, "_crc", "de7ad708");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "ip4_table_index", a->ip4_table_index);
    cJSON_AddNumberToObject(o, "ip6_table_index", a->ip6_table_index);
    cJSON_AddNumberToObject(o, "l2_table_index", a->l2_table_index);
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    return o;
}
static inline cJSON *vl_api_policer_classify_set_interface_reply_t_tojson (vl_api_policer_classify_set_interface_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "policer_classify_set_interface_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_policer_classify_dump_t_tojson (vl_api_policer_classify_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "policer_classify_dump");
    cJSON_AddStringToObject(o, "_crc", "56cbb5fb");
    cJSON_AddItemToObject(o, "type", vl_api_policer_classify_table_t_tojson(a->type));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_policer_classify_details_t_tojson (vl_api_policer_classify_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "policer_classify_details");
    cJSON_AddStringToObject(o, "_crc", "dfd08765");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "table_index", a->table_index);
    return o;
}
static inline cJSON *vl_api_classify_table_ids_t_tojson (vl_api_classify_table_ids_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "classify_table_ids");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_classify_table_ids_reply_t_tojson (vl_api_classify_table_ids_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "classify_table_ids_reply");
    cJSON_AddStringToObject(o, "_crc", "d1d20e1d");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "count", a->count);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "ids");
        for (i = 0; i < a->count; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->ids[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_classify_table_by_interface_t_tojson (vl_api_classify_table_by_interface_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "classify_table_by_interface");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_classify_table_by_interface_reply_t_tojson (vl_api_classify_table_by_interface_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "classify_table_by_interface_reply");
    cJSON_AddStringToObject(o, "_crc", "ed4197db");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "l2_table_id", a->l2_table_id);
    cJSON_AddNumberToObject(o, "ip4_table_id", a->ip4_table_id);
    cJSON_AddNumberToObject(o, "ip6_table_id", a->ip6_table_id);
    return o;
}
static inline cJSON *vl_api_classify_table_info_t_tojson (vl_api_classify_table_info_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "classify_table_info");
    cJSON_AddStringToObject(o, "_crc", "0cca2cd9");
    cJSON_AddNumberToObject(o, "table_id", a->table_id);
    return o;
}
static inline cJSON *vl_api_classify_table_info_reply_t_tojson (vl_api_classify_table_info_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "classify_table_info_reply");
    cJSON_AddStringToObject(o, "_crc", "4a573c0e");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "table_id", a->table_id);
    cJSON_AddNumberToObject(o, "nbuckets", a->nbuckets);
    cJSON_AddNumberToObject(o, "match_n_vectors", a->match_n_vectors);
    cJSON_AddNumberToObject(o, "skip_n_vectors", a->skip_n_vectors);
    cJSON_AddNumberToObject(o, "active_sessions", a->active_sessions);
    cJSON_AddNumberToObject(o, "next_table_index", a->next_table_index);
    cJSON_AddNumberToObject(o, "miss_next_index", a->miss_next_index);
    cJSON_AddNumberToObject(o, "mask_length", a->mask_length);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->mask, a->mask_length);
    cJSON_AddStringToObject(o, "mask", s);
    vec_free(s);
    }
    return o;
}
static inline cJSON *vl_api_classify_session_dump_t_tojson (vl_api_classify_session_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "classify_session_dump");
    cJSON_AddStringToObject(o, "_crc", "0cca2cd9");
    cJSON_AddNumberToObject(o, "table_id", a->table_id);
    return o;
}
static inline cJSON *vl_api_classify_session_details_t_tojson (vl_api_classify_session_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "classify_session_details");
    cJSON_AddStringToObject(o, "_crc", "60e3ef94");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "table_id", a->table_id);
    cJSON_AddNumberToObject(o, "hit_next_index", a->hit_next_index);
    cJSON_AddNumberToObject(o, "advance", a->advance);
    cJSON_AddNumberToObject(o, "opaque_index", a->opaque_index);
    cJSON_AddNumberToObject(o, "match_length", a->match_length);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->match, a->match_length);
    cJSON_AddStringToObject(o, "match", s);
    vec_free(s);
    }
    return o;
}
static inline cJSON *vl_api_flow_classify_set_interface_t_tojson (vl_api_flow_classify_set_interface_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "flow_classify_set_interface");
    cJSON_AddStringToObject(o, "_crc", "b6192f1c");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "ip4_table_index", a->ip4_table_index);
    cJSON_AddNumberToObject(o, "ip6_table_index", a->ip6_table_index);
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    return o;
}
static inline cJSON *vl_api_flow_classify_set_interface_reply_t_tojson (vl_api_flow_classify_set_interface_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "flow_classify_set_interface_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_flow_classify_dump_t_tojson (vl_api_flow_classify_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "flow_classify_dump");
    cJSON_AddStringToObject(o, "_crc", "25dd3e4c");
    cJSON_AddItemToObject(o, "type", vl_api_flow_classify_table_t_tojson(a->type));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_flow_classify_details_t_tojson (vl_api_flow_classify_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "flow_classify_details");
    cJSON_AddStringToObject(o, "_crc", "dfd08765");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "table_index", a->table_index);
    return o;
}
static inline cJSON *vl_api_classify_set_interface_ip_table_t_tojson (vl_api_classify_set_interface_ip_table_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "classify_set_interface_ip_table");
    cJSON_AddStringToObject(o, "_crc", "e0b097c7");
    cJSON_AddBoolToObject(o, "is_ipv6", a->is_ipv6);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "table_index", a->table_index);
    return o;
}
static inline cJSON *vl_api_classify_set_interface_ip_table_reply_t_tojson (vl_api_classify_set_interface_ip_table_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "classify_set_interface_ip_table_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_classify_set_interface_l2_tables_t_tojson (vl_api_classify_set_interface_l2_tables_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "classify_set_interface_l2_tables");
    cJSON_AddStringToObject(o, "_crc", "5a6ddf65");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "ip4_table_index", a->ip4_table_index);
    cJSON_AddNumberToObject(o, "ip6_table_index", a->ip6_table_index);
    cJSON_AddNumberToObject(o, "other_table_index", a->other_table_index);
    cJSON_AddBoolToObject(o, "is_input", a->is_input);
    return o;
}
static inline cJSON *vl_api_classify_set_interface_l2_tables_reply_t_tojson (vl_api_classify_set_interface_l2_tables_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "classify_set_interface_l2_tables_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_input_acl_set_interface_t_tojson (vl_api_input_acl_set_interface_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "input_acl_set_interface");
    cJSON_AddStringToObject(o, "_crc", "de7ad708");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "ip4_table_index", a->ip4_table_index);
    cJSON_AddNumberToObject(o, "ip6_table_index", a->ip6_table_index);
    cJSON_AddNumberToObject(o, "l2_table_index", a->l2_table_index);
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    return o;
}
static inline cJSON *vl_api_input_acl_set_interface_reply_t_tojson (vl_api_input_acl_set_interface_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "input_acl_set_interface_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_punt_acl_add_del_t_tojson (vl_api_punt_acl_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "punt_acl_add_del");
    cJSON_AddStringToObject(o, "_crc", "a93bf3a0");
    cJSON_AddNumberToObject(o, "ip4_table_index", a->ip4_table_index);
    cJSON_AddNumberToObject(o, "ip6_table_index", a->ip6_table_index);
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    return o;
}
static inline cJSON *vl_api_punt_acl_add_del_reply_t_tojson (vl_api_punt_acl_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "punt_acl_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_punt_acl_get_t_tojson (vl_api_punt_acl_get_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "punt_acl_get");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_punt_acl_get_reply_t_tojson (vl_api_punt_acl_get_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "punt_acl_get_reply");
    cJSON_AddStringToObject(o, "_crc", "8409b9dd");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "ip4_table_index", a->ip4_table_index);
    cJSON_AddNumberToObject(o, "ip6_table_index", a->ip6_table_index);
    return o;
}
static inline cJSON *vl_api_output_acl_set_interface_t_tojson (vl_api_output_acl_set_interface_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "output_acl_set_interface");
    cJSON_AddStringToObject(o, "_crc", "de7ad708");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "ip4_table_index", a->ip4_table_index);
    cJSON_AddNumberToObject(o, "ip6_table_index", a->ip6_table_index);
    cJSON_AddNumberToObject(o, "l2_table_index", a->l2_table_index);
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    return o;
}
static inline cJSON *vl_api_output_acl_set_interface_reply_t_tojson (vl_api_output_acl_set_interface_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "output_acl_set_interface_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_classify_pcap_lookup_table_t_tojson (vl_api_classify_pcap_lookup_table_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "classify_pcap_lookup_table");
    cJSON_AddStringToObject(o, "_crc", "e1b4cc6b");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "skip_n_vectors", a->skip_n_vectors);
    cJSON_AddNumberToObject(o, "match_n_vectors", a->match_n_vectors);
    cJSON_AddNumberToObject(o, "mask_len", a->mask_len);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->mask, a->mask_len);
    cJSON_AddStringToObject(o, "mask", s);
    vec_free(s);
    }
    return o;
}
static inline cJSON *vl_api_classify_pcap_lookup_table_reply_t_tojson (vl_api_classify_pcap_lookup_table_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "classify_pcap_lookup_table_reply");
    cJSON_AddStringToObject(o, "_crc", "9c6c6773");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "table_index", a->table_index);
    return o;
}
static inline cJSON *vl_api_classify_pcap_set_table_t_tojson (vl_api_classify_pcap_set_table_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "classify_pcap_set_table");
    cJSON_AddStringToObject(o, "_crc", "006051b3");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "table_index", a->table_index);
    cJSON_AddBoolToObject(o, "sort_masks", a->sort_masks);
    return o;
}
static inline cJSON *vl_api_classify_pcap_set_table_reply_t_tojson (vl_api_classify_pcap_set_table_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "classify_pcap_set_table_reply");
    cJSON_AddStringToObject(o, "_crc", "9c6c6773");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "table_index", a->table_index);
    return o;
}
static inline cJSON *vl_api_classify_pcap_get_tables_t_tojson (vl_api_classify_pcap_get_tables_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "classify_pcap_get_tables");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_classify_pcap_get_tables_reply_t_tojson (vl_api_classify_pcap_get_tables_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "classify_pcap_get_tables_reply");
    cJSON_AddStringToObject(o, "_crc", "5f5bc9e6");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "count", a->count);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "indices");
        for (i = 0; i < a->count; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->indices[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_classify_trace_lookup_table_t_tojson (vl_api_classify_trace_lookup_table_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "classify_trace_lookup_table");
    cJSON_AddStringToObject(o, "_crc", "3f7b72e4");
    cJSON_AddNumberToObject(o, "skip_n_vectors", a->skip_n_vectors);
    cJSON_AddNumberToObject(o, "match_n_vectors", a->match_n_vectors);
    cJSON_AddNumberToObject(o, "mask_len", a->mask_len);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->mask, a->mask_len);
    cJSON_AddStringToObject(o, "mask", s);
    vec_free(s);
    }
    return o;
}
static inline cJSON *vl_api_classify_trace_lookup_table_reply_t_tojson (vl_api_classify_trace_lookup_table_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "classify_trace_lookup_table_reply");
    cJSON_AddStringToObject(o, "_crc", "9c6c6773");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "table_index", a->table_index);
    return o;
}
static inline cJSON *vl_api_classify_trace_set_table_t_tojson (vl_api_classify_trace_set_table_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "classify_trace_set_table");
    cJSON_AddStringToObject(o, "_crc", "3909b55a");
    cJSON_AddNumberToObject(o, "table_index", a->table_index);
    cJSON_AddBoolToObject(o, "sort_masks", a->sort_masks);
    return o;
}
static inline cJSON *vl_api_classify_trace_set_table_reply_t_tojson (vl_api_classify_trace_set_table_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "classify_trace_set_table_reply");
    cJSON_AddStringToObject(o, "_crc", "9c6c6773");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "table_index", a->table_index);
    return o;
}
static inline cJSON *vl_api_classify_trace_get_tables_t_tojson (vl_api_classify_trace_get_tables_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "classify_trace_get_tables");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_classify_trace_get_tables_reply_t_tojson (vl_api_classify_trace_get_tables_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "classify_trace_get_tables_reply");
    cJSON_AddStringToObject(o, "_crc", "5f5bc9e6");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "count", a->count);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "indices");
        for (i = 0; i < a->count; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->indices[i]));
        }
    }
    return o;
}
#endif
