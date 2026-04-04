/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#ifndef included_lcp_api_tojson_h
#define included_lcp_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_lcp_itf_host_type_t_tojson (vl_api_lcp_itf_host_type_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("LCP_API_ITF_HOST_TAP");
    case 1:
        return cJSON_CreateString("LCP_API_ITF_HOST_TUN");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_lcp_default_ns_set_t_tojson (vl_api_lcp_default_ns_set_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lcp_default_ns_set");
    cJSON_AddStringToObject(o, "_crc", "69749409");
    cJSON_AddStringToObject(o, "netns", (char *)a->netns);
    return o;
}
static inline cJSON *vl_api_lcp_default_ns_set_reply_t_tojson (vl_api_lcp_default_ns_set_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lcp_default_ns_set_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_lcp_default_ns_get_t_tojson (vl_api_lcp_default_ns_get_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lcp_default_ns_get");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_lcp_default_ns_get_reply_t_tojson (vl_api_lcp_default_ns_get_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lcp_default_ns_get_reply");
    cJSON_AddStringToObject(o, "_crc", "5102feee");
    cJSON_AddStringToObject(o, "netns", (char *)a->netns);
    return o;
}
static inline cJSON *vl_api_lcp_itf_pair_add_del_t_tojson (vl_api_lcp_itf_pair_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lcp_itf_pair_add_del");
    cJSON_AddStringToObject(o, "_crc", "40482b80");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddStringToObject(o, "host_if_name", (char *)a->host_if_name);
    cJSON_AddItemToObject(o, "host_if_type", vl_api_lcp_itf_host_type_t_tojson(a->host_if_type));
    cJSON_AddStringToObject(o, "netns", (char *)a->netns);
    return o;
}
static inline cJSON *vl_api_lcp_itf_pair_add_del_reply_t_tojson (vl_api_lcp_itf_pair_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lcp_itf_pair_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_lcp_itf_pair_add_del_v2_t_tojson (vl_api_lcp_itf_pair_add_del_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lcp_itf_pair_add_del_v2");
    cJSON_AddStringToObject(o, "_crc", "40482b80");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddStringToObject(o, "host_if_name", (char *)a->host_if_name);
    cJSON_AddItemToObject(o, "host_if_type", vl_api_lcp_itf_host_type_t_tojson(a->host_if_type));
    cJSON_AddStringToObject(o, "netns", (char *)a->netns);
    return o;
}
static inline cJSON *vl_api_lcp_itf_pair_add_del_v2_reply_t_tojson (vl_api_lcp_itf_pair_add_del_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lcp_itf_pair_add_del_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "39452f52");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "host_sw_if_index", a->host_sw_if_index);
    return o;
}
static inline cJSON *vl_api_lcp_itf_pair_add_del_v3_t_tojson (vl_api_lcp_itf_pair_add_del_v3_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lcp_itf_pair_add_del_v3");
    cJSON_AddStringToObject(o, "_crc", "40482b80");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddStringToObject(o, "host_if_name", (char *)a->host_if_name);
    cJSON_AddItemToObject(o, "host_if_type", vl_api_lcp_itf_host_type_t_tojson(a->host_if_type));
    cJSON_AddStringToObject(o, "netns", (char *)a->netns);
    return o;
}
static inline cJSON *vl_api_lcp_itf_pair_add_del_v3_reply_t_tojson (vl_api_lcp_itf_pair_add_del_v3_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lcp_itf_pair_add_del_v3_reply");
    cJSON_AddStringToObject(o, "_crc", "c2502663");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "vif_index", a->vif_index);
    cJSON_AddNumberToObject(o, "host_sw_if_index", a->host_sw_if_index);
    return o;
}
static inline cJSON *vl_api_lcp_itf_pair_get_t_tojson (vl_api_lcp_itf_pair_get_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lcp_itf_pair_get");
    cJSON_AddStringToObject(o, "_crc", "f75ba505");
    cJSON_AddNumberToObject(o, "cursor", a->cursor);
    return o;
}
static inline cJSON *vl_api_lcp_itf_pair_get_reply_t_tojson (vl_api_lcp_itf_pair_get_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lcp_itf_pair_get_reply");
    cJSON_AddStringToObject(o, "_crc", "53b48f5d");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "cursor", a->cursor);
    return o;
}
static inline cJSON *vl_api_lcp_itf_pair_get_v2_t_tojson (vl_api_lcp_itf_pair_get_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lcp_itf_pair_get_v2");
    cJSON_AddStringToObject(o, "_crc", "47250981");
    cJSON_AddNumberToObject(o, "cursor", a->cursor);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_lcp_itf_pair_get_v2_reply_t_tojson (vl_api_lcp_itf_pair_get_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lcp_itf_pair_get_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "53b48f5d");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "cursor", a->cursor);
    return o;
}
static inline cJSON *vl_api_lcp_itf_pair_details_t_tojson (vl_api_lcp_itf_pair_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lcp_itf_pair_details");
    cJSON_AddStringToObject(o, "_crc", "8b5481af");
    cJSON_AddNumberToObject(o, "phy_sw_if_index", a->phy_sw_if_index);
    cJSON_AddNumberToObject(o, "host_sw_if_index", a->host_sw_if_index);
    cJSON_AddNumberToObject(o, "vif_index", a->vif_index);
    cJSON_AddStringToObject(o, "host_if_name", (char *)a->host_if_name);
    cJSON_AddItemToObject(o, "host_if_type", vl_api_lcp_itf_host_type_t_tojson(a->host_if_type));
    cJSON_AddStringToObject(o, "netns", (char *)a->netns);
    return o;
}
static inline cJSON *vl_api_lcp_ethertype_enable_t_tojson (vl_api_lcp_ethertype_enable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lcp_ethertype_enable");
    cJSON_AddStringToObject(o, "_crc", "f893dae1");
    cJSON_AddNumberToObject(o, "ethertype", a->ethertype);
    return o;
}
static inline cJSON *vl_api_lcp_ethertype_enable_reply_t_tojson (vl_api_lcp_ethertype_enable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lcp_ethertype_enable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_lcp_ethertype_get_t_tojson (vl_api_lcp_ethertype_get_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lcp_ethertype_get");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_lcp_ethertype_get_reply_t_tojson (vl_api_lcp_ethertype_get_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lcp_ethertype_get_reply");
    cJSON_AddStringToObject(o, "_crc", "db48c31e");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "count", a->count);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "ethertypes");
        for (i = 0; i < a->count; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->ethertypes[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_lcp_itf_pair_replace_begin_t_tojson (vl_api_lcp_itf_pair_replace_begin_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lcp_itf_pair_replace_begin");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_lcp_itf_pair_replace_begin_reply_t_tojson (vl_api_lcp_itf_pair_replace_begin_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lcp_itf_pair_replace_begin_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_lcp_itf_pair_replace_end_t_tojson (vl_api_lcp_itf_pair_replace_end_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lcp_itf_pair_replace_end");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_lcp_itf_pair_replace_end_reply_t_tojson (vl_api_lcp_itf_pair_replace_end_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lcp_itf_pair_replace_end_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
