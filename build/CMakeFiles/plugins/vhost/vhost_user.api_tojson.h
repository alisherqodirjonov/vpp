/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ethernet/ethernet_types.api_tojson.h>
#include <vnet/devices/virtio/virtio_types.api_tojson.h>
#ifndef included_vhost_user_api_tojson_h
#define included_vhost_user_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_create_vhost_user_if_t_tojson (vl_api_create_vhost_user_if_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "create_vhost_user_if");
    cJSON_AddStringToObject(o, "_crc", "c785c6fc");
    cJSON_AddBoolToObject(o, "is_server", a->is_server);
    cJSON_AddStringToObject(o, "sock_filename", (char *)a->sock_filename);
    cJSON_AddBoolToObject(o, "renumber", a->renumber);
    cJSON_AddBoolToObject(o, "disable_mrg_rxbuf", a->disable_mrg_rxbuf);
    cJSON_AddBoolToObject(o, "disable_indirect_desc", a->disable_indirect_desc);
    cJSON_AddBoolToObject(o, "enable_gso", a->enable_gso);
    cJSON_AddBoolToObject(o, "enable_packed", a->enable_packed);
    cJSON_AddNumberToObject(o, "custom_dev_instance", a->custom_dev_instance);
    cJSON_AddBoolToObject(o, "use_custom_mac", a->use_custom_mac);
    cJSON_AddItemToObject(o, "mac_address", vl_api_mac_address_t_tojson(&a->mac_address));
    cJSON_AddStringToObject(o, "tag", (char *)a->tag);
    return o;
}
static inline cJSON *vl_api_create_vhost_user_if_reply_t_tojson (vl_api_create_vhost_user_if_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "create_vhost_user_if_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_modify_vhost_user_if_t_tojson (vl_api_modify_vhost_user_if_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "modify_vhost_user_if");
    cJSON_AddStringToObject(o, "_crc", "0e71d40b");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "is_server", a->is_server);
    cJSON_AddStringToObject(o, "sock_filename", (char *)a->sock_filename);
    cJSON_AddBoolToObject(o, "renumber", a->renumber);
    cJSON_AddBoolToObject(o, "enable_gso", a->enable_gso);
    cJSON_AddBoolToObject(o, "enable_packed", a->enable_packed);
    cJSON_AddNumberToObject(o, "custom_dev_instance", a->custom_dev_instance);
    return o;
}
static inline cJSON *vl_api_modify_vhost_user_if_reply_t_tojson (vl_api_modify_vhost_user_if_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "modify_vhost_user_if_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_create_vhost_user_if_v2_t_tojson (vl_api_create_vhost_user_if_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "create_vhost_user_if_v2");
    cJSON_AddStringToObject(o, "_crc", "dba1cc1d");
    cJSON_AddBoolToObject(o, "is_server", a->is_server);
    cJSON_AddStringToObject(o, "sock_filename", (char *)a->sock_filename);
    cJSON_AddBoolToObject(o, "renumber", a->renumber);
    cJSON_AddBoolToObject(o, "disable_mrg_rxbuf", a->disable_mrg_rxbuf);
    cJSON_AddBoolToObject(o, "disable_indirect_desc", a->disable_indirect_desc);
    cJSON_AddBoolToObject(o, "enable_gso", a->enable_gso);
    cJSON_AddBoolToObject(o, "enable_packed", a->enable_packed);
    cJSON_AddBoolToObject(o, "enable_event_idx", a->enable_event_idx);
    cJSON_AddNumberToObject(o, "custom_dev_instance", a->custom_dev_instance);
    cJSON_AddBoolToObject(o, "use_custom_mac", a->use_custom_mac);
    cJSON_AddItemToObject(o, "mac_address", vl_api_mac_address_t_tojson(&a->mac_address));
    cJSON_AddStringToObject(o, "tag", (char *)a->tag);
    return o;
}
static inline cJSON *vl_api_create_vhost_user_if_v2_reply_t_tojson (vl_api_create_vhost_user_if_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "create_vhost_user_if_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_modify_vhost_user_if_v2_t_tojson (vl_api_modify_vhost_user_if_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "modify_vhost_user_if_v2");
    cJSON_AddStringToObject(o, "_crc", "b2483771");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "is_server", a->is_server);
    cJSON_AddStringToObject(o, "sock_filename", (char *)a->sock_filename);
    cJSON_AddBoolToObject(o, "renumber", a->renumber);
    cJSON_AddBoolToObject(o, "enable_gso", a->enable_gso);
    cJSON_AddBoolToObject(o, "enable_packed", a->enable_packed);
    cJSON_AddBoolToObject(o, "enable_event_idx", a->enable_event_idx);
    cJSON_AddNumberToObject(o, "custom_dev_instance", a->custom_dev_instance);
    return o;
}
static inline cJSON *vl_api_modify_vhost_user_if_v2_reply_t_tojson (vl_api_modify_vhost_user_if_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "modify_vhost_user_if_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_delete_vhost_user_if_t_tojson (vl_api_delete_vhost_user_if_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "delete_vhost_user_if");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_delete_vhost_user_if_reply_t_tojson (vl_api_delete_vhost_user_if_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "delete_vhost_user_if_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sw_interface_vhost_user_details_t_tojson (vl_api_sw_interface_vhost_user_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_vhost_user_details");
    cJSON_AddStringToObject(o, "_crc", "0cee1e53");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddStringToObject(o, "interface_name", (char *)a->interface_name);
    cJSON_AddNumberToObject(o, "virtio_net_hdr_sz", a->virtio_net_hdr_sz);
    cJSON_AddItemToObject(o, "features_first_32", vl_api_virtio_net_features_first_32_t_tojson(a->features_first_32));
    cJSON_AddItemToObject(o, "features_last_32", vl_api_virtio_net_features_last_32_t_tojson(a->features_last_32));
    cJSON_AddBoolToObject(o, "is_server", a->is_server);
    cJSON_AddStringToObject(o, "sock_filename", (char *)a->sock_filename);
    cJSON_AddNumberToObject(o, "num_regions", a->num_regions);
    cJSON_AddNumberToObject(o, "sock_errno", a->sock_errno);
    return o;
}
static inline cJSON *vl_api_sw_interface_vhost_user_dump_t_tojson (vl_api_sw_interface_vhost_user_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_vhost_user_dump");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
#endif
