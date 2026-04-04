/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ethernet/ethernet_types.api_tojson.h>
#ifndef included_bond_api_tojson_h
#define included_bond_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_bond_mode_t_tojson (vl_api_bond_mode_t a) {
    switch(a) {
    case 1:
        return cJSON_CreateString("BOND_API_MODE_ROUND_ROBIN");
    case 2:
        return cJSON_CreateString("BOND_API_MODE_ACTIVE_BACKUP");
    case 3:
        return cJSON_CreateString("BOND_API_MODE_XOR");
    case 4:
        return cJSON_CreateString("BOND_API_MODE_BROADCAST");
    case 5:
        return cJSON_CreateString("BOND_API_MODE_LACP");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_bond_lb_algo_t_tojson (vl_api_bond_lb_algo_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("BOND_API_LB_ALGO_L2");
    case 1:
        return cJSON_CreateString("BOND_API_LB_ALGO_L34");
    case 2:
        return cJSON_CreateString("BOND_API_LB_ALGO_L23");
    case 3:
        return cJSON_CreateString("BOND_API_LB_ALGO_RR");
    case 4:
        return cJSON_CreateString("BOND_API_LB_ALGO_BC");
    case 5:
        return cJSON_CreateString("BOND_API_LB_ALGO_AB");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_bond_create_t_tojson (vl_api_bond_create_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bond_create");
    cJSON_AddStringToObject(o, "_crc", "f1dbd4ff");
    cJSON_AddNumberToObject(o, "id", a->id);
    cJSON_AddBoolToObject(o, "use_custom_mac", a->use_custom_mac);
    cJSON_AddItemToObject(o, "mac_address", vl_api_mac_address_t_tojson(&a->mac_address));
    cJSON_AddItemToObject(o, "mode", vl_api_bond_mode_t_tojson(a->mode));
    cJSON_AddItemToObject(o, "lb", vl_api_bond_lb_algo_t_tojson(a->lb));
    cJSON_AddBoolToObject(o, "numa_only", a->numa_only);
    return o;
}
static inline cJSON *vl_api_bond_create_reply_t_tojson (vl_api_bond_create_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bond_create_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_bond_create2_t_tojson (vl_api_bond_create2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bond_create2");
    cJSON_AddStringToObject(o, "_crc", "912fda76");
    cJSON_AddItemToObject(o, "mode", vl_api_bond_mode_t_tojson(a->mode));
    cJSON_AddItemToObject(o, "lb", vl_api_bond_lb_algo_t_tojson(a->lb));
    cJSON_AddBoolToObject(o, "numa_only", a->numa_only);
    cJSON_AddBoolToObject(o, "enable_gso", a->enable_gso);
    cJSON_AddBoolToObject(o, "use_custom_mac", a->use_custom_mac);
    cJSON_AddItemToObject(o, "mac_address", vl_api_mac_address_t_tojson(&a->mac_address));
    cJSON_AddNumberToObject(o, "id", a->id);
    return o;
}
static inline cJSON *vl_api_bond_create2_reply_t_tojson (vl_api_bond_create2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bond_create2_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_bond_delete_t_tojson (vl_api_bond_delete_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bond_delete");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_bond_delete_reply_t_tojson (vl_api_bond_delete_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bond_delete_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_bond_enslave_t_tojson (vl_api_bond_enslave_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bond_enslave");
    cJSON_AddStringToObject(o, "_crc", "e7d14948");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "bond_sw_if_index", a->bond_sw_if_index);
    cJSON_AddBoolToObject(o, "is_passive", a->is_passive);
    cJSON_AddBoolToObject(o, "is_long_timeout", a->is_long_timeout);
    return o;
}
static inline cJSON *vl_api_bond_enslave_reply_t_tojson (vl_api_bond_enslave_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bond_enslave_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_bond_add_member_t_tojson (vl_api_bond_add_member_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bond_add_member");
    cJSON_AddStringToObject(o, "_crc", "e7d14948");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "bond_sw_if_index", a->bond_sw_if_index);
    cJSON_AddBoolToObject(o, "is_passive", a->is_passive);
    cJSON_AddBoolToObject(o, "is_long_timeout", a->is_long_timeout);
    return o;
}
static inline cJSON *vl_api_bond_add_member_reply_t_tojson (vl_api_bond_add_member_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bond_add_member_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_bond_detach_slave_t_tojson (vl_api_bond_detach_slave_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bond_detach_slave");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_bond_detach_slave_reply_t_tojson (vl_api_bond_detach_slave_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bond_detach_slave_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_bond_detach_member_t_tojson (vl_api_bond_detach_member_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bond_detach_member");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_bond_detach_member_reply_t_tojson (vl_api_bond_detach_member_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bond_detach_member_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sw_interface_bond_dump_t_tojson (vl_api_sw_interface_bond_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_bond_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_sw_interface_bond_details_t_tojson (vl_api_sw_interface_bond_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_bond_details");
    cJSON_AddStringToObject(o, "_crc", "bb7c929b");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "id", a->id);
    cJSON_AddItemToObject(o, "mode", vl_api_bond_mode_t_tojson(a->mode));
    cJSON_AddItemToObject(o, "lb", vl_api_bond_lb_algo_t_tojson(a->lb));
    cJSON_AddBoolToObject(o, "numa_only", a->numa_only);
    cJSON_AddNumberToObject(o, "active_slaves", a->active_slaves);
    cJSON_AddNumberToObject(o, "slaves", a->slaves);
    cJSON_AddStringToObject(o, "interface_name", (char *)a->interface_name);
    return o;
}
static inline cJSON *vl_api_sw_bond_interface_dump_t_tojson (vl_api_sw_bond_interface_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_bond_interface_dump");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_sw_bond_interface_details_t_tojson (vl_api_sw_bond_interface_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_bond_interface_details");
    cJSON_AddStringToObject(o, "_crc", "9428a69c");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "id", a->id);
    cJSON_AddItemToObject(o, "mode", vl_api_bond_mode_t_tojson(a->mode));
    cJSON_AddItemToObject(o, "lb", vl_api_bond_lb_algo_t_tojson(a->lb));
    cJSON_AddBoolToObject(o, "numa_only", a->numa_only);
    cJSON_AddNumberToObject(o, "active_members", a->active_members);
    cJSON_AddNumberToObject(o, "members", a->members);
    cJSON_AddStringToObject(o, "interface_name", (char *)a->interface_name);
    return o;
}
static inline cJSON *vl_api_sw_interface_slave_dump_t_tojson (vl_api_sw_interface_slave_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_slave_dump");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_sw_interface_slave_details_t_tojson (vl_api_sw_interface_slave_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_slave_details");
    cJSON_AddStringToObject(o, "_crc", "3c4a0e23");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddStringToObject(o, "interface_name", (char *)a->interface_name);
    cJSON_AddBoolToObject(o, "is_passive", a->is_passive);
    cJSON_AddBoolToObject(o, "is_long_timeout", a->is_long_timeout);
    cJSON_AddBoolToObject(o, "is_local_numa", a->is_local_numa);
    cJSON_AddNumberToObject(o, "weight", a->weight);
    return o;
}
static inline cJSON *vl_api_sw_member_interface_dump_t_tojson (vl_api_sw_member_interface_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_member_interface_dump");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_sw_member_interface_details_t_tojson (vl_api_sw_member_interface_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_member_interface_details");
    cJSON_AddStringToObject(o, "_crc", "3c4a0e23");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddStringToObject(o, "interface_name", (char *)a->interface_name);
    cJSON_AddBoolToObject(o, "is_passive", a->is_passive);
    cJSON_AddBoolToObject(o, "is_long_timeout", a->is_long_timeout);
    cJSON_AddBoolToObject(o, "is_local_numa", a->is_local_numa);
    cJSON_AddNumberToObject(o, "weight", a->weight);
    return o;
}
static inline cJSON *vl_api_sw_interface_set_bond_weight_t_tojson (vl_api_sw_interface_set_bond_weight_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_bond_weight");
    cJSON_AddStringToObject(o, "_crc", "deb510a0");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "weight", a->weight);
    return o;
}
static inline cJSON *vl_api_sw_interface_set_bond_weight_reply_t_tojson (vl_api_sw_interface_set_bond_weight_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_bond_weight_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
