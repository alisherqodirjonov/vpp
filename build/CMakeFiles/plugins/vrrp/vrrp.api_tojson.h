/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ip/ip_types.api_tojson.h>
#include <vnet/ethernet/ethernet_types.api_tojson.h>
#ifndef included_vrrp_api_tojson_h
#define included_vrrp_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_vrrp_vr_key_t_tojson (vl_api_vrrp_vr_key_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "vr_id", a->vr_id);
    cJSON_AddNumberToObject(o, "is_ipv6", a->is_ipv6);
    return o;
}
static inline cJSON *vl_api_vrrp_vr_flags_t_tojson (vl_api_vrrp_vr_flags_t a) {
    switch(a) {
    case 1:
        return cJSON_CreateString("VRRP_API_VR_PREEMPT");
    case 2:
        return cJSON_CreateString("VRRP_API_VR_ACCEPT");
    case 4:
        return cJSON_CreateString("VRRP_API_VR_UNICAST");
    case 8:
        return cJSON_CreateString("VRRP_API_VR_IPV6");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_vrrp_vr_conf_t_tojson (vl_api_vrrp_vr_conf_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "vr_id", a->vr_id);
    cJSON_AddNumberToObject(o, "priority", a->priority);
    cJSON_AddNumberToObject(o, "interval", a->interval);
    cJSON_AddItemToObject(o, "flags", vl_api_vrrp_vr_flags_t_tojson(a->flags));
    return o;
}
static inline cJSON *vl_api_vrrp_vr_state_t_tojson (vl_api_vrrp_vr_state_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("VRRP_API_VR_STATE_INIT");
    case 1:
        return cJSON_CreateString("VRRP_API_VR_STATE_BACKUP");
    case 2:
        return cJSON_CreateString("VRRP_API_VR_STATE_MASTER");
    case 3:
        return cJSON_CreateString("VRRP_API_VR_STATE_INTF_DOWN");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_vrrp_vr_tracking_t_tojson (vl_api_vrrp_vr_tracking_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "interfaces_dec", a->interfaces_dec);
    cJSON_AddNumberToObject(o, "priority", a->priority);
    return o;
}
static inline cJSON *vl_api_vrrp_vr_runtime_t_tojson (vl_api_vrrp_vr_runtime_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "state", vl_api_vrrp_vr_state_t_tojson(a->state));
    cJSON_AddNumberToObject(o, "master_adv_int", a->master_adv_int);
    cJSON_AddNumberToObject(o, "skew", a->skew);
    cJSON_AddNumberToObject(o, "master_down_int", a->master_down_int);
    cJSON_AddItemToObject(o, "mac", vl_api_mac_address_t_tojson(&a->mac));
    cJSON_AddItemToObject(o, "tracking", vl_api_vrrp_vr_tracking_t_tojson(&a->tracking));
    return o;
}
static inline cJSON *vl_api_vrrp_vr_track_if_t_tojson (vl_api_vrrp_vr_track_if_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "priority", a->priority);
    return o;
}
static inline cJSON *vl_api_vrrp_vr_add_del_t_tojson (vl_api_vrrp_vr_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vrrp_vr_add_del");
    cJSON_AddStringToObject(o, "_crc", "c5cf15aa");
    cJSON_AddNumberToObject(o, "is_add", a->is_add);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "vr_id", a->vr_id);
    cJSON_AddNumberToObject(o, "priority", a->priority);
    cJSON_AddNumberToObject(o, "interval", a->interval);
    cJSON_AddItemToObject(o, "flags", vl_api_vrrp_vr_flags_t_tojson(a->flags));
    cJSON_AddNumberToObject(o, "n_addrs", a->n_addrs);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "addrs");
        for (i = 0; i < a->n_addrs; i++) {
            cJSON_AddItemToArray(array, vl_api_address_t_tojson(&a->addrs[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_vrrp_vr_add_del_reply_t_tojson (vl_api_vrrp_vr_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vrrp_vr_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_vrrp_vr_update_t_tojson (vl_api_vrrp_vr_update_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vrrp_vr_update");
    cJSON_AddStringToObject(o, "_crc", "0b51e2f4");
    cJSON_AddNumberToObject(o, "vrrp_index", a->vrrp_index);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "vr_id", a->vr_id);
    cJSON_AddNumberToObject(o, "priority", a->priority);
    cJSON_AddNumberToObject(o, "interval", a->interval);
    cJSON_AddItemToObject(o, "flags", vl_api_vrrp_vr_flags_t_tojson(a->flags));
    cJSON_AddNumberToObject(o, "n_addrs", a->n_addrs);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "addrs");
        for (i = 0; i < a->n_addrs; i++) {
            cJSON_AddItemToArray(array, vl_api_address_t_tojson(&a->addrs[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_vrrp_vr_update_reply_t_tojson (vl_api_vrrp_vr_update_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vrrp_vr_update_reply");
    cJSON_AddStringToObject(o, "_crc", "5317d608");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "vrrp_index", a->vrrp_index);
    return o;
}
static inline cJSON *vl_api_vrrp_vr_del_t_tojson (vl_api_vrrp_vr_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vrrp_vr_del");
    cJSON_AddStringToObject(o, "_crc", "6029baa1");
    cJSON_AddNumberToObject(o, "vrrp_index", a->vrrp_index);
    return o;
}
static inline cJSON *vl_api_vrrp_vr_del_reply_t_tojson (vl_api_vrrp_vr_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vrrp_vr_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_vrrp_vr_dump_t_tojson (vl_api_vrrp_vr_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vrrp_vr_dump");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_vrrp_vr_details_t_tojson (vl_api_vrrp_vr_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vrrp_vr_details");
    cJSON_AddStringToObject(o, "_crc", "46edcebd");
    cJSON_AddItemToObject(o, "config", vl_api_vrrp_vr_conf_t_tojson(&a->config));
    cJSON_AddItemToObject(o, "runtime", vl_api_vrrp_vr_runtime_t_tojson(&a->runtime));
    cJSON_AddNumberToObject(o, "n_addrs", a->n_addrs);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "addrs");
        for (i = 0; i < a->n_addrs; i++) {
            cJSON_AddItemToArray(array, vl_api_address_t_tojson(&a->addrs[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_vrrp_vr_start_stop_t_tojson (vl_api_vrrp_vr_start_stop_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vrrp_vr_start_stop");
    cJSON_AddStringToObject(o, "_crc", "0662a3b7");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "vr_id", a->vr_id);
    cJSON_AddNumberToObject(o, "is_ipv6", a->is_ipv6);
    cJSON_AddNumberToObject(o, "is_start", a->is_start);
    return o;
}
static inline cJSON *vl_api_vrrp_vr_start_stop_reply_t_tojson (vl_api_vrrp_vr_start_stop_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vrrp_vr_start_stop_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_vrrp_vr_set_peers_t_tojson (vl_api_vrrp_vr_set_peers_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vrrp_vr_set_peers");
    cJSON_AddStringToObject(o, "_crc", "20bec71f");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "vr_id", a->vr_id);
    cJSON_AddNumberToObject(o, "is_ipv6", a->is_ipv6);
    cJSON_AddNumberToObject(o, "n_addrs", a->n_addrs);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "addrs");
        for (i = 0; i < a->n_addrs; i++) {
            cJSON_AddItemToArray(array, vl_api_address_t_tojson(&a->addrs[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_vrrp_vr_set_peers_reply_t_tojson (vl_api_vrrp_vr_set_peers_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vrrp_vr_set_peers_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_vrrp_vr_peer_dump_t_tojson (vl_api_vrrp_vr_peer_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vrrp_vr_peer_dump");
    cJSON_AddStringToObject(o, "_crc", "6fa3f7c4");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "is_ipv6", a->is_ipv6);
    cJSON_AddNumberToObject(o, "vr_id", a->vr_id);
    return o;
}
static inline cJSON *vl_api_vrrp_vr_peer_details_t_tojson (vl_api_vrrp_vr_peer_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vrrp_vr_peer_details");
    cJSON_AddStringToObject(o, "_crc", "3d99c108");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "vr_id", a->vr_id);
    cJSON_AddNumberToObject(o, "is_ipv6", a->is_ipv6);
    cJSON_AddNumberToObject(o, "n_peer_addrs", a->n_peer_addrs);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "peer_addrs");
        for (i = 0; i < a->n_peer_addrs; i++) {
            cJSON_AddItemToArray(array, vl_api_address_t_tojson(&a->peer_addrs[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_vrrp_vr_track_if_add_del_t_tojson (vl_api_vrrp_vr_track_if_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vrrp_vr_track_if_add_del");
    cJSON_AddStringToObject(o, "_crc", "d67df299");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "is_ipv6", a->is_ipv6);
    cJSON_AddNumberToObject(o, "vr_id", a->vr_id);
    cJSON_AddNumberToObject(o, "is_add", a->is_add);
    cJSON_AddNumberToObject(o, "n_ifs", a->n_ifs);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "ifs");
        for (i = 0; i < a->n_ifs; i++) {
            cJSON_AddItemToArray(array, vl_api_vrrp_vr_track_if_t_tojson(&a->ifs[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_vrrp_vr_track_if_add_del_reply_t_tojson (vl_api_vrrp_vr_track_if_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vrrp_vr_track_if_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_vrrp_vr_track_if_dump_t_tojson (vl_api_vrrp_vr_track_if_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vrrp_vr_track_if_dump");
    cJSON_AddStringToObject(o, "_crc", "a34dfc6d");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "is_ipv6", a->is_ipv6);
    cJSON_AddNumberToObject(o, "vr_id", a->vr_id);
    cJSON_AddNumberToObject(o, "dump_all", a->dump_all);
    return o;
}
static inline cJSON *vl_api_vrrp_vr_track_if_details_t_tojson (vl_api_vrrp_vr_track_if_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vrrp_vr_track_if_details");
    cJSON_AddStringToObject(o, "_crc", "73c36f81");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "vr_id", a->vr_id);
    cJSON_AddNumberToObject(o, "is_ipv6", a->is_ipv6);
    cJSON_AddNumberToObject(o, "n_ifs", a->n_ifs);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "ifs");
        for (i = 0; i < a->n_ifs; i++) {
            cJSON_AddItemToArray(array, vl_api_vrrp_vr_track_if_t_tojson(&a->ifs[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_vrrp_vr_event_t_tojson (vl_api_vrrp_vr_event_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vrrp_vr_event");
    cJSON_AddStringToObject(o, "_crc", "c1fea6a5");
    cJSON_AddNumberToObject(o, "pid", a->pid);
    cJSON_AddItemToObject(o, "vr", vl_api_vrrp_vr_key_t_tojson(&a->vr));
    cJSON_AddItemToObject(o, "old_state", vl_api_vrrp_vr_state_t_tojson(a->old_state));
    cJSON_AddItemToObject(o, "new_state", vl_api_vrrp_vr_state_t_tojson(a->new_state));
    return o;
}
static inline cJSON *vl_api_want_vrrp_vr_events_t_tojson (vl_api_want_vrrp_vr_events_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "want_vrrp_vr_events");
    cJSON_AddStringToObject(o, "_crc", "c5e2af94");
    cJSON_AddBoolToObject(o, "enable_disable", a->enable_disable);
    cJSON_AddNumberToObject(o, "pid", a->pid);
    return o;
}
static inline cJSON *vl_api_want_vrrp_vr_events_reply_t_tojson (vl_api_want_vrrp_vr_events_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "want_vrrp_vr_events_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
