/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ip/ip_types.api_tojson.h>
#include <vnet/ethernet/ethernet_types.api_tojson.h>
#ifndef included_dhcp_api_tojson_h
#define included_dhcp_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_vss_type_t_tojson (vl_api_vss_type_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("VSS_TYPE_API_ASCII");
    case 1:
        return cJSON_CreateString("VSS_TYPE_API_VPN_ID");
    case 123:
        return cJSON_CreateString("VSS_TYPE_API_INVALID");
    case 255:
        return cJSON_CreateString("VSS_TYPE_API_DEFAULT");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_dhcp_client_state_t_tojson (vl_api_dhcp_client_state_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("DHCP_CLIENT_STATE_API_DISCOVER");
    case 1:
        return cJSON_CreateString("DHCP_CLIENT_STATE_API_REQUEST");
    case 2:
        return cJSON_CreateString("DHCP_CLIENT_STATE_API_BOUND");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_dhcpv6_msg_type_t_tojson (vl_api_dhcpv6_msg_type_t a) {
    switch(a) {
    case 1:
        return cJSON_CreateString("DHCPV6_MSG_API_SOLICIT");
    case 2:
        return cJSON_CreateString("DHCPV6_MSG_API_ADVERTISE");
    case 3:
        return cJSON_CreateString("DHCPV6_MSG_API_REQUEST");
    case 4:
        return cJSON_CreateString("DHCPV6_MSG_API_CONFIRM");
    case 5:
        return cJSON_CreateString("DHCPV6_MSG_API_RENEW");
    case 6:
        return cJSON_CreateString("DHCPV6_MSG_API_REBIND");
    case 7:
        return cJSON_CreateString("DHCPV6_MSG_API_REPLY");
    case 8:
        return cJSON_CreateString("DHCPV6_MSG_API_RELEASE");
    case 9:
        return cJSON_CreateString("DHCPV6_MSG_API_DECLINE");
    case 10:
        return cJSON_CreateString("DHCPV6_MSG_API_RECONFIGURE");
    case 11:
        return cJSON_CreateString("DHCPV6_MSG_API_INFORMATION_REQUEST");
    case 12:
        return cJSON_CreateString("DHCPV6_MSG_API_RELAY_FORW");
    case 13:
        return cJSON_CreateString("DHCPV6_MSG_API_RELAY_REPL");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_dhcp_client_t_tojson (vl_api_dhcp_client_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddStringToObject(o, "hostname", (char *)a->hostname);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->id, 64);
    cJSON_AddStringToObject(o, "id", s);
    vec_free(s);
    }
    cJSON_AddBoolToObject(o, "want_dhcp_event", a->want_dhcp_event);
    cJSON_AddBoolToObject(o, "set_broadcast_flag", a->set_broadcast_flag);
    cJSON_AddItemToObject(o, "dscp", vl_api_ip_dscp_t_tojson(a->dscp));
    cJSON_AddNumberToObject(o, "pid", a->pid);
    return o;
}
static inline cJSON *vl_api_domain_server_t_tojson (vl_api_domain_server_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "address", vl_api_address_t_tojson(&a->address));
    return o;
}
static inline cJSON *vl_api_dhcp_lease_t_tojson (vl_api_dhcp_lease_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "state", vl_api_dhcp_client_state_t_tojson(a->state));
    cJSON_AddBoolToObject(o, "is_ipv6", a->is_ipv6);
    cJSON_AddStringToObject(o, "hostname", (char *)a->hostname);
    cJSON_AddNumberToObject(o, "mask_width", a->mask_width);
    cJSON_AddItemToObject(o, "host_address", vl_api_address_t_tojson(&a->host_address));
    cJSON_AddItemToObject(o, "router_address", vl_api_address_t_tojson(&a->router_address));
    cJSON_AddItemToObject(o, "host_mac", vl_api_mac_address_t_tojson(&a->host_mac));
    cJSON_AddNumberToObject(o, "count", a->count);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "domain_server");
        for (i = 0; i < a->count; i++) {
            cJSON_AddItemToArray(array, vl_api_domain_server_t_tojson(&a->domain_server[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_dhcp_server_t_tojson (vl_api_dhcp_server_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "server_vrf_id", a->server_vrf_id);
    cJSON_AddItemToObject(o, "dhcp_server", vl_api_address_t_tojson(&a->dhcp_server));
    return o;
}
static inline cJSON *vl_api_dhcp6_address_info_t_tojson (vl_api_dhcp6_address_info_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "address", vl_api_ip6_address_t_tojson(&a->address));
    cJSON_AddNumberToObject(o, "valid_time", a->valid_time);
    cJSON_AddNumberToObject(o, "preferred_time", a->preferred_time);
    return o;
}
static inline cJSON *vl_api_dhcp6_pd_prefix_info_t_tojson (vl_api_dhcp6_pd_prefix_info_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "prefix", vl_api_ip6_prefix_t_tojson(&a->prefix));
    cJSON_AddNumberToObject(o, "valid_time", a->valid_time);
    cJSON_AddNumberToObject(o, "preferred_time", a->preferred_time);
    return o;
}
static inline cJSON *vl_api_dhcp_plugin_get_version_t_tojson (vl_api_dhcp_plugin_get_version_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dhcp_plugin_get_version");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_dhcp_plugin_get_version_reply_t_tojson (vl_api_dhcp_plugin_get_version_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dhcp_plugin_get_version_reply");
    cJSON_AddStringToObject(o, "_crc", "9b32cf86");
    cJSON_AddNumberToObject(o, "major", a->major);
    cJSON_AddNumberToObject(o, "minor", a->minor);
    return o;
}
static inline cJSON *vl_api_dhcp_plugin_control_ping_t_tojson (vl_api_dhcp_plugin_control_ping_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dhcp_plugin_control_ping");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_dhcp_plugin_control_ping_reply_t_tojson (vl_api_dhcp_plugin_control_ping_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dhcp_plugin_control_ping_reply");
    cJSON_AddStringToObject(o, "_crc", "f6b0b8ca");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "vpe_pid", a->vpe_pid);
    return o;
}
static inline cJSON *vl_api_dhcp_proxy_config_t_tojson (vl_api_dhcp_proxy_config_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dhcp_proxy_config");
    cJSON_AddStringToObject(o, "_crc", "4058a689");
    cJSON_AddNumberToObject(o, "rx_vrf_id", a->rx_vrf_id);
    cJSON_AddNumberToObject(o, "server_vrf_id", a->server_vrf_id);
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "dhcp_server", vl_api_address_t_tojson(&a->dhcp_server));
    cJSON_AddItemToObject(o, "dhcp_src_address", vl_api_address_t_tojson(&a->dhcp_src_address));
    return o;
}
static inline cJSON *vl_api_dhcp_proxy_config_reply_t_tojson (vl_api_dhcp_proxy_config_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dhcp_proxy_config_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_dhcp_proxy_set_vss_t_tojson (vl_api_dhcp_proxy_set_vss_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dhcp_proxy_set_vss");
    cJSON_AddStringToObject(o, "_crc", "50537301");
    cJSON_AddNumberToObject(o, "tbl_id", a->tbl_id);
    cJSON_AddItemToObject(o, "vss_type", vl_api_vss_type_t_tojson(a->vss_type));
    cJSON_AddStringToObject(o, "vpn_ascii_id", (char *)a->vpn_ascii_id);
    cJSON_AddNumberToObject(o, "oui", a->oui);
    cJSON_AddNumberToObject(o, "vpn_index", a->vpn_index);
    cJSON_AddBoolToObject(o, "is_ipv6", a->is_ipv6);
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    return o;
}
static inline cJSON *vl_api_dhcp_proxy_set_vss_reply_t_tojson (vl_api_dhcp_proxy_set_vss_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dhcp_proxy_set_vss_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_dhcp_client_config_t_tojson (vl_api_dhcp_client_config_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dhcp_client_config");
    cJSON_AddStringToObject(o, "_crc", "1af013ea");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "client", vl_api_dhcp_client_t_tojson(&a->client));
    return o;
}
static inline cJSON *vl_api_dhcp_client_config_reply_t_tojson (vl_api_dhcp_client_config_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dhcp_client_config_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_dhcp_compl_event_t_tojson (vl_api_dhcp_compl_event_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dhcp_compl_event");
    cJSON_AddStringToObject(o, "_crc", "e18124b7");
    cJSON_AddNumberToObject(o, "pid", a->pid);
    cJSON_AddItemToObject(o, "lease", vl_api_dhcp_lease_t_tojson(&a->lease));
    return o;
}
static inline cJSON *vl_api_dhcp_client_dump_t_tojson (vl_api_dhcp_client_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dhcp_client_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_dhcp_client_details_t_tojson (vl_api_dhcp_client_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dhcp_client_details");
    cJSON_AddStringToObject(o, "_crc", "8897b2d8");
    cJSON_AddItemToObject(o, "client", vl_api_dhcp_client_t_tojson(&a->client));
    cJSON_AddItemToObject(o, "lease", vl_api_dhcp_lease_t_tojson(&a->lease));
    return o;
}
static inline cJSON *vl_api_dhcp_proxy_dump_t_tojson (vl_api_dhcp_proxy_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dhcp_proxy_dump");
    cJSON_AddStringToObject(o, "_crc", "5c5b063f");
    cJSON_AddBoolToObject(o, "is_ip6", a->is_ip6);
    return o;
}
static inline cJSON *vl_api_dhcp_proxy_details_t_tojson (vl_api_dhcp_proxy_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dhcp_proxy_details");
    cJSON_AddStringToObject(o, "_crc", "dcbaf540");
    cJSON_AddNumberToObject(o, "rx_vrf_id", a->rx_vrf_id);
    cJSON_AddNumberToObject(o, "vss_oui", a->vss_oui);
    cJSON_AddNumberToObject(o, "vss_fib_id", a->vss_fib_id);
    cJSON_AddItemToObject(o, "vss_type", vl_api_vss_type_t_tojson(a->vss_type));
    cJSON_AddBoolToObject(o, "is_ipv6", a->is_ipv6);
    cJSON_AddStringToObject(o, "vss_vpn_ascii_id", (char *)a->vss_vpn_ascii_id);
    cJSON_AddItemToObject(o, "dhcp_src_address", vl_api_address_t_tojson(&a->dhcp_src_address));
    cJSON_AddNumberToObject(o, "count", a->count);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "servers");
        for (i = 0; i < a->count; i++) {
            cJSON_AddItemToArray(array, vl_api_dhcp_server_t_tojson(&a->servers[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_dhcp_client_detect_enable_disable_t_tojson (vl_api_dhcp_client_detect_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dhcp_client_detect_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "ae6cfcfb");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "enable", a->enable);
    return o;
}
static inline cJSON *vl_api_dhcp_client_detect_enable_disable_reply_t_tojson (vl_api_dhcp_client_detect_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dhcp_client_detect_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_dhcp6_duid_ll_set_t_tojson (vl_api_dhcp6_duid_ll_set_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dhcp6_duid_ll_set");
    cJSON_AddStringToObject(o, "_crc", "0f6ca323");
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->duid_ll, 10);
    cJSON_AddStringToObject(o, "duid_ll", s);
    vec_free(s);
    }
    return o;
}
static inline cJSON *vl_api_dhcp6_duid_ll_set_reply_t_tojson (vl_api_dhcp6_duid_ll_set_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dhcp6_duid_ll_set_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_dhcp6_clients_enable_disable_t_tojson (vl_api_dhcp6_clients_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dhcp6_clients_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "b3e225d2");
    cJSON_AddBoolToObject(o, "enable", a->enable);
    return o;
}
static inline cJSON *vl_api_dhcp6_clients_enable_disable_reply_t_tojson (vl_api_dhcp6_clients_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dhcp6_clients_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_dhcp6_send_client_message_t_tojson (vl_api_dhcp6_send_client_message_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dhcp6_send_client_message");
    cJSON_AddStringToObject(o, "_crc", "f8222476");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "server_index", a->server_index);
    cJSON_AddNumberToObject(o, "irt", a->irt);
    cJSON_AddNumberToObject(o, "mrt", a->mrt);
    cJSON_AddNumberToObject(o, "mrc", a->mrc);
    cJSON_AddNumberToObject(o, "mrd", a->mrd);
    cJSON_AddBoolToObject(o, "stop", a->stop);
    cJSON_AddItemToObject(o, "msg_type", vl_api_dhcpv6_msg_type_t_tojson(a->msg_type));
    cJSON_AddNumberToObject(o, "T1", a->T1);
    cJSON_AddNumberToObject(o, "T2", a->T2);
    cJSON_AddNumberToObject(o, "n_addresses", a->n_addresses);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "addresses");
        for (i = 0; i < a->n_addresses; i++) {
            cJSON_AddItemToArray(array, vl_api_dhcp6_address_info_t_tojson(&a->addresses[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_dhcp6_send_client_message_reply_t_tojson (vl_api_dhcp6_send_client_message_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dhcp6_send_client_message_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_dhcp6_pd_send_client_message_t_tojson (vl_api_dhcp6_pd_send_client_message_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dhcp6_pd_send_client_message");
    cJSON_AddStringToObject(o, "_crc", "3739fd8d");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "server_index", a->server_index);
    cJSON_AddNumberToObject(o, "irt", a->irt);
    cJSON_AddNumberToObject(o, "mrt", a->mrt);
    cJSON_AddNumberToObject(o, "mrc", a->mrc);
    cJSON_AddNumberToObject(o, "mrd", a->mrd);
    cJSON_AddBoolToObject(o, "stop", a->stop);
    cJSON_AddItemToObject(o, "msg_type", vl_api_dhcpv6_msg_type_t_tojson(a->msg_type));
    cJSON_AddNumberToObject(o, "T1", a->T1);
    cJSON_AddNumberToObject(o, "T2", a->T2);
    cJSON_AddNumberToObject(o, "n_prefixes", a->n_prefixes);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "prefixes");
        for (i = 0; i < a->n_prefixes; i++) {
            cJSON_AddItemToArray(array, vl_api_dhcp6_pd_prefix_info_t_tojson(&a->prefixes[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_dhcp6_pd_send_client_message_reply_t_tojson (vl_api_dhcp6_pd_send_client_message_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dhcp6_pd_send_client_message_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_want_dhcp6_reply_events_t_tojson (vl_api_want_dhcp6_reply_events_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "want_dhcp6_reply_events");
    cJSON_AddStringToObject(o, "_crc", "05b454b5");
    cJSON_AddNumberToObject(o, "enable_disable", a->enable_disable);
    cJSON_AddNumberToObject(o, "pid", a->pid);
    return o;
}
static inline cJSON *vl_api_want_dhcp6_reply_events_reply_t_tojson (vl_api_want_dhcp6_reply_events_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "want_dhcp6_reply_events_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_want_dhcp6_pd_reply_events_t_tojson (vl_api_want_dhcp6_pd_reply_events_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "want_dhcp6_pd_reply_events");
    cJSON_AddStringToObject(o, "_crc", "c5e2af94");
    cJSON_AddBoolToObject(o, "enable_disable", a->enable_disable);
    cJSON_AddNumberToObject(o, "pid", a->pid);
    return o;
}
static inline cJSON *vl_api_want_dhcp6_pd_reply_events_reply_t_tojson (vl_api_want_dhcp6_pd_reply_events_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "want_dhcp6_pd_reply_events_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_dhcp6_reply_event_t_tojson (vl_api_dhcp6_reply_event_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dhcp6_reply_event");
    cJSON_AddStringToObject(o, "_crc", "85b7b17e");
    cJSON_AddNumberToObject(o, "pid", a->pid);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "server_index", a->server_index);
    cJSON_AddItemToObject(o, "msg_type", vl_api_dhcpv6_msg_type_t_tojson(a->msg_type));
    cJSON_AddNumberToObject(o, "T1", a->T1);
    cJSON_AddNumberToObject(o, "T2", a->T2);
    cJSON_AddNumberToObject(o, "inner_status_code", a->inner_status_code);
    cJSON_AddNumberToObject(o, "status_code", a->status_code);
    cJSON_AddNumberToObject(o, "preference", a->preference);
    cJSON_AddNumberToObject(o, "n_addresses", a->n_addresses);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "addresses");
        for (i = 0; i < a->n_addresses; i++) {
            cJSON_AddItemToArray(array, vl_api_dhcp6_address_info_t_tojson(&a->addresses[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_dhcp6_pd_reply_event_t_tojson (vl_api_dhcp6_pd_reply_event_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dhcp6_pd_reply_event");
    cJSON_AddStringToObject(o, "_crc", "5e878029");
    cJSON_AddNumberToObject(o, "pid", a->pid);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "server_index", a->server_index);
    cJSON_AddItemToObject(o, "msg_type", vl_api_dhcpv6_msg_type_t_tojson(a->msg_type));
    cJSON_AddNumberToObject(o, "T1", a->T1);
    cJSON_AddNumberToObject(o, "T2", a->T2);
    cJSON_AddNumberToObject(o, "inner_status_code", a->inner_status_code);
    cJSON_AddNumberToObject(o, "status_code", a->status_code);
    cJSON_AddNumberToObject(o, "preference", a->preference);
    cJSON_AddNumberToObject(o, "n_prefixes", a->n_prefixes);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "prefixes");
        for (i = 0; i < a->n_prefixes; i++) {
            cJSON_AddItemToArray(array, vl_api_dhcp6_pd_prefix_info_t_tojson(&a->prefixes[i]));
        }
    }
    return o;
}
#endif
