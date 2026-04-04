/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/ip/ip_types.api_fromjson.h>
#include <vnet/ethernet/ethernet_types.api_fromjson.h>
#ifndef included_dhcp_api_fromjson_h
#define included_dhcp_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_vss_type_t_fromjson(void **mp, int *len, cJSON *o, vl_api_vss_type_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "VSS_TYPE_API_ASCII") == 0) {*a = 0; return 0;}
    if (strcmp(p, "VSS_TYPE_API_VPN_ID") == 0) {*a = 1; return 0;}
    if (strcmp(p, "VSS_TYPE_API_INVALID") == 0) {*a = 123; return 0;}
    if (strcmp(p, "VSS_TYPE_API_DEFAULT") == 0) {*a = 255; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_dhcp_client_state_t_fromjson(void **mp, int *len, cJSON *o, vl_api_dhcp_client_state_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "DHCP_CLIENT_STATE_API_DISCOVER") == 0) {*a = 0; return 0;}
    if (strcmp(p, "DHCP_CLIENT_STATE_API_REQUEST") == 0) {*a = 1; return 0;}
    if (strcmp(p, "DHCP_CLIENT_STATE_API_BOUND") == 0) {*a = 2; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_dhcpv6_msg_type_t_fromjson(void **mp, int *len, cJSON *o, vl_api_dhcpv6_msg_type_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "DHCPV6_MSG_API_SOLICIT") == 0) {*a = 1; return 0;}
    if (strcmp(p, "DHCPV6_MSG_API_ADVERTISE") == 0) {*a = 2; return 0;}
    if (strcmp(p, "DHCPV6_MSG_API_REQUEST") == 0) {*a = 3; return 0;}
    if (strcmp(p, "DHCPV6_MSG_API_CONFIRM") == 0) {*a = 4; return 0;}
    if (strcmp(p, "DHCPV6_MSG_API_RENEW") == 0) {*a = 5; return 0;}
    if (strcmp(p, "DHCPV6_MSG_API_REBIND") == 0) {*a = 6; return 0;}
    if (strcmp(p, "DHCPV6_MSG_API_REPLY") == 0) {*a = 7; return 0;}
    if (strcmp(p, "DHCPV6_MSG_API_RELEASE") == 0) {*a = 8; return 0;}
    if (strcmp(p, "DHCPV6_MSG_API_DECLINE") == 0) {*a = 9; return 0;}
    if (strcmp(p, "DHCPV6_MSG_API_RECONFIGURE") == 0) {*a = 10; return 0;}
    if (strcmp(p, "DHCPV6_MSG_API_INFORMATION_REQUEST") == 0) {*a = 11; return 0;}
    if (strcmp(p, "DHCPV6_MSG_API_RELAY_FORW") == 0) {*a = 12; return 0;}
    if (strcmp(p, "DHCPV6_MSG_API_RELAY_REPL") == 0) {*a = 13; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_dhcp_client_t_fromjson (void **mp, int *len, cJSON *o, vl_api_dhcp_client_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson(mp, len, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "hostname");
    if (!item) goto error;
    strncpy_s((char *)a->hostname, sizeof(a->hostname), cJSON_GetStringValue(item), sizeof(a->hostname) - 1);

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    if (u8string_fromjson2(o, "id", a->id) < 0) goto error;

    item = cJSON_GetObjectItem(o, "want_dhcp_event");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->want_dhcp_event);

    item = cJSON_GetObjectItem(o, "set_broadcast_flag");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->set_broadcast_flag);

    item = cJSON_GetObjectItem(o, "dscp");
    if (!item) goto error;
    if (vl_api_ip_dscp_t_fromjson(mp, len, item, &a->dscp) < 0) goto error;

    item = cJSON_GetObjectItem(o, "pid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->pid);

    return 0;

  error:
    return -1;
}
static inline int vl_api_domain_server_t_fromjson (void **mp, int *len, cJSON *o, vl_api_domain_server_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->address) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_dhcp_lease_t_fromjson (void **mp, int *len, cJSON *o, vl_api_dhcp_lease_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson(mp, len, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "state");
    if (!item) goto error;
    if (vl_api_dhcp_client_state_t_fromjson(mp, len, item, &a->state) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_ipv6");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_ipv6);

    item = cJSON_GetObjectItem(o, "hostname");
    if (!item) goto error;
    strncpy_s((char *)a->hostname, sizeof(a->hostname), cJSON_GetStringValue(item), sizeof(a->hostname) - 1);

    item = cJSON_GetObjectItem(o, "mask_width");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->mask_width);

    item = cJSON_GetObjectItem(o, "host_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->host_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "router_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->router_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "host_mac");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson(mp, len, item, &a->host_mac) < 0) goto error;

    item = cJSON_GetObjectItem(o, "domain_server");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "domain_server");
        int size = cJSON_GetArraySize(array);
        a->count = size;
        *mp = cJSON_realloc(*mp, *len + sizeof(vl_api_domain_server_t) * size);
        vl_api_domain_server_t *d = (void *)*mp + *len;
        *len += sizeof(vl_api_domain_server_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_domain_server_t_fromjson(mp, len, e, &d[i]) < 0) goto error; 
        }
    }

    return 0;

  error:
    return -1;
}
static inline int vl_api_dhcp_server_t_fromjson (void **mp, int *len, cJSON *o, vl_api_dhcp_server_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "server_vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->server_vrf_id);

    item = cJSON_GetObjectItem(o, "dhcp_server");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->dhcp_server) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_dhcp6_address_info_t_fromjson (void **mp, int *len, cJSON *o, vl_api_dhcp6_address_info_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "address");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson(mp, len, item, &a->address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "valid_time");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->valid_time);

    item = cJSON_GetObjectItem(o, "preferred_time");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->preferred_time);

    return 0;

  error:
    return -1;
}
static inline int vl_api_dhcp6_pd_prefix_info_t_fromjson (void **mp, int *len, cJSON *o, vl_api_dhcp6_pd_prefix_info_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "prefix");
    if (!item) goto error;
    if (vl_api_ip6_prefix_t_fromjson(mp, len, item, &a->prefix) < 0) goto error;

    item = cJSON_GetObjectItem(o, "valid_time");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->valid_time);

    item = cJSON_GetObjectItem(o, "preferred_time");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->preferred_time);

    return 0;

  error:
    return -1;
}
static inline vl_api_dhcp_plugin_get_version_t *vl_api_dhcp_plugin_get_version_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dhcp_plugin_get_version_t);
    vl_api_dhcp_plugin_get_version_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_dhcp_plugin_get_version_reply_t *vl_api_dhcp_plugin_get_version_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dhcp_plugin_get_version_reply_t);
    vl_api_dhcp_plugin_get_version_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "major");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->major);

    item = cJSON_GetObjectItem(o, "minor");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->minor);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dhcp_plugin_control_ping_t *vl_api_dhcp_plugin_control_ping_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dhcp_plugin_control_ping_t);
    vl_api_dhcp_plugin_control_ping_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_dhcp_plugin_control_ping_reply_t *vl_api_dhcp_plugin_control_ping_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dhcp_plugin_control_ping_reply_t);
    vl_api_dhcp_plugin_control_ping_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "vpe_pid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vpe_pid);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dhcp_proxy_config_t *vl_api_dhcp_proxy_config_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dhcp_proxy_config_t);
    vl_api_dhcp_proxy_config_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "rx_vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->rx_vrf_id);

    item = cJSON_GetObjectItem(o, "server_vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->server_vrf_id);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "dhcp_server");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->dhcp_server) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dhcp_src_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->dhcp_src_address) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dhcp_proxy_config_reply_t *vl_api_dhcp_proxy_config_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dhcp_proxy_config_reply_t);
    vl_api_dhcp_proxy_config_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dhcp_proxy_set_vss_t *vl_api_dhcp_proxy_set_vss_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dhcp_proxy_set_vss_t);
    vl_api_dhcp_proxy_set_vss_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "tbl_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->tbl_id);

    item = cJSON_GetObjectItem(o, "vss_type");
    if (!item) goto error;
    if (vl_api_vss_type_t_fromjson((void **)&a, &l, item, &a->vss_type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vpn_ascii_id");
    if (!item) goto error;
    strncpy_s((char *)a->vpn_ascii_id, sizeof(a->vpn_ascii_id), cJSON_GetStringValue(item), sizeof(a->vpn_ascii_id) - 1);

    item = cJSON_GetObjectItem(o, "oui");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->oui);

    item = cJSON_GetObjectItem(o, "vpn_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vpn_index);

    item = cJSON_GetObjectItem(o, "is_ipv6");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_ipv6);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dhcp_proxy_set_vss_reply_t *vl_api_dhcp_proxy_set_vss_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dhcp_proxy_set_vss_reply_t);
    vl_api_dhcp_proxy_set_vss_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dhcp_client_config_t *vl_api_dhcp_client_config_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dhcp_client_config_t);
    vl_api_dhcp_client_config_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "client");
    if (!item) goto error;
    if (vl_api_dhcp_client_t_fromjson((void **)&a, &l, item, &a->client) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dhcp_client_config_reply_t *vl_api_dhcp_client_config_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dhcp_client_config_reply_t);
    vl_api_dhcp_client_config_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dhcp_compl_event_t *vl_api_dhcp_compl_event_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dhcp_compl_event_t);
    vl_api_dhcp_compl_event_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "pid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->pid);

    item = cJSON_GetObjectItem(o, "lease");
    if (!item) goto error;
    if (vl_api_dhcp_lease_t_fromjson((void **)&a, &l, item, &a->lease) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dhcp_client_dump_t *vl_api_dhcp_client_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dhcp_client_dump_t);
    vl_api_dhcp_client_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_dhcp_client_details_t *vl_api_dhcp_client_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dhcp_client_details_t);
    vl_api_dhcp_client_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "client");
    if (!item) goto error;
    if (vl_api_dhcp_client_t_fromjson((void **)&a, &l, item, &a->client) < 0) goto error;

    item = cJSON_GetObjectItem(o, "lease");
    if (!item) goto error;
    if (vl_api_dhcp_lease_t_fromjson((void **)&a, &l, item, &a->lease) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dhcp_proxy_dump_t *vl_api_dhcp_proxy_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dhcp_proxy_dump_t);
    vl_api_dhcp_proxy_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_ip6");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_ip6);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dhcp_proxy_details_t *vl_api_dhcp_proxy_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dhcp_proxy_details_t);
    vl_api_dhcp_proxy_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "rx_vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->rx_vrf_id);

    item = cJSON_GetObjectItem(o, "vss_oui");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vss_oui);

    item = cJSON_GetObjectItem(o, "vss_fib_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vss_fib_id);

    item = cJSON_GetObjectItem(o, "vss_type");
    if (!item) goto error;
    if (vl_api_vss_type_t_fromjson((void **)&a, &l, item, &a->vss_type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_ipv6");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_ipv6);

    item = cJSON_GetObjectItem(o, "vss_vpn_ascii_id");
    if (!item) goto error;
    strncpy_s((char *)a->vss_vpn_ascii_id, sizeof(a->vss_vpn_ascii_id), cJSON_GetStringValue(item), sizeof(a->vss_vpn_ascii_id) - 1);

    item = cJSON_GetObjectItem(o, "dhcp_src_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->dhcp_src_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "servers");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "servers");
        int size = cJSON_GetArraySize(array);
        a->count = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_dhcp_server_t) * size);
        vl_api_dhcp_server_t *d = (void *)a + l;
        l += sizeof(vl_api_dhcp_server_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_dhcp_server_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dhcp_client_detect_enable_disable_t *vl_api_dhcp_client_detect_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dhcp_client_detect_enable_disable_t);
    vl_api_dhcp_client_detect_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dhcp_client_detect_enable_disable_reply_t *vl_api_dhcp_client_detect_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dhcp_client_detect_enable_disable_reply_t);
    vl_api_dhcp_client_detect_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dhcp6_duid_ll_set_t *vl_api_dhcp6_duid_ll_set_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dhcp6_duid_ll_set_t);
    vl_api_dhcp6_duid_ll_set_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "duid_ll");
    if (!item) goto error;
    if (u8string_fromjson2(o, "duid_ll", a->duid_ll) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dhcp6_duid_ll_set_reply_t *vl_api_dhcp6_duid_ll_set_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dhcp6_duid_ll_set_reply_t);
    vl_api_dhcp6_duid_ll_set_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dhcp6_clients_enable_disable_t *vl_api_dhcp6_clients_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dhcp6_clients_enable_disable_t);
    vl_api_dhcp6_clients_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dhcp6_clients_enable_disable_reply_t *vl_api_dhcp6_clients_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dhcp6_clients_enable_disable_reply_t);
    vl_api_dhcp6_clients_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dhcp6_send_client_message_t *vl_api_dhcp6_send_client_message_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dhcp6_send_client_message_t);
    vl_api_dhcp6_send_client_message_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "server_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->server_index);

    item = cJSON_GetObjectItem(o, "irt");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->irt);

    item = cJSON_GetObjectItem(o, "mrt");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->mrt);

    item = cJSON_GetObjectItem(o, "mrc");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->mrc);

    item = cJSON_GetObjectItem(o, "mrd");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->mrd);

    item = cJSON_GetObjectItem(o, "stop");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->stop);

    item = cJSON_GetObjectItem(o, "msg_type");
    if (!item) goto error;
    if (vl_api_dhcpv6_msg_type_t_fromjson((void **)&a, &l, item, &a->msg_type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "T1");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->T1);

    item = cJSON_GetObjectItem(o, "T2");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->T2);

    item = cJSON_GetObjectItem(o, "addresses");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "addresses");
        int size = cJSON_GetArraySize(array);
        a->n_addresses = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_dhcp6_address_info_t) * size);
        vl_api_dhcp6_address_info_t *d = (void *)a + l;
        l += sizeof(vl_api_dhcp6_address_info_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_dhcp6_address_info_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dhcp6_send_client_message_reply_t *vl_api_dhcp6_send_client_message_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dhcp6_send_client_message_reply_t);
    vl_api_dhcp6_send_client_message_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dhcp6_pd_send_client_message_t *vl_api_dhcp6_pd_send_client_message_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dhcp6_pd_send_client_message_t);
    vl_api_dhcp6_pd_send_client_message_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "server_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->server_index);

    item = cJSON_GetObjectItem(o, "irt");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->irt);

    item = cJSON_GetObjectItem(o, "mrt");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->mrt);

    item = cJSON_GetObjectItem(o, "mrc");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->mrc);

    item = cJSON_GetObjectItem(o, "mrd");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->mrd);

    item = cJSON_GetObjectItem(o, "stop");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->stop);

    item = cJSON_GetObjectItem(o, "msg_type");
    if (!item) goto error;
    if (vl_api_dhcpv6_msg_type_t_fromjson((void **)&a, &l, item, &a->msg_type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "T1");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->T1);

    item = cJSON_GetObjectItem(o, "T2");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->T2);

    item = cJSON_GetObjectItem(o, "prefixes");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "prefixes");
        int size = cJSON_GetArraySize(array);
        a->n_prefixes = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_dhcp6_pd_prefix_info_t) * size);
        vl_api_dhcp6_pd_prefix_info_t *d = (void *)a + l;
        l += sizeof(vl_api_dhcp6_pd_prefix_info_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_dhcp6_pd_prefix_info_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dhcp6_pd_send_client_message_reply_t *vl_api_dhcp6_pd_send_client_message_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dhcp6_pd_send_client_message_reply_t);
    vl_api_dhcp6_pd_send_client_message_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_want_dhcp6_reply_events_t *vl_api_want_dhcp6_reply_events_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_want_dhcp6_reply_events_t);
    vl_api_want_dhcp6_reply_events_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "enable_disable");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->enable_disable);

    item = cJSON_GetObjectItem(o, "pid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->pid);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_want_dhcp6_reply_events_reply_t *vl_api_want_dhcp6_reply_events_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_want_dhcp6_reply_events_reply_t);
    vl_api_want_dhcp6_reply_events_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_want_dhcp6_pd_reply_events_t *vl_api_want_dhcp6_pd_reply_events_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_want_dhcp6_pd_reply_events_t);
    vl_api_want_dhcp6_pd_reply_events_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "enable_disable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable_disable);

    item = cJSON_GetObjectItem(o, "pid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->pid);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_want_dhcp6_pd_reply_events_reply_t *vl_api_want_dhcp6_pd_reply_events_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_want_dhcp6_pd_reply_events_reply_t);
    vl_api_want_dhcp6_pd_reply_events_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dhcp6_reply_event_t *vl_api_dhcp6_reply_event_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dhcp6_reply_event_t);
    vl_api_dhcp6_reply_event_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "pid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->pid);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "server_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->server_index);

    item = cJSON_GetObjectItem(o, "msg_type");
    if (!item) goto error;
    if (vl_api_dhcpv6_msg_type_t_fromjson((void **)&a, &l, item, &a->msg_type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "T1");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->T1);

    item = cJSON_GetObjectItem(o, "T2");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->T2);

    item = cJSON_GetObjectItem(o, "inner_status_code");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->inner_status_code);

    item = cJSON_GetObjectItem(o, "status_code");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->status_code);

    item = cJSON_GetObjectItem(o, "preference");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->preference);

    item = cJSON_GetObjectItem(o, "addresses");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "addresses");
        int size = cJSON_GetArraySize(array);
        a->n_addresses = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_dhcp6_address_info_t) * size);
        vl_api_dhcp6_address_info_t *d = (void *)a + l;
        l += sizeof(vl_api_dhcp6_address_info_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_dhcp6_address_info_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dhcp6_pd_reply_event_t *vl_api_dhcp6_pd_reply_event_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dhcp6_pd_reply_event_t);
    vl_api_dhcp6_pd_reply_event_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "pid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->pid);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "server_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->server_index);

    item = cJSON_GetObjectItem(o, "msg_type");
    if (!item) goto error;
    if (vl_api_dhcpv6_msg_type_t_fromjson((void **)&a, &l, item, &a->msg_type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "T1");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->T1);

    item = cJSON_GetObjectItem(o, "T2");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->T2);

    item = cJSON_GetObjectItem(o, "inner_status_code");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->inner_status_code);

    item = cJSON_GetObjectItem(o, "status_code");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->status_code);

    item = cJSON_GetObjectItem(o, "preference");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->preference);

    item = cJSON_GetObjectItem(o, "prefixes");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "prefixes");
        int size = cJSON_GetArraySize(array);
        a->n_prefixes = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_dhcp6_pd_prefix_info_t) * size);
        vl_api_dhcp6_pd_prefix_info_t *d = (void *)a + l;
        l += sizeof(vl_api_dhcp6_pd_prefix_info_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_dhcp6_pd_prefix_info_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
