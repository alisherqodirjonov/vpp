/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/ip/ip_types.api_fromjson.h>
#ifndef included_vxlan_gpe_api_fromjson_h
#define included_vxlan_gpe_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_vxlan_gpe_add_del_tunnel_t *vl_api_vxlan_gpe_add_del_tunnel_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vxlan_gpe_add_del_tunnel_t);
    vl_api_vxlan_gpe_add_del_tunnel_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "local");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->local) < 0) goto error;

    item = cJSON_GetObjectItem(o, "remote");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->remote) < 0) goto error;

    item = cJSON_GetObjectItem(o, "mcast_sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->mcast_sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "encap_vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->encap_vrf_id);

    item = cJSON_GetObjectItem(o, "decap_vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->decap_vrf_id);

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    if (vl_api_ip_proto_t_fromjson((void **)&a, &l, item, &a->protocol) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vni");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vni);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vxlan_gpe_add_del_tunnel_v2_t *vl_api_vxlan_gpe_add_del_tunnel_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vxlan_gpe_add_del_tunnel_v2_t);
    vl_api_vxlan_gpe_add_del_tunnel_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "local");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->local) < 0) goto error;

    item = cJSON_GetObjectItem(o, "remote");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->remote) < 0) goto error;

    item = cJSON_GetObjectItem(o, "local_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->local_port);

    item = cJSON_GetObjectItem(o, "remote_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->remote_port);

    item = cJSON_GetObjectItem(o, "mcast_sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->mcast_sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "encap_vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->encap_vrf_id);

    item = cJSON_GetObjectItem(o, "decap_vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->decap_vrf_id);

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    if (vl_api_ip_proto_t_fromjson((void **)&a, &l, item, &a->protocol) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vni");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vni);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vxlan_gpe_add_del_tunnel_reply_t *vl_api_vxlan_gpe_add_del_tunnel_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vxlan_gpe_add_del_tunnel_reply_t);
    vl_api_vxlan_gpe_add_del_tunnel_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vxlan_gpe_add_del_tunnel_v2_reply_t *vl_api_vxlan_gpe_add_del_tunnel_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vxlan_gpe_add_del_tunnel_v2_reply_t);
    vl_api_vxlan_gpe_add_del_tunnel_v2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vxlan_gpe_tunnel_dump_t *vl_api_vxlan_gpe_tunnel_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vxlan_gpe_tunnel_dump_t);
    vl_api_vxlan_gpe_tunnel_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vxlan_gpe_tunnel_v2_dump_t *vl_api_vxlan_gpe_tunnel_v2_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vxlan_gpe_tunnel_v2_dump_t);
    vl_api_vxlan_gpe_tunnel_v2_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vxlan_gpe_tunnel_details_t *vl_api_vxlan_gpe_tunnel_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vxlan_gpe_tunnel_details_t);
    vl_api_vxlan_gpe_tunnel_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "local");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->local) < 0) goto error;

    item = cJSON_GetObjectItem(o, "remote");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->remote) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vni");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vni);

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    if (vl_api_ip_proto_t_fromjson((void **)&a, &l, item, &a->protocol) < 0) goto error;

    item = cJSON_GetObjectItem(o, "mcast_sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->mcast_sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "encap_vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->encap_vrf_id);

    item = cJSON_GetObjectItem(o, "decap_vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->decap_vrf_id);

    item = cJSON_GetObjectItem(o, "is_ipv6");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_ipv6);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vxlan_gpe_tunnel_v2_details_t *vl_api_vxlan_gpe_tunnel_v2_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vxlan_gpe_tunnel_v2_details_t);
    vl_api_vxlan_gpe_tunnel_v2_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "local");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->local) < 0) goto error;

    item = cJSON_GetObjectItem(o, "remote");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->remote) < 0) goto error;

    item = cJSON_GetObjectItem(o, "local_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->local_port);

    item = cJSON_GetObjectItem(o, "remote_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->remote_port);

    item = cJSON_GetObjectItem(o, "vni");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vni);

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    if (vl_api_ip_proto_t_fromjson((void **)&a, &l, item, &a->protocol) < 0) goto error;

    item = cJSON_GetObjectItem(o, "mcast_sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->mcast_sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "encap_vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->encap_vrf_id);

    item = cJSON_GetObjectItem(o, "decap_vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->decap_vrf_id);

    item = cJSON_GetObjectItem(o, "is_ipv6");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_ipv6);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_set_vxlan_gpe_bypass_t *vl_api_sw_interface_set_vxlan_gpe_bypass_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_vxlan_gpe_bypass_t);
    vl_api_sw_interface_set_vxlan_gpe_bypass_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_ipv6");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_ipv6);

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_set_vxlan_gpe_bypass_reply_t *vl_api_sw_interface_set_vxlan_gpe_bypass_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_vxlan_gpe_bypass_reply_t);
    vl_api_sw_interface_set_vxlan_gpe_bypass_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
