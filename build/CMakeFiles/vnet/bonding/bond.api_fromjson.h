/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/ethernet/ethernet_types.api_fromjson.h>
#ifndef included_bond_api_fromjson_h
#define included_bond_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_bond_mode_t_fromjson(void **mp, int *len, cJSON *o, vl_api_bond_mode_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "BOND_API_MODE_ROUND_ROBIN") == 0) {*a = 1; return 0;}
    if (strcmp(p, "BOND_API_MODE_ACTIVE_BACKUP") == 0) {*a = 2; return 0;}
    if (strcmp(p, "BOND_API_MODE_XOR") == 0) {*a = 3; return 0;}
    if (strcmp(p, "BOND_API_MODE_BROADCAST") == 0) {*a = 4; return 0;}
    if (strcmp(p, "BOND_API_MODE_LACP") == 0) {*a = 5; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_bond_lb_algo_t_fromjson(void **mp, int *len, cJSON *o, vl_api_bond_lb_algo_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "BOND_API_LB_ALGO_L2") == 0) {*a = 0; return 0;}
    if (strcmp(p, "BOND_API_LB_ALGO_L34") == 0) {*a = 1; return 0;}
    if (strcmp(p, "BOND_API_LB_ALGO_L23") == 0) {*a = 2; return 0;}
    if (strcmp(p, "BOND_API_LB_ALGO_RR") == 0) {*a = 3; return 0;}
    if (strcmp(p, "BOND_API_LB_ALGO_BC") == 0) {*a = 4; return 0;}
    if (strcmp(p, "BOND_API_LB_ALGO_AB") == 0) {*a = 5; return 0;}
    *a = 0;
    return -1;
}
static inline vl_api_bond_create_t *vl_api_bond_create_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bond_create_t);
    vl_api_bond_create_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->id);

    item = cJSON_GetObjectItem(o, "use_custom_mac");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->use_custom_mac);

    item = cJSON_GetObjectItem(o, "mac_address");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->mac_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "mode");
    if (!item) goto error;
    if (vl_api_bond_mode_t_fromjson((void **)&a, &l, item, &a->mode) < 0) goto error;

    item = cJSON_GetObjectItem(o, "lb");
    if (!item) goto error;
    if (vl_api_bond_lb_algo_t_fromjson((void **)&a, &l, item, &a->lb) < 0) goto error;

    item = cJSON_GetObjectItem(o, "numa_only");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->numa_only);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bond_create_reply_t *vl_api_bond_create_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bond_create_reply_t);
    vl_api_bond_create_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_bond_create2_t *vl_api_bond_create2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bond_create2_t);
    vl_api_bond_create2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "mode");
    if (!item) goto error;
    if (vl_api_bond_mode_t_fromjson((void **)&a, &l, item, &a->mode) < 0) goto error;

    item = cJSON_GetObjectItem(o, "lb");
    if (!item) goto error;
    if (vl_api_bond_lb_algo_t_fromjson((void **)&a, &l, item, &a->lb) < 0) goto error;

    item = cJSON_GetObjectItem(o, "numa_only");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->numa_only);

    item = cJSON_GetObjectItem(o, "enable_gso");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable_gso);

    item = cJSON_GetObjectItem(o, "use_custom_mac");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->use_custom_mac);

    item = cJSON_GetObjectItem(o, "mac_address");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->mac_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bond_create2_reply_t *vl_api_bond_create2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bond_create2_reply_t);
    vl_api_bond_create2_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_bond_delete_t *vl_api_bond_delete_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bond_delete_t);
    vl_api_bond_delete_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bond_delete_reply_t *vl_api_bond_delete_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bond_delete_reply_t);
    vl_api_bond_delete_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bond_enslave_t *vl_api_bond_enslave_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bond_enslave_t);
    vl_api_bond_enslave_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "bond_sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->bond_sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_passive");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_passive);

    item = cJSON_GetObjectItem(o, "is_long_timeout");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_long_timeout);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bond_enslave_reply_t *vl_api_bond_enslave_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bond_enslave_reply_t);
    vl_api_bond_enslave_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bond_add_member_t *vl_api_bond_add_member_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bond_add_member_t);
    vl_api_bond_add_member_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "bond_sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->bond_sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_passive");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_passive);

    item = cJSON_GetObjectItem(o, "is_long_timeout");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_long_timeout);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bond_add_member_reply_t *vl_api_bond_add_member_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bond_add_member_reply_t);
    vl_api_bond_add_member_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bond_detach_slave_t *vl_api_bond_detach_slave_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bond_detach_slave_t);
    vl_api_bond_detach_slave_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bond_detach_slave_reply_t *vl_api_bond_detach_slave_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bond_detach_slave_reply_t);
    vl_api_bond_detach_slave_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bond_detach_member_t *vl_api_bond_detach_member_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bond_detach_member_t);
    vl_api_bond_detach_member_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bond_detach_member_reply_t *vl_api_bond_detach_member_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bond_detach_member_reply_t);
    vl_api_bond_detach_member_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_bond_dump_t *vl_api_sw_interface_bond_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_bond_dump_t);
    vl_api_sw_interface_bond_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_sw_interface_bond_details_t *vl_api_sw_interface_bond_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_bond_details_t);
    vl_api_sw_interface_bond_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->id);

    item = cJSON_GetObjectItem(o, "mode");
    if (!item) goto error;
    if (vl_api_bond_mode_t_fromjson((void **)&a, &l, item, &a->mode) < 0) goto error;

    item = cJSON_GetObjectItem(o, "lb");
    if (!item) goto error;
    if (vl_api_bond_lb_algo_t_fromjson((void **)&a, &l, item, &a->lb) < 0) goto error;

    item = cJSON_GetObjectItem(o, "numa_only");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->numa_only);

    item = cJSON_GetObjectItem(o, "active_slaves");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->active_slaves);

    item = cJSON_GetObjectItem(o, "slaves");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->slaves);

    item = cJSON_GetObjectItem(o, "interface_name");
    if (!item) goto error;
    strncpy_s((char *)a->interface_name, sizeof(a->interface_name), cJSON_GetStringValue(item), sizeof(a->interface_name) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_bond_interface_dump_t *vl_api_sw_bond_interface_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_bond_interface_dump_t);
    vl_api_sw_bond_interface_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_bond_interface_details_t *vl_api_sw_bond_interface_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_bond_interface_details_t);
    vl_api_sw_bond_interface_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->id);

    item = cJSON_GetObjectItem(o, "mode");
    if (!item) goto error;
    if (vl_api_bond_mode_t_fromjson((void **)&a, &l, item, &a->mode) < 0) goto error;

    item = cJSON_GetObjectItem(o, "lb");
    if (!item) goto error;
    if (vl_api_bond_lb_algo_t_fromjson((void **)&a, &l, item, &a->lb) < 0) goto error;

    item = cJSON_GetObjectItem(o, "numa_only");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->numa_only);

    item = cJSON_GetObjectItem(o, "active_members");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->active_members);

    item = cJSON_GetObjectItem(o, "members");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->members);

    item = cJSON_GetObjectItem(o, "interface_name");
    if (!item) goto error;
    strncpy_s((char *)a->interface_name, sizeof(a->interface_name), cJSON_GetStringValue(item), sizeof(a->interface_name) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_slave_dump_t *vl_api_sw_interface_slave_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_slave_dump_t);
    vl_api_sw_interface_slave_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_slave_details_t *vl_api_sw_interface_slave_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_slave_details_t);
    vl_api_sw_interface_slave_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "interface_name");
    if (!item) goto error;
    strncpy_s((char *)a->interface_name, sizeof(a->interface_name), cJSON_GetStringValue(item), sizeof(a->interface_name) - 1);

    item = cJSON_GetObjectItem(o, "is_passive");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_passive);

    item = cJSON_GetObjectItem(o, "is_long_timeout");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_long_timeout);

    item = cJSON_GetObjectItem(o, "is_local_numa");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_local_numa);

    item = cJSON_GetObjectItem(o, "weight");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->weight);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_member_interface_dump_t *vl_api_sw_member_interface_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_member_interface_dump_t);
    vl_api_sw_member_interface_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_member_interface_details_t *vl_api_sw_member_interface_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_member_interface_details_t);
    vl_api_sw_member_interface_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "interface_name");
    if (!item) goto error;
    strncpy_s((char *)a->interface_name, sizeof(a->interface_name), cJSON_GetStringValue(item), sizeof(a->interface_name) - 1);

    item = cJSON_GetObjectItem(o, "is_passive");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_passive);

    item = cJSON_GetObjectItem(o, "is_long_timeout");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_long_timeout);

    item = cJSON_GetObjectItem(o, "is_local_numa");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_local_numa);

    item = cJSON_GetObjectItem(o, "weight");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->weight);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_set_bond_weight_t *vl_api_sw_interface_set_bond_weight_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_bond_weight_t);
    vl_api_sw_interface_set_bond_weight_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "weight");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->weight);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_set_bond_weight_reply_t *vl_api_sw_interface_set_bond_weight_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_bond_weight_reply_t);
    vl_api_sw_interface_set_bond_weight_reply_t *a = cJSON_malloc(l);

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
