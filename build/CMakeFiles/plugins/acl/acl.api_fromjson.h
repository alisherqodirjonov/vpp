/* Imported API files */
#include <acl/acl_types.api_fromjson.h>
#include <vnet/interface_types.api_fromjson.h>
#ifndef included_acl_api_fromjson_h
#define included_acl_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_acl_plugin_get_version_t *vl_api_acl_plugin_get_version_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_acl_plugin_get_version_t);
    vl_api_acl_plugin_get_version_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_acl_plugin_get_version_reply_t *vl_api_acl_plugin_get_version_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_acl_plugin_get_version_reply_t);
    vl_api_acl_plugin_get_version_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_acl_plugin_control_ping_t *vl_api_acl_plugin_control_ping_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_acl_plugin_control_ping_t);
    vl_api_acl_plugin_control_ping_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_acl_plugin_control_ping_reply_t *vl_api_acl_plugin_control_ping_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_acl_plugin_control_ping_reply_t);
    vl_api_acl_plugin_control_ping_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_acl_plugin_get_conn_table_max_entries_t *vl_api_acl_plugin_get_conn_table_max_entries_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_acl_plugin_get_conn_table_max_entries_t);
    vl_api_acl_plugin_get_conn_table_max_entries_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_acl_plugin_get_conn_table_max_entries_reply_t *vl_api_acl_plugin_get_conn_table_max_entries_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_acl_plugin_get_conn_table_max_entries_reply_t);
    vl_api_acl_plugin_get_conn_table_max_entries_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "conn_table_max_entries");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->conn_table_max_entries);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_acl_add_replace_t *vl_api_acl_add_replace_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_acl_add_replace_t);
    vl_api_acl_add_replace_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "acl_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->acl_index);

    item = cJSON_GetObjectItem(o, "tag");
    if (!item) goto error;
    strncpy_s((char *)a->tag, sizeof(a->tag), cJSON_GetStringValue(item), sizeof(a->tag) - 1);

    item = cJSON_GetObjectItem(o, "r");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "r");
        int size = cJSON_GetArraySize(array);
        a->count = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_acl_rule_t) * size);
        vl_api_acl_rule_t *d = (void *)a + l;
        l += sizeof(vl_api_acl_rule_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_acl_rule_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_acl_add_replace_reply_t *vl_api_acl_add_replace_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_acl_add_replace_reply_t);
    vl_api_acl_add_replace_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "acl_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->acl_index);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_acl_del_t *vl_api_acl_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_acl_del_t);
    vl_api_acl_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "acl_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->acl_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_acl_del_reply_t *vl_api_acl_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_acl_del_reply_t);
    vl_api_acl_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_acl_interface_add_del_t *vl_api_acl_interface_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_acl_interface_add_del_t);
    vl_api_acl_interface_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "is_input");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_input);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "acl_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->acl_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_acl_interface_add_del_reply_t *vl_api_acl_interface_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_acl_interface_add_del_reply_t);
    vl_api_acl_interface_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_acl_interface_set_acl_list_t *vl_api_acl_interface_set_acl_list_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_acl_interface_set_acl_list_t);
    vl_api_acl_interface_set_acl_list_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "n_input");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->n_input);

    item = cJSON_GetObjectItem(o, "acls");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "acls");
        int size = cJSON_GetArraySize(array);
        a->count = size;
        a = cJSON_realloc(a, l + sizeof(u32) * size);
        u32 *d = (void *)a + l;
        l += sizeof(u32) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_u32_fromjson(e, &d[i]);
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_acl_interface_set_acl_list_reply_t *vl_api_acl_interface_set_acl_list_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_acl_interface_set_acl_list_reply_t);
    vl_api_acl_interface_set_acl_list_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_acl_dump_t *vl_api_acl_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_acl_dump_t);
    vl_api_acl_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "acl_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->acl_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_acl_details_t *vl_api_acl_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_acl_details_t);
    vl_api_acl_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "acl_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->acl_index);

    item = cJSON_GetObjectItem(o, "tag");
    if (!item) goto error;
    strncpy_s((char *)a->tag, sizeof(a->tag), cJSON_GetStringValue(item), sizeof(a->tag) - 1);

    item = cJSON_GetObjectItem(o, "r");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "r");
        int size = cJSON_GetArraySize(array);
        a->count = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_acl_rule_t) * size);
        vl_api_acl_rule_t *d = (void *)a + l;
        l += sizeof(vl_api_acl_rule_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_acl_rule_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_acl_interface_list_dump_t *vl_api_acl_interface_list_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_acl_interface_list_dump_t);
    vl_api_acl_interface_list_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_acl_interface_list_details_t *vl_api_acl_interface_list_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_acl_interface_list_details_t);
    vl_api_acl_interface_list_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "n_input");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->n_input);

    item = cJSON_GetObjectItem(o, "acls");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "acls");
        int size = cJSON_GetArraySize(array);
        a->count = size;
        a = cJSON_realloc(a, l + sizeof(u32) * size);
        u32 *d = (void *)a + l;
        l += sizeof(u32) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_u32_fromjson(e, &d[i]);
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_macip_acl_add_t *vl_api_macip_acl_add_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_macip_acl_add_t);
    vl_api_macip_acl_add_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "tag");
    if (!item) goto error;
    strncpy_s((char *)a->tag, sizeof(a->tag), cJSON_GetStringValue(item), sizeof(a->tag) - 1);

    item = cJSON_GetObjectItem(o, "r");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "r");
        int size = cJSON_GetArraySize(array);
        a->count = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_macip_acl_rule_t) * size);
        vl_api_macip_acl_rule_t *d = (void *)a + l;
        l += sizeof(vl_api_macip_acl_rule_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_macip_acl_rule_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_macip_acl_add_reply_t *vl_api_macip_acl_add_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_macip_acl_add_reply_t);
    vl_api_macip_acl_add_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "acl_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->acl_index);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_macip_acl_add_replace_t *vl_api_macip_acl_add_replace_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_macip_acl_add_replace_t);
    vl_api_macip_acl_add_replace_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "acl_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->acl_index);

    item = cJSON_GetObjectItem(o, "tag");
    if (!item) goto error;
    strncpy_s((char *)a->tag, sizeof(a->tag), cJSON_GetStringValue(item), sizeof(a->tag) - 1);

    item = cJSON_GetObjectItem(o, "r");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "r");
        int size = cJSON_GetArraySize(array);
        a->count = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_macip_acl_rule_t) * size);
        vl_api_macip_acl_rule_t *d = (void *)a + l;
        l += sizeof(vl_api_macip_acl_rule_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_macip_acl_rule_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_macip_acl_add_replace_reply_t *vl_api_macip_acl_add_replace_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_macip_acl_add_replace_reply_t);
    vl_api_macip_acl_add_replace_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "acl_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->acl_index);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_macip_acl_del_t *vl_api_macip_acl_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_macip_acl_del_t);
    vl_api_macip_acl_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "acl_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->acl_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_macip_acl_del_reply_t *vl_api_macip_acl_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_macip_acl_del_reply_t);
    vl_api_macip_acl_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_macip_acl_interface_add_del_t *vl_api_macip_acl_interface_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_macip_acl_interface_add_del_t);
    vl_api_macip_acl_interface_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "acl_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->acl_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_macip_acl_interface_add_del_reply_t *vl_api_macip_acl_interface_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_macip_acl_interface_add_del_reply_t);
    vl_api_macip_acl_interface_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_macip_acl_dump_t *vl_api_macip_acl_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_macip_acl_dump_t);
    vl_api_macip_acl_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "acl_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->acl_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_macip_acl_details_t *vl_api_macip_acl_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_macip_acl_details_t);
    vl_api_macip_acl_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "acl_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->acl_index);

    item = cJSON_GetObjectItem(o, "tag");
    if (!item) goto error;
    strncpy_s((char *)a->tag, sizeof(a->tag), cJSON_GetStringValue(item), sizeof(a->tag) - 1);

    item = cJSON_GetObjectItem(o, "r");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "r");
        int size = cJSON_GetArraySize(array);
        a->count = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_macip_acl_rule_t) * size);
        vl_api_macip_acl_rule_t *d = (void *)a + l;
        l += sizeof(vl_api_macip_acl_rule_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_macip_acl_rule_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_macip_acl_interface_get_t *vl_api_macip_acl_interface_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_macip_acl_interface_get_t);
    vl_api_macip_acl_interface_get_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_macip_acl_interface_get_reply_t *vl_api_macip_acl_interface_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_macip_acl_interface_get_reply_t);
    vl_api_macip_acl_interface_get_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "acls");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "acls");
        int size = cJSON_GetArraySize(array);
        a->count = size;
        a = cJSON_realloc(a, l + sizeof(u32) * size);
        u32 *d = (void *)a + l;
        l += sizeof(u32) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_u32_fromjson(e, &d[i]);
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_macip_acl_interface_list_dump_t *vl_api_macip_acl_interface_list_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_macip_acl_interface_list_dump_t);
    vl_api_macip_acl_interface_list_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_macip_acl_interface_list_details_t *vl_api_macip_acl_interface_list_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_macip_acl_interface_list_details_t);
    vl_api_macip_acl_interface_list_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "acls");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "acls");
        int size = cJSON_GetArraySize(array);
        a->count = size;
        a = cJSON_realloc(a, l + sizeof(u32) * size);
        u32 *d = (void *)a + l;
        l += sizeof(u32) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_u32_fromjson(e, &d[i]);
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_acl_interface_set_etype_whitelist_t *vl_api_acl_interface_set_etype_whitelist_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_acl_interface_set_etype_whitelist_t);
    vl_api_acl_interface_set_etype_whitelist_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "n_input");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->n_input);

    item = cJSON_GetObjectItem(o, "whitelist");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "whitelist");
        int size = cJSON_GetArraySize(array);
        a->count = size;
        a = cJSON_realloc(a, l + sizeof(u16) * size);
        u16 *d = (void *)a + l;
        l += sizeof(u16) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_u16_fromjson(e, &d[i]);
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_acl_interface_set_etype_whitelist_reply_t *vl_api_acl_interface_set_etype_whitelist_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_acl_interface_set_etype_whitelist_reply_t);
    vl_api_acl_interface_set_etype_whitelist_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_acl_interface_etype_whitelist_dump_t *vl_api_acl_interface_etype_whitelist_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_acl_interface_etype_whitelist_dump_t);
    vl_api_acl_interface_etype_whitelist_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_acl_interface_etype_whitelist_details_t *vl_api_acl_interface_etype_whitelist_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_acl_interface_etype_whitelist_details_t);
    vl_api_acl_interface_etype_whitelist_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "n_input");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->n_input);

    item = cJSON_GetObjectItem(o, "whitelist");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "whitelist");
        int size = cJSON_GetArraySize(array);
        a->count = size;
        a = cJSON_realloc(a, l + sizeof(u16) * size);
        u16 *d = (void *)a + l;
        l += sizeof(u16) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_u16_fromjson(e, &d[i]);
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_acl_stats_intf_counters_enable_t *vl_api_acl_stats_intf_counters_enable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_acl_stats_intf_counters_enable_t);
    vl_api_acl_stats_intf_counters_enable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_acl_stats_intf_counters_enable_reply_t *vl_api_acl_stats_intf_counters_enable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_acl_stats_intf_counters_enable_reply_t);
    vl_api_acl_stats_intf_counters_enable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_acl_plugin_use_hash_lookup_set_t *vl_api_acl_plugin_use_hash_lookup_set_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_acl_plugin_use_hash_lookup_set_t);
    vl_api_acl_plugin_use_hash_lookup_set_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_acl_plugin_use_hash_lookup_set_reply_t *vl_api_acl_plugin_use_hash_lookup_set_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_acl_plugin_use_hash_lookup_set_reply_t);
    vl_api_acl_plugin_use_hash_lookup_set_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_acl_plugin_use_hash_lookup_get_t *vl_api_acl_plugin_use_hash_lookup_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_acl_plugin_use_hash_lookup_get_t);
    vl_api_acl_plugin_use_hash_lookup_get_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_acl_plugin_use_hash_lookup_get_reply_t *vl_api_acl_plugin_use_hash_lookup_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_acl_plugin_use_hash_lookup_get_reply_t);
    vl_api_acl_plugin_use_hash_lookup_get_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
