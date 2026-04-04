/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/ethernet/ethernet_types.api_fromjson.h>
#ifndef included_vmxnet3_api_fromjson_h
#define included_vmxnet3_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_vmxnet3_tx_list_t_fromjson (void **mp, int *len, cJSON *o, vl_api_vmxnet3_tx_list_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "tx_qsize");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->tx_qsize);

    item = cJSON_GetObjectItem(o, "tx_next");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->tx_next);

    item = cJSON_GetObjectItem(o, "tx_produce");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->tx_produce);

    item = cJSON_GetObjectItem(o, "tx_consume");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->tx_consume);

    return 0;

  error:
    return -1;
}
static inline int vl_api_vmxnet3_rx_list_t_fromjson (void **mp, int *len, cJSON *o, vl_api_vmxnet3_rx_list_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "rx_qsize");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->rx_qsize);

    item = cJSON_GetObjectItem(o, "rx_fill");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "rx_fill");
        int size = cJSON_GetArraySize(array);
        if (size != 2) goto error;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_u16_fromjson(e, &a->rx_fill[i]);
        }
    }

    item = cJSON_GetObjectItem(o, "rx_next");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->rx_next);

    item = cJSON_GetObjectItem(o, "rx_produce");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "rx_produce");
        int size = cJSON_GetArraySize(array);
        if (size != 2) goto error;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_u16_fromjson(e, &a->rx_produce[i]);
        }
    }

    item = cJSON_GetObjectItem(o, "rx_consume");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "rx_consume");
        int size = cJSON_GetArraySize(array);
        if (size != 2) goto error;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_u16_fromjson(e, &a->rx_consume[i]);
        }
    }

    return 0;

  error:
    return -1;
}
static inline vl_api_vmxnet3_create_t *vl_api_vmxnet3_create_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vmxnet3_create_t);
    vl_api_vmxnet3_create_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "pci_addr");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->pci_addr);

    item = cJSON_GetObjectItem(o, "enable_elog");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->enable_elog);

    item = cJSON_GetObjectItem(o, "rxq_size");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->rxq_size);

    item = cJSON_GetObjectItem(o, "rxq_num");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->rxq_num);

    item = cJSON_GetObjectItem(o, "txq_size");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->txq_size);

    item = cJSON_GetObjectItem(o, "txq_num");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->txq_num);

    item = cJSON_GetObjectItem(o, "bind");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->bind);

    item = cJSON_GetObjectItem(o, "enable_gso");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable_gso);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vmxnet3_create_reply_t *vl_api_vmxnet3_create_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vmxnet3_create_reply_t);
    vl_api_vmxnet3_create_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_vmxnet3_delete_t *vl_api_vmxnet3_delete_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vmxnet3_delete_t);
    vl_api_vmxnet3_delete_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vmxnet3_delete_reply_t *vl_api_vmxnet3_delete_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vmxnet3_delete_reply_t);
    vl_api_vmxnet3_delete_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vmxnet3_details_t *vl_api_vmxnet3_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vmxnet3_details_t);
    vl_api_vmxnet3_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "if_name");
    if (!item) goto error;
    strncpy_s((char *)a->if_name, sizeof(a->if_name), cJSON_GetStringValue(item), sizeof(a->if_name) - 1);

    item = cJSON_GetObjectItem(o, "hw_addr");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->hw_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "pci_addr");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->pci_addr);

    item = cJSON_GetObjectItem(o, "version");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->version);

    item = cJSON_GetObjectItem(o, "admin_up_down");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->admin_up_down);

    item = cJSON_GetObjectItem(o, "rx_count");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->rx_count);

    item = cJSON_GetObjectItem(o, "rx_list");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "rx_list");
        int size = cJSON_GetArraySize(array);
        if (size != 16) goto error;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_vmxnet3_rx_list_t_fromjson((void **)&a, len, e, &a->rx_list[i]) < 0) goto error;
        }
    }

    item = cJSON_GetObjectItem(o, "tx_count");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->tx_count);

    item = cJSON_GetObjectItem(o, "tx_list");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "tx_list");
        int size = cJSON_GetArraySize(array);
        if (size != 8) goto error;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_vmxnet3_tx_list_t_fromjson((void **)&a, len, e, &a->tx_list[i]) < 0) goto error;
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vmxnet3_dump_t *vl_api_vmxnet3_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vmxnet3_dump_t);
    vl_api_vmxnet3_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_sw_vmxnet3_interface_dump_t *vl_api_sw_vmxnet3_interface_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_vmxnet3_interface_dump_t);
    vl_api_sw_vmxnet3_interface_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_vmxnet3_interface_details_t *vl_api_sw_vmxnet3_interface_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_vmxnet3_interface_details_t);
    vl_api_sw_vmxnet3_interface_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "if_name");
    if (!item) goto error;
    strncpy_s((char *)a->if_name, sizeof(a->if_name), cJSON_GetStringValue(item), sizeof(a->if_name) - 1);

    item = cJSON_GetObjectItem(o, "hw_addr");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->hw_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "pci_addr");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->pci_addr);

    item = cJSON_GetObjectItem(o, "version");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->version);

    item = cJSON_GetObjectItem(o, "admin_up_down");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->admin_up_down);

    item = cJSON_GetObjectItem(o, "rx_count");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->rx_count);

    item = cJSON_GetObjectItem(o, "rx_list");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "rx_list");
        int size = cJSON_GetArraySize(array);
        if (size != 16) goto error;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_vmxnet3_rx_list_t_fromjson((void **)&a, len, e, &a->rx_list[i]) < 0) goto error;
        }
    }

    item = cJSON_GetObjectItem(o, "tx_count");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->tx_count);

    item = cJSON_GetObjectItem(o, "tx_list");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "tx_list");
        int size = cJSON_GetArraySize(array);
        if (size != 8) goto error;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_vmxnet3_tx_list_t_fromjson((void **)&a, len, e, &a->tx_list[i]) < 0) goto error;
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
