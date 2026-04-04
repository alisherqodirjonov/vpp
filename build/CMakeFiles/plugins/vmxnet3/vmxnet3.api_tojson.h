/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ethernet/ethernet_types.api_tojson.h>
#ifndef included_vmxnet3_api_tojson_h
#define included_vmxnet3_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_vmxnet3_tx_list_t_tojson (vl_api_vmxnet3_tx_list_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "tx_qsize", a->tx_qsize);
    cJSON_AddNumberToObject(o, "tx_next", a->tx_next);
    cJSON_AddNumberToObject(o, "tx_produce", a->tx_produce);
    cJSON_AddNumberToObject(o, "tx_consume", a->tx_consume);
    return o;
}
static inline cJSON *vl_api_vmxnet3_rx_list_t_tojson (vl_api_vmxnet3_rx_list_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "rx_qsize", a->rx_qsize);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "rx_fill");
        for (i = 0; i < 2; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->rx_fill[i]));
        }
    }
    cJSON_AddNumberToObject(o, "rx_next", a->rx_next);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "rx_produce");
        for (i = 0; i < 2; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->rx_produce[i]));
        }
    }
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "rx_consume");
        for (i = 0; i < 2; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->rx_consume[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_vmxnet3_create_t_tojson (vl_api_vmxnet3_create_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vmxnet3_create");
    cJSON_AddStringToObject(o, "_crc", "71a07314");
    cJSON_AddNumberToObject(o, "pci_addr", a->pci_addr);
    cJSON_AddNumberToObject(o, "enable_elog", a->enable_elog);
    cJSON_AddNumberToObject(o, "rxq_size", a->rxq_size);
    cJSON_AddNumberToObject(o, "rxq_num", a->rxq_num);
    cJSON_AddNumberToObject(o, "txq_size", a->txq_size);
    cJSON_AddNumberToObject(o, "txq_num", a->txq_num);
    cJSON_AddNumberToObject(o, "bind", a->bind);
    cJSON_AddBoolToObject(o, "enable_gso", a->enable_gso);
    return o;
}
static inline cJSON *vl_api_vmxnet3_create_reply_t_tojson (vl_api_vmxnet3_create_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vmxnet3_create_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_vmxnet3_delete_t_tojson (vl_api_vmxnet3_delete_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vmxnet3_delete");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_vmxnet3_delete_reply_t_tojson (vl_api_vmxnet3_delete_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vmxnet3_delete_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_vmxnet3_details_t_tojson (vl_api_vmxnet3_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vmxnet3_details");
    cJSON_AddStringToObject(o, "_crc", "6a1a5498");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddStringToObject(o, "if_name", (char *)a->if_name);
    cJSON_AddItemToObject(o, "hw_addr", vl_api_mac_address_t_tojson(&a->hw_addr));
    cJSON_AddNumberToObject(o, "pci_addr", a->pci_addr);
    cJSON_AddNumberToObject(o, "version", a->version);
    cJSON_AddBoolToObject(o, "admin_up_down", a->admin_up_down);
    cJSON_AddNumberToObject(o, "rx_count", a->rx_count);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "rx_list");
        for (i = 0; i < 16; i++) {
            cJSON_AddItemToArray(array, vl_api_vmxnet3_rx_list_t_tojson(&a->rx_list[i]));
        }
    }
    cJSON_AddNumberToObject(o, "tx_count", a->tx_count);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "tx_list");
        for (i = 0; i < 8; i++) {
            cJSON_AddItemToArray(array, vl_api_vmxnet3_tx_list_t_tojson(&a->tx_list[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_vmxnet3_dump_t_tojson (vl_api_vmxnet3_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vmxnet3_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_sw_vmxnet3_interface_dump_t_tojson (vl_api_sw_vmxnet3_interface_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_vmxnet3_interface_dump");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_sw_vmxnet3_interface_details_t_tojson (vl_api_sw_vmxnet3_interface_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_vmxnet3_interface_details");
    cJSON_AddStringToObject(o, "_crc", "6a1a5498");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddStringToObject(o, "if_name", (char *)a->if_name);
    cJSON_AddItemToObject(o, "hw_addr", vl_api_mac_address_t_tojson(&a->hw_addr));
    cJSON_AddNumberToObject(o, "pci_addr", a->pci_addr);
    cJSON_AddNumberToObject(o, "version", a->version);
    cJSON_AddBoolToObject(o, "admin_up_down", a->admin_up_down);
    cJSON_AddNumberToObject(o, "rx_count", a->rx_count);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "rx_list");
        for (i = 0; i < 16; i++) {
            cJSON_AddItemToArray(array, vl_api_vmxnet3_rx_list_t_tojson(&a->rx_list[i]));
        }
    }
    cJSON_AddNumberToObject(o, "tx_count", a->tx_count);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "tx_list");
        for (i = 0; i < 8; i++) {
            cJSON_AddItemToArray(array, vl_api_vmxnet3_tx_list_t_tojson(&a->tx_list[i]));
        }
    }
    return o;
}
#endif
