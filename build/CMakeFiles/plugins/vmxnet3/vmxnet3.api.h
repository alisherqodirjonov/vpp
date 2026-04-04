/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: vmxnet3.api
 * Automatically generated: please edit the input file NOT this file!
 */

#include <stdbool.h>
#if defined(vl_msg_id)||defined(vl_union_id) \
    || defined(vl_printfun) ||defined(vl_endianfun) \
    || defined(vl_api_version)||defined(vl_typedefs) \
    || defined(vl_msg_name)||defined(vl_msg_name_crc_list) \
    || defined(vl_api_version_tuple) || defined(vl_calcsizefun)
/* ok, something was selected */
#else
#warning no content included from vmxnet3.api
#endif

#define VL_API_PACKED(x) x __attribute__ ((packed))

/*
 * Note: VL_API_MAX_ARRAY_SIZE is set to an arbitrarily large limit.
 *
 * However, any message with a ~2 billion element array is likely to break the
 * api handling long before this limit causes array element endian issues.
 *
 * Applications should be written to create reasonable api messages.
 */
#define VL_API_MAX_ARRAY_SIZE 0x7fffffff

/* Imported API files */
#ifndef vl_api_version
#include <vnet/interface_types.api.h>
#include <vnet/ethernet/ethernet_types.api.h>
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_VMXNET3_CREATE, vl_api_vmxnet3_create_t_handler)
vl_msg_id(VL_API_VMXNET3_CREATE_REPLY, vl_api_vmxnet3_create_reply_t_handler)
vl_msg_id(VL_API_VMXNET3_DELETE, vl_api_vmxnet3_delete_t_handler)
vl_msg_id(VL_API_VMXNET3_DELETE_REPLY, vl_api_vmxnet3_delete_reply_t_handler)
vl_msg_id(VL_API_VMXNET3_DETAILS, vl_api_vmxnet3_details_t_handler)
vl_msg_id(VL_API_VMXNET3_DUMP, vl_api_vmxnet3_dump_t_handler)
vl_msg_id(VL_API_SW_VMXNET3_INTERFACE_DUMP, vl_api_sw_vmxnet3_interface_dump_t_handler)
vl_msg_id(VL_API_SW_VMXNET3_INTERFACE_DETAILS, vl_api_sw_vmxnet3_interface_details_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_vmxnet3_create_t, 1)
vl_msg_name(vl_api_vmxnet3_create_reply_t, 1)
vl_msg_name(vl_api_vmxnet3_delete_t, 1)
vl_msg_name(vl_api_vmxnet3_delete_reply_t, 1)
vl_msg_name(vl_api_vmxnet3_details_t, 1)
vl_msg_name(vl_api_vmxnet3_dump_t, 1)
vl_msg_name(vl_api_sw_vmxnet3_interface_dump_t, 1)
vl_msg_name(vl_api_sw_vmxnet3_interface_details_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_vmxnet3 \
_(VL_API_VMXNET3_CREATE, vmxnet3_create, 71a07314) \
_(VL_API_VMXNET3_CREATE_REPLY, vmxnet3_create_reply, 5383d31f) \
_(VL_API_VMXNET3_DELETE, vmxnet3_delete, f9e6675e) \
_(VL_API_VMXNET3_DELETE_REPLY, vmxnet3_delete_reply, e8d4e804) \
_(VL_API_VMXNET3_DETAILS, vmxnet3_details, 6a1a5498) \
_(VL_API_VMXNET3_DUMP, vmxnet3_dump, 51077d14) \
_(VL_API_SW_VMXNET3_INTERFACE_DUMP, sw_vmxnet3_interface_dump, f9e6675e) \
_(VL_API_SW_VMXNET3_INTERFACE_DETAILS, sw_vmxnet3_interface_details, 6a1a5498) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "vmxnet3.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_vmxnet3_printfun_types
#define included_vmxnet3_printfun_types

static inline u8 *format_vl_api_vmxnet3_tx_list_t (u8 *s, va_list * args)
{
    vl_api_vmxnet3_tx_list_t *a = va_arg (*args, vl_api_vmxnet3_tx_list_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Utx_qsize: %u", format_white_space, indent, a->tx_qsize);
    s = format(s, "\n%Utx_next: %u", format_white_space, indent, a->tx_next);
    s = format(s, "\n%Utx_produce: %u", format_white_space, indent, a->tx_produce);
    s = format(s, "\n%Utx_consume: %u", format_white_space, indent, a->tx_consume);
    return s;
}

static inline u8 *format_vl_api_vmxnet3_rx_list_t (u8 *s, va_list * args)
{
    vl_api_vmxnet3_rx_list_t *a = va_arg (*args, vl_api_vmxnet3_rx_list_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Urx_qsize: %u", format_white_space, indent, a->rx_qsize);
    for (i = 0; i < 2; i++) {
        s = format(s, "\n%Urx_fill: %u",
                   format_white_space, indent, a->rx_fill[i]);
    }
    s = format(s, "\n%Urx_next: %u", format_white_space, indent, a->rx_next);
    for (i = 0; i < 2; i++) {
        s = format(s, "\n%Urx_produce: %u",
                   format_white_space, indent, a->rx_produce[i]);
    }
    for (i = 0; i < 2; i++) {
        s = format(s, "\n%Urx_consume: %u",
                   format_white_space, indent, a->rx_consume[i]);
    }
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_vmxnet3_printfun
#define included_vmxnet3_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "vmxnet3.api_tojson.h"
#include "vmxnet3.api_fromjson.h"

static inline u8 *vl_api_vmxnet3_create_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vmxnet3_create_t *a = va_arg (*args, vl_api_vmxnet3_create_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vmxnet3_create_t: */
    s = format(s, "vl_api_vmxnet3_create_t:");
    s = format(s, "\n%Upci_addr: %u", format_white_space, indent, a->pci_addr);
    s = format(s, "\n%Uenable_elog: %ld", format_white_space, indent, a->enable_elog);
    s = format(s, "\n%Urxq_size: %u", format_white_space, indent, a->rxq_size);
    s = format(s, "\n%Urxq_num: %u", format_white_space, indent, a->rxq_num);
    s = format(s, "\n%Utxq_size: %u", format_white_space, indent, a->txq_size);
    s = format(s, "\n%Utxq_num: %u", format_white_space, indent, a->txq_num);
    s = format(s, "\n%Ubind: %u", format_white_space, indent, a->bind);
    s = format(s, "\n%Uenable_gso: %u", format_white_space, indent, a->enable_gso);
    return s;
}

static inline u8 *vl_api_vmxnet3_create_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vmxnet3_create_reply_t *a = va_arg (*args, vl_api_vmxnet3_create_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vmxnet3_create_reply_t: */
    s = format(s, "vl_api_vmxnet3_create_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_vmxnet3_delete_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vmxnet3_delete_t *a = va_arg (*args, vl_api_vmxnet3_delete_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vmxnet3_delete_t: */
    s = format(s, "vl_api_vmxnet3_delete_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_vmxnet3_delete_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vmxnet3_delete_reply_t *a = va_arg (*args, vl_api_vmxnet3_delete_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vmxnet3_delete_reply_t: */
    s = format(s, "vl_api_vmxnet3_delete_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_vmxnet3_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vmxnet3_details_t *a = va_arg (*args, vl_api_vmxnet3_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vmxnet3_details_t: */
    s = format(s, "vl_api_vmxnet3_details_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uif_name: %s", format_white_space, indent, a->if_name);
    s = format(s, "\n%Uhw_addr: %U", format_white_space, indent, format_vl_api_mac_address_t, &a->hw_addr, indent);
    s = format(s, "\n%Upci_addr: %u", format_white_space, indent, a->pci_addr);
    s = format(s, "\n%Uversion: %u", format_white_space, indent, a->version);
    s = format(s, "\n%Uadmin_up_down: %u", format_white_space, indent, a->admin_up_down);
    s = format(s, "\n%Urx_count: %u", format_white_space, indent, a->rx_count);
    for (i = 0; i < 16; i++) {
        s = format(s, "\n%Urx_list: %U",
                   format_white_space, indent, format_vl_api_vmxnet3_rx_list_t, &a->rx_list[i], indent);
    }
    s = format(s, "\n%Utx_count: %u", format_white_space, indent, a->tx_count);
    for (i = 0; i < 8; i++) {
        s = format(s, "\n%Utx_list: %U",
                   format_white_space, indent, format_vl_api_vmxnet3_tx_list_t, &a->tx_list[i], indent);
    }
    return s;
}

static inline u8 *vl_api_vmxnet3_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vmxnet3_dump_t *a = va_arg (*args, vl_api_vmxnet3_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vmxnet3_dump_t: */
    s = format(s, "vl_api_vmxnet3_dump_t:");
    return s;
}

static inline u8 *vl_api_sw_vmxnet3_interface_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sw_vmxnet3_interface_dump_t *a = va_arg (*args, vl_api_sw_vmxnet3_interface_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sw_vmxnet3_interface_dump_t: */
    s = format(s, "vl_api_sw_vmxnet3_interface_dump_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_sw_vmxnet3_interface_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sw_vmxnet3_interface_details_t *a = va_arg (*args, vl_api_sw_vmxnet3_interface_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sw_vmxnet3_interface_details_t: */
    s = format(s, "vl_api_sw_vmxnet3_interface_details_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uif_name: %s", format_white_space, indent, a->if_name);
    s = format(s, "\n%Uhw_addr: %U", format_white_space, indent, format_vl_api_mac_address_t, &a->hw_addr, indent);
    s = format(s, "\n%Upci_addr: %u", format_white_space, indent, a->pci_addr);
    s = format(s, "\n%Uversion: %u", format_white_space, indent, a->version);
    s = format(s, "\n%Uadmin_up_down: %u", format_white_space, indent, a->admin_up_down);
    s = format(s, "\n%Urx_count: %u", format_white_space, indent, a->rx_count);
    for (i = 0; i < 16; i++) {
        s = format(s, "\n%Urx_list: %U",
                   format_white_space, indent, format_vl_api_vmxnet3_rx_list_t, &a->rx_list[i], indent);
    }
    s = format(s, "\n%Utx_count: %u", format_white_space, indent, a->tx_count);
    for (i = 0; i < 8; i++) {
        s = format(s, "\n%Utx_list: %U",
                   format_white_space, indent, format_vl_api_vmxnet3_tx_list_t, &a->tx_list[i], indent);
    }
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_vmxnet3_endianfun
#define included_vmxnet3_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_vmxnet3_tx_list_t_endian (vl_api_vmxnet3_tx_list_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->tx_qsize = clib_net_to_host_u16(a->tx_qsize);
    a->tx_next = clib_net_to_host_u16(a->tx_next);
    a->tx_produce = clib_net_to_host_u16(a->tx_produce);
    a->tx_consume = clib_net_to_host_u16(a->tx_consume);
}

static inline void vl_api_vmxnet3_rx_list_t_endian (vl_api_vmxnet3_rx_list_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->rx_qsize = clib_net_to_host_u16(a->rx_qsize);
    ASSERT((u32)2 <= (u32)VL_API_MAX_ARRAY_SIZE);
    for (i = 0; i < 2; i++) {
        a->rx_fill[i] = clib_net_to_host_u16(a->rx_fill[i]);
    }
    a->rx_next = clib_net_to_host_u16(a->rx_next);
    ASSERT((u32)2 <= (u32)VL_API_MAX_ARRAY_SIZE);
    for (i = 0; i < 2; i++) {
        a->rx_produce[i] = clib_net_to_host_u16(a->rx_produce[i]);
    }
    ASSERT((u32)2 <= (u32)VL_API_MAX_ARRAY_SIZE);
    for (i = 0; i < 2; i++) {
        a->rx_consume[i] = clib_net_to_host_u16(a->rx_consume[i]);
    }
}

static inline void vl_api_vmxnet3_create_t_endian (vl_api_vmxnet3_create_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->pci_addr = clib_net_to_host_u32(a->pci_addr);
    a->enable_elog = clib_net_to_host_i32(a->enable_elog);
    a->rxq_size = clib_net_to_host_u16(a->rxq_size);
    a->rxq_num = clib_net_to_host_u16(a->rxq_num);
    a->txq_size = clib_net_to_host_u16(a->txq_size);
    a->txq_num = clib_net_to_host_u16(a->txq_num);
    /* a->bind = a->bind (no-op) */
    /* a->enable_gso = a->enable_gso (no-op) */
}

static inline void vl_api_vmxnet3_create_reply_t_endian (vl_api_vmxnet3_create_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_vmxnet3_delete_t_endian (vl_api_vmxnet3_delete_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_vmxnet3_delete_reply_t_endian (vl_api_vmxnet3_delete_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_vmxnet3_details_t_endian (vl_api_vmxnet3_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->if_name = a->if_name (no-op) */
    vl_api_mac_address_t_endian(&a->hw_addr, to_net);
    a->pci_addr = clib_net_to_host_u32(a->pci_addr);
    /* a->version = a->version (no-op) */
    /* a->admin_up_down = a->admin_up_down (no-op) */
    /* a->rx_count = a->rx_count (no-op) */
    for (i = 0; i < 16; i++) {
        vl_api_vmxnet3_rx_list_t_endian(&a->rx_list[i], to_net);
    }
    /* a->tx_count = a->tx_count (no-op) */
    for (i = 0; i < 8; i++) {
        vl_api_vmxnet3_tx_list_t_endian(&a->tx_list[i], to_net);
    }
}

static inline void vl_api_vmxnet3_dump_t_endian (vl_api_vmxnet3_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_sw_vmxnet3_interface_dump_t_endian (vl_api_sw_vmxnet3_interface_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_sw_vmxnet3_interface_details_t_endian (vl_api_sw_vmxnet3_interface_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->if_name = a->if_name (no-op) */
    vl_api_mac_address_t_endian(&a->hw_addr, to_net);
    a->pci_addr = clib_net_to_host_u32(a->pci_addr);
    /* a->version = a->version (no-op) */
    /* a->admin_up_down = a->admin_up_down (no-op) */
    /* a->rx_count = a->rx_count (no-op) */
    for (i = 0; i < 16; i++) {
        vl_api_vmxnet3_rx_list_t_endian(&a->rx_list[i], to_net);
    }
    /* a->tx_count = a->tx_count (no-op) */
    for (i = 0; i < 8; i++) {
        vl_api_vmxnet3_tx_list_t_endian(&a->tx_list[i], to_net);
    }
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_vmxnet3_calcsizefun
#define included_vmxnet3_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_vmxnet3_tx_list_t_calc_size (vl_api_vmxnet3_tx_list_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vmxnet3_rx_list_t_calc_size (vl_api_vmxnet3_rx_list_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vmxnet3_create_t_calc_size (vl_api_vmxnet3_create_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vmxnet3_create_reply_t_calc_size (vl_api_vmxnet3_create_reply_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vmxnet3_delete_t_calc_size (vl_api_vmxnet3_delete_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vmxnet3_delete_reply_t_calc_size (vl_api_vmxnet3_delete_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vmxnet3_details_t_calc_size (vl_api_vmxnet3_details_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->hw_addr) + vl_api_mac_address_t_calc_size(&a->hw_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vmxnet3_dump_t_calc_size (vl_api_vmxnet3_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sw_vmxnet3_interface_dump_t_calc_size (vl_api_sw_vmxnet3_interface_dump_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sw_vmxnet3_interface_details_t_calc_size (vl_api_sw_vmxnet3_interface_details_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->hw_addr) + vl_api_mac_address_t_calc_size(&a->hw_addr);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(vmxnet3.api, 1, 2, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(vmxnet3.api, 0x233e078b)

#endif

