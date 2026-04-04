/*
 * VLIB API definitions 2026-04-04 08:31:58
 * Input file: virtio.api
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
#warning no content included from virtio.api
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
#include <vlib/pci/pci_types.api.h>
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_VIRTIO_PCI_CREATE, vl_api_virtio_pci_create_t_handler)
vl_msg_id(VL_API_VIRTIO_PCI_CREATE_REPLY, vl_api_virtio_pci_create_reply_t_handler)
vl_msg_id(VL_API_VIRTIO_PCI_CREATE_V2, vl_api_virtio_pci_create_v2_t_handler)
vl_msg_id(VL_API_VIRTIO_PCI_CREATE_V2_REPLY, vl_api_virtio_pci_create_v2_reply_t_handler)
vl_msg_id(VL_API_VIRTIO_PCI_DELETE, vl_api_virtio_pci_delete_t_handler)
vl_msg_id(VL_API_VIRTIO_PCI_DELETE_REPLY, vl_api_virtio_pci_delete_reply_t_handler)
vl_msg_id(VL_API_SW_INTERFACE_VIRTIO_PCI_DUMP, vl_api_sw_interface_virtio_pci_dump_t_handler)
vl_msg_id(VL_API_SW_INTERFACE_VIRTIO_PCI_DETAILS, vl_api_sw_interface_virtio_pci_details_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_virtio_pci_create_t, 1)
vl_msg_name(vl_api_virtio_pci_create_reply_t, 1)
vl_msg_name(vl_api_virtio_pci_create_v2_t, 1)
vl_msg_name(vl_api_virtio_pci_create_v2_reply_t, 1)
vl_msg_name(vl_api_virtio_pci_delete_t, 1)
vl_msg_name(vl_api_virtio_pci_delete_reply_t, 1)
vl_msg_name(vl_api_sw_interface_virtio_pci_dump_t, 1)
vl_msg_name(vl_api_sw_interface_virtio_pci_details_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_virtio \
_(VL_API_VIRTIO_PCI_CREATE, virtio_pci_create, 1944f8db) \
_(VL_API_VIRTIO_PCI_CREATE_REPLY, virtio_pci_create_reply, 5383d31f) \
_(VL_API_VIRTIO_PCI_CREATE_V2, virtio_pci_create_v2, 5d096e1a) \
_(VL_API_VIRTIO_PCI_CREATE_V2_REPLY, virtio_pci_create_v2_reply, 5383d31f) \
_(VL_API_VIRTIO_PCI_DELETE, virtio_pci_delete, f9e6675e) \
_(VL_API_VIRTIO_PCI_DELETE_REPLY, virtio_pci_delete_reply, e8d4e804) \
_(VL_API_SW_INTERFACE_VIRTIO_PCI_DUMP, sw_interface_virtio_pci_dump, 51077d14) \
_(VL_API_SW_INTERFACE_VIRTIO_PCI_DETAILS, sw_interface_virtio_pci_details, 6ca9c167) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "virtio.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_virtio_printfun_types
#define included_virtio_printfun_types

static inline u8 *format_vl_api_virtio_flags_t (u8 *s, va_list * args)
{
    vl_api_virtio_flags_t *a = va_arg (*args, vl_api_virtio_flags_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 1:
        return format(s, "VIRTIO_API_FLAG_GSO");
    case 2:
        return format(s, "VIRTIO_API_FLAG_CSUM_OFFLOAD");
    case 4:
        return format(s, "VIRTIO_API_FLAG_GRO_COALESCE");
    case 8:
        return format(s, "VIRTIO_API_FLAG_PACKED");
    case 16:
        return format(s, "VIRTIO_API_FLAG_IN_ORDER");
    case 32:
        return format(s, "VIRTIO_API_FLAG_BUFFERING");
    case 64:
        return format(s, "VIRTIO_API_FLAG_RSS");
    }
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_virtio_printfun
#define included_virtio_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "virtio.api_tojson.h"
#include "virtio.api_fromjson.h"

static inline u8 *vl_api_virtio_pci_create_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_virtio_pci_create_t *a = va_arg (*args, vl_api_virtio_pci_create_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_virtio_pci_create_t: */
    s = format(s, "vl_api_virtio_pci_create_t:");
    s = format(s, "\n%Upci_addr: %U", format_white_space, indent, format_vl_api_pci_address_t, &a->pci_addr, indent);
    s = format(s, "\n%Uuse_random_mac: %u", format_white_space, indent, a->use_random_mac);
    s = format(s, "\n%Umac_address: %U", format_white_space, indent, format_vl_api_mac_address_t, &a->mac_address, indent);
    s = format(s, "\n%Ugso_enabled: %u", format_white_space, indent, a->gso_enabled);
    s = format(s, "\n%Uchecksum_offload_enabled: %u", format_white_space, indent, a->checksum_offload_enabled);
    s = format(s, "\n%Ufeatures: %llu", format_white_space, indent, a->features);
    return s;
}

static inline u8 *vl_api_virtio_pci_create_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_virtio_pci_create_reply_t *a = va_arg (*args, vl_api_virtio_pci_create_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_virtio_pci_create_reply_t: */
    s = format(s, "vl_api_virtio_pci_create_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_virtio_pci_create_v2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_virtio_pci_create_v2_t *a = va_arg (*args, vl_api_virtio_pci_create_v2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_virtio_pci_create_v2_t: */
    s = format(s, "vl_api_virtio_pci_create_v2_t:");
    s = format(s, "\n%Upci_addr: %U", format_white_space, indent, format_vl_api_pci_address_t, &a->pci_addr, indent);
    s = format(s, "\n%Uuse_random_mac: %u", format_white_space, indent, a->use_random_mac);
    s = format(s, "\n%Umac_address: %U", format_white_space, indent, format_vl_api_mac_address_t, &a->mac_address, indent);
    s = format(s, "\n%Uvirtio_flags: %U", format_white_space, indent, format_vl_api_virtio_flags_t, &a->virtio_flags, indent);
    s = format(s, "\n%Ufeatures: %llu", format_white_space, indent, a->features);
    return s;
}

static inline u8 *vl_api_virtio_pci_create_v2_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_virtio_pci_create_v2_reply_t *a = va_arg (*args, vl_api_virtio_pci_create_v2_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_virtio_pci_create_v2_reply_t: */
    s = format(s, "vl_api_virtio_pci_create_v2_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_virtio_pci_delete_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_virtio_pci_delete_t *a = va_arg (*args, vl_api_virtio_pci_delete_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_virtio_pci_delete_t: */
    s = format(s, "vl_api_virtio_pci_delete_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_virtio_pci_delete_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_virtio_pci_delete_reply_t *a = va_arg (*args, vl_api_virtio_pci_delete_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_virtio_pci_delete_reply_t: */
    s = format(s, "vl_api_virtio_pci_delete_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_sw_interface_virtio_pci_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sw_interface_virtio_pci_dump_t *a = va_arg (*args, vl_api_sw_interface_virtio_pci_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sw_interface_virtio_pci_dump_t: */
    s = format(s, "vl_api_sw_interface_virtio_pci_dump_t:");
    return s;
}

static inline u8 *vl_api_sw_interface_virtio_pci_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sw_interface_virtio_pci_details_t *a = va_arg (*args, vl_api_sw_interface_virtio_pci_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sw_interface_virtio_pci_details_t: */
    s = format(s, "vl_api_sw_interface_virtio_pci_details_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Upci_addr: %U", format_white_space, indent, format_vl_api_pci_address_t, &a->pci_addr, indent);
    s = format(s, "\n%Umac_addr: %U", format_white_space, indent, format_vl_api_mac_address_t, &a->mac_addr, indent);
    s = format(s, "\n%Utx_ring_sz: %u", format_white_space, indent, a->tx_ring_sz);
    s = format(s, "\n%Urx_ring_sz: %u", format_white_space, indent, a->rx_ring_sz);
    s = format(s, "\n%Ufeatures: %llu", format_white_space, indent, a->features);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_virtio_endianfun
#define included_virtio_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_virtio_flags_t_endian (vl_api_virtio_flags_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_virtio_pci_create_t_endian (vl_api_virtio_pci_create_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_pci_address_t_endian(&a->pci_addr, to_net);
    /* a->use_random_mac = a->use_random_mac (no-op) */
    vl_api_mac_address_t_endian(&a->mac_address, to_net);
    /* a->gso_enabled = a->gso_enabled (no-op) */
    /* a->checksum_offload_enabled = a->checksum_offload_enabled (no-op) */
    a->features = clib_net_to_host_u64(a->features);
}

static inline void vl_api_virtio_pci_create_reply_t_endian (vl_api_virtio_pci_create_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_virtio_pci_create_v2_t_endian (vl_api_virtio_pci_create_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_pci_address_t_endian(&a->pci_addr, to_net);
    /* a->use_random_mac = a->use_random_mac (no-op) */
    vl_api_mac_address_t_endian(&a->mac_address, to_net);
    vl_api_virtio_flags_t_endian(&a->virtio_flags, to_net);
    a->features = clib_net_to_host_u64(a->features);
}

static inline void vl_api_virtio_pci_create_v2_reply_t_endian (vl_api_virtio_pci_create_v2_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_virtio_pci_delete_t_endian (vl_api_virtio_pci_delete_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_virtio_pci_delete_reply_t_endian (vl_api_virtio_pci_delete_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_sw_interface_virtio_pci_dump_t_endian (vl_api_sw_interface_virtio_pci_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_sw_interface_virtio_pci_details_t_endian (vl_api_sw_interface_virtio_pci_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    vl_api_pci_address_t_endian(&a->pci_addr, to_net);
    vl_api_mac_address_t_endian(&a->mac_addr, to_net);
    a->tx_ring_sz = clib_net_to_host_u16(a->tx_ring_sz);
    a->rx_ring_sz = clib_net_to_host_u16(a->rx_ring_sz);
    a->features = clib_net_to_host_u64(a->features);
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_virtio_calcsizefun
#define included_virtio_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_virtio_flags_t_calc_size (vl_api_virtio_flags_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_virtio_pci_create_t_calc_size (vl_api_virtio_pci_create_t *a)
{
      return sizeof(*a) - sizeof(a->pci_addr) + vl_api_pci_address_t_calc_size(&a->pci_addr) - sizeof(a->mac_address) + vl_api_mac_address_t_calc_size(&a->mac_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_virtio_pci_create_reply_t_calc_size (vl_api_virtio_pci_create_reply_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_virtio_pci_create_v2_t_calc_size (vl_api_virtio_pci_create_v2_t *a)
{
      return sizeof(*a) - sizeof(a->pci_addr) + vl_api_pci_address_t_calc_size(&a->pci_addr) - sizeof(a->mac_address) + vl_api_mac_address_t_calc_size(&a->mac_address) - sizeof(a->virtio_flags) + vl_api_virtio_flags_t_calc_size(&a->virtio_flags);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_virtio_pci_create_v2_reply_t_calc_size (vl_api_virtio_pci_create_v2_reply_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_virtio_pci_delete_t_calc_size (vl_api_virtio_pci_delete_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_virtio_pci_delete_reply_t_calc_size (vl_api_virtio_pci_delete_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sw_interface_virtio_pci_dump_t_calc_size (vl_api_sw_interface_virtio_pci_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sw_interface_virtio_pci_details_t_calc_size (vl_api_sw_interface_virtio_pci_details_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->pci_addr) + vl_api_pci_address_t_calc_size(&a->pci_addr) - sizeof(a->mac_addr) + vl_api_mac_address_t_calc_size(&a->mac_addr);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(virtio.api, 3, 0, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(virtio.api, 0xfa492ad7)

#endif

