#ifndef __included_pci_types_api_json
#define __included_pci_types_api_json

#include <stdlib.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <vapi/vapi_internal.h>
#include <vapi/vapi.h>
#include <vapi/vapi_dbg.h>

#ifdef __cplusplus
extern "C" {
#endif
#ifndef __vl_api_string_swap_fns_defined__
#define __vl_api_string_swap_fns_defined__

#include <vlibapi/api_types.h>

static inline void vl_api_string_t_hton(vl_api_string_t *msg)
{
  msg->length = htobe32(msg->length);
}

static inline void vl_api_string_t_ntoh(vl_api_string_t *msg)
{
  msg->length = be32toh(msg->length);
}

#endif //__vl_api_string_swap_fns_defined__
#include <vapi/vlib.api.vapi.h>


#define DEFINE_VAPI_MSG_IDS_PCI_TYPES_API_JSON\



#ifndef defined_vapi_type_pci_address
#define defined_vapi_type_pci_address
typedef struct __attribute__((__packed__)) {
  u16 domain;
  u8 bus;
  u8 slot;
  u8 function;
} vapi_type_pci_address;

static inline void vapi_type_pci_address_hton(vapi_type_pci_address *msg)
{
  msg->domain = htobe16(msg->domain);
}

static inline void vapi_type_pci_address_ntoh(vapi_type_pci_address *msg)
{
  msg->domain = be16toh(msg->domain);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
