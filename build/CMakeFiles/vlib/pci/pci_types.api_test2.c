#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>
#include <vnet/ip/ip_format_fns.h>
#include <vnet/ethernet/ethernet_format_fns.h>

#define vl_typedefs             /* define message structures */
#include <vlibmemory/vl_memory_api_h.h>
#include <vlibmemory/vlib.api_types.h>
#include <vlibmemory/vlib.api.h>
#undef vl_typedefs

#include "pci_types.api_enum.h"
#include "pci_types.api_types.h"

#define vl_endianfun		/* define message structures */
#include "pci_types.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "pci_types.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "pci_types.api.h"
#undef vl_printfun

#include "pci_types.api_tojson.h"
#include "pci_types.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   return 0;
}
