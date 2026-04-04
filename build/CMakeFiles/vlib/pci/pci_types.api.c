#define vl_endianfun		/* define message structures */
#include "pci_types.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "pci_types.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "pci_types.api.h"
#undef vl_printfun

#include "pci_types.api_json.h"
