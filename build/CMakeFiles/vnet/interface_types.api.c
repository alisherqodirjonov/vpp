#define vl_endianfun		/* define message structures */
#include "interface_types.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "interface_types.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "interface_types.api.h"
#undef vl_printfun

#include "interface_types.api_json.h"
