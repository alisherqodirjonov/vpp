#define vl_endianfun		/* define message structures */
#include "sr_types.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "sr_types.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "sr_types.api.h"
#undef vl_printfun

#include "sr_types.api_json.h"
