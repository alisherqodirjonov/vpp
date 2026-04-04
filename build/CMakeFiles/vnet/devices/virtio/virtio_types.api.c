#define vl_endianfun		/* define message structures */
#include "virtio_types.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "virtio_types.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "virtio_types.api.h"
#undef vl_printfun

#include "virtio_types.api_json.h"
