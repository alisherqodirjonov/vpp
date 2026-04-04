#define vl_endianfun            /* define message structures */
#include "flow_types.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "flow_types.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "flow_types.api.h"
#undef vl_printfun

static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   flow_types_test_main_t * mainp = &flow_types_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("flow_types_e5fe0905");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "flow_types plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
