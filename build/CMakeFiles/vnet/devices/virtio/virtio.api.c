#define vl_endianfun		/* define message structures */
#include "virtio.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "virtio.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "virtio.api.h"
#undef vl_printfun

#include "virtio.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("virtio_fa492ad7", VL_MSG_VIRTIO_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_virtio);
   vl_msg_api_add_msg_name_crc (am, "virtio_pci_create_1944f8db",
                                VL_API_VIRTIO_PCI_CREATE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "virtio_pci_create_reply_5383d31f",
                                VL_API_VIRTIO_PCI_CREATE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "virtio_pci_create_v2_5d096e1a",
                                VL_API_VIRTIO_PCI_CREATE_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "virtio_pci_create_v2_reply_5383d31f",
                                VL_API_VIRTIO_PCI_CREATE_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "virtio_pci_delete_f9e6675e",
                                VL_API_VIRTIO_PCI_DELETE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "virtio_pci_delete_reply_e8d4e804",
                                VL_API_VIRTIO_PCI_DELETE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_virtio_pci_dump_51077d14",
                                VL_API_SW_INTERFACE_VIRTIO_PCI_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_virtio_pci_details_6ca9c167",
                                VL_API_SW_INTERFACE_VIRTIO_PCI_DETAILS + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_VIRTIO_PCI_CREATE + msg_id_base,
   .name = "virtio_pci_create",
   .handler = vl_api_virtio_pci_create_t_handler,
   .endian = vl_api_virtio_pci_create_t_endian,
   .format_fn = vl_api_virtio_pci_create_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_virtio_pci_create_t_tojson,
   .fromjson = vl_api_virtio_pci_create_t_fromjson,
   .calc_size = vl_api_virtio_pci_create_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_VIRTIO_PCI_CREATE_REPLY + msg_id_base,
  .name = "virtio_pci_create_reply",
  .handler = 0,
  .endian = vl_api_virtio_pci_create_reply_t_endian,
  .format_fn = vl_api_virtio_pci_create_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_virtio_pci_create_reply_t_tojson,
  .fromjson = vl_api_virtio_pci_create_reply_t_fromjson,
  .calc_size = vl_api_virtio_pci_create_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_VIRTIO_PCI_CREATE_V2 + msg_id_base,
   .name = "virtio_pci_create_v2",
   .handler = vl_api_virtio_pci_create_v2_t_handler,
   .endian = vl_api_virtio_pci_create_v2_t_endian,
   .format_fn = vl_api_virtio_pci_create_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_virtio_pci_create_v2_t_tojson,
   .fromjson = vl_api_virtio_pci_create_v2_t_fromjson,
   .calc_size = vl_api_virtio_pci_create_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_VIRTIO_PCI_CREATE_V2_REPLY + msg_id_base,
  .name = "virtio_pci_create_v2_reply",
  .handler = 0,
  .endian = vl_api_virtio_pci_create_v2_reply_t_endian,
  .format_fn = vl_api_virtio_pci_create_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_virtio_pci_create_v2_reply_t_tojson,
  .fromjson = vl_api_virtio_pci_create_v2_reply_t_fromjson,
  .calc_size = vl_api_virtio_pci_create_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_VIRTIO_PCI_DELETE + msg_id_base,
   .name = "virtio_pci_delete",
   .handler = vl_api_virtio_pci_delete_t_handler,
   .endian = vl_api_virtio_pci_delete_t_endian,
   .format_fn = vl_api_virtio_pci_delete_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_virtio_pci_delete_t_tojson,
   .fromjson = vl_api_virtio_pci_delete_t_fromjson,
   .calc_size = vl_api_virtio_pci_delete_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_VIRTIO_PCI_DELETE_REPLY + msg_id_base,
  .name = "virtio_pci_delete_reply",
  .handler = 0,
  .endian = vl_api_virtio_pci_delete_reply_t_endian,
  .format_fn = vl_api_virtio_pci_delete_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_virtio_pci_delete_reply_t_tojson,
  .fromjson = vl_api_virtio_pci_delete_reply_t_fromjson,
  .calc_size = vl_api_virtio_pci_delete_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_VIRTIO_PCI_DUMP + msg_id_base,
   .name = "sw_interface_virtio_pci_dump",
   .handler = vl_api_sw_interface_virtio_pci_dump_t_handler,
   .endian = vl_api_sw_interface_virtio_pci_dump_t_endian,
   .format_fn = vl_api_sw_interface_virtio_pci_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_virtio_pci_dump_t_tojson,
   .fromjson = vl_api_sw_interface_virtio_pci_dump_t_fromjson,
   .calc_size = vl_api_sw_interface_virtio_pci_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_VIRTIO_PCI_DETAILS + msg_id_base,
  .name = "sw_interface_virtio_pci_details",
  .handler = 0,
  .endian = vl_api_sw_interface_virtio_pci_details_t_endian,
  .format_fn = vl_api_sw_interface_virtio_pci_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_virtio_pci_details_t_tojson,
  .fromjson = vl_api_sw_interface_virtio_pci_details_t_fromjson,
  .calc_size = vl_api_sw_interface_virtio_pci_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
