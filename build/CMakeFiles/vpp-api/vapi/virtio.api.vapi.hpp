#ifndef __included_hpp_virtio_api_json
#define __included_hpp_virtio_api_json

#include <vapi/vapi.hpp>
#include <vapi/virtio.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_virtio_pci_create>(vapi_msg_virtio_pci_create *msg)
{
  vapi_msg_virtio_pci_create_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_virtio_pci_create>(vapi_msg_virtio_pci_create *msg)
{
  vapi_msg_virtio_pci_create_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_virtio_pci_create>()
{
  return ::vapi_msg_id_virtio_pci_create; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_virtio_pci_create>>()
{
  return ::vapi_msg_id_virtio_pci_create; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_virtio_pci_create()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_virtio_pci_create>(vapi_msg_id_virtio_pci_create);
}

template <> inline vapi_msg_virtio_pci_create* vapi_alloc<vapi_msg_virtio_pci_create>(Connection &con)
{
  vapi_msg_virtio_pci_create* result = vapi_alloc_virtio_pci_create(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_virtio_pci_create>;

template class Request<vapi_msg_virtio_pci_create, vapi_msg_virtio_pci_create_reply>;

using Virtio_pci_create = Request<vapi_msg_virtio_pci_create, vapi_msg_virtio_pci_create_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_virtio_pci_create_reply>(vapi_msg_virtio_pci_create_reply *msg)
{
  vapi_msg_virtio_pci_create_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_virtio_pci_create_reply>(vapi_msg_virtio_pci_create_reply *msg)
{
  vapi_msg_virtio_pci_create_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_virtio_pci_create_reply>()
{
  return ::vapi_msg_id_virtio_pci_create_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_virtio_pci_create_reply>>()
{
  return ::vapi_msg_id_virtio_pci_create_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_virtio_pci_create_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_virtio_pci_create_reply>(vapi_msg_id_virtio_pci_create_reply);
}

template class Msg<vapi_msg_virtio_pci_create_reply>;

using Virtio_pci_create_reply = Msg<vapi_msg_virtio_pci_create_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_virtio_pci_create_v2>(vapi_msg_virtio_pci_create_v2 *msg)
{
  vapi_msg_virtio_pci_create_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_virtio_pci_create_v2>(vapi_msg_virtio_pci_create_v2 *msg)
{
  vapi_msg_virtio_pci_create_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_virtio_pci_create_v2>()
{
  return ::vapi_msg_id_virtio_pci_create_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_virtio_pci_create_v2>>()
{
  return ::vapi_msg_id_virtio_pci_create_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_virtio_pci_create_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_virtio_pci_create_v2>(vapi_msg_id_virtio_pci_create_v2);
}

template <> inline vapi_msg_virtio_pci_create_v2* vapi_alloc<vapi_msg_virtio_pci_create_v2>(Connection &con)
{
  vapi_msg_virtio_pci_create_v2* result = vapi_alloc_virtio_pci_create_v2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_virtio_pci_create_v2>;

template class Request<vapi_msg_virtio_pci_create_v2, vapi_msg_virtio_pci_create_v2_reply>;

using Virtio_pci_create_v2 = Request<vapi_msg_virtio_pci_create_v2, vapi_msg_virtio_pci_create_v2_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_virtio_pci_create_v2_reply>(vapi_msg_virtio_pci_create_v2_reply *msg)
{
  vapi_msg_virtio_pci_create_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_virtio_pci_create_v2_reply>(vapi_msg_virtio_pci_create_v2_reply *msg)
{
  vapi_msg_virtio_pci_create_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_virtio_pci_create_v2_reply>()
{
  return ::vapi_msg_id_virtio_pci_create_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_virtio_pci_create_v2_reply>>()
{
  return ::vapi_msg_id_virtio_pci_create_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_virtio_pci_create_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_virtio_pci_create_v2_reply>(vapi_msg_id_virtio_pci_create_v2_reply);
}

template class Msg<vapi_msg_virtio_pci_create_v2_reply>;

using Virtio_pci_create_v2_reply = Msg<vapi_msg_virtio_pci_create_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_virtio_pci_delete>(vapi_msg_virtio_pci_delete *msg)
{
  vapi_msg_virtio_pci_delete_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_virtio_pci_delete>(vapi_msg_virtio_pci_delete *msg)
{
  vapi_msg_virtio_pci_delete_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_virtio_pci_delete>()
{
  return ::vapi_msg_id_virtio_pci_delete; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_virtio_pci_delete>>()
{
  return ::vapi_msg_id_virtio_pci_delete; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_virtio_pci_delete()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_virtio_pci_delete>(vapi_msg_id_virtio_pci_delete);
}

template <> inline vapi_msg_virtio_pci_delete* vapi_alloc<vapi_msg_virtio_pci_delete>(Connection &con)
{
  vapi_msg_virtio_pci_delete* result = vapi_alloc_virtio_pci_delete(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_virtio_pci_delete>;

template class Request<vapi_msg_virtio_pci_delete, vapi_msg_virtio_pci_delete_reply>;

using Virtio_pci_delete = Request<vapi_msg_virtio_pci_delete, vapi_msg_virtio_pci_delete_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_virtio_pci_delete_reply>(vapi_msg_virtio_pci_delete_reply *msg)
{
  vapi_msg_virtio_pci_delete_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_virtio_pci_delete_reply>(vapi_msg_virtio_pci_delete_reply *msg)
{
  vapi_msg_virtio_pci_delete_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_virtio_pci_delete_reply>()
{
  return ::vapi_msg_id_virtio_pci_delete_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_virtio_pci_delete_reply>>()
{
  return ::vapi_msg_id_virtio_pci_delete_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_virtio_pci_delete_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_virtio_pci_delete_reply>(vapi_msg_id_virtio_pci_delete_reply);
}

template class Msg<vapi_msg_virtio_pci_delete_reply>;

using Virtio_pci_delete_reply = Msg<vapi_msg_virtio_pci_delete_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_virtio_pci_dump>(vapi_msg_sw_interface_virtio_pci_dump *msg)
{
  vapi_msg_sw_interface_virtio_pci_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_virtio_pci_dump>(vapi_msg_sw_interface_virtio_pci_dump *msg)
{
  vapi_msg_sw_interface_virtio_pci_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_virtio_pci_dump>()
{
  return ::vapi_msg_id_sw_interface_virtio_pci_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_virtio_pci_dump>>()
{
  return ::vapi_msg_id_sw_interface_virtio_pci_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_virtio_pci_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_virtio_pci_dump>(vapi_msg_id_sw_interface_virtio_pci_dump);
}

template <> inline vapi_msg_sw_interface_virtio_pci_dump* vapi_alloc<vapi_msg_sw_interface_virtio_pci_dump>(Connection &con)
{
  vapi_msg_sw_interface_virtio_pci_dump* result = vapi_alloc_sw_interface_virtio_pci_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_virtio_pci_dump>;

template class Dump<vapi_msg_sw_interface_virtio_pci_dump, vapi_msg_sw_interface_virtio_pci_details>;

using Sw_interface_virtio_pci_dump = Dump<vapi_msg_sw_interface_virtio_pci_dump, vapi_msg_sw_interface_virtio_pci_details>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_virtio_pci_details>(vapi_msg_sw_interface_virtio_pci_details *msg)
{
  vapi_msg_sw_interface_virtio_pci_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_virtio_pci_details>(vapi_msg_sw_interface_virtio_pci_details *msg)
{
  vapi_msg_sw_interface_virtio_pci_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_virtio_pci_details>()
{
  return ::vapi_msg_id_sw_interface_virtio_pci_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_virtio_pci_details>>()
{
  return ::vapi_msg_id_sw_interface_virtio_pci_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_virtio_pci_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_virtio_pci_details>(vapi_msg_id_sw_interface_virtio_pci_details);
}

template class Msg<vapi_msg_sw_interface_virtio_pci_details>;

using Sw_interface_virtio_pci_details = Msg<vapi_msg_sw_interface_virtio_pci_details>;
}
#endif
