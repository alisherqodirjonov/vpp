#ifndef __included_hpp_vmxnet3_api_json
#define __included_hpp_vmxnet3_api_json

#include <vapi/vapi.hpp>
#include <vapi/vmxnet3.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_vmxnet3_create>(vapi_msg_vmxnet3_create *msg)
{
  vapi_msg_vmxnet3_create_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vmxnet3_create>(vapi_msg_vmxnet3_create *msg)
{
  vapi_msg_vmxnet3_create_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vmxnet3_create>()
{
  return ::vapi_msg_id_vmxnet3_create; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vmxnet3_create>>()
{
  return ::vapi_msg_id_vmxnet3_create; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vmxnet3_create()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vmxnet3_create>(vapi_msg_id_vmxnet3_create);
}

template <> inline vapi_msg_vmxnet3_create* vapi_alloc<vapi_msg_vmxnet3_create>(Connection &con)
{
  vapi_msg_vmxnet3_create* result = vapi_alloc_vmxnet3_create(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_vmxnet3_create>;

template class Request<vapi_msg_vmxnet3_create, vapi_msg_vmxnet3_create_reply>;

using Vmxnet3_create = Request<vapi_msg_vmxnet3_create, vapi_msg_vmxnet3_create_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_vmxnet3_create_reply>(vapi_msg_vmxnet3_create_reply *msg)
{
  vapi_msg_vmxnet3_create_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vmxnet3_create_reply>(vapi_msg_vmxnet3_create_reply *msg)
{
  vapi_msg_vmxnet3_create_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vmxnet3_create_reply>()
{
  return ::vapi_msg_id_vmxnet3_create_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vmxnet3_create_reply>>()
{
  return ::vapi_msg_id_vmxnet3_create_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vmxnet3_create_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vmxnet3_create_reply>(vapi_msg_id_vmxnet3_create_reply);
}

template class Msg<vapi_msg_vmxnet3_create_reply>;

using Vmxnet3_create_reply = Msg<vapi_msg_vmxnet3_create_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_vmxnet3_delete>(vapi_msg_vmxnet3_delete *msg)
{
  vapi_msg_vmxnet3_delete_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vmxnet3_delete>(vapi_msg_vmxnet3_delete *msg)
{
  vapi_msg_vmxnet3_delete_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vmxnet3_delete>()
{
  return ::vapi_msg_id_vmxnet3_delete; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vmxnet3_delete>>()
{
  return ::vapi_msg_id_vmxnet3_delete; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vmxnet3_delete()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vmxnet3_delete>(vapi_msg_id_vmxnet3_delete);
}

template <> inline vapi_msg_vmxnet3_delete* vapi_alloc<vapi_msg_vmxnet3_delete>(Connection &con)
{
  vapi_msg_vmxnet3_delete* result = vapi_alloc_vmxnet3_delete(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_vmxnet3_delete>;

template class Request<vapi_msg_vmxnet3_delete, vapi_msg_vmxnet3_delete_reply>;

using Vmxnet3_delete = Request<vapi_msg_vmxnet3_delete, vapi_msg_vmxnet3_delete_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_vmxnet3_delete_reply>(vapi_msg_vmxnet3_delete_reply *msg)
{
  vapi_msg_vmxnet3_delete_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vmxnet3_delete_reply>(vapi_msg_vmxnet3_delete_reply *msg)
{
  vapi_msg_vmxnet3_delete_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vmxnet3_delete_reply>()
{
  return ::vapi_msg_id_vmxnet3_delete_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vmxnet3_delete_reply>>()
{
  return ::vapi_msg_id_vmxnet3_delete_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vmxnet3_delete_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vmxnet3_delete_reply>(vapi_msg_id_vmxnet3_delete_reply);
}

template class Msg<vapi_msg_vmxnet3_delete_reply>;

using Vmxnet3_delete_reply = Msg<vapi_msg_vmxnet3_delete_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_vmxnet3_details>(vapi_msg_vmxnet3_details *msg)
{
  vapi_msg_vmxnet3_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vmxnet3_details>(vapi_msg_vmxnet3_details *msg)
{
  vapi_msg_vmxnet3_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vmxnet3_details>()
{
  return ::vapi_msg_id_vmxnet3_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vmxnet3_details>>()
{
  return ::vapi_msg_id_vmxnet3_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vmxnet3_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vmxnet3_details>(vapi_msg_id_vmxnet3_details);
}

template class Msg<vapi_msg_vmxnet3_details>;

using Vmxnet3_details = Msg<vapi_msg_vmxnet3_details>;
template <> inline void vapi_swap_to_be<vapi_msg_vmxnet3_dump>(vapi_msg_vmxnet3_dump *msg)
{
  vapi_msg_vmxnet3_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vmxnet3_dump>(vapi_msg_vmxnet3_dump *msg)
{
  vapi_msg_vmxnet3_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vmxnet3_dump>()
{
  return ::vapi_msg_id_vmxnet3_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vmxnet3_dump>>()
{
  return ::vapi_msg_id_vmxnet3_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vmxnet3_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vmxnet3_dump>(vapi_msg_id_vmxnet3_dump);
}

template <> inline vapi_msg_vmxnet3_dump* vapi_alloc<vapi_msg_vmxnet3_dump>(Connection &con)
{
  vapi_msg_vmxnet3_dump* result = vapi_alloc_vmxnet3_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_vmxnet3_dump>;

template class Dump<vapi_msg_vmxnet3_dump, vapi_msg_vmxnet3_details>;

using Vmxnet3_dump = Dump<vapi_msg_vmxnet3_dump, vapi_msg_vmxnet3_details>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_vmxnet3_interface_dump>(vapi_msg_sw_vmxnet3_interface_dump *msg)
{
  vapi_msg_sw_vmxnet3_interface_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_vmxnet3_interface_dump>(vapi_msg_sw_vmxnet3_interface_dump *msg)
{
  vapi_msg_sw_vmxnet3_interface_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_vmxnet3_interface_dump>()
{
  return ::vapi_msg_id_sw_vmxnet3_interface_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_vmxnet3_interface_dump>>()
{
  return ::vapi_msg_id_sw_vmxnet3_interface_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_vmxnet3_interface_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_vmxnet3_interface_dump>(vapi_msg_id_sw_vmxnet3_interface_dump);
}

template <> inline vapi_msg_sw_vmxnet3_interface_dump* vapi_alloc<vapi_msg_sw_vmxnet3_interface_dump>(Connection &con)
{
  vapi_msg_sw_vmxnet3_interface_dump* result = vapi_alloc_sw_vmxnet3_interface_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_vmxnet3_interface_dump>;

template class Dump<vapi_msg_sw_vmxnet3_interface_dump, vapi_msg_sw_vmxnet3_interface_details>;

using Sw_vmxnet3_interface_dump = Dump<vapi_msg_sw_vmxnet3_interface_dump, vapi_msg_sw_vmxnet3_interface_details>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_vmxnet3_interface_details>(vapi_msg_sw_vmxnet3_interface_details *msg)
{
  vapi_msg_sw_vmxnet3_interface_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_vmxnet3_interface_details>(vapi_msg_sw_vmxnet3_interface_details *msg)
{
  vapi_msg_sw_vmxnet3_interface_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_vmxnet3_interface_details>()
{
  return ::vapi_msg_id_sw_vmxnet3_interface_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_vmxnet3_interface_details>>()
{
  return ::vapi_msg_id_sw_vmxnet3_interface_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_vmxnet3_interface_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_vmxnet3_interface_details>(vapi_msg_id_sw_vmxnet3_interface_details);
}

template class Msg<vapi_msg_sw_vmxnet3_interface_details>;

using Sw_vmxnet3_interface_details = Msg<vapi_msg_sw_vmxnet3_interface_details>;
}
#endif
