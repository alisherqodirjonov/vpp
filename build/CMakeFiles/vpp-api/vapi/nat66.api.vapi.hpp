#ifndef __included_hpp_nat66_api_json
#define __included_hpp_nat66_api_json

#include <vapi/vapi.hpp>
#include <vapi/nat66.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_nat66_plugin_enable_disable>(vapi_msg_nat66_plugin_enable_disable *msg)
{
  vapi_msg_nat66_plugin_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat66_plugin_enable_disable>(vapi_msg_nat66_plugin_enable_disable *msg)
{
  vapi_msg_nat66_plugin_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat66_plugin_enable_disable>()
{
  return ::vapi_msg_id_nat66_plugin_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat66_plugin_enable_disable>>()
{
  return ::vapi_msg_id_nat66_plugin_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat66_plugin_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat66_plugin_enable_disable>(vapi_msg_id_nat66_plugin_enable_disable);
}

template <> inline vapi_msg_nat66_plugin_enable_disable* vapi_alloc<vapi_msg_nat66_plugin_enable_disable>(Connection &con)
{
  vapi_msg_nat66_plugin_enable_disable* result = vapi_alloc_nat66_plugin_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat66_plugin_enable_disable>;

template class Request<vapi_msg_nat66_plugin_enable_disable, vapi_msg_nat66_plugin_enable_disable_reply>;

using Nat66_plugin_enable_disable = Request<vapi_msg_nat66_plugin_enable_disable, vapi_msg_nat66_plugin_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat66_plugin_enable_disable_reply>(vapi_msg_nat66_plugin_enable_disable_reply *msg)
{
  vapi_msg_nat66_plugin_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat66_plugin_enable_disable_reply>(vapi_msg_nat66_plugin_enable_disable_reply *msg)
{
  vapi_msg_nat66_plugin_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat66_plugin_enable_disable_reply>()
{
  return ::vapi_msg_id_nat66_plugin_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat66_plugin_enable_disable_reply>>()
{
  return ::vapi_msg_id_nat66_plugin_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat66_plugin_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat66_plugin_enable_disable_reply>(vapi_msg_id_nat66_plugin_enable_disable_reply);
}

template class Msg<vapi_msg_nat66_plugin_enable_disable_reply>;

using Nat66_plugin_enable_disable_reply = Msg<vapi_msg_nat66_plugin_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat66_add_del_interface>(vapi_msg_nat66_add_del_interface *msg)
{
  vapi_msg_nat66_add_del_interface_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat66_add_del_interface>(vapi_msg_nat66_add_del_interface *msg)
{
  vapi_msg_nat66_add_del_interface_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat66_add_del_interface>()
{
  return ::vapi_msg_id_nat66_add_del_interface; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat66_add_del_interface>>()
{
  return ::vapi_msg_id_nat66_add_del_interface; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat66_add_del_interface()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat66_add_del_interface>(vapi_msg_id_nat66_add_del_interface);
}

template <> inline vapi_msg_nat66_add_del_interface* vapi_alloc<vapi_msg_nat66_add_del_interface>(Connection &con)
{
  vapi_msg_nat66_add_del_interface* result = vapi_alloc_nat66_add_del_interface(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat66_add_del_interface>;

template class Request<vapi_msg_nat66_add_del_interface, vapi_msg_nat66_add_del_interface_reply>;

using Nat66_add_del_interface = Request<vapi_msg_nat66_add_del_interface, vapi_msg_nat66_add_del_interface_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat66_add_del_interface_reply>(vapi_msg_nat66_add_del_interface_reply *msg)
{
  vapi_msg_nat66_add_del_interface_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat66_add_del_interface_reply>(vapi_msg_nat66_add_del_interface_reply *msg)
{
  vapi_msg_nat66_add_del_interface_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat66_add_del_interface_reply>()
{
  return ::vapi_msg_id_nat66_add_del_interface_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat66_add_del_interface_reply>>()
{
  return ::vapi_msg_id_nat66_add_del_interface_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat66_add_del_interface_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat66_add_del_interface_reply>(vapi_msg_id_nat66_add_del_interface_reply);
}

template class Msg<vapi_msg_nat66_add_del_interface_reply>;

using Nat66_add_del_interface_reply = Msg<vapi_msg_nat66_add_del_interface_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat66_interface_dump>(vapi_msg_nat66_interface_dump *msg)
{
  vapi_msg_nat66_interface_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat66_interface_dump>(vapi_msg_nat66_interface_dump *msg)
{
  vapi_msg_nat66_interface_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat66_interface_dump>()
{
  return ::vapi_msg_id_nat66_interface_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat66_interface_dump>>()
{
  return ::vapi_msg_id_nat66_interface_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat66_interface_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat66_interface_dump>(vapi_msg_id_nat66_interface_dump);
}

template <> inline vapi_msg_nat66_interface_dump* vapi_alloc<vapi_msg_nat66_interface_dump>(Connection &con)
{
  vapi_msg_nat66_interface_dump* result = vapi_alloc_nat66_interface_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat66_interface_dump>;

template class Dump<vapi_msg_nat66_interface_dump, vapi_msg_nat66_interface_details>;

using Nat66_interface_dump = Dump<vapi_msg_nat66_interface_dump, vapi_msg_nat66_interface_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nat66_interface_details>(vapi_msg_nat66_interface_details *msg)
{
  vapi_msg_nat66_interface_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat66_interface_details>(vapi_msg_nat66_interface_details *msg)
{
  vapi_msg_nat66_interface_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat66_interface_details>()
{
  return ::vapi_msg_id_nat66_interface_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat66_interface_details>>()
{
  return ::vapi_msg_id_nat66_interface_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat66_interface_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat66_interface_details>(vapi_msg_id_nat66_interface_details);
}

template class Msg<vapi_msg_nat66_interface_details>;

using Nat66_interface_details = Msg<vapi_msg_nat66_interface_details>;
template <> inline void vapi_swap_to_be<vapi_msg_nat66_add_del_static_mapping>(vapi_msg_nat66_add_del_static_mapping *msg)
{
  vapi_msg_nat66_add_del_static_mapping_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat66_add_del_static_mapping>(vapi_msg_nat66_add_del_static_mapping *msg)
{
  vapi_msg_nat66_add_del_static_mapping_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat66_add_del_static_mapping>()
{
  return ::vapi_msg_id_nat66_add_del_static_mapping; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat66_add_del_static_mapping>>()
{
  return ::vapi_msg_id_nat66_add_del_static_mapping; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat66_add_del_static_mapping()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat66_add_del_static_mapping>(vapi_msg_id_nat66_add_del_static_mapping);
}

template <> inline vapi_msg_nat66_add_del_static_mapping* vapi_alloc<vapi_msg_nat66_add_del_static_mapping>(Connection &con)
{
  vapi_msg_nat66_add_del_static_mapping* result = vapi_alloc_nat66_add_del_static_mapping(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat66_add_del_static_mapping>;

template class Request<vapi_msg_nat66_add_del_static_mapping, vapi_msg_nat66_add_del_static_mapping_reply>;

using Nat66_add_del_static_mapping = Request<vapi_msg_nat66_add_del_static_mapping, vapi_msg_nat66_add_del_static_mapping_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat66_add_del_static_mapping_reply>(vapi_msg_nat66_add_del_static_mapping_reply *msg)
{
  vapi_msg_nat66_add_del_static_mapping_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat66_add_del_static_mapping_reply>(vapi_msg_nat66_add_del_static_mapping_reply *msg)
{
  vapi_msg_nat66_add_del_static_mapping_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat66_add_del_static_mapping_reply>()
{
  return ::vapi_msg_id_nat66_add_del_static_mapping_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat66_add_del_static_mapping_reply>>()
{
  return ::vapi_msg_id_nat66_add_del_static_mapping_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat66_add_del_static_mapping_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat66_add_del_static_mapping_reply>(vapi_msg_id_nat66_add_del_static_mapping_reply);
}

template class Msg<vapi_msg_nat66_add_del_static_mapping_reply>;

using Nat66_add_del_static_mapping_reply = Msg<vapi_msg_nat66_add_del_static_mapping_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat66_static_mapping_dump>(vapi_msg_nat66_static_mapping_dump *msg)
{
  vapi_msg_nat66_static_mapping_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat66_static_mapping_dump>(vapi_msg_nat66_static_mapping_dump *msg)
{
  vapi_msg_nat66_static_mapping_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat66_static_mapping_dump>()
{
  return ::vapi_msg_id_nat66_static_mapping_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat66_static_mapping_dump>>()
{
  return ::vapi_msg_id_nat66_static_mapping_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat66_static_mapping_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat66_static_mapping_dump>(vapi_msg_id_nat66_static_mapping_dump);
}

template <> inline vapi_msg_nat66_static_mapping_dump* vapi_alloc<vapi_msg_nat66_static_mapping_dump>(Connection &con)
{
  vapi_msg_nat66_static_mapping_dump* result = vapi_alloc_nat66_static_mapping_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat66_static_mapping_dump>;

template class Dump<vapi_msg_nat66_static_mapping_dump, vapi_msg_nat66_static_mapping_details>;

using Nat66_static_mapping_dump = Dump<vapi_msg_nat66_static_mapping_dump, vapi_msg_nat66_static_mapping_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nat66_static_mapping_details>(vapi_msg_nat66_static_mapping_details *msg)
{
  vapi_msg_nat66_static_mapping_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat66_static_mapping_details>(vapi_msg_nat66_static_mapping_details *msg)
{
  vapi_msg_nat66_static_mapping_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat66_static_mapping_details>()
{
  return ::vapi_msg_id_nat66_static_mapping_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat66_static_mapping_details>>()
{
  return ::vapi_msg_id_nat66_static_mapping_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat66_static_mapping_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat66_static_mapping_details>(vapi_msg_id_nat66_static_mapping_details);
}

template class Msg<vapi_msg_nat66_static_mapping_details>;

using Nat66_static_mapping_details = Msg<vapi_msg_nat66_static_mapping_details>;
}
#endif
