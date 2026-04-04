#ifndef __included_hpp_nat64_api_json
#define __included_hpp_nat64_api_json

#include <vapi/vapi.hpp>
#include <vapi/nat64.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_nat64_plugin_enable_disable>(vapi_msg_nat64_plugin_enable_disable *msg)
{
  vapi_msg_nat64_plugin_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat64_plugin_enable_disable>(vapi_msg_nat64_plugin_enable_disable *msg)
{
  vapi_msg_nat64_plugin_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat64_plugin_enable_disable>()
{
  return ::vapi_msg_id_nat64_plugin_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat64_plugin_enable_disable>>()
{
  return ::vapi_msg_id_nat64_plugin_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat64_plugin_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat64_plugin_enable_disable>(vapi_msg_id_nat64_plugin_enable_disable);
}

template <> inline vapi_msg_nat64_plugin_enable_disable* vapi_alloc<vapi_msg_nat64_plugin_enable_disable>(Connection &con)
{
  vapi_msg_nat64_plugin_enable_disable* result = vapi_alloc_nat64_plugin_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat64_plugin_enable_disable>;

template class Request<vapi_msg_nat64_plugin_enable_disable, vapi_msg_nat64_plugin_enable_disable_reply>;

using Nat64_plugin_enable_disable = Request<vapi_msg_nat64_plugin_enable_disable, vapi_msg_nat64_plugin_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat64_plugin_enable_disable_reply>(vapi_msg_nat64_plugin_enable_disable_reply *msg)
{
  vapi_msg_nat64_plugin_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat64_plugin_enable_disable_reply>(vapi_msg_nat64_plugin_enable_disable_reply *msg)
{
  vapi_msg_nat64_plugin_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat64_plugin_enable_disable_reply>()
{
  return ::vapi_msg_id_nat64_plugin_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat64_plugin_enable_disable_reply>>()
{
  return ::vapi_msg_id_nat64_plugin_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat64_plugin_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat64_plugin_enable_disable_reply>(vapi_msg_id_nat64_plugin_enable_disable_reply);
}

template class Msg<vapi_msg_nat64_plugin_enable_disable_reply>;

using Nat64_plugin_enable_disable_reply = Msg<vapi_msg_nat64_plugin_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat64_set_timeouts>(vapi_msg_nat64_set_timeouts *msg)
{
  vapi_msg_nat64_set_timeouts_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat64_set_timeouts>(vapi_msg_nat64_set_timeouts *msg)
{
  vapi_msg_nat64_set_timeouts_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat64_set_timeouts>()
{
  return ::vapi_msg_id_nat64_set_timeouts; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat64_set_timeouts>>()
{
  return ::vapi_msg_id_nat64_set_timeouts; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat64_set_timeouts()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat64_set_timeouts>(vapi_msg_id_nat64_set_timeouts);
}

template <> inline vapi_msg_nat64_set_timeouts* vapi_alloc<vapi_msg_nat64_set_timeouts>(Connection &con)
{
  vapi_msg_nat64_set_timeouts* result = vapi_alloc_nat64_set_timeouts(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat64_set_timeouts>;

template class Request<vapi_msg_nat64_set_timeouts, vapi_msg_nat64_set_timeouts_reply>;

using Nat64_set_timeouts = Request<vapi_msg_nat64_set_timeouts, vapi_msg_nat64_set_timeouts_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat64_set_timeouts_reply>(vapi_msg_nat64_set_timeouts_reply *msg)
{
  vapi_msg_nat64_set_timeouts_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat64_set_timeouts_reply>(vapi_msg_nat64_set_timeouts_reply *msg)
{
  vapi_msg_nat64_set_timeouts_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat64_set_timeouts_reply>()
{
  return ::vapi_msg_id_nat64_set_timeouts_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat64_set_timeouts_reply>>()
{
  return ::vapi_msg_id_nat64_set_timeouts_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat64_set_timeouts_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat64_set_timeouts_reply>(vapi_msg_id_nat64_set_timeouts_reply);
}

template class Msg<vapi_msg_nat64_set_timeouts_reply>;

using Nat64_set_timeouts_reply = Msg<vapi_msg_nat64_set_timeouts_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat64_get_timeouts>(vapi_msg_nat64_get_timeouts *msg)
{
  vapi_msg_nat64_get_timeouts_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat64_get_timeouts>(vapi_msg_nat64_get_timeouts *msg)
{
  vapi_msg_nat64_get_timeouts_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat64_get_timeouts>()
{
  return ::vapi_msg_id_nat64_get_timeouts; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat64_get_timeouts>>()
{
  return ::vapi_msg_id_nat64_get_timeouts; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat64_get_timeouts()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat64_get_timeouts>(vapi_msg_id_nat64_get_timeouts);
}

template <> inline vapi_msg_nat64_get_timeouts* vapi_alloc<vapi_msg_nat64_get_timeouts>(Connection &con)
{
  vapi_msg_nat64_get_timeouts* result = vapi_alloc_nat64_get_timeouts(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat64_get_timeouts>;

template class Request<vapi_msg_nat64_get_timeouts, vapi_msg_nat64_get_timeouts_reply>;

using Nat64_get_timeouts = Request<vapi_msg_nat64_get_timeouts, vapi_msg_nat64_get_timeouts_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat64_get_timeouts_reply>(vapi_msg_nat64_get_timeouts_reply *msg)
{
  vapi_msg_nat64_get_timeouts_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat64_get_timeouts_reply>(vapi_msg_nat64_get_timeouts_reply *msg)
{
  vapi_msg_nat64_get_timeouts_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat64_get_timeouts_reply>()
{
  return ::vapi_msg_id_nat64_get_timeouts_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat64_get_timeouts_reply>>()
{
  return ::vapi_msg_id_nat64_get_timeouts_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat64_get_timeouts_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat64_get_timeouts_reply>(vapi_msg_id_nat64_get_timeouts_reply);
}

template class Msg<vapi_msg_nat64_get_timeouts_reply>;

using Nat64_get_timeouts_reply = Msg<vapi_msg_nat64_get_timeouts_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat64_add_del_pool_addr_range>(vapi_msg_nat64_add_del_pool_addr_range *msg)
{
  vapi_msg_nat64_add_del_pool_addr_range_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat64_add_del_pool_addr_range>(vapi_msg_nat64_add_del_pool_addr_range *msg)
{
  vapi_msg_nat64_add_del_pool_addr_range_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat64_add_del_pool_addr_range>()
{
  return ::vapi_msg_id_nat64_add_del_pool_addr_range; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat64_add_del_pool_addr_range>>()
{
  return ::vapi_msg_id_nat64_add_del_pool_addr_range; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat64_add_del_pool_addr_range()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat64_add_del_pool_addr_range>(vapi_msg_id_nat64_add_del_pool_addr_range);
}

template <> inline vapi_msg_nat64_add_del_pool_addr_range* vapi_alloc<vapi_msg_nat64_add_del_pool_addr_range>(Connection &con)
{
  vapi_msg_nat64_add_del_pool_addr_range* result = vapi_alloc_nat64_add_del_pool_addr_range(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat64_add_del_pool_addr_range>;

template class Request<vapi_msg_nat64_add_del_pool_addr_range, vapi_msg_nat64_add_del_pool_addr_range_reply>;

using Nat64_add_del_pool_addr_range = Request<vapi_msg_nat64_add_del_pool_addr_range, vapi_msg_nat64_add_del_pool_addr_range_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat64_add_del_pool_addr_range_reply>(vapi_msg_nat64_add_del_pool_addr_range_reply *msg)
{
  vapi_msg_nat64_add_del_pool_addr_range_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat64_add_del_pool_addr_range_reply>(vapi_msg_nat64_add_del_pool_addr_range_reply *msg)
{
  vapi_msg_nat64_add_del_pool_addr_range_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat64_add_del_pool_addr_range_reply>()
{
  return ::vapi_msg_id_nat64_add_del_pool_addr_range_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat64_add_del_pool_addr_range_reply>>()
{
  return ::vapi_msg_id_nat64_add_del_pool_addr_range_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat64_add_del_pool_addr_range_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat64_add_del_pool_addr_range_reply>(vapi_msg_id_nat64_add_del_pool_addr_range_reply);
}

template class Msg<vapi_msg_nat64_add_del_pool_addr_range_reply>;

using Nat64_add_del_pool_addr_range_reply = Msg<vapi_msg_nat64_add_del_pool_addr_range_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat64_pool_addr_dump>(vapi_msg_nat64_pool_addr_dump *msg)
{
  vapi_msg_nat64_pool_addr_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat64_pool_addr_dump>(vapi_msg_nat64_pool_addr_dump *msg)
{
  vapi_msg_nat64_pool_addr_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat64_pool_addr_dump>()
{
  return ::vapi_msg_id_nat64_pool_addr_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat64_pool_addr_dump>>()
{
  return ::vapi_msg_id_nat64_pool_addr_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat64_pool_addr_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat64_pool_addr_dump>(vapi_msg_id_nat64_pool_addr_dump);
}

template <> inline vapi_msg_nat64_pool_addr_dump* vapi_alloc<vapi_msg_nat64_pool_addr_dump>(Connection &con)
{
  vapi_msg_nat64_pool_addr_dump* result = vapi_alloc_nat64_pool_addr_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat64_pool_addr_dump>;

template class Dump<vapi_msg_nat64_pool_addr_dump, vapi_msg_nat64_pool_addr_details>;

using Nat64_pool_addr_dump = Dump<vapi_msg_nat64_pool_addr_dump, vapi_msg_nat64_pool_addr_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nat64_pool_addr_details>(vapi_msg_nat64_pool_addr_details *msg)
{
  vapi_msg_nat64_pool_addr_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat64_pool_addr_details>(vapi_msg_nat64_pool_addr_details *msg)
{
  vapi_msg_nat64_pool_addr_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat64_pool_addr_details>()
{
  return ::vapi_msg_id_nat64_pool_addr_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat64_pool_addr_details>>()
{
  return ::vapi_msg_id_nat64_pool_addr_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat64_pool_addr_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat64_pool_addr_details>(vapi_msg_id_nat64_pool_addr_details);
}

template class Msg<vapi_msg_nat64_pool_addr_details>;

using Nat64_pool_addr_details = Msg<vapi_msg_nat64_pool_addr_details>;
template <> inline void vapi_swap_to_be<vapi_msg_nat64_add_del_interface>(vapi_msg_nat64_add_del_interface *msg)
{
  vapi_msg_nat64_add_del_interface_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat64_add_del_interface>(vapi_msg_nat64_add_del_interface *msg)
{
  vapi_msg_nat64_add_del_interface_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat64_add_del_interface>()
{
  return ::vapi_msg_id_nat64_add_del_interface; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat64_add_del_interface>>()
{
  return ::vapi_msg_id_nat64_add_del_interface; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat64_add_del_interface()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat64_add_del_interface>(vapi_msg_id_nat64_add_del_interface);
}

template <> inline vapi_msg_nat64_add_del_interface* vapi_alloc<vapi_msg_nat64_add_del_interface>(Connection &con)
{
  vapi_msg_nat64_add_del_interface* result = vapi_alloc_nat64_add_del_interface(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat64_add_del_interface>;

template class Request<vapi_msg_nat64_add_del_interface, vapi_msg_nat64_add_del_interface_reply>;

using Nat64_add_del_interface = Request<vapi_msg_nat64_add_del_interface, vapi_msg_nat64_add_del_interface_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat64_add_del_interface_reply>(vapi_msg_nat64_add_del_interface_reply *msg)
{
  vapi_msg_nat64_add_del_interface_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat64_add_del_interface_reply>(vapi_msg_nat64_add_del_interface_reply *msg)
{
  vapi_msg_nat64_add_del_interface_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat64_add_del_interface_reply>()
{
  return ::vapi_msg_id_nat64_add_del_interface_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat64_add_del_interface_reply>>()
{
  return ::vapi_msg_id_nat64_add_del_interface_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat64_add_del_interface_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat64_add_del_interface_reply>(vapi_msg_id_nat64_add_del_interface_reply);
}

template class Msg<vapi_msg_nat64_add_del_interface_reply>;

using Nat64_add_del_interface_reply = Msg<vapi_msg_nat64_add_del_interface_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat64_interface_dump>(vapi_msg_nat64_interface_dump *msg)
{
  vapi_msg_nat64_interface_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat64_interface_dump>(vapi_msg_nat64_interface_dump *msg)
{
  vapi_msg_nat64_interface_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat64_interface_dump>()
{
  return ::vapi_msg_id_nat64_interface_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat64_interface_dump>>()
{
  return ::vapi_msg_id_nat64_interface_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat64_interface_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat64_interface_dump>(vapi_msg_id_nat64_interface_dump);
}

template <> inline vapi_msg_nat64_interface_dump* vapi_alloc<vapi_msg_nat64_interface_dump>(Connection &con)
{
  vapi_msg_nat64_interface_dump* result = vapi_alloc_nat64_interface_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat64_interface_dump>;

template class Dump<vapi_msg_nat64_interface_dump, vapi_msg_nat64_interface_details>;

using Nat64_interface_dump = Dump<vapi_msg_nat64_interface_dump, vapi_msg_nat64_interface_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nat64_interface_details>(vapi_msg_nat64_interface_details *msg)
{
  vapi_msg_nat64_interface_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat64_interface_details>(vapi_msg_nat64_interface_details *msg)
{
  vapi_msg_nat64_interface_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat64_interface_details>()
{
  return ::vapi_msg_id_nat64_interface_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat64_interface_details>>()
{
  return ::vapi_msg_id_nat64_interface_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat64_interface_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat64_interface_details>(vapi_msg_id_nat64_interface_details);
}

template class Msg<vapi_msg_nat64_interface_details>;

using Nat64_interface_details = Msg<vapi_msg_nat64_interface_details>;
template <> inline void vapi_swap_to_be<vapi_msg_nat64_add_del_static_bib>(vapi_msg_nat64_add_del_static_bib *msg)
{
  vapi_msg_nat64_add_del_static_bib_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat64_add_del_static_bib>(vapi_msg_nat64_add_del_static_bib *msg)
{
  vapi_msg_nat64_add_del_static_bib_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat64_add_del_static_bib>()
{
  return ::vapi_msg_id_nat64_add_del_static_bib; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat64_add_del_static_bib>>()
{
  return ::vapi_msg_id_nat64_add_del_static_bib; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat64_add_del_static_bib()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat64_add_del_static_bib>(vapi_msg_id_nat64_add_del_static_bib);
}

template <> inline vapi_msg_nat64_add_del_static_bib* vapi_alloc<vapi_msg_nat64_add_del_static_bib>(Connection &con)
{
  vapi_msg_nat64_add_del_static_bib* result = vapi_alloc_nat64_add_del_static_bib(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat64_add_del_static_bib>;

template class Request<vapi_msg_nat64_add_del_static_bib, vapi_msg_nat64_add_del_static_bib_reply>;

using Nat64_add_del_static_bib = Request<vapi_msg_nat64_add_del_static_bib, vapi_msg_nat64_add_del_static_bib_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat64_add_del_static_bib_reply>(vapi_msg_nat64_add_del_static_bib_reply *msg)
{
  vapi_msg_nat64_add_del_static_bib_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat64_add_del_static_bib_reply>(vapi_msg_nat64_add_del_static_bib_reply *msg)
{
  vapi_msg_nat64_add_del_static_bib_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat64_add_del_static_bib_reply>()
{
  return ::vapi_msg_id_nat64_add_del_static_bib_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat64_add_del_static_bib_reply>>()
{
  return ::vapi_msg_id_nat64_add_del_static_bib_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat64_add_del_static_bib_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat64_add_del_static_bib_reply>(vapi_msg_id_nat64_add_del_static_bib_reply);
}

template class Msg<vapi_msg_nat64_add_del_static_bib_reply>;

using Nat64_add_del_static_bib_reply = Msg<vapi_msg_nat64_add_del_static_bib_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat64_bib_dump>(vapi_msg_nat64_bib_dump *msg)
{
  vapi_msg_nat64_bib_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat64_bib_dump>(vapi_msg_nat64_bib_dump *msg)
{
  vapi_msg_nat64_bib_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat64_bib_dump>()
{
  return ::vapi_msg_id_nat64_bib_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat64_bib_dump>>()
{
  return ::vapi_msg_id_nat64_bib_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat64_bib_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat64_bib_dump>(vapi_msg_id_nat64_bib_dump);
}

template <> inline vapi_msg_nat64_bib_dump* vapi_alloc<vapi_msg_nat64_bib_dump>(Connection &con)
{
  vapi_msg_nat64_bib_dump* result = vapi_alloc_nat64_bib_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat64_bib_dump>;

template class Dump<vapi_msg_nat64_bib_dump, vapi_msg_nat64_bib_details>;

using Nat64_bib_dump = Dump<vapi_msg_nat64_bib_dump, vapi_msg_nat64_bib_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nat64_bib_details>(vapi_msg_nat64_bib_details *msg)
{
  vapi_msg_nat64_bib_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat64_bib_details>(vapi_msg_nat64_bib_details *msg)
{
  vapi_msg_nat64_bib_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat64_bib_details>()
{
  return ::vapi_msg_id_nat64_bib_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat64_bib_details>>()
{
  return ::vapi_msg_id_nat64_bib_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat64_bib_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat64_bib_details>(vapi_msg_id_nat64_bib_details);
}

template class Msg<vapi_msg_nat64_bib_details>;

using Nat64_bib_details = Msg<vapi_msg_nat64_bib_details>;
template <> inline void vapi_swap_to_be<vapi_msg_nat64_st_dump>(vapi_msg_nat64_st_dump *msg)
{
  vapi_msg_nat64_st_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat64_st_dump>(vapi_msg_nat64_st_dump *msg)
{
  vapi_msg_nat64_st_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat64_st_dump>()
{
  return ::vapi_msg_id_nat64_st_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat64_st_dump>>()
{
  return ::vapi_msg_id_nat64_st_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat64_st_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat64_st_dump>(vapi_msg_id_nat64_st_dump);
}

template <> inline vapi_msg_nat64_st_dump* vapi_alloc<vapi_msg_nat64_st_dump>(Connection &con)
{
  vapi_msg_nat64_st_dump* result = vapi_alloc_nat64_st_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat64_st_dump>;

template class Dump<vapi_msg_nat64_st_dump, vapi_msg_nat64_st_details>;

using Nat64_st_dump = Dump<vapi_msg_nat64_st_dump, vapi_msg_nat64_st_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nat64_st_details>(vapi_msg_nat64_st_details *msg)
{
  vapi_msg_nat64_st_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat64_st_details>(vapi_msg_nat64_st_details *msg)
{
  vapi_msg_nat64_st_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat64_st_details>()
{
  return ::vapi_msg_id_nat64_st_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat64_st_details>>()
{
  return ::vapi_msg_id_nat64_st_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat64_st_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat64_st_details>(vapi_msg_id_nat64_st_details);
}

template class Msg<vapi_msg_nat64_st_details>;

using Nat64_st_details = Msg<vapi_msg_nat64_st_details>;
template <> inline void vapi_swap_to_be<vapi_msg_nat64_add_del_prefix>(vapi_msg_nat64_add_del_prefix *msg)
{
  vapi_msg_nat64_add_del_prefix_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat64_add_del_prefix>(vapi_msg_nat64_add_del_prefix *msg)
{
  vapi_msg_nat64_add_del_prefix_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat64_add_del_prefix>()
{
  return ::vapi_msg_id_nat64_add_del_prefix; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat64_add_del_prefix>>()
{
  return ::vapi_msg_id_nat64_add_del_prefix; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat64_add_del_prefix()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat64_add_del_prefix>(vapi_msg_id_nat64_add_del_prefix);
}

template <> inline vapi_msg_nat64_add_del_prefix* vapi_alloc<vapi_msg_nat64_add_del_prefix>(Connection &con)
{
  vapi_msg_nat64_add_del_prefix* result = vapi_alloc_nat64_add_del_prefix(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat64_add_del_prefix>;

template class Request<vapi_msg_nat64_add_del_prefix, vapi_msg_nat64_add_del_prefix_reply>;

using Nat64_add_del_prefix = Request<vapi_msg_nat64_add_del_prefix, vapi_msg_nat64_add_del_prefix_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat64_add_del_prefix_reply>(vapi_msg_nat64_add_del_prefix_reply *msg)
{
  vapi_msg_nat64_add_del_prefix_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat64_add_del_prefix_reply>(vapi_msg_nat64_add_del_prefix_reply *msg)
{
  vapi_msg_nat64_add_del_prefix_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat64_add_del_prefix_reply>()
{
  return ::vapi_msg_id_nat64_add_del_prefix_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat64_add_del_prefix_reply>>()
{
  return ::vapi_msg_id_nat64_add_del_prefix_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat64_add_del_prefix_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat64_add_del_prefix_reply>(vapi_msg_id_nat64_add_del_prefix_reply);
}

template class Msg<vapi_msg_nat64_add_del_prefix_reply>;

using Nat64_add_del_prefix_reply = Msg<vapi_msg_nat64_add_del_prefix_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat64_prefix_dump>(vapi_msg_nat64_prefix_dump *msg)
{
  vapi_msg_nat64_prefix_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat64_prefix_dump>(vapi_msg_nat64_prefix_dump *msg)
{
  vapi_msg_nat64_prefix_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat64_prefix_dump>()
{
  return ::vapi_msg_id_nat64_prefix_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat64_prefix_dump>>()
{
  return ::vapi_msg_id_nat64_prefix_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat64_prefix_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat64_prefix_dump>(vapi_msg_id_nat64_prefix_dump);
}

template <> inline vapi_msg_nat64_prefix_dump* vapi_alloc<vapi_msg_nat64_prefix_dump>(Connection &con)
{
  vapi_msg_nat64_prefix_dump* result = vapi_alloc_nat64_prefix_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat64_prefix_dump>;

template class Dump<vapi_msg_nat64_prefix_dump, vapi_msg_nat64_prefix_details>;

using Nat64_prefix_dump = Dump<vapi_msg_nat64_prefix_dump, vapi_msg_nat64_prefix_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nat64_prefix_details>(vapi_msg_nat64_prefix_details *msg)
{
  vapi_msg_nat64_prefix_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat64_prefix_details>(vapi_msg_nat64_prefix_details *msg)
{
  vapi_msg_nat64_prefix_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat64_prefix_details>()
{
  return ::vapi_msg_id_nat64_prefix_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat64_prefix_details>>()
{
  return ::vapi_msg_id_nat64_prefix_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat64_prefix_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat64_prefix_details>(vapi_msg_id_nat64_prefix_details);
}

template class Msg<vapi_msg_nat64_prefix_details>;

using Nat64_prefix_details = Msg<vapi_msg_nat64_prefix_details>;
template <> inline void vapi_swap_to_be<vapi_msg_nat64_add_del_interface_addr>(vapi_msg_nat64_add_del_interface_addr *msg)
{
  vapi_msg_nat64_add_del_interface_addr_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat64_add_del_interface_addr>(vapi_msg_nat64_add_del_interface_addr *msg)
{
  vapi_msg_nat64_add_del_interface_addr_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat64_add_del_interface_addr>()
{
  return ::vapi_msg_id_nat64_add_del_interface_addr; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat64_add_del_interface_addr>>()
{
  return ::vapi_msg_id_nat64_add_del_interface_addr; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat64_add_del_interface_addr()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat64_add_del_interface_addr>(vapi_msg_id_nat64_add_del_interface_addr);
}

template <> inline vapi_msg_nat64_add_del_interface_addr* vapi_alloc<vapi_msg_nat64_add_del_interface_addr>(Connection &con)
{
  vapi_msg_nat64_add_del_interface_addr* result = vapi_alloc_nat64_add_del_interface_addr(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat64_add_del_interface_addr>;

template class Request<vapi_msg_nat64_add_del_interface_addr, vapi_msg_nat64_add_del_interface_addr_reply>;

using Nat64_add_del_interface_addr = Request<vapi_msg_nat64_add_del_interface_addr, vapi_msg_nat64_add_del_interface_addr_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat64_add_del_interface_addr_reply>(vapi_msg_nat64_add_del_interface_addr_reply *msg)
{
  vapi_msg_nat64_add_del_interface_addr_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat64_add_del_interface_addr_reply>(vapi_msg_nat64_add_del_interface_addr_reply *msg)
{
  vapi_msg_nat64_add_del_interface_addr_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat64_add_del_interface_addr_reply>()
{
  return ::vapi_msg_id_nat64_add_del_interface_addr_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat64_add_del_interface_addr_reply>>()
{
  return ::vapi_msg_id_nat64_add_del_interface_addr_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat64_add_del_interface_addr_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat64_add_del_interface_addr_reply>(vapi_msg_id_nat64_add_del_interface_addr_reply);
}

template class Msg<vapi_msg_nat64_add_del_interface_addr_reply>;

using Nat64_add_del_interface_addr_reply = Msg<vapi_msg_nat64_add_del_interface_addr_reply>;
}
#endif
