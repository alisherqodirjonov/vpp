#ifndef __included_hpp_pnat_api_json
#define __included_hpp_pnat_api_json

#include <vapi/vapi.hpp>
#include <vapi/pnat.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_pnat_binding_add>(vapi_msg_pnat_binding_add *msg)
{
  vapi_msg_pnat_binding_add_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pnat_binding_add>(vapi_msg_pnat_binding_add *msg)
{
  vapi_msg_pnat_binding_add_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pnat_binding_add>()
{
  return ::vapi_msg_id_pnat_binding_add; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pnat_binding_add>>()
{
  return ::vapi_msg_id_pnat_binding_add; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pnat_binding_add()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pnat_binding_add>(vapi_msg_id_pnat_binding_add);
}

template <> inline vapi_msg_pnat_binding_add* vapi_alloc<vapi_msg_pnat_binding_add>(Connection &con)
{
  vapi_msg_pnat_binding_add* result = vapi_alloc_pnat_binding_add(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_pnat_binding_add>;

template class Request<vapi_msg_pnat_binding_add, vapi_msg_pnat_binding_add_reply>;

using Pnat_binding_add = Request<vapi_msg_pnat_binding_add, vapi_msg_pnat_binding_add_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_pnat_binding_add_reply>(vapi_msg_pnat_binding_add_reply *msg)
{
  vapi_msg_pnat_binding_add_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pnat_binding_add_reply>(vapi_msg_pnat_binding_add_reply *msg)
{
  vapi_msg_pnat_binding_add_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pnat_binding_add_reply>()
{
  return ::vapi_msg_id_pnat_binding_add_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pnat_binding_add_reply>>()
{
  return ::vapi_msg_id_pnat_binding_add_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pnat_binding_add_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pnat_binding_add_reply>(vapi_msg_id_pnat_binding_add_reply);
}

template class Msg<vapi_msg_pnat_binding_add_reply>;

using Pnat_binding_add_reply = Msg<vapi_msg_pnat_binding_add_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_pnat_binding_add_v2>(vapi_msg_pnat_binding_add_v2 *msg)
{
  vapi_msg_pnat_binding_add_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pnat_binding_add_v2>(vapi_msg_pnat_binding_add_v2 *msg)
{
  vapi_msg_pnat_binding_add_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pnat_binding_add_v2>()
{
  return ::vapi_msg_id_pnat_binding_add_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pnat_binding_add_v2>>()
{
  return ::vapi_msg_id_pnat_binding_add_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pnat_binding_add_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pnat_binding_add_v2>(vapi_msg_id_pnat_binding_add_v2);
}

template <> inline vapi_msg_pnat_binding_add_v2* vapi_alloc<vapi_msg_pnat_binding_add_v2>(Connection &con)
{
  vapi_msg_pnat_binding_add_v2* result = vapi_alloc_pnat_binding_add_v2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_pnat_binding_add_v2>;

template class Request<vapi_msg_pnat_binding_add_v2, vapi_msg_pnat_binding_add_v2_reply>;

using Pnat_binding_add_v2 = Request<vapi_msg_pnat_binding_add_v2, vapi_msg_pnat_binding_add_v2_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_pnat_binding_add_v2_reply>(vapi_msg_pnat_binding_add_v2_reply *msg)
{
  vapi_msg_pnat_binding_add_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pnat_binding_add_v2_reply>(vapi_msg_pnat_binding_add_v2_reply *msg)
{
  vapi_msg_pnat_binding_add_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pnat_binding_add_v2_reply>()
{
  return ::vapi_msg_id_pnat_binding_add_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pnat_binding_add_v2_reply>>()
{
  return ::vapi_msg_id_pnat_binding_add_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pnat_binding_add_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pnat_binding_add_v2_reply>(vapi_msg_id_pnat_binding_add_v2_reply);
}

template class Msg<vapi_msg_pnat_binding_add_v2_reply>;

using Pnat_binding_add_v2_reply = Msg<vapi_msg_pnat_binding_add_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_pnat_binding_del>(vapi_msg_pnat_binding_del *msg)
{
  vapi_msg_pnat_binding_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pnat_binding_del>(vapi_msg_pnat_binding_del *msg)
{
  vapi_msg_pnat_binding_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pnat_binding_del>()
{
  return ::vapi_msg_id_pnat_binding_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pnat_binding_del>>()
{
  return ::vapi_msg_id_pnat_binding_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pnat_binding_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pnat_binding_del>(vapi_msg_id_pnat_binding_del);
}

template <> inline vapi_msg_pnat_binding_del* vapi_alloc<vapi_msg_pnat_binding_del>(Connection &con)
{
  vapi_msg_pnat_binding_del* result = vapi_alloc_pnat_binding_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_pnat_binding_del>;

template class Request<vapi_msg_pnat_binding_del, vapi_msg_pnat_binding_del_reply>;

using Pnat_binding_del = Request<vapi_msg_pnat_binding_del, vapi_msg_pnat_binding_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_pnat_binding_del_reply>(vapi_msg_pnat_binding_del_reply *msg)
{
  vapi_msg_pnat_binding_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pnat_binding_del_reply>(vapi_msg_pnat_binding_del_reply *msg)
{
  vapi_msg_pnat_binding_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pnat_binding_del_reply>()
{
  return ::vapi_msg_id_pnat_binding_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pnat_binding_del_reply>>()
{
  return ::vapi_msg_id_pnat_binding_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pnat_binding_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pnat_binding_del_reply>(vapi_msg_id_pnat_binding_del_reply);
}

template class Msg<vapi_msg_pnat_binding_del_reply>;

using Pnat_binding_del_reply = Msg<vapi_msg_pnat_binding_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_pnat_binding_attach>(vapi_msg_pnat_binding_attach *msg)
{
  vapi_msg_pnat_binding_attach_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pnat_binding_attach>(vapi_msg_pnat_binding_attach *msg)
{
  vapi_msg_pnat_binding_attach_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pnat_binding_attach>()
{
  return ::vapi_msg_id_pnat_binding_attach; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pnat_binding_attach>>()
{
  return ::vapi_msg_id_pnat_binding_attach; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pnat_binding_attach()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pnat_binding_attach>(vapi_msg_id_pnat_binding_attach);
}

template <> inline vapi_msg_pnat_binding_attach* vapi_alloc<vapi_msg_pnat_binding_attach>(Connection &con)
{
  vapi_msg_pnat_binding_attach* result = vapi_alloc_pnat_binding_attach(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_pnat_binding_attach>;

template class Request<vapi_msg_pnat_binding_attach, vapi_msg_pnat_binding_attach_reply>;

using Pnat_binding_attach = Request<vapi_msg_pnat_binding_attach, vapi_msg_pnat_binding_attach_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_pnat_binding_attach_reply>(vapi_msg_pnat_binding_attach_reply *msg)
{
  vapi_msg_pnat_binding_attach_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pnat_binding_attach_reply>(vapi_msg_pnat_binding_attach_reply *msg)
{
  vapi_msg_pnat_binding_attach_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pnat_binding_attach_reply>()
{
  return ::vapi_msg_id_pnat_binding_attach_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pnat_binding_attach_reply>>()
{
  return ::vapi_msg_id_pnat_binding_attach_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pnat_binding_attach_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pnat_binding_attach_reply>(vapi_msg_id_pnat_binding_attach_reply);
}

template class Msg<vapi_msg_pnat_binding_attach_reply>;

using Pnat_binding_attach_reply = Msg<vapi_msg_pnat_binding_attach_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_pnat_binding_detach>(vapi_msg_pnat_binding_detach *msg)
{
  vapi_msg_pnat_binding_detach_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pnat_binding_detach>(vapi_msg_pnat_binding_detach *msg)
{
  vapi_msg_pnat_binding_detach_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pnat_binding_detach>()
{
  return ::vapi_msg_id_pnat_binding_detach; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pnat_binding_detach>>()
{
  return ::vapi_msg_id_pnat_binding_detach; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pnat_binding_detach()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pnat_binding_detach>(vapi_msg_id_pnat_binding_detach);
}

template <> inline vapi_msg_pnat_binding_detach* vapi_alloc<vapi_msg_pnat_binding_detach>(Connection &con)
{
  vapi_msg_pnat_binding_detach* result = vapi_alloc_pnat_binding_detach(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_pnat_binding_detach>;

template class Request<vapi_msg_pnat_binding_detach, vapi_msg_pnat_binding_detach_reply>;

using Pnat_binding_detach = Request<vapi_msg_pnat_binding_detach, vapi_msg_pnat_binding_detach_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_pnat_binding_detach_reply>(vapi_msg_pnat_binding_detach_reply *msg)
{
  vapi_msg_pnat_binding_detach_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pnat_binding_detach_reply>(vapi_msg_pnat_binding_detach_reply *msg)
{
  vapi_msg_pnat_binding_detach_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pnat_binding_detach_reply>()
{
  return ::vapi_msg_id_pnat_binding_detach_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pnat_binding_detach_reply>>()
{
  return ::vapi_msg_id_pnat_binding_detach_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pnat_binding_detach_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pnat_binding_detach_reply>(vapi_msg_id_pnat_binding_detach_reply);
}

template class Msg<vapi_msg_pnat_binding_detach_reply>;

using Pnat_binding_detach_reply = Msg<vapi_msg_pnat_binding_detach_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_pnat_bindings_get>(vapi_msg_pnat_bindings_get *msg)
{
  vapi_msg_pnat_bindings_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pnat_bindings_get>(vapi_msg_pnat_bindings_get *msg)
{
  vapi_msg_pnat_bindings_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pnat_bindings_get>()
{
  return ::vapi_msg_id_pnat_bindings_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pnat_bindings_get>>()
{
  return ::vapi_msg_id_pnat_bindings_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pnat_bindings_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pnat_bindings_get>(vapi_msg_id_pnat_bindings_get);
}

template <> inline vapi_msg_pnat_bindings_get* vapi_alloc<vapi_msg_pnat_bindings_get>(Connection &con)
{
  vapi_msg_pnat_bindings_get* result = vapi_alloc_pnat_bindings_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_pnat_bindings_get>;

template class Stream<vapi_msg_pnat_bindings_get, vapi_msg_pnat_bindings_get_reply, vapi_msg_pnat_bindings_details>;

using Pnat_bindings_get = Stream<vapi_msg_pnat_bindings_get, vapi_msg_pnat_bindings_get_reply, vapi_msg_pnat_bindings_details>;

template <> inline void vapi_swap_to_be<vapi_msg_pnat_bindings_get_reply>(vapi_msg_pnat_bindings_get_reply *msg)
{
  vapi_msg_pnat_bindings_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pnat_bindings_get_reply>(vapi_msg_pnat_bindings_get_reply *msg)
{
  vapi_msg_pnat_bindings_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pnat_bindings_get_reply>()
{
  return ::vapi_msg_id_pnat_bindings_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pnat_bindings_get_reply>>()
{
  return ::vapi_msg_id_pnat_bindings_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pnat_bindings_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pnat_bindings_get_reply>(vapi_msg_id_pnat_bindings_get_reply);
}

template class Msg<vapi_msg_pnat_bindings_get_reply>;

using Pnat_bindings_get_reply = Msg<vapi_msg_pnat_bindings_get_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_pnat_bindings_details>(vapi_msg_pnat_bindings_details *msg)
{
  vapi_msg_pnat_bindings_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pnat_bindings_details>(vapi_msg_pnat_bindings_details *msg)
{
  vapi_msg_pnat_bindings_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pnat_bindings_details>()
{
  return ::vapi_msg_id_pnat_bindings_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pnat_bindings_details>>()
{
  return ::vapi_msg_id_pnat_bindings_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pnat_bindings_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pnat_bindings_details>(vapi_msg_id_pnat_bindings_details);
}

template class Msg<vapi_msg_pnat_bindings_details>;

template <> inline void vapi_swap_to_be<vapi_msg_pnat_interfaces_get>(vapi_msg_pnat_interfaces_get *msg)
{
  vapi_msg_pnat_interfaces_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pnat_interfaces_get>(vapi_msg_pnat_interfaces_get *msg)
{
  vapi_msg_pnat_interfaces_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pnat_interfaces_get>()
{
  return ::vapi_msg_id_pnat_interfaces_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pnat_interfaces_get>>()
{
  return ::vapi_msg_id_pnat_interfaces_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pnat_interfaces_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pnat_interfaces_get>(vapi_msg_id_pnat_interfaces_get);
}

template <> inline vapi_msg_pnat_interfaces_get* vapi_alloc<vapi_msg_pnat_interfaces_get>(Connection &con)
{
  vapi_msg_pnat_interfaces_get* result = vapi_alloc_pnat_interfaces_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_pnat_interfaces_get>;

template class Stream<vapi_msg_pnat_interfaces_get, vapi_msg_pnat_interfaces_get_reply, vapi_msg_pnat_interfaces_details>;

using Pnat_interfaces_get = Stream<vapi_msg_pnat_interfaces_get, vapi_msg_pnat_interfaces_get_reply, vapi_msg_pnat_interfaces_details>;

template <> inline void vapi_swap_to_be<vapi_msg_pnat_interfaces_get_reply>(vapi_msg_pnat_interfaces_get_reply *msg)
{
  vapi_msg_pnat_interfaces_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pnat_interfaces_get_reply>(vapi_msg_pnat_interfaces_get_reply *msg)
{
  vapi_msg_pnat_interfaces_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pnat_interfaces_get_reply>()
{
  return ::vapi_msg_id_pnat_interfaces_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pnat_interfaces_get_reply>>()
{
  return ::vapi_msg_id_pnat_interfaces_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pnat_interfaces_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pnat_interfaces_get_reply>(vapi_msg_id_pnat_interfaces_get_reply);
}

template class Msg<vapi_msg_pnat_interfaces_get_reply>;

using Pnat_interfaces_get_reply = Msg<vapi_msg_pnat_interfaces_get_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_pnat_interfaces_details>(vapi_msg_pnat_interfaces_details *msg)
{
  vapi_msg_pnat_interfaces_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pnat_interfaces_details>(vapi_msg_pnat_interfaces_details *msg)
{
  vapi_msg_pnat_interfaces_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pnat_interfaces_details>()
{
  return ::vapi_msg_id_pnat_interfaces_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pnat_interfaces_details>>()
{
  return ::vapi_msg_id_pnat_interfaces_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pnat_interfaces_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pnat_interfaces_details>(vapi_msg_id_pnat_interfaces_details);
}

template class Msg<vapi_msg_pnat_interfaces_details>;

template <> inline void vapi_swap_to_be<vapi_msg_pnat_flow_lookup>(vapi_msg_pnat_flow_lookup *msg)
{
  vapi_msg_pnat_flow_lookup_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pnat_flow_lookup>(vapi_msg_pnat_flow_lookup *msg)
{
  vapi_msg_pnat_flow_lookup_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pnat_flow_lookup>()
{
  return ::vapi_msg_id_pnat_flow_lookup; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pnat_flow_lookup>>()
{
  return ::vapi_msg_id_pnat_flow_lookup; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pnat_flow_lookup()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pnat_flow_lookup>(vapi_msg_id_pnat_flow_lookup);
}

template <> inline vapi_msg_pnat_flow_lookup* vapi_alloc<vapi_msg_pnat_flow_lookup>(Connection &con)
{
  vapi_msg_pnat_flow_lookup* result = vapi_alloc_pnat_flow_lookup(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_pnat_flow_lookup>;

template class Request<vapi_msg_pnat_flow_lookup, vapi_msg_pnat_flow_lookup_reply>;

using Pnat_flow_lookup = Request<vapi_msg_pnat_flow_lookup, vapi_msg_pnat_flow_lookup_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_pnat_flow_lookup_reply>(vapi_msg_pnat_flow_lookup_reply *msg)
{
  vapi_msg_pnat_flow_lookup_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pnat_flow_lookup_reply>(vapi_msg_pnat_flow_lookup_reply *msg)
{
  vapi_msg_pnat_flow_lookup_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pnat_flow_lookup_reply>()
{
  return ::vapi_msg_id_pnat_flow_lookup_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pnat_flow_lookup_reply>>()
{
  return ::vapi_msg_id_pnat_flow_lookup_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pnat_flow_lookup_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pnat_flow_lookup_reply>(vapi_msg_id_pnat_flow_lookup_reply);
}

template class Msg<vapi_msg_pnat_flow_lookup_reply>;

using Pnat_flow_lookup_reply = Msg<vapi_msg_pnat_flow_lookup_reply>;
}
#endif
