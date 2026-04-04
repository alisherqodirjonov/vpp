#ifndef __included_hpp_arp_api_json
#define __included_hpp_arp_api_json

#include <vapi/vapi.hpp>
#include <vapi/arp.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_proxy_arp_add_del>(vapi_msg_proxy_arp_add_del *msg)
{
  vapi_msg_proxy_arp_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_proxy_arp_add_del>(vapi_msg_proxy_arp_add_del *msg)
{
  vapi_msg_proxy_arp_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_proxy_arp_add_del>()
{
  return ::vapi_msg_id_proxy_arp_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_proxy_arp_add_del>>()
{
  return ::vapi_msg_id_proxy_arp_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_proxy_arp_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_proxy_arp_add_del>(vapi_msg_id_proxy_arp_add_del);
}

template <> inline vapi_msg_proxy_arp_add_del* vapi_alloc<vapi_msg_proxy_arp_add_del>(Connection &con)
{
  vapi_msg_proxy_arp_add_del* result = vapi_alloc_proxy_arp_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_proxy_arp_add_del>;

template class Request<vapi_msg_proxy_arp_add_del, vapi_msg_proxy_arp_add_del_reply>;

using Proxy_arp_add_del = Request<vapi_msg_proxy_arp_add_del, vapi_msg_proxy_arp_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_proxy_arp_add_del_reply>(vapi_msg_proxy_arp_add_del_reply *msg)
{
  vapi_msg_proxy_arp_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_proxy_arp_add_del_reply>(vapi_msg_proxy_arp_add_del_reply *msg)
{
  vapi_msg_proxy_arp_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_proxy_arp_add_del_reply>()
{
  return ::vapi_msg_id_proxy_arp_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_proxy_arp_add_del_reply>>()
{
  return ::vapi_msg_id_proxy_arp_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_proxy_arp_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_proxy_arp_add_del_reply>(vapi_msg_id_proxy_arp_add_del_reply);
}

template class Msg<vapi_msg_proxy_arp_add_del_reply>;

using Proxy_arp_add_del_reply = Msg<vapi_msg_proxy_arp_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_proxy_arp_dump>(vapi_msg_proxy_arp_dump *msg)
{
  vapi_msg_proxy_arp_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_proxy_arp_dump>(vapi_msg_proxy_arp_dump *msg)
{
  vapi_msg_proxy_arp_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_proxy_arp_dump>()
{
  return ::vapi_msg_id_proxy_arp_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_proxy_arp_dump>>()
{
  return ::vapi_msg_id_proxy_arp_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_proxy_arp_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_proxy_arp_dump>(vapi_msg_id_proxy_arp_dump);
}

template <> inline vapi_msg_proxy_arp_dump* vapi_alloc<vapi_msg_proxy_arp_dump>(Connection &con)
{
  vapi_msg_proxy_arp_dump* result = vapi_alloc_proxy_arp_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_proxy_arp_dump>;

template class Dump<vapi_msg_proxy_arp_dump, vapi_msg_proxy_arp_details>;

using Proxy_arp_dump = Dump<vapi_msg_proxy_arp_dump, vapi_msg_proxy_arp_details>;

template <> inline void vapi_swap_to_be<vapi_msg_proxy_arp_details>(vapi_msg_proxy_arp_details *msg)
{
  vapi_msg_proxy_arp_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_proxy_arp_details>(vapi_msg_proxy_arp_details *msg)
{
  vapi_msg_proxy_arp_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_proxy_arp_details>()
{
  return ::vapi_msg_id_proxy_arp_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_proxy_arp_details>>()
{
  return ::vapi_msg_id_proxy_arp_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_proxy_arp_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_proxy_arp_details>(vapi_msg_id_proxy_arp_details);
}

template class Msg<vapi_msg_proxy_arp_details>;

using Proxy_arp_details = Msg<vapi_msg_proxy_arp_details>;
template <> inline void vapi_swap_to_be<vapi_msg_proxy_arp_intfc_enable_disable>(vapi_msg_proxy_arp_intfc_enable_disable *msg)
{
  vapi_msg_proxy_arp_intfc_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_proxy_arp_intfc_enable_disable>(vapi_msg_proxy_arp_intfc_enable_disable *msg)
{
  vapi_msg_proxy_arp_intfc_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_proxy_arp_intfc_enable_disable>()
{
  return ::vapi_msg_id_proxy_arp_intfc_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_proxy_arp_intfc_enable_disable>>()
{
  return ::vapi_msg_id_proxy_arp_intfc_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_proxy_arp_intfc_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_proxy_arp_intfc_enable_disable>(vapi_msg_id_proxy_arp_intfc_enable_disable);
}

template <> inline vapi_msg_proxy_arp_intfc_enable_disable* vapi_alloc<vapi_msg_proxy_arp_intfc_enable_disable>(Connection &con)
{
  vapi_msg_proxy_arp_intfc_enable_disable* result = vapi_alloc_proxy_arp_intfc_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_proxy_arp_intfc_enable_disable>;

template class Request<vapi_msg_proxy_arp_intfc_enable_disable, vapi_msg_proxy_arp_intfc_enable_disable_reply>;

using Proxy_arp_intfc_enable_disable = Request<vapi_msg_proxy_arp_intfc_enable_disable, vapi_msg_proxy_arp_intfc_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_proxy_arp_intfc_enable_disable_reply>(vapi_msg_proxy_arp_intfc_enable_disable_reply *msg)
{
  vapi_msg_proxy_arp_intfc_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_proxy_arp_intfc_enable_disable_reply>(vapi_msg_proxy_arp_intfc_enable_disable_reply *msg)
{
  vapi_msg_proxy_arp_intfc_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_proxy_arp_intfc_enable_disable_reply>()
{
  return ::vapi_msg_id_proxy_arp_intfc_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_proxy_arp_intfc_enable_disable_reply>>()
{
  return ::vapi_msg_id_proxy_arp_intfc_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_proxy_arp_intfc_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_proxy_arp_intfc_enable_disable_reply>(vapi_msg_id_proxy_arp_intfc_enable_disable_reply);
}

template class Msg<vapi_msg_proxy_arp_intfc_enable_disable_reply>;

using Proxy_arp_intfc_enable_disable_reply = Msg<vapi_msg_proxy_arp_intfc_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_proxy_arp_intfc_dump>(vapi_msg_proxy_arp_intfc_dump *msg)
{
  vapi_msg_proxy_arp_intfc_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_proxy_arp_intfc_dump>(vapi_msg_proxy_arp_intfc_dump *msg)
{
  vapi_msg_proxy_arp_intfc_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_proxy_arp_intfc_dump>()
{
  return ::vapi_msg_id_proxy_arp_intfc_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_proxy_arp_intfc_dump>>()
{
  return ::vapi_msg_id_proxy_arp_intfc_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_proxy_arp_intfc_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_proxy_arp_intfc_dump>(vapi_msg_id_proxy_arp_intfc_dump);
}

template <> inline vapi_msg_proxy_arp_intfc_dump* vapi_alloc<vapi_msg_proxy_arp_intfc_dump>(Connection &con)
{
  vapi_msg_proxy_arp_intfc_dump* result = vapi_alloc_proxy_arp_intfc_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_proxy_arp_intfc_dump>;

template class Dump<vapi_msg_proxy_arp_intfc_dump, vapi_msg_proxy_arp_intfc_details>;

using Proxy_arp_intfc_dump = Dump<vapi_msg_proxy_arp_intfc_dump, vapi_msg_proxy_arp_intfc_details>;

template <> inline void vapi_swap_to_be<vapi_msg_proxy_arp_intfc_details>(vapi_msg_proxy_arp_intfc_details *msg)
{
  vapi_msg_proxy_arp_intfc_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_proxy_arp_intfc_details>(vapi_msg_proxy_arp_intfc_details *msg)
{
  vapi_msg_proxy_arp_intfc_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_proxy_arp_intfc_details>()
{
  return ::vapi_msg_id_proxy_arp_intfc_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_proxy_arp_intfc_details>>()
{
  return ::vapi_msg_id_proxy_arp_intfc_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_proxy_arp_intfc_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_proxy_arp_intfc_details>(vapi_msg_id_proxy_arp_intfc_details);
}

template class Msg<vapi_msg_proxy_arp_intfc_details>;

using Proxy_arp_intfc_details = Msg<vapi_msg_proxy_arp_intfc_details>;
}
#endif
