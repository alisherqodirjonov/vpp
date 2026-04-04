#ifndef __included_hpp_ipip_api_json
#define __included_hpp_ipip_api_json

#include <vapi/vapi.hpp>
#include <vapi/ipip.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_ipip_add_tunnel>(vapi_msg_ipip_add_tunnel *msg)
{
  vapi_msg_ipip_add_tunnel_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipip_add_tunnel>(vapi_msg_ipip_add_tunnel *msg)
{
  vapi_msg_ipip_add_tunnel_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipip_add_tunnel>()
{
  return ::vapi_msg_id_ipip_add_tunnel; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipip_add_tunnel>>()
{
  return ::vapi_msg_id_ipip_add_tunnel; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipip_add_tunnel()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipip_add_tunnel>(vapi_msg_id_ipip_add_tunnel);
}

template <> inline vapi_msg_ipip_add_tunnel* vapi_alloc<vapi_msg_ipip_add_tunnel>(Connection &con)
{
  vapi_msg_ipip_add_tunnel* result = vapi_alloc_ipip_add_tunnel(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipip_add_tunnel>;

template class Request<vapi_msg_ipip_add_tunnel, vapi_msg_ipip_add_tunnel_reply>;

using Ipip_add_tunnel = Request<vapi_msg_ipip_add_tunnel, vapi_msg_ipip_add_tunnel_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ipip_add_tunnel_reply>(vapi_msg_ipip_add_tunnel_reply *msg)
{
  vapi_msg_ipip_add_tunnel_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipip_add_tunnel_reply>(vapi_msg_ipip_add_tunnel_reply *msg)
{
  vapi_msg_ipip_add_tunnel_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipip_add_tunnel_reply>()
{
  return ::vapi_msg_id_ipip_add_tunnel_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipip_add_tunnel_reply>>()
{
  return ::vapi_msg_id_ipip_add_tunnel_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipip_add_tunnel_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipip_add_tunnel_reply>(vapi_msg_id_ipip_add_tunnel_reply);
}

template class Msg<vapi_msg_ipip_add_tunnel_reply>;

using Ipip_add_tunnel_reply = Msg<vapi_msg_ipip_add_tunnel_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ipip_del_tunnel>(vapi_msg_ipip_del_tunnel *msg)
{
  vapi_msg_ipip_del_tunnel_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipip_del_tunnel>(vapi_msg_ipip_del_tunnel *msg)
{
  vapi_msg_ipip_del_tunnel_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipip_del_tunnel>()
{
  return ::vapi_msg_id_ipip_del_tunnel; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipip_del_tunnel>>()
{
  return ::vapi_msg_id_ipip_del_tunnel; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipip_del_tunnel()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipip_del_tunnel>(vapi_msg_id_ipip_del_tunnel);
}

template <> inline vapi_msg_ipip_del_tunnel* vapi_alloc<vapi_msg_ipip_del_tunnel>(Connection &con)
{
  vapi_msg_ipip_del_tunnel* result = vapi_alloc_ipip_del_tunnel(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipip_del_tunnel>;

template class Request<vapi_msg_ipip_del_tunnel, vapi_msg_ipip_del_tunnel_reply>;

using Ipip_del_tunnel = Request<vapi_msg_ipip_del_tunnel, vapi_msg_ipip_del_tunnel_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ipip_del_tunnel_reply>(vapi_msg_ipip_del_tunnel_reply *msg)
{
  vapi_msg_ipip_del_tunnel_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipip_del_tunnel_reply>(vapi_msg_ipip_del_tunnel_reply *msg)
{
  vapi_msg_ipip_del_tunnel_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipip_del_tunnel_reply>()
{
  return ::vapi_msg_id_ipip_del_tunnel_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipip_del_tunnel_reply>>()
{
  return ::vapi_msg_id_ipip_del_tunnel_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipip_del_tunnel_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipip_del_tunnel_reply>(vapi_msg_id_ipip_del_tunnel_reply);
}

template class Msg<vapi_msg_ipip_del_tunnel_reply>;

using Ipip_del_tunnel_reply = Msg<vapi_msg_ipip_del_tunnel_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ipip_6rd_add_tunnel>(vapi_msg_ipip_6rd_add_tunnel *msg)
{
  vapi_msg_ipip_6rd_add_tunnel_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipip_6rd_add_tunnel>(vapi_msg_ipip_6rd_add_tunnel *msg)
{
  vapi_msg_ipip_6rd_add_tunnel_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipip_6rd_add_tunnel>()
{
  return ::vapi_msg_id_ipip_6rd_add_tunnel; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipip_6rd_add_tunnel>>()
{
  return ::vapi_msg_id_ipip_6rd_add_tunnel; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipip_6rd_add_tunnel()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipip_6rd_add_tunnel>(vapi_msg_id_ipip_6rd_add_tunnel);
}

template <> inline vapi_msg_ipip_6rd_add_tunnel* vapi_alloc<vapi_msg_ipip_6rd_add_tunnel>(Connection &con)
{
  vapi_msg_ipip_6rd_add_tunnel* result = vapi_alloc_ipip_6rd_add_tunnel(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipip_6rd_add_tunnel>;

template class Request<vapi_msg_ipip_6rd_add_tunnel, vapi_msg_ipip_6rd_add_tunnel_reply>;

using Ipip_6rd_add_tunnel = Request<vapi_msg_ipip_6rd_add_tunnel, vapi_msg_ipip_6rd_add_tunnel_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ipip_6rd_add_tunnel_reply>(vapi_msg_ipip_6rd_add_tunnel_reply *msg)
{
  vapi_msg_ipip_6rd_add_tunnel_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipip_6rd_add_tunnel_reply>(vapi_msg_ipip_6rd_add_tunnel_reply *msg)
{
  vapi_msg_ipip_6rd_add_tunnel_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipip_6rd_add_tunnel_reply>()
{
  return ::vapi_msg_id_ipip_6rd_add_tunnel_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipip_6rd_add_tunnel_reply>>()
{
  return ::vapi_msg_id_ipip_6rd_add_tunnel_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipip_6rd_add_tunnel_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipip_6rd_add_tunnel_reply>(vapi_msg_id_ipip_6rd_add_tunnel_reply);
}

template class Msg<vapi_msg_ipip_6rd_add_tunnel_reply>;

using Ipip_6rd_add_tunnel_reply = Msg<vapi_msg_ipip_6rd_add_tunnel_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ipip_6rd_del_tunnel>(vapi_msg_ipip_6rd_del_tunnel *msg)
{
  vapi_msg_ipip_6rd_del_tunnel_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipip_6rd_del_tunnel>(vapi_msg_ipip_6rd_del_tunnel *msg)
{
  vapi_msg_ipip_6rd_del_tunnel_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipip_6rd_del_tunnel>()
{
  return ::vapi_msg_id_ipip_6rd_del_tunnel; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipip_6rd_del_tunnel>>()
{
  return ::vapi_msg_id_ipip_6rd_del_tunnel; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipip_6rd_del_tunnel()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipip_6rd_del_tunnel>(vapi_msg_id_ipip_6rd_del_tunnel);
}

template <> inline vapi_msg_ipip_6rd_del_tunnel* vapi_alloc<vapi_msg_ipip_6rd_del_tunnel>(Connection &con)
{
  vapi_msg_ipip_6rd_del_tunnel* result = vapi_alloc_ipip_6rd_del_tunnel(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipip_6rd_del_tunnel>;

template class Request<vapi_msg_ipip_6rd_del_tunnel, vapi_msg_ipip_6rd_del_tunnel_reply>;

using Ipip_6rd_del_tunnel = Request<vapi_msg_ipip_6rd_del_tunnel, vapi_msg_ipip_6rd_del_tunnel_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ipip_6rd_del_tunnel_reply>(vapi_msg_ipip_6rd_del_tunnel_reply *msg)
{
  vapi_msg_ipip_6rd_del_tunnel_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipip_6rd_del_tunnel_reply>(vapi_msg_ipip_6rd_del_tunnel_reply *msg)
{
  vapi_msg_ipip_6rd_del_tunnel_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipip_6rd_del_tunnel_reply>()
{
  return ::vapi_msg_id_ipip_6rd_del_tunnel_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipip_6rd_del_tunnel_reply>>()
{
  return ::vapi_msg_id_ipip_6rd_del_tunnel_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipip_6rd_del_tunnel_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipip_6rd_del_tunnel_reply>(vapi_msg_id_ipip_6rd_del_tunnel_reply);
}

template class Msg<vapi_msg_ipip_6rd_del_tunnel_reply>;

using Ipip_6rd_del_tunnel_reply = Msg<vapi_msg_ipip_6rd_del_tunnel_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ipip_tunnel_dump>(vapi_msg_ipip_tunnel_dump *msg)
{
  vapi_msg_ipip_tunnel_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipip_tunnel_dump>(vapi_msg_ipip_tunnel_dump *msg)
{
  vapi_msg_ipip_tunnel_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipip_tunnel_dump>()
{
  return ::vapi_msg_id_ipip_tunnel_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipip_tunnel_dump>>()
{
  return ::vapi_msg_id_ipip_tunnel_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipip_tunnel_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipip_tunnel_dump>(vapi_msg_id_ipip_tunnel_dump);
}

template <> inline vapi_msg_ipip_tunnel_dump* vapi_alloc<vapi_msg_ipip_tunnel_dump>(Connection &con)
{
  vapi_msg_ipip_tunnel_dump* result = vapi_alloc_ipip_tunnel_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipip_tunnel_dump>;

template class Dump<vapi_msg_ipip_tunnel_dump, vapi_msg_ipip_tunnel_details>;

using Ipip_tunnel_dump = Dump<vapi_msg_ipip_tunnel_dump, vapi_msg_ipip_tunnel_details>;

template <> inline void vapi_swap_to_be<vapi_msg_ipip_tunnel_details>(vapi_msg_ipip_tunnel_details *msg)
{
  vapi_msg_ipip_tunnel_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipip_tunnel_details>(vapi_msg_ipip_tunnel_details *msg)
{
  vapi_msg_ipip_tunnel_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipip_tunnel_details>()
{
  return ::vapi_msg_id_ipip_tunnel_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipip_tunnel_details>>()
{
  return ::vapi_msg_id_ipip_tunnel_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipip_tunnel_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipip_tunnel_details>(vapi_msg_id_ipip_tunnel_details);
}

template class Msg<vapi_msg_ipip_tunnel_details>;

using Ipip_tunnel_details = Msg<vapi_msg_ipip_tunnel_details>;
}
#endif
