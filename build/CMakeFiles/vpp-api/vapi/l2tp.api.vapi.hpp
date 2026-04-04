#ifndef __included_hpp_l2tp_api_json
#define __included_hpp_l2tp_api_json

#include <vapi/vapi.hpp>
#include <vapi/l2tp.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_l2tpv3_create_tunnel>(vapi_msg_l2tpv3_create_tunnel *msg)
{
  vapi_msg_l2tpv3_create_tunnel_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l2tpv3_create_tunnel>(vapi_msg_l2tpv3_create_tunnel *msg)
{
  vapi_msg_l2tpv3_create_tunnel_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l2tpv3_create_tunnel>()
{
  return ::vapi_msg_id_l2tpv3_create_tunnel; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l2tpv3_create_tunnel>>()
{
  return ::vapi_msg_id_l2tpv3_create_tunnel; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l2tpv3_create_tunnel()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l2tpv3_create_tunnel>(vapi_msg_id_l2tpv3_create_tunnel);
}

template <> inline vapi_msg_l2tpv3_create_tunnel* vapi_alloc<vapi_msg_l2tpv3_create_tunnel>(Connection &con)
{
  vapi_msg_l2tpv3_create_tunnel* result = vapi_alloc_l2tpv3_create_tunnel(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_l2tpv3_create_tunnel>;

template class Request<vapi_msg_l2tpv3_create_tunnel, vapi_msg_l2tpv3_create_tunnel_reply>;

using L2tpv3_create_tunnel = Request<vapi_msg_l2tpv3_create_tunnel, vapi_msg_l2tpv3_create_tunnel_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_l2tpv3_create_tunnel_reply>(vapi_msg_l2tpv3_create_tunnel_reply *msg)
{
  vapi_msg_l2tpv3_create_tunnel_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l2tpv3_create_tunnel_reply>(vapi_msg_l2tpv3_create_tunnel_reply *msg)
{
  vapi_msg_l2tpv3_create_tunnel_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l2tpv3_create_tunnel_reply>()
{
  return ::vapi_msg_id_l2tpv3_create_tunnel_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l2tpv3_create_tunnel_reply>>()
{
  return ::vapi_msg_id_l2tpv3_create_tunnel_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l2tpv3_create_tunnel_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l2tpv3_create_tunnel_reply>(vapi_msg_id_l2tpv3_create_tunnel_reply);
}

template class Msg<vapi_msg_l2tpv3_create_tunnel_reply>;

using L2tpv3_create_tunnel_reply = Msg<vapi_msg_l2tpv3_create_tunnel_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_l2tpv3_set_tunnel_cookies>(vapi_msg_l2tpv3_set_tunnel_cookies *msg)
{
  vapi_msg_l2tpv3_set_tunnel_cookies_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l2tpv3_set_tunnel_cookies>(vapi_msg_l2tpv3_set_tunnel_cookies *msg)
{
  vapi_msg_l2tpv3_set_tunnel_cookies_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l2tpv3_set_tunnel_cookies>()
{
  return ::vapi_msg_id_l2tpv3_set_tunnel_cookies; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l2tpv3_set_tunnel_cookies>>()
{
  return ::vapi_msg_id_l2tpv3_set_tunnel_cookies; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l2tpv3_set_tunnel_cookies()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l2tpv3_set_tunnel_cookies>(vapi_msg_id_l2tpv3_set_tunnel_cookies);
}

template <> inline vapi_msg_l2tpv3_set_tunnel_cookies* vapi_alloc<vapi_msg_l2tpv3_set_tunnel_cookies>(Connection &con)
{
  vapi_msg_l2tpv3_set_tunnel_cookies* result = vapi_alloc_l2tpv3_set_tunnel_cookies(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_l2tpv3_set_tunnel_cookies>;

template class Request<vapi_msg_l2tpv3_set_tunnel_cookies, vapi_msg_l2tpv3_set_tunnel_cookies_reply>;

using L2tpv3_set_tunnel_cookies = Request<vapi_msg_l2tpv3_set_tunnel_cookies, vapi_msg_l2tpv3_set_tunnel_cookies_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_l2tpv3_set_tunnel_cookies_reply>(vapi_msg_l2tpv3_set_tunnel_cookies_reply *msg)
{
  vapi_msg_l2tpv3_set_tunnel_cookies_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l2tpv3_set_tunnel_cookies_reply>(vapi_msg_l2tpv3_set_tunnel_cookies_reply *msg)
{
  vapi_msg_l2tpv3_set_tunnel_cookies_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l2tpv3_set_tunnel_cookies_reply>()
{
  return ::vapi_msg_id_l2tpv3_set_tunnel_cookies_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l2tpv3_set_tunnel_cookies_reply>>()
{
  return ::vapi_msg_id_l2tpv3_set_tunnel_cookies_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l2tpv3_set_tunnel_cookies_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l2tpv3_set_tunnel_cookies_reply>(vapi_msg_id_l2tpv3_set_tunnel_cookies_reply);
}

template class Msg<vapi_msg_l2tpv3_set_tunnel_cookies_reply>;

using L2tpv3_set_tunnel_cookies_reply = Msg<vapi_msg_l2tpv3_set_tunnel_cookies_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_if_l2tpv3_tunnel_details>(vapi_msg_sw_if_l2tpv3_tunnel_details *msg)
{
  vapi_msg_sw_if_l2tpv3_tunnel_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_if_l2tpv3_tunnel_details>(vapi_msg_sw_if_l2tpv3_tunnel_details *msg)
{
  vapi_msg_sw_if_l2tpv3_tunnel_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_if_l2tpv3_tunnel_details>()
{
  return ::vapi_msg_id_sw_if_l2tpv3_tunnel_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_if_l2tpv3_tunnel_details>>()
{
  return ::vapi_msg_id_sw_if_l2tpv3_tunnel_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_if_l2tpv3_tunnel_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_if_l2tpv3_tunnel_details>(vapi_msg_id_sw_if_l2tpv3_tunnel_details);
}

template class Msg<vapi_msg_sw_if_l2tpv3_tunnel_details>;

using Sw_if_l2tpv3_tunnel_details = Msg<vapi_msg_sw_if_l2tpv3_tunnel_details>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_if_l2tpv3_tunnel_dump>(vapi_msg_sw_if_l2tpv3_tunnel_dump *msg)
{
  vapi_msg_sw_if_l2tpv3_tunnel_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_if_l2tpv3_tunnel_dump>(vapi_msg_sw_if_l2tpv3_tunnel_dump *msg)
{
  vapi_msg_sw_if_l2tpv3_tunnel_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_if_l2tpv3_tunnel_dump>()
{
  return ::vapi_msg_id_sw_if_l2tpv3_tunnel_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_if_l2tpv3_tunnel_dump>>()
{
  return ::vapi_msg_id_sw_if_l2tpv3_tunnel_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_if_l2tpv3_tunnel_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_if_l2tpv3_tunnel_dump>(vapi_msg_id_sw_if_l2tpv3_tunnel_dump);
}

template <> inline vapi_msg_sw_if_l2tpv3_tunnel_dump* vapi_alloc<vapi_msg_sw_if_l2tpv3_tunnel_dump>(Connection &con)
{
  vapi_msg_sw_if_l2tpv3_tunnel_dump* result = vapi_alloc_sw_if_l2tpv3_tunnel_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_if_l2tpv3_tunnel_dump>;

template class Dump<vapi_msg_sw_if_l2tpv3_tunnel_dump, vapi_msg_sw_if_l2tpv3_tunnel_details>;

using Sw_if_l2tpv3_tunnel_dump = Dump<vapi_msg_sw_if_l2tpv3_tunnel_dump, vapi_msg_sw_if_l2tpv3_tunnel_details>;

template <> inline void vapi_swap_to_be<vapi_msg_l2tpv3_interface_enable_disable>(vapi_msg_l2tpv3_interface_enable_disable *msg)
{
  vapi_msg_l2tpv3_interface_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l2tpv3_interface_enable_disable>(vapi_msg_l2tpv3_interface_enable_disable *msg)
{
  vapi_msg_l2tpv3_interface_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l2tpv3_interface_enable_disable>()
{
  return ::vapi_msg_id_l2tpv3_interface_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l2tpv3_interface_enable_disable>>()
{
  return ::vapi_msg_id_l2tpv3_interface_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l2tpv3_interface_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l2tpv3_interface_enable_disable>(vapi_msg_id_l2tpv3_interface_enable_disable);
}

template <> inline vapi_msg_l2tpv3_interface_enable_disable* vapi_alloc<vapi_msg_l2tpv3_interface_enable_disable>(Connection &con)
{
  vapi_msg_l2tpv3_interface_enable_disable* result = vapi_alloc_l2tpv3_interface_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_l2tpv3_interface_enable_disable>;

template class Request<vapi_msg_l2tpv3_interface_enable_disable, vapi_msg_l2tpv3_interface_enable_disable_reply>;

using L2tpv3_interface_enable_disable = Request<vapi_msg_l2tpv3_interface_enable_disable, vapi_msg_l2tpv3_interface_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_l2tpv3_interface_enable_disable_reply>(vapi_msg_l2tpv3_interface_enable_disable_reply *msg)
{
  vapi_msg_l2tpv3_interface_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l2tpv3_interface_enable_disable_reply>(vapi_msg_l2tpv3_interface_enable_disable_reply *msg)
{
  vapi_msg_l2tpv3_interface_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l2tpv3_interface_enable_disable_reply>()
{
  return ::vapi_msg_id_l2tpv3_interface_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l2tpv3_interface_enable_disable_reply>>()
{
  return ::vapi_msg_id_l2tpv3_interface_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l2tpv3_interface_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l2tpv3_interface_enable_disable_reply>(vapi_msg_id_l2tpv3_interface_enable_disable_reply);
}

template class Msg<vapi_msg_l2tpv3_interface_enable_disable_reply>;

using L2tpv3_interface_enable_disable_reply = Msg<vapi_msg_l2tpv3_interface_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_l2tpv3_set_lookup_key>(vapi_msg_l2tpv3_set_lookup_key *msg)
{
  vapi_msg_l2tpv3_set_lookup_key_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l2tpv3_set_lookup_key>(vapi_msg_l2tpv3_set_lookup_key *msg)
{
  vapi_msg_l2tpv3_set_lookup_key_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l2tpv3_set_lookup_key>()
{
  return ::vapi_msg_id_l2tpv3_set_lookup_key; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l2tpv3_set_lookup_key>>()
{
  return ::vapi_msg_id_l2tpv3_set_lookup_key; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l2tpv3_set_lookup_key()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l2tpv3_set_lookup_key>(vapi_msg_id_l2tpv3_set_lookup_key);
}

template <> inline vapi_msg_l2tpv3_set_lookup_key* vapi_alloc<vapi_msg_l2tpv3_set_lookup_key>(Connection &con)
{
  vapi_msg_l2tpv3_set_lookup_key* result = vapi_alloc_l2tpv3_set_lookup_key(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_l2tpv3_set_lookup_key>;

template class Request<vapi_msg_l2tpv3_set_lookup_key, vapi_msg_l2tpv3_set_lookup_key_reply>;

using L2tpv3_set_lookup_key = Request<vapi_msg_l2tpv3_set_lookup_key, vapi_msg_l2tpv3_set_lookup_key_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_l2tpv3_set_lookup_key_reply>(vapi_msg_l2tpv3_set_lookup_key_reply *msg)
{
  vapi_msg_l2tpv3_set_lookup_key_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l2tpv3_set_lookup_key_reply>(vapi_msg_l2tpv3_set_lookup_key_reply *msg)
{
  vapi_msg_l2tpv3_set_lookup_key_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l2tpv3_set_lookup_key_reply>()
{
  return ::vapi_msg_id_l2tpv3_set_lookup_key_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l2tpv3_set_lookup_key_reply>>()
{
  return ::vapi_msg_id_l2tpv3_set_lookup_key_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l2tpv3_set_lookup_key_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l2tpv3_set_lookup_key_reply>(vapi_msg_id_l2tpv3_set_lookup_key_reply);
}

template class Msg<vapi_msg_l2tpv3_set_lookup_key_reply>;

using L2tpv3_set_lookup_key_reply = Msg<vapi_msg_l2tpv3_set_lookup_key_reply>;
}
#endif
