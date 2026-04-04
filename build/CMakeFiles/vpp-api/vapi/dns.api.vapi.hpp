#ifndef __included_hpp_dns_api_json
#define __included_hpp_dns_api_json

#include <vapi/vapi.hpp>
#include <vapi/dns.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_dns_enable_disable>(vapi_msg_dns_enable_disable *msg)
{
  vapi_msg_dns_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dns_enable_disable>(vapi_msg_dns_enable_disable *msg)
{
  vapi_msg_dns_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dns_enable_disable>()
{
  return ::vapi_msg_id_dns_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dns_enable_disable>>()
{
  return ::vapi_msg_id_dns_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dns_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dns_enable_disable>(vapi_msg_id_dns_enable_disable);
}

template <> inline vapi_msg_dns_enable_disable* vapi_alloc<vapi_msg_dns_enable_disable>(Connection &con)
{
  vapi_msg_dns_enable_disable* result = vapi_alloc_dns_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_dns_enable_disable>;

template class Request<vapi_msg_dns_enable_disable, vapi_msg_dns_enable_disable_reply>;

using Dns_enable_disable = Request<vapi_msg_dns_enable_disable, vapi_msg_dns_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_dns_enable_disable_reply>(vapi_msg_dns_enable_disable_reply *msg)
{
  vapi_msg_dns_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dns_enable_disable_reply>(vapi_msg_dns_enable_disable_reply *msg)
{
  vapi_msg_dns_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dns_enable_disable_reply>()
{
  return ::vapi_msg_id_dns_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dns_enable_disable_reply>>()
{
  return ::vapi_msg_id_dns_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dns_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dns_enable_disable_reply>(vapi_msg_id_dns_enable_disable_reply);
}

template class Msg<vapi_msg_dns_enable_disable_reply>;

using Dns_enable_disable_reply = Msg<vapi_msg_dns_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_dns_name_server_add_del>(vapi_msg_dns_name_server_add_del *msg)
{
  vapi_msg_dns_name_server_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dns_name_server_add_del>(vapi_msg_dns_name_server_add_del *msg)
{
  vapi_msg_dns_name_server_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dns_name_server_add_del>()
{
  return ::vapi_msg_id_dns_name_server_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dns_name_server_add_del>>()
{
  return ::vapi_msg_id_dns_name_server_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dns_name_server_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dns_name_server_add_del>(vapi_msg_id_dns_name_server_add_del);
}

template <> inline vapi_msg_dns_name_server_add_del* vapi_alloc<vapi_msg_dns_name_server_add_del>(Connection &con)
{
  vapi_msg_dns_name_server_add_del* result = vapi_alloc_dns_name_server_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_dns_name_server_add_del>;

template class Request<vapi_msg_dns_name_server_add_del, vapi_msg_dns_name_server_add_del_reply>;

using Dns_name_server_add_del = Request<vapi_msg_dns_name_server_add_del, vapi_msg_dns_name_server_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_dns_name_server_add_del_reply>(vapi_msg_dns_name_server_add_del_reply *msg)
{
  vapi_msg_dns_name_server_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dns_name_server_add_del_reply>(vapi_msg_dns_name_server_add_del_reply *msg)
{
  vapi_msg_dns_name_server_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dns_name_server_add_del_reply>()
{
  return ::vapi_msg_id_dns_name_server_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dns_name_server_add_del_reply>>()
{
  return ::vapi_msg_id_dns_name_server_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dns_name_server_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dns_name_server_add_del_reply>(vapi_msg_id_dns_name_server_add_del_reply);
}

template class Msg<vapi_msg_dns_name_server_add_del_reply>;

using Dns_name_server_add_del_reply = Msg<vapi_msg_dns_name_server_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_dns_resolve_name>(vapi_msg_dns_resolve_name *msg)
{
  vapi_msg_dns_resolve_name_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dns_resolve_name>(vapi_msg_dns_resolve_name *msg)
{
  vapi_msg_dns_resolve_name_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dns_resolve_name>()
{
  return ::vapi_msg_id_dns_resolve_name; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dns_resolve_name>>()
{
  return ::vapi_msg_id_dns_resolve_name; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dns_resolve_name()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dns_resolve_name>(vapi_msg_id_dns_resolve_name);
}

template <> inline vapi_msg_dns_resolve_name* vapi_alloc<vapi_msg_dns_resolve_name>(Connection &con)
{
  vapi_msg_dns_resolve_name* result = vapi_alloc_dns_resolve_name(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_dns_resolve_name>;

template class Request<vapi_msg_dns_resolve_name, vapi_msg_dns_resolve_name_reply>;

using Dns_resolve_name = Request<vapi_msg_dns_resolve_name, vapi_msg_dns_resolve_name_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_dns_resolve_name_reply>(vapi_msg_dns_resolve_name_reply *msg)
{
  vapi_msg_dns_resolve_name_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dns_resolve_name_reply>(vapi_msg_dns_resolve_name_reply *msg)
{
  vapi_msg_dns_resolve_name_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dns_resolve_name_reply>()
{
  return ::vapi_msg_id_dns_resolve_name_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dns_resolve_name_reply>>()
{
  return ::vapi_msg_id_dns_resolve_name_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dns_resolve_name_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dns_resolve_name_reply>(vapi_msg_id_dns_resolve_name_reply);
}

template class Msg<vapi_msg_dns_resolve_name_reply>;

using Dns_resolve_name_reply = Msg<vapi_msg_dns_resolve_name_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_dns_resolve_ip>(vapi_msg_dns_resolve_ip *msg)
{
  vapi_msg_dns_resolve_ip_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dns_resolve_ip>(vapi_msg_dns_resolve_ip *msg)
{
  vapi_msg_dns_resolve_ip_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dns_resolve_ip>()
{
  return ::vapi_msg_id_dns_resolve_ip; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dns_resolve_ip>>()
{
  return ::vapi_msg_id_dns_resolve_ip; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dns_resolve_ip()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dns_resolve_ip>(vapi_msg_id_dns_resolve_ip);
}

template <> inline vapi_msg_dns_resolve_ip* vapi_alloc<vapi_msg_dns_resolve_ip>(Connection &con)
{
  vapi_msg_dns_resolve_ip* result = vapi_alloc_dns_resolve_ip(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_dns_resolve_ip>;

template class Request<vapi_msg_dns_resolve_ip, vapi_msg_dns_resolve_ip_reply>;

using Dns_resolve_ip = Request<vapi_msg_dns_resolve_ip, vapi_msg_dns_resolve_ip_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_dns_resolve_ip_reply>(vapi_msg_dns_resolve_ip_reply *msg)
{
  vapi_msg_dns_resolve_ip_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dns_resolve_ip_reply>(vapi_msg_dns_resolve_ip_reply *msg)
{
  vapi_msg_dns_resolve_ip_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dns_resolve_ip_reply>()
{
  return ::vapi_msg_id_dns_resolve_ip_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dns_resolve_ip_reply>>()
{
  return ::vapi_msg_id_dns_resolve_ip_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dns_resolve_ip_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dns_resolve_ip_reply>(vapi_msg_id_dns_resolve_ip_reply);
}

template class Msg<vapi_msg_dns_resolve_ip_reply>;

using Dns_resolve_ip_reply = Msg<vapi_msg_dns_resolve_ip_reply>;
}
#endif
