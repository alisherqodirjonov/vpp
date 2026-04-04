#ifndef __included_hpp_ip6_nd_api_json
#define __included_hpp_ip6_nd_api_json

#include <vapi/vapi.hpp>
#include <vapi/ip6_nd.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_ip6nd_ra_config>(vapi_msg_sw_interface_ip6nd_ra_config *msg)
{
  vapi_msg_sw_interface_ip6nd_ra_config_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_ip6nd_ra_config>(vapi_msg_sw_interface_ip6nd_ra_config *msg)
{
  vapi_msg_sw_interface_ip6nd_ra_config_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_ip6nd_ra_config>()
{
  return ::vapi_msg_id_sw_interface_ip6nd_ra_config; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_ip6nd_ra_config>>()
{
  return ::vapi_msg_id_sw_interface_ip6nd_ra_config; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_ip6nd_ra_config()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_ip6nd_ra_config>(vapi_msg_id_sw_interface_ip6nd_ra_config);
}

template <> inline vapi_msg_sw_interface_ip6nd_ra_config* vapi_alloc<vapi_msg_sw_interface_ip6nd_ra_config>(Connection &con)
{
  vapi_msg_sw_interface_ip6nd_ra_config* result = vapi_alloc_sw_interface_ip6nd_ra_config(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_ip6nd_ra_config>;

template class Request<vapi_msg_sw_interface_ip6nd_ra_config, vapi_msg_sw_interface_ip6nd_ra_config_reply>;

using Sw_interface_ip6nd_ra_config = Request<vapi_msg_sw_interface_ip6nd_ra_config, vapi_msg_sw_interface_ip6nd_ra_config_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_ip6nd_ra_config_reply>(vapi_msg_sw_interface_ip6nd_ra_config_reply *msg)
{
  vapi_msg_sw_interface_ip6nd_ra_config_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_ip6nd_ra_config_reply>(vapi_msg_sw_interface_ip6nd_ra_config_reply *msg)
{
  vapi_msg_sw_interface_ip6nd_ra_config_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_ip6nd_ra_config_reply>()
{
  return ::vapi_msg_id_sw_interface_ip6nd_ra_config_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_ip6nd_ra_config_reply>>()
{
  return ::vapi_msg_id_sw_interface_ip6nd_ra_config_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_ip6nd_ra_config_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_ip6nd_ra_config_reply>(vapi_msg_id_sw_interface_ip6nd_ra_config_reply);
}

template class Msg<vapi_msg_sw_interface_ip6nd_ra_config_reply>;

using Sw_interface_ip6nd_ra_config_reply = Msg<vapi_msg_sw_interface_ip6nd_ra_config_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_ip6nd_ra_prefix>(vapi_msg_sw_interface_ip6nd_ra_prefix *msg)
{
  vapi_msg_sw_interface_ip6nd_ra_prefix_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_ip6nd_ra_prefix>(vapi_msg_sw_interface_ip6nd_ra_prefix *msg)
{
  vapi_msg_sw_interface_ip6nd_ra_prefix_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_ip6nd_ra_prefix>()
{
  return ::vapi_msg_id_sw_interface_ip6nd_ra_prefix; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_ip6nd_ra_prefix>>()
{
  return ::vapi_msg_id_sw_interface_ip6nd_ra_prefix; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_ip6nd_ra_prefix()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_ip6nd_ra_prefix>(vapi_msg_id_sw_interface_ip6nd_ra_prefix);
}

template <> inline vapi_msg_sw_interface_ip6nd_ra_prefix* vapi_alloc<vapi_msg_sw_interface_ip6nd_ra_prefix>(Connection &con)
{
  vapi_msg_sw_interface_ip6nd_ra_prefix* result = vapi_alloc_sw_interface_ip6nd_ra_prefix(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_ip6nd_ra_prefix>;

template class Request<vapi_msg_sw_interface_ip6nd_ra_prefix, vapi_msg_sw_interface_ip6nd_ra_prefix_reply>;

using Sw_interface_ip6nd_ra_prefix = Request<vapi_msg_sw_interface_ip6nd_ra_prefix, vapi_msg_sw_interface_ip6nd_ra_prefix_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_ip6nd_ra_prefix_reply>(vapi_msg_sw_interface_ip6nd_ra_prefix_reply *msg)
{
  vapi_msg_sw_interface_ip6nd_ra_prefix_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_ip6nd_ra_prefix_reply>(vapi_msg_sw_interface_ip6nd_ra_prefix_reply *msg)
{
  vapi_msg_sw_interface_ip6nd_ra_prefix_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_ip6nd_ra_prefix_reply>()
{
  return ::vapi_msg_id_sw_interface_ip6nd_ra_prefix_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_ip6nd_ra_prefix_reply>>()
{
  return ::vapi_msg_id_sw_interface_ip6nd_ra_prefix_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_ip6nd_ra_prefix_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_ip6nd_ra_prefix_reply>(vapi_msg_id_sw_interface_ip6nd_ra_prefix_reply);
}

template class Msg<vapi_msg_sw_interface_ip6nd_ra_prefix_reply>;

using Sw_interface_ip6nd_ra_prefix_reply = Msg<vapi_msg_sw_interface_ip6nd_ra_prefix_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_ip6nd_ra_dump>(vapi_msg_sw_interface_ip6nd_ra_dump *msg)
{
  vapi_msg_sw_interface_ip6nd_ra_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_ip6nd_ra_dump>(vapi_msg_sw_interface_ip6nd_ra_dump *msg)
{
  vapi_msg_sw_interface_ip6nd_ra_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_ip6nd_ra_dump>()
{
  return ::vapi_msg_id_sw_interface_ip6nd_ra_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_ip6nd_ra_dump>>()
{
  return ::vapi_msg_id_sw_interface_ip6nd_ra_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_ip6nd_ra_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_ip6nd_ra_dump>(vapi_msg_id_sw_interface_ip6nd_ra_dump);
}

template <> inline vapi_msg_sw_interface_ip6nd_ra_dump* vapi_alloc<vapi_msg_sw_interface_ip6nd_ra_dump>(Connection &con)
{
  vapi_msg_sw_interface_ip6nd_ra_dump* result = vapi_alloc_sw_interface_ip6nd_ra_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_ip6nd_ra_dump>;

template class Dump<vapi_msg_sw_interface_ip6nd_ra_dump, vapi_msg_sw_interface_ip6nd_ra_details>;

using Sw_interface_ip6nd_ra_dump = Dump<vapi_msg_sw_interface_ip6nd_ra_dump, vapi_msg_sw_interface_ip6nd_ra_details>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_ip6nd_ra_details>(vapi_msg_sw_interface_ip6nd_ra_details *msg)
{
  vapi_msg_sw_interface_ip6nd_ra_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_ip6nd_ra_details>(vapi_msg_sw_interface_ip6nd_ra_details *msg)
{
  vapi_msg_sw_interface_ip6nd_ra_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_ip6nd_ra_details>()
{
  return ::vapi_msg_id_sw_interface_ip6nd_ra_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_ip6nd_ra_details>>()
{
  return ::vapi_msg_id_sw_interface_ip6nd_ra_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_ip6nd_ra_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_ip6nd_ra_details>(vapi_msg_id_sw_interface_ip6nd_ra_details);
}

template class Msg<vapi_msg_sw_interface_ip6nd_ra_details>;

using Sw_interface_ip6nd_ra_details = Msg<vapi_msg_sw_interface_ip6nd_ra_details>;
template <> inline void vapi_swap_to_be<vapi_msg_ip6nd_proxy_enable_disable>(vapi_msg_ip6nd_proxy_enable_disable *msg)
{
  vapi_msg_ip6nd_proxy_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip6nd_proxy_enable_disable>(vapi_msg_ip6nd_proxy_enable_disable *msg)
{
  vapi_msg_ip6nd_proxy_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip6nd_proxy_enable_disable>()
{
  return ::vapi_msg_id_ip6nd_proxy_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip6nd_proxy_enable_disable>>()
{
  return ::vapi_msg_id_ip6nd_proxy_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip6nd_proxy_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip6nd_proxy_enable_disable>(vapi_msg_id_ip6nd_proxy_enable_disable);
}

template <> inline vapi_msg_ip6nd_proxy_enable_disable* vapi_alloc<vapi_msg_ip6nd_proxy_enable_disable>(Connection &con)
{
  vapi_msg_ip6nd_proxy_enable_disable* result = vapi_alloc_ip6nd_proxy_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip6nd_proxy_enable_disable>;

template class Request<vapi_msg_ip6nd_proxy_enable_disable, vapi_msg_ip6nd_proxy_enable_disable_reply>;

using Ip6nd_proxy_enable_disable = Request<vapi_msg_ip6nd_proxy_enable_disable, vapi_msg_ip6nd_proxy_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ip6nd_proxy_enable_disable_reply>(vapi_msg_ip6nd_proxy_enable_disable_reply *msg)
{
  vapi_msg_ip6nd_proxy_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip6nd_proxy_enable_disable_reply>(vapi_msg_ip6nd_proxy_enable_disable_reply *msg)
{
  vapi_msg_ip6nd_proxy_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip6nd_proxy_enable_disable_reply>()
{
  return ::vapi_msg_id_ip6nd_proxy_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip6nd_proxy_enable_disable_reply>>()
{
  return ::vapi_msg_id_ip6nd_proxy_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip6nd_proxy_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip6nd_proxy_enable_disable_reply>(vapi_msg_id_ip6nd_proxy_enable_disable_reply);
}

template class Msg<vapi_msg_ip6nd_proxy_enable_disable_reply>;

using Ip6nd_proxy_enable_disable_reply = Msg<vapi_msg_ip6nd_proxy_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ip6nd_proxy_add_del>(vapi_msg_ip6nd_proxy_add_del *msg)
{
  vapi_msg_ip6nd_proxy_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip6nd_proxy_add_del>(vapi_msg_ip6nd_proxy_add_del *msg)
{
  vapi_msg_ip6nd_proxy_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip6nd_proxy_add_del>()
{
  return ::vapi_msg_id_ip6nd_proxy_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip6nd_proxy_add_del>>()
{
  return ::vapi_msg_id_ip6nd_proxy_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip6nd_proxy_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip6nd_proxy_add_del>(vapi_msg_id_ip6nd_proxy_add_del);
}

template <> inline vapi_msg_ip6nd_proxy_add_del* vapi_alloc<vapi_msg_ip6nd_proxy_add_del>(Connection &con)
{
  vapi_msg_ip6nd_proxy_add_del* result = vapi_alloc_ip6nd_proxy_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip6nd_proxy_add_del>;

template class Request<vapi_msg_ip6nd_proxy_add_del, vapi_msg_ip6nd_proxy_add_del_reply>;

using Ip6nd_proxy_add_del = Request<vapi_msg_ip6nd_proxy_add_del, vapi_msg_ip6nd_proxy_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ip6nd_proxy_add_del_reply>(vapi_msg_ip6nd_proxy_add_del_reply *msg)
{
  vapi_msg_ip6nd_proxy_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip6nd_proxy_add_del_reply>(vapi_msg_ip6nd_proxy_add_del_reply *msg)
{
  vapi_msg_ip6nd_proxy_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip6nd_proxy_add_del_reply>()
{
  return ::vapi_msg_id_ip6nd_proxy_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip6nd_proxy_add_del_reply>>()
{
  return ::vapi_msg_id_ip6nd_proxy_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip6nd_proxy_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip6nd_proxy_add_del_reply>(vapi_msg_id_ip6nd_proxy_add_del_reply);
}

template class Msg<vapi_msg_ip6nd_proxy_add_del_reply>;

using Ip6nd_proxy_add_del_reply = Msg<vapi_msg_ip6nd_proxy_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ip6nd_proxy_details>(vapi_msg_ip6nd_proxy_details *msg)
{
  vapi_msg_ip6nd_proxy_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip6nd_proxy_details>(vapi_msg_ip6nd_proxy_details *msg)
{
  vapi_msg_ip6nd_proxy_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip6nd_proxy_details>()
{
  return ::vapi_msg_id_ip6nd_proxy_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip6nd_proxy_details>>()
{
  return ::vapi_msg_id_ip6nd_proxy_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip6nd_proxy_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip6nd_proxy_details>(vapi_msg_id_ip6nd_proxy_details);
}

template class Msg<vapi_msg_ip6nd_proxy_details>;

using Ip6nd_proxy_details = Msg<vapi_msg_ip6nd_proxy_details>;
template <> inline void vapi_swap_to_be<vapi_msg_ip6nd_proxy_dump>(vapi_msg_ip6nd_proxy_dump *msg)
{
  vapi_msg_ip6nd_proxy_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip6nd_proxy_dump>(vapi_msg_ip6nd_proxy_dump *msg)
{
  vapi_msg_ip6nd_proxy_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip6nd_proxy_dump>()
{
  return ::vapi_msg_id_ip6nd_proxy_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip6nd_proxy_dump>>()
{
  return ::vapi_msg_id_ip6nd_proxy_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip6nd_proxy_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip6nd_proxy_dump>(vapi_msg_id_ip6nd_proxy_dump);
}

template <> inline vapi_msg_ip6nd_proxy_dump* vapi_alloc<vapi_msg_ip6nd_proxy_dump>(Connection &con)
{
  vapi_msg_ip6nd_proxy_dump* result = vapi_alloc_ip6nd_proxy_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip6nd_proxy_dump>;

template class Dump<vapi_msg_ip6nd_proxy_dump, vapi_msg_ip6nd_proxy_details>;

using Ip6nd_proxy_dump = Dump<vapi_msg_ip6nd_proxy_dump, vapi_msg_ip6nd_proxy_details>;

template <> inline void vapi_swap_to_be<vapi_msg_ip6nd_send_router_solicitation>(vapi_msg_ip6nd_send_router_solicitation *msg)
{
  vapi_msg_ip6nd_send_router_solicitation_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip6nd_send_router_solicitation>(vapi_msg_ip6nd_send_router_solicitation *msg)
{
  vapi_msg_ip6nd_send_router_solicitation_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip6nd_send_router_solicitation>()
{
  return ::vapi_msg_id_ip6nd_send_router_solicitation; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip6nd_send_router_solicitation>>()
{
  return ::vapi_msg_id_ip6nd_send_router_solicitation; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip6nd_send_router_solicitation()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip6nd_send_router_solicitation>(vapi_msg_id_ip6nd_send_router_solicitation);
}

template <> inline vapi_msg_ip6nd_send_router_solicitation* vapi_alloc<vapi_msg_ip6nd_send_router_solicitation>(Connection &con)
{
  vapi_msg_ip6nd_send_router_solicitation* result = vapi_alloc_ip6nd_send_router_solicitation(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip6nd_send_router_solicitation>;

template class Request<vapi_msg_ip6nd_send_router_solicitation, vapi_msg_ip6nd_send_router_solicitation_reply>;

using Ip6nd_send_router_solicitation = Request<vapi_msg_ip6nd_send_router_solicitation, vapi_msg_ip6nd_send_router_solicitation_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ip6nd_send_router_solicitation_reply>(vapi_msg_ip6nd_send_router_solicitation_reply *msg)
{
  vapi_msg_ip6nd_send_router_solicitation_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip6nd_send_router_solicitation_reply>(vapi_msg_ip6nd_send_router_solicitation_reply *msg)
{
  vapi_msg_ip6nd_send_router_solicitation_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip6nd_send_router_solicitation_reply>()
{
  return ::vapi_msg_id_ip6nd_send_router_solicitation_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip6nd_send_router_solicitation_reply>>()
{
  return ::vapi_msg_id_ip6nd_send_router_solicitation_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip6nd_send_router_solicitation_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip6nd_send_router_solicitation_reply>(vapi_msg_id_ip6nd_send_router_solicitation_reply);
}

template class Msg<vapi_msg_ip6nd_send_router_solicitation_reply>;

using Ip6nd_send_router_solicitation_reply = Msg<vapi_msg_ip6nd_send_router_solicitation_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_want_ip6_ra_events>(vapi_msg_want_ip6_ra_events *msg)
{
  vapi_msg_want_ip6_ra_events_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_want_ip6_ra_events>(vapi_msg_want_ip6_ra_events *msg)
{
  vapi_msg_want_ip6_ra_events_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_want_ip6_ra_events>()
{
  return ::vapi_msg_id_want_ip6_ra_events; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_want_ip6_ra_events>>()
{
  return ::vapi_msg_id_want_ip6_ra_events; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_want_ip6_ra_events()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_want_ip6_ra_events>(vapi_msg_id_want_ip6_ra_events);
}

template <> inline vapi_msg_want_ip6_ra_events* vapi_alloc<vapi_msg_want_ip6_ra_events>(Connection &con)
{
  vapi_msg_want_ip6_ra_events* result = vapi_alloc_want_ip6_ra_events(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_want_ip6_ra_events>;

template class Request<vapi_msg_want_ip6_ra_events, vapi_msg_want_ip6_ra_events_reply>;

using Want_ip6_ra_events = Request<vapi_msg_want_ip6_ra_events, vapi_msg_want_ip6_ra_events_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_want_ip6_ra_events_reply>(vapi_msg_want_ip6_ra_events_reply *msg)
{
  vapi_msg_want_ip6_ra_events_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_want_ip6_ra_events_reply>(vapi_msg_want_ip6_ra_events_reply *msg)
{
  vapi_msg_want_ip6_ra_events_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_want_ip6_ra_events_reply>()
{
  return ::vapi_msg_id_want_ip6_ra_events_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_want_ip6_ra_events_reply>>()
{
  return ::vapi_msg_id_want_ip6_ra_events_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_want_ip6_ra_events_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_want_ip6_ra_events_reply>(vapi_msg_id_want_ip6_ra_events_reply);
}

template class Msg<vapi_msg_want_ip6_ra_events_reply>;

using Want_ip6_ra_events_reply = Msg<vapi_msg_want_ip6_ra_events_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ip6_ra_event>(vapi_msg_ip6_ra_event *msg)
{
  vapi_msg_ip6_ra_event_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip6_ra_event>(vapi_msg_ip6_ra_event *msg)
{
  vapi_msg_ip6_ra_event_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip6_ra_event>()
{
  return ::vapi_msg_id_ip6_ra_event; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip6_ra_event>>()
{
  return ::vapi_msg_id_ip6_ra_event; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip6_ra_event()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip6_ra_event>(vapi_msg_id_ip6_ra_event);
}

template class Msg<vapi_msg_ip6_ra_event>;

using Ip6_ra_event = Msg<vapi_msg_ip6_ra_event>;
}
#endif
