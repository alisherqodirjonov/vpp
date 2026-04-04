#ifndef __included_hpp_rd_cp_api_json
#define __included_hpp_rd_cp_api_json

#include <vapi/vapi.hpp>
#include <vapi/rd_cp.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_ip6_nd_address_autoconfig>(vapi_msg_ip6_nd_address_autoconfig *msg)
{
  vapi_msg_ip6_nd_address_autoconfig_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip6_nd_address_autoconfig>(vapi_msg_ip6_nd_address_autoconfig *msg)
{
  vapi_msg_ip6_nd_address_autoconfig_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip6_nd_address_autoconfig>()
{
  return ::vapi_msg_id_ip6_nd_address_autoconfig; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip6_nd_address_autoconfig>>()
{
  return ::vapi_msg_id_ip6_nd_address_autoconfig; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip6_nd_address_autoconfig()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip6_nd_address_autoconfig>(vapi_msg_id_ip6_nd_address_autoconfig);
}

template <> inline vapi_msg_ip6_nd_address_autoconfig* vapi_alloc<vapi_msg_ip6_nd_address_autoconfig>(Connection &con)
{
  vapi_msg_ip6_nd_address_autoconfig* result = vapi_alloc_ip6_nd_address_autoconfig(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip6_nd_address_autoconfig>;

template class Request<vapi_msg_ip6_nd_address_autoconfig, vapi_msg_ip6_nd_address_autoconfig_reply>;

using Ip6_nd_address_autoconfig = Request<vapi_msg_ip6_nd_address_autoconfig, vapi_msg_ip6_nd_address_autoconfig_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ip6_nd_address_autoconfig_reply>(vapi_msg_ip6_nd_address_autoconfig_reply *msg)
{
  vapi_msg_ip6_nd_address_autoconfig_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip6_nd_address_autoconfig_reply>(vapi_msg_ip6_nd_address_autoconfig_reply *msg)
{
  vapi_msg_ip6_nd_address_autoconfig_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip6_nd_address_autoconfig_reply>()
{
  return ::vapi_msg_id_ip6_nd_address_autoconfig_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip6_nd_address_autoconfig_reply>>()
{
  return ::vapi_msg_id_ip6_nd_address_autoconfig_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip6_nd_address_autoconfig_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip6_nd_address_autoconfig_reply>(vapi_msg_id_ip6_nd_address_autoconfig_reply);
}

template class Msg<vapi_msg_ip6_nd_address_autoconfig_reply>;

using Ip6_nd_address_autoconfig_reply = Msg<vapi_msg_ip6_nd_address_autoconfig_reply>;
}
#endif
