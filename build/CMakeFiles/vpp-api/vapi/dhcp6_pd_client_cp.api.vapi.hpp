#ifndef __included_hpp_dhcp6_pd_client_cp_api_json
#define __included_hpp_dhcp6_pd_client_cp_api_json

#include <vapi/vapi.hpp>
#include <vapi/dhcp6_pd_client_cp.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_dhcp6_pd_client_enable_disable>(vapi_msg_dhcp6_pd_client_enable_disable *msg)
{
  vapi_msg_dhcp6_pd_client_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dhcp6_pd_client_enable_disable>(vapi_msg_dhcp6_pd_client_enable_disable *msg)
{
  vapi_msg_dhcp6_pd_client_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dhcp6_pd_client_enable_disable>()
{
  return ::vapi_msg_id_dhcp6_pd_client_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dhcp6_pd_client_enable_disable>>()
{
  return ::vapi_msg_id_dhcp6_pd_client_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dhcp6_pd_client_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dhcp6_pd_client_enable_disable>(vapi_msg_id_dhcp6_pd_client_enable_disable);
}

template <> inline vapi_msg_dhcp6_pd_client_enable_disable* vapi_alloc<vapi_msg_dhcp6_pd_client_enable_disable>(Connection &con)
{
  vapi_msg_dhcp6_pd_client_enable_disable* result = vapi_alloc_dhcp6_pd_client_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_dhcp6_pd_client_enable_disable>;

template class Request<vapi_msg_dhcp6_pd_client_enable_disable, vapi_msg_dhcp6_pd_client_enable_disable_reply>;

using Dhcp6_pd_client_enable_disable = Request<vapi_msg_dhcp6_pd_client_enable_disable, vapi_msg_dhcp6_pd_client_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_dhcp6_pd_client_enable_disable_reply>(vapi_msg_dhcp6_pd_client_enable_disable_reply *msg)
{
  vapi_msg_dhcp6_pd_client_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dhcp6_pd_client_enable_disable_reply>(vapi_msg_dhcp6_pd_client_enable_disable_reply *msg)
{
  vapi_msg_dhcp6_pd_client_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dhcp6_pd_client_enable_disable_reply>()
{
  return ::vapi_msg_id_dhcp6_pd_client_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dhcp6_pd_client_enable_disable_reply>>()
{
  return ::vapi_msg_id_dhcp6_pd_client_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dhcp6_pd_client_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dhcp6_pd_client_enable_disable_reply>(vapi_msg_id_dhcp6_pd_client_enable_disable_reply);
}

template class Msg<vapi_msg_dhcp6_pd_client_enable_disable_reply>;

using Dhcp6_pd_client_enable_disable_reply = Msg<vapi_msg_dhcp6_pd_client_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ip6_add_del_address_using_prefix>(vapi_msg_ip6_add_del_address_using_prefix *msg)
{
  vapi_msg_ip6_add_del_address_using_prefix_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip6_add_del_address_using_prefix>(vapi_msg_ip6_add_del_address_using_prefix *msg)
{
  vapi_msg_ip6_add_del_address_using_prefix_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip6_add_del_address_using_prefix>()
{
  return ::vapi_msg_id_ip6_add_del_address_using_prefix; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip6_add_del_address_using_prefix>>()
{
  return ::vapi_msg_id_ip6_add_del_address_using_prefix; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip6_add_del_address_using_prefix()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip6_add_del_address_using_prefix>(vapi_msg_id_ip6_add_del_address_using_prefix);
}

template <> inline vapi_msg_ip6_add_del_address_using_prefix* vapi_alloc<vapi_msg_ip6_add_del_address_using_prefix>(Connection &con)
{
  vapi_msg_ip6_add_del_address_using_prefix* result = vapi_alloc_ip6_add_del_address_using_prefix(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip6_add_del_address_using_prefix>;

template class Request<vapi_msg_ip6_add_del_address_using_prefix, vapi_msg_ip6_add_del_address_using_prefix_reply>;

using Ip6_add_del_address_using_prefix = Request<vapi_msg_ip6_add_del_address_using_prefix, vapi_msg_ip6_add_del_address_using_prefix_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ip6_add_del_address_using_prefix_reply>(vapi_msg_ip6_add_del_address_using_prefix_reply *msg)
{
  vapi_msg_ip6_add_del_address_using_prefix_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip6_add_del_address_using_prefix_reply>(vapi_msg_ip6_add_del_address_using_prefix_reply *msg)
{
  vapi_msg_ip6_add_del_address_using_prefix_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip6_add_del_address_using_prefix_reply>()
{
  return ::vapi_msg_id_ip6_add_del_address_using_prefix_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip6_add_del_address_using_prefix_reply>>()
{
  return ::vapi_msg_id_ip6_add_del_address_using_prefix_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip6_add_del_address_using_prefix_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip6_add_del_address_using_prefix_reply>(vapi_msg_id_ip6_add_del_address_using_prefix_reply);
}

template class Msg<vapi_msg_ip6_add_del_address_using_prefix_reply>;

using Ip6_add_del_address_using_prefix_reply = Msg<vapi_msg_ip6_add_del_address_using_prefix_reply>;
}
#endif
