#ifndef __included_hpp_tcp_api_json
#define __included_hpp_tcp_api_json

#include <vapi/vapi.hpp>
#include <vapi/tcp.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_tcp_configure_src_addresses>(vapi_msg_tcp_configure_src_addresses *msg)
{
  vapi_msg_tcp_configure_src_addresses_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_tcp_configure_src_addresses>(vapi_msg_tcp_configure_src_addresses *msg)
{
  vapi_msg_tcp_configure_src_addresses_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_tcp_configure_src_addresses>()
{
  return ::vapi_msg_id_tcp_configure_src_addresses; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_tcp_configure_src_addresses>>()
{
  return ::vapi_msg_id_tcp_configure_src_addresses; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_tcp_configure_src_addresses()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_tcp_configure_src_addresses>(vapi_msg_id_tcp_configure_src_addresses);
}

template <> inline vapi_msg_tcp_configure_src_addresses* vapi_alloc<vapi_msg_tcp_configure_src_addresses>(Connection &con)
{
  vapi_msg_tcp_configure_src_addresses* result = vapi_alloc_tcp_configure_src_addresses(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_tcp_configure_src_addresses>;

template class Request<vapi_msg_tcp_configure_src_addresses, vapi_msg_tcp_configure_src_addresses_reply>;

using Tcp_configure_src_addresses = Request<vapi_msg_tcp_configure_src_addresses, vapi_msg_tcp_configure_src_addresses_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_tcp_configure_src_addresses_reply>(vapi_msg_tcp_configure_src_addresses_reply *msg)
{
  vapi_msg_tcp_configure_src_addresses_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_tcp_configure_src_addresses_reply>(vapi_msg_tcp_configure_src_addresses_reply *msg)
{
  vapi_msg_tcp_configure_src_addresses_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_tcp_configure_src_addresses_reply>()
{
  return ::vapi_msg_id_tcp_configure_src_addresses_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_tcp_configure_src_addresses_reply>>()
{
  return ::vapi_msg_id_tcp_configure_src_addresses_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_tcp_configure_src_addresses_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_tcp_configure_src_addresses_reply>(vapi_msg_id_tcp_configure_src_addresses_reply);
}

template class Msg<vapi_msg_tcp_configure_src_addresses_reply>;

using Tcp_configure_src_addresses_reply = Msg<vapi_msg_tcp_configure_src_addresses_reply>;
}
#endif
