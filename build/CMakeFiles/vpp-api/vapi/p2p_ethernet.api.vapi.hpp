#ifndef __included_hpp_p2p_ethernet_api_json
#define __included_hpp_p2p_ethernet_api_json

#include <vapi/vapi.hpp>
#include <vapi/p2p_ethernet.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_p2p_ethernet_add>(vapi_msg_p2p_ethernet_add *msg)
{
  vapi_msg_p2p_ethernet_add_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_p2p_ethernet_add>(vapi_msg_p2p_ethernet_add *msg)
{
  vapi_msg_p2p_ethernet_add_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_p2p_ethernet_add>()
{
  return ::vapi_msg_id_p2p_ethernet_add; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_p2p_ethernet_add>>()
{
  return ::vapi_msg_id_p2p_ethernet_add; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_p2p_ethernet_add()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_p2p_ethernet_add>(vapi_msg_id_p2p_ethernet_add);
}

template <> inline vapi_msg_p2p_ethernet_add* vapi_alloc<vapi_msg_p2p_ethernet_add>(Connection &con)
{
  vapi_msg_p2p_ethernet_add* result = vapi_alloc_p2p_ethernet_add(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_p2p_ethernet_add>;

template class Request<vapi_msg_p2p_ethernet_add, vapi_msg_p2p_ethernet_add_reply>;

using P2p_ethernet_add = Request<vapi_msg_p2p_ethernet_add, vapi_msg_p2p_ethernet_add_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_p2p_ethernet_add_reply>(vapi_msg_p2p_ethernet_add_reply *msg)
{
  vapi_msg_p2p_ethernet_add_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_p2p_ethernet_add_reply>(vapi_msg_p2p_ethernet_add_reply *msg)
{
  vapi_msg_p2p_ethernet_add_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_p2p_ethernet_add_reply>()
{
  return ::vapi_msg_id_p2p_ethernet_add_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_p2p_ethernet_add_reply>>()
{
  return ::vapi_msg_id_p2p_ethernet_add_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_p2p_ethernet_add_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_p2p_ethernet_add_reply>(vapi_msg_id_p2p_ethernet_add_reply);
}

template class Msg<vapi_msg_p2p_ethernet_add_reply>;

using P2p_ethernet_add_reply = Msg<vapi_msg_p2p_ethernet_add_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_p2p_ethernet_del>(vapi_msg_p2p_ethernet_del *msg)
{
  vapi_msg_p2p_ethernet_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_p2p_ethernet_del>(vapi_msg_p2p_ethernet_del *msg)
{
  vapi_msg_p2p_ethernet_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_p2p_ethernet_del>()
{
  return ::vapi_msg_id_p2p_ethernet_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_p2p_ethernet_del>>()
{
  return ::vapi_msg_id_p2p_ethernet_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_p2p_ethernet_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_p2p_ethernet_del>(vapi_msg_id_p2p_ethernet_del);
}

template <> inline vapi_msg_p2p_ethernet_del* vapi_alloc<vapi_msg_p2p_ethernet_del>(Connection &con)
{
  vapi_msg_p2p_ethernet_del* result = vapi_alloc_p2p_ethernet_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_p2p_ethernet_del>;

template class Request<vapi_msg_p2p_ethernet_del, vapi_msg_p2p_ethernet_del_reply>;

using P2p_ethernet_del = Request<vapi_msg_p2p_ethernet_del, vapi_msg_p2p_ethernet_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_p2p_ethernet_del_reply>(vapi_msg_p2p_ethernet_del_reply *msg)
{
  vapi_msg_p2p_ethernet_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_p2p_ethernet_del_reply>(vapi_msg_p2p_ethernet_del_reply *msg)
{
  vapi_msg_p2p_ethernet_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_p2p_ethernet_del_reply>()
{
  return ::vapi_msg_id_p2p_ethernet_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_p2p_ethernet_del_reply>>()
{
  return ::vapi_msg_id_p2p_ethernet_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_p2p_ethernet_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_p2p_ethernet_del_reply>(vapi_msg_id_p2p_ethernet_del_reply);
}

template class Msg<vapi_msg_p2p_ethernet_del_reply>;

using P2p_ethernet_del_reply = Msg<vapi_msg_p2p_ethernet_del_reply>;
}
#endif
