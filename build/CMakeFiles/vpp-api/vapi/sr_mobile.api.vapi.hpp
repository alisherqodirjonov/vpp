#ifndef __included_hpp_sr_mobile_api_json
#define __included_hpp_sr_mobile_api_json

#include <vapi/vapi.hpp>
#include <vapi/sr_mobile.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_sr_mobile_localsid_add_del>(vapi_msg_sr_mobile_localsid_add_del *msg)
{
  vapi_msg_sr_mobile_localsid_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_mobile_localsid_add_del>(vapi_msg_sr_mobile_localsid_add_del *msg)
{
  vapi_msg_sr_mobile_localsid_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_mobile_localsid_add_del>()
{
  return ::vapi_msg_id_sr_mobile_localsid_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_mobile_localsid_add_del>>()
{
  return ::vapi_msg_id_sr_mobile_localsid_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_mobile_localsid_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_mobile_localsid_add_del>(vapi_msg_id_sr_mobile_localsid_add_del);
}

template <> inline vapi_msg_sr_mobile_localsid_add_del* vapi_alloc<vapi_msg_sr_mobile_localsid_add_del>(Connection &con)
{
  vapi_msg_sr_mobile_localsid_add_del* result = vapi_alloc_sr_mobile_localsid_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sr_mobile_localsid_add_del>;

template class Request<vapi_msg_sr_mobile_localsid_add_del, vapi_msg_sr_mobile_localsid_add_del_reply>;

using Sr_mobile_localsid_add_del = Request<vapi_msg_sr_mobile_localsid_add_del, vapi_msg_sr_mobile_localsid_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sr_mobile_localsid_add_del_reply>(vapi_msg_sr_mobile_localsid_add_del_reply *msg)
{
  vapi_msg_sr_mobile_localsid_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_mobile_localsid_add_del_reply>(vapi_msg_sr_mobile_localsid_add_del_reply *msg)
{
  vapi_msg_sr_mobile_localsid_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_mobile_localsid_add_del_reply>()
{
  return ::vapi_msg_id_sr_mobile_localsid_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_mobile_localsid_add_del_reply>>()
{
  return ::vapi_msg_id_sr_mobile_localsid_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_mobile_localsid_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_mobile_localsid_add_del_reply>(vapi_msg_id_sr_mobile_localsid_add_del_reply);
}

template class Msg<vapi_msg_sr_mobile_localsid_add_del_reply>;

using Sr_mobile_localsid_add_del_reply = Msg<vapi_msg_sr_mobile_localsid_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sr_mobile_policy_add>(vapi_msg_sr_mobile_policy_add *msg)
{
  vapi_msg_sr_mobile_policy_add_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_mobile_policy_add>(vapi_msg_sr_mobile_policy_add *msg)
{
  vapi_msg_sr_mobile_policy_add_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_mobile_policy_add>()
{
  return ::vapi_msg_id_sr_mobile_policy_add; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_mobile_policy_add>>()
{
  return ::vapi_msg_id_sr_mobile_policy_add; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_mobile_policy_add()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_mobile_policy_add>(vapi_msg_id_sr_mobile_policy_add);
}

template <> inline vapi_msg_sr_mobile_policy_add* vapi_alloc<vapi_msg_sr_mobile_policy_add>(Connection &con)
{
  vapi_msg_sr_mobile_policy_add* result = vapi_alloc_sr_mobile_policy_add(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sr_mobile_policy_add>;

template class Request<vapi_msg_sr_mobile_policy_add, vapi_msg_sr_mobile_policy_add_reply>;

using Sr_mobile_policy_add = Request<vapi_msg_sr_mobile_policy_add, vapi_msg_sr_mobile_policy_add_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sr_mobile_policy_add_reply>(vapi_msg_sr_mobile_policy_add_reply *msg)
{
  vapi_msg_sr_mobile_policy_add_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_mobile_policy_add_reply>(vapi_msg_sr_mobile_policy_add_reply *msg)
{
  vapi_msg_sr_mobile_policy_add_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_mobile_policy_add_reply>()
{
  return ::vapi_msg_id_sr_mobile_policy_add_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_mobile_policy_add_reply>>()
{
  return ::vapi_msg_id_sr_mobile_policy_add_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_mobile_policy_add_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_mobile_policy_add_reply>(vapi_msg_id_sr_mobile_policy_add_reply);
}

template class Msg<vapi_msg_sr_mobile_policy_add_reply>;

using Sr_mobile_policy_add_reply = Msg<vapi_msg_sr_mobile_policy_add_reply>;
}
#endif
