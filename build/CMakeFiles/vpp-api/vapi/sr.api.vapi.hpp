#ifndef __included_hpp_sr_api_json
#define __included_hpp_sr_api_json

#include <vapi/vapi.hpp>
#include <vapi/sr.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_sr_localsid_add_del>(vapi_msg_sr_localsid_add_del *msg)
{
  vapi_msg_sr_localsid_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_localsid_add_del>(vapi_msg_sr_localsid_add_del *msg)
{
  vapi_msg_sr_localsid_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_localsid_add_del>()
{
  return ::vapi_msg_id_sr_localsid_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_localsid_add_del>>()
{
  return ::vapi_msg_id_sr_localsid_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_localsid_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_localsid_add_del>(vapi_msg_id_sr_localsid_add_del);
}

template <> inline vapi_msg_sr_localsid_add_del* vapi_alloc<vapi_msg_sr_localsid_add_del>(Connection &con)
{
  vapi_msg_sr_localsid_add_del* result = vapi_alloc_sr_localsid_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sr_localsid_add_del>;

template class Request<vapi_msg_sr_localsid_add_del, vapi_msg_sr_localsid_add_del_reply>;

using Sr_localsid_add_del = Request<vapi_msg_sr_localsid_add_del, vapi_msg_sr_localsid_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sr_localsid_add_del_reply>(vapi_msg_sr_localsid_add_del_reply *msg)
{
  vapi_msg_sr_localsid_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_localsid_add_del_reply>(vapi_msg_sr_localsid_add_del_reply *msg)
{
  vapi_msg_sr_localsid_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_localsid_add_del_reply>()
{
  return ::vapi_msg_id_sr_localsid_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_localsid_add_del_reply>>()
{
  return ::vapi_msg_id_sr_localsid_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_localsid_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_localsid_add_del_reply>(vapi_msg_id_sr_localsid_add_del_reply);
}

template class Msg<vapi_msg_sr_localsid_add_del_reply>;

using Sr_localsid_add_del_reply = Msg<vapi_msg_sr_localsid_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sr_policy_add>(vapi_msg_sr_policy_add *msg)
{
  vapi_msg_sr_policy_add_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_policy_add>(vapi_msg_sr_policy_add *msg)
{
  vapi_msg_sr_policy_add_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_policy_add>()
{
  return ::vapi_msg_id_sr_policy_add; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_policy_add>>()
{
  return ::vapi_msg_id_sr_policy_add; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_policy_add()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_policy_add>(vapi_msg_id_sr_policy_add);
}

template <> inline vapi_msg_sr_policy_add* vapi_alloc<vapi_msg_sr_policy_add>(Connection &con)
{
  vapi_msg_sr_policy_add* result = vapi_alloc_sr_policy_add(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sr_policy_add>;

template class Request<vapi_msg_sr_policy_add, vapi_msg_sr_policy_add_reply>;

using Sr_policy_add = Request<vapi_msg_sr_policy_add, vapi_msg_sr_policy_add_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sr_policy_add_reply>(vapi_msg_sr_policy_add_reply *msg)
{
  vapi_msg_sr_policy_add_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_policy_add_reply>(vapi_msg_sr_policy_add_reply *msg)
{
  vapi_msg_sr_policy_add_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_policy_add_reply>()
{
  return ::vapi_msg_id_sr_policy_add_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_policy_add_reply>>()
{
  return ::vapi_msg_id_sr_policy_add_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_policy_add_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_policy_add_reply>(vapi_msg_id_sr_policy_add_reply);
}

template class Msg<vapi_msg_sr_policy_add_reply>;

using Sr_policy_add_reply = Msg<vapi_msg_sr_policy_add_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sr_policy_mod>(vapi_msg_sr_policy_mod *msg)
{
  vapi_msg_sr_policy_mod_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_policy_mod>(vapi_msg_sr_policy_mod *msg)
{
  vapi_msg_sr_policy_mod_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_policy_mod>()
{
  return ::vapi_msg_id_sr_policy_mod; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_policy_mod>>()
{
  return ::vapi_msg_id_sr_policy_mod; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_policy_mod()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_policy_mod>(vapi_msg_id_sr_policy_mod);
}

template <> inline vapi_msg_sr_policy_mod* vapi_alloc<vapi_msg_sr_policy_mod>(Connection &con)
{
  vapi_msg_sr_policy_mod* result = vapi_alloc_sr_policy_mod(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sr_policy_mod>;

template class Request<vapi_msg_sr_policy_mod, vapi_msg_sr_policy_mod_reply>;

using Sr_policy_mod = Request<vapi_msg_sr_policy_mod, vapi_msg_sr_policy_mod_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sr_policy_mod_reply>(vapi_msg_sr_policy_mod_reply *msg)
{
  vapi_msg_sr_policy_mod_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_policy_mod_reply>(vapi_msg_sr_policy_mod_reply *msg)
{
  vapi_msg_sr_policy_mod_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_policy_mod_reply>()
{
  return ::vapi_msg_id_sr_policy_mod_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_policy_mod_reply>>()
{
  return ::vapi_msg_id_sr_policy_mod_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_policy_mod_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_policy_mod_reply>(vapi_msg_id_sr_policy_mod_reply);
}

template class Msg<vapi_msg_sr_policy_mod_reply>;

using Sr_policy_mod_reply = Msg<vapi_msg_sr_policy_mod_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sr_policy_add_v2>(vapi_msg_sr_policy_add_v2 *msg)
{
  vapi_msg_sr_policy_add_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_policy_add_v2>(vapi_msg_sr_policy_add_v2 *msg)
{
  vapi_msg_sr_policy_add_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_policy_add_v2>()
{
  return ::vapi_msg_id_sr_policy_add_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_policy_add_v2>>()
{
  return ::vapi_msg_id_sr_policy_add_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_policy_add_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_policy_add_v2>(vapi_msg_id_sr_policy_add_v2);
}

template <> inline vapi_msg_sr_policy_add_v2* vapi_alloc<vapi_msg_sr_policy_add_v2>(Connection &con)
{
  vapi_msg_sr_policy_add_v2* result = vapi_alloc_sr_policy_add_v2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sr_policy_add_v2>;

template class Request<vapi_msg_sr_policy_add_v2, vapi_msg_sr_policy_add_v2_reply>;

using Sr_policy_add_v2 = Request<vapi_msg_sr_policy_add_v2, vapi_msg_sr_policy_add_v2_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sr_policy_add_v2_reply>(vapi_msg_sr_policy_add_v2_reply *msg)
{
  vapi_msg_sr_policy_add_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_policy_add_v2_reply>(vapi_msg_sr_policy_add_v2_reply *msg)
{
  vapi_msg_sr_policy_add_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_policy_add_v2_reply>()
{
  return ::vapi_msg_id_sr_policy_add_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_policy_add_v2_reply>>()
{
  return ::vapi_msg_id_sr_policy_add_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_policy_add_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_policy_add_v2_reply>(vapi_msg_id_sr_policy_add_v2_reply);
}

template class Msg<vapi_msg_sr_policy_add_v2_reply>;

using Sr_policy_add_v2_reply = Msg<vapi_msg_sr_policy_add_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sr_policy_mod_v2>(vapi_msg_sr_policy_mod_v2 *msg)
{
  vapi_msg_sr_policy_mod_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_policy_mod_v2>(vapi_msg_sr_policy_mod_v2 *msg)
{
  vapi_msg_sr_policy_mod_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_policy_mod_v2>()
{
  return ::vapi_msg_id_sr_policy_mod_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_policy_mod_v2>>()
{
  return ::vapi_msg_id_sr_policy_mod_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_policy_mod_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_policy_mod_v2>(vapi_msg_id_sr_policy_mod_v2);
}

template <> inline vapi_msg_sr_policy_mod_v2* vapi_alloc<vapi_msg_sr_policy_mod_v2>(Connection &con)
{
  vapi_msg_sr_policy_mod_v2* result = vapi_alloc_sr_policy_mod_v2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sr_policy_mod_v2>;

template class Request<vapi_msg_sr_policy_mod_v2, vapi_msg_sr_policy_mod_v2_reply>;

using Sr_policy_mod_v2 = Request<vapi_msg_sr_policy_mod_v2, vapi_msg_sr_policy_mod_v2_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sr_policy_mod_v2_reply>(vapi_msg_sr_policy_mod_v2_reply *msg)
{
  vapi_msg_sr_policy_mod_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_policy_mod_v2_reply>(vapi_msg_sr_policy_mod_v2_reply *msg)
{
  vapi_msg_sr_policy_mod_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_policy_mod_v2_reply>()
{
  return ::vapi_msg_id_sr_policy_mod_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_policy_mod_v2_reply>>()
{
  return ::vapi_msg_id_sr_policy_mod_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_policy_mod_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_policy_mod_v2_reply>(vapi_msg_id_sr_policy_mod_v2_reply);
}

template class Msg<vapi_msg_sr_policy_mod_v2_reply>;

using Sr_policy_mod_v2_reply = Msg<vapi_msg_sr_policy_mod_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sr_policy_del>(vapi_msg_sr_policy_del *msg)
{
  vapi_msg_sr_policy_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_policy_del>(vapi_msg_sr_policy_del *msg)
{
  vapi_msg_sr_policy_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_policy_del>()
{
  return ::vapi_msg_id_sr_policy_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_policy_del>>()
{
  return ::vapi_msg_id_sr_policy_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_policy_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_policy_del>(vapi_msg_id_sr_policy_del);
}

template <> inline vapi_msg_sr_policy_del* vapi_alloc<vapi_msg_sr_policy_del>(Connection &con)
{
  vapi_msg_sr_policy_del* result = vapi_alloc_sr_policy_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sr_policy_del>;

template class Request<vapi_msg_sr_policy_del, vapi_msg_sr_policy_del_reply>;

using Sr_policy_del = Request<vapi_msg_sr_policy_del, vapi_msg_sr_policy_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sr_policy_del_reply>(vapi_msg_sr_policy_del_reply *msg)
{
  vapi_msg_sr_policy_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_policy_del_reply>(vapi_msg_sr_policy_del_reply *msg)
{
  vapi_msg_sr_policy_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_policy_del_reply>()
{
  return ::vapi_msg_id_sr_policy_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_policy_del_reply>>()
{
  return ::vapi_msg_id_sr_policy_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_policy_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_policy_del_reply>(vapi_msg_id_sr_policy_del_reply);
}

template class Msg<vapi_msg_sr_policy_del_reply>;

using Sr_policy_del_reply = Msg<vapi_msg_sr_policy_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sr_set_encap_source>(vapi_msg_sr_set_encap_source *msg)
{
  vapi_msg_sr_set_encap_source_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_set_encap_source>(vapi_msg_sr_set_encap_source *msg)
{
  vapi_msg_sr_set_encap_source_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_set_encap_source>()
{
  return ::vapi_msg_id_sr_set_encap_source; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_set_encap_source>>()
{
  return ::vapi_msg_id_sr_set_encap_source; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_set_encap_source()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_set_encap_source>(vapi_msg_id_sr_set_encap_source);
}

template <> inline vapi_msg_sr_set_encap_source* vapi_alloc<vapi_msg_sr_set_encap_source>(Connection &con)
{
  vapi_msg_sr_set_encap_source* result = vapi_alloc_sr_set_encap_source(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sr_set_encap_source>;

template class Request<vapi_msg_sr_set_encap_source, vapi_msg_sr_set_encap_source_reply>;

using Sr_set_encap_source = Request<vapi_msg_sr_set_encap_source, vapi_msg_sr_set_encap_source_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sr_set_encap_source_reply>(vapi_msg_sr_set_encap_source_reply *msg)
{
  vapi_msg_sr_set_encap_source_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_set_encap_source_reply>(vapi_msg_sr_set_encap_source_reply *msg)
{
  vapi_msg_sr_set_encap_source_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_set_encap_source_reply>()
{
  return ::vapi_msg_id_sr_set_encap_source_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_set_encap_source_reply>>()
{
  return ::vapi_msg_id_sr_set_encap_source_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_set_encap_source_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_set_encap_source_reply>(vapi_msg_id_sr_set_encap_source_reply);
}

template class Msg<vapi_msg_sr_set_encap_source_reply>;

using Sr_set_encap_source_reply = Msg<vapi_msg_sr_set_encap_source_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sr_set_encap_hop_limit>(vapi_msg_sr_set_encap_hop_limit *msg)
{
  vapi_msg_sr_set_encap_hop_limit_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_set_encap_hop_limit>(vapi_msg_sr_set_encap_hop_limit *msg)
{
  vapi_msg_sr_set_encap_hop_limit_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_set_encap_hop_limit>()
{
  return ::vapi_msg_id_sr_set_encap_hop_limit; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_set_encap_hop_limit>>()
{
  return ::vapi_msg_id_sr_set_encap_hop_limit; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_set_encap_hop_limit()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_set_encap_hop_limit>(vapi_msg_id_sr_set_encap_hop_limit);
}

template <> inline vapi_msg_sr_set_encap_hop_limit* vapi_alloc<vapi_msg_sr_set_encap_hop_limit>(Connection &con)
{
  vapi_msg_sr_set_encap_hop_limit* result = vapi_alloc_sr_set_encap_hop_limit(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sr_set_encap_hop_limit>;

template class Request<vapi_msg_sr_set_encap_hop_limit, vapi_msg_sr_set_encap_hop_limit_reply>;

using Sr_set_encap_hop_limit = Request<vapi_msg_sr_set_encap_hop_limit, vapi_msg_sr_set_encap_hop_limit_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sr_set_encap_hop_limit_reply>(vapi_msg_sr_set_encap_hop_limit_reply *msg)
{
  vapi_msg_sr_set_encap_hop_limit_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_set_encap_hop_limit_reply>(vapi_msg_sr_set_encap_hop_limit_reply *msg)
{
  vapi_msg_sr_set_encap_hop_limit_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_set_encap_hop_limit_reply>()
{
  return ::vapi_msg_id_sr_set_encap_hop_limit_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_set_encap_hop_limit_reply>>()
{
  return ::vapi_msg_id_sr_set_encap_hop_limit_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_set_encap_hop_limit_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_set_encap_hop_limit_reply>(vapi_msg_id_sr_set_encap_hop_limit_reply);
}

template class Msg<vapi_msg_sr_set_encap_hop_limit_reply>;

using Sr_set_encap_hop_limit_reply = Msg<vapi_msg_sr_set_encap_hop_limit_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sr_steering_add_del>(vapi_msg_sr_steering_add_del *msg)
{
  vapi_msg_sr_steering_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_steering_add_del>(vapi_msg_sr_steering_add_del *msg)
{
  vapi_msg_sr_steering_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_steering_add_del>()
{
  return ::vapi_msg_id_sr_steering_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_steering_add_del>>()
{
  return ::vapi_msg_id_sr_steering_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_steering_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_steering_add_del>(vapi_msg_id_sr_steering_add_del);
}

template <> inline vapi_msg_sr_steering_add_del* vapi_alloc<vapi_msg_sr_steering_add_del>(Connection &con)
{
  vapi_msg_sr_steering_add_del* result = vapi_alloc_sr_steering_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sr_steering_add_del>;

template class Request<vapi_msg_sr_steering_add_del, vapi_msg_sr_steering_add_del_reply>;

using Sr_steering_add_del = Request<vapi_msg_sr_steering_add_del, vapi_msg_sr_steering_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sr_steering_add_del_reply>(vapi_msg_sr_steering_add_del_reply *msg)
{
  vapi_msg_sr_steering_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_steering_add_del_reply>(vapi_msg_sr_steering_add_del_reply *msg)
{
  vapi_msg_sr_steering_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_steering_add_del_reply>()
{
  return ::vapi_msg_id_sr_steering_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_steering_add_del_reply>>()
{
  return ::vapi_msg_id_sr_steering_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_steering_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_steering_add_del_reply>(vapi_msg_id_sr_steering_add_del_reply);
}

template class Msg<vapi_msg_sr_steering_add_del_reply>;

using Sr_steering_add_del_reply = Msg<vapi_msg_sr_steering_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sr_localsids_dump>(vapi_msg_sr_localsids_dump *msg)
{
  vapi_msg_sr_localsids_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_localsids_dump>(vapi_msg_sr_localsids_dump *msg)
{
  vapi_msg_sr_localsids_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_localsids_dump>()
{
  return ::vapi_msg_id_sr_localsids_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_localsids_dump>>()
{
  return ::vapi_msg_id_sr_localsids_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_localsids_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_localsids_dump>(vapi_msg_id_sr_localsids_dump);
}

template <> inline vapi_msg_sr_localsids_dump* vapi_alloc<vapi_msg_sr_localsids_dump>(Connection &con)
{
  vapi_msg_sr_localsids_dump* result = vapi_alloc_sr_localsids_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sr_localsids_dump>;

template class Dump<vapi_msg_sr_localsids_dump, vapi_msg_sr_localsids_details>;

using Sr_localsids_dump = Dump<vapi_msg_sr_localsids_dump, vapi_msg_sr_localsids_details>;

template <> inline void vapi_swap_to_be<vapi_msg_sr_localsids_details>(vapi_msg_sr_localsids_details *msg)
{
  vapi_msg_sr_localsids_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_localsids_details>(vapi_msg_sr_localsids_details *msg)
{
  vapi_msg_sr_localsids_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_localsids_details>()
{
  return ::vapi_msg_id_sr_localsids_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_localsids_details>>()
{
  return ::vapi_msg_id_sr_localsids_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_localsids_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_localsids_details>(vapi_msg_id_sr_localsids_details);
}

template class Msg<vapi_msg_sr_localsids_details>;

using Sr_localsids_details = Msg<vapi_msg_sr_localsids_details>;
template <> inline void vapi_swap_to_be<vapi_msg_sr_localsids_with_packet_stats_dump>(vapi_msg_sr_localsids_with_packet_stats_dump *msg)
{
  vapi_msg_sr_localsids_with_packet_stats_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_localsids_with_packet_stats_dump>(vapi_msg_sr_localsids_with_packet_stats_dump *msg)
{
  vapi_msg_sr_localsids_with_packet_stats_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_localsids_with_packet_stats_dump>()
{
  return ::vapi_msg_id_sr_localsids_with_packet_stats_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_localsids_with_packet_stats_dump>>()
{
  return ::vapi_msg_id_sr_localsids_with_packet_stats_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_localsids_with_packet_stats_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_localsids_with_packet_stats_dump>(vapi_msg_id_sr_localsids_with_packet_stats_dump);
}

template <> inline vapi_msg_sr_localsids_with_packet_stats_dump* vapi_alloc<vapi_msg_sr_localsids_with_packet_stats_dump>(Connection &con)
{
  vapi_msg_sr_localsids_with_packet_stats_dump* result = vapi_alloc_sr_localsids_with_packet_stats_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sr_localsids_with_packet_stats_dump>;

template class Dump<vapi_msg_sr_localsids_with_packet_stats_dump, vapi_msg_sr_localsids_with_packet_stats_details>;

using Sr_localsids_with_packet_stats_dump = Dump<vapi_msg_sr_localsids_with_packet_stats_dump, vapi_msg_sr_localsids_with_packet_stats_details>;

template <> inline void vapi_swap_to_be<vapi_msg_sr_localsids_with_packet_stats_details>(vapi_msg_sr_localsids_with_packet_stats_details *msg)
{
  vapi_msg_sr_localsids_with_packet_stats_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_localsids_with_packet_stats_details>(vapi_msg_sr_localsids_with_packet_stats_details *msg)
{
  vapi_msg_sr_localsids_with_packet_stats_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_localsids_with_packet_stats_details>()
{
  return ::vapi_msg_id_sr_localsids_with_packet_stats_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_localsids_with_packet_stats_details>>()
{
  return ::vapi_msg_id_sr_localsids_with_packet_stats_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_localsids_with_packet_stats_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_localsids_with_packet_stats_details>(vapi_msg_id_sr_localsids_with_packet_stats_details);
}

template class Msg<vapi_msg_sr_localsids_with_packet_stats_details>;

using Sr_localsids_with_packet_stats_details = Msg<vapi_msg_sr_localsids_with_packet_stats_details>;
template <> inline void vapi_swap_to_be<vapi_msg_sr_policies_dump>(vapi_msg_sr_policies_dump *msg)
{
  vapi_msg_sr_policies_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_policies_dump>(vapi_msg_sr_policies_dump *msg)
{
  vapi_msg_sr_policies_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_policies_dump>()
{
  return ::vapi_msg_id_sr_policies_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_policies_dump>>()
{
  return ::vapi_msg_id_sr_policies_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_policies_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_policies_dump>(vapi_msg_id_sr_policies_dump);
}

template <> inline vapi_msg_sr_policies_dump* vapi_alloc<vapi_msg_sr_policies_dump>(Connection &con)
{
  vapi_msg_sr_policies_dump* result = vapi_alloc_sr_policies_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sr_policies_dump>;

template class Dump<vapi_msg_sr_policies_dump, vapi_msg_sr_policies_details>;

using Sr_policies_dump = Dump<vapi_msg_sr_policies_dump, vapi_msg_sr_policies_details>;

template <> inline void vapi_swap_to_be<vapi_msg_sr_policies_details>(vapi_msg_sr_policies_details *msg)
{
  vapi_msg_sr_policies_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_policies_details>(vapi_msg_sr_policies_details *msg)
{
  vapi_msg_sr_policies_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_policies_details>()
{
  return ::vapi_msg_id_sr_policies_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_policies_details>>()
{
  return ::vapi_msg_id_sr_policies_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_policies_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_policies_details>(vapi_msg_id_sr_policies_details);
}

template class Msg<vapi_msg_sr_policies_details>;

using Sr_policies_details = Msg<vapi_msg_sr_policies_details>;
template <> inline void vapi_swap_to_be<vapi_msg_sr_policies_v2_dump>(vapi_msg_sr_policies_v2_dump *msg)
{
  vapi_msg_sr_policies_v2_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_policies_v2_dump>(vapi_msg_sr_policies_v2_dump *msg)
{
  vapi_msg_sr_policies_v2_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_policies_v2_dump>()
{
  return ::vapi_msg_id_sr_policies_v2_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_policies_v2_dump>>()
{
  return ::vapi_msg_id_sr_policies_v2_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_policies_v2_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_policies_v2_dump>(vapi_msg_id_sr_policies_v2_dump);
}

template <> inline vapi_msg_sr_policies_v2_dump* vapi_alloc<vapi_msg_sr_policies_v2_dump>(Connection &con)
{
  vapi_msg_sr_policies_v2_dump* result = vapi_alloc_sr_policies_v2_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sr_policies_v2_dump>;

template class Dump<vapi_msg_sr_policies_v2_dump, vapi_msg_sr_policies_v2_details>;

using Sr_policies_v2_dump = Dump<vapi_msg_sr_policies_v2_dump, vapi_msg_sr_policies_v2_details>;

template <> inline void vapi_swap_to_be<vapi_msg_sr_policies_v2_details>(vapi_msg_sr_policies_v2_details *msg)
{
  vapi_msg_sr_policies_v2_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_policies_v2_details>(vapi_msg_sr_policies_v2_details *msg)
{
  vapi_msg_sr_policies_v2_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_policies_v2_details>()
{
  return ::vapi_msg_id_sr_policies_v2_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_policies_v2_details>>()
{
  return ::vapi_msg_id_sr_policies_v2_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_policies_v2_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_policies_v2_details>(vapi_msg_id_sr_policies_v2_details);
}

template class Msg<vapi_msg_sr_policies_v2_details>;

using Sr_policies_v2_details = Msg<vapi_msg_sr_policies_v2_details>;
template <> inline void vapi_swap_to_be<vapi_msg_sr_policies_with_sl_index_dump>(vapi_msg_sr_policies_with_sl_index_dump *msg)
{
  vapi_msg_sr_policies_with_sl_index_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_policies_with_sl_index_dump>(vapi_msg_sr_policies_with_sl_index_dump *msg)
{
  vapi_msg_sr_policies_with_sl_index_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_policies_with_sl_index_dump>()
{
  return ::vapi_msg_id_sr_policies_with_sl_index_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_policies_with_sl_index_dump>>()
{
  return ::vapi_msg_id_sr_policies_with_sl_index_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_policies_with_sl_index_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_policies_with_sl_index_dump>(vapi_msg_id_sr_policies_with_sl_index_dump);
}

template <> inline vapi_msg_sr_policies_with_sl_index_dump* vapi_alloc<vapi_msg_sr_policies_with_sl_index_dump>(Connection &con)
{
  vapi_msg_sr_policies_with_sl_index_dump* result = vapi_alloc_sr_policies_with_sl_index_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sr_policies_with_sl_index_dump>;

template class Dump<vapi_msg_sr_policies_with_sl_index_dump, vapi_msg_sr_policies_with_sl_index_details>;

using Sr_policies_with_sl_index_dump = Dump<vapi_msg_sr_policies_with_sl_index_dump, vapi_msg_sr_policies_with_sl_index_details>;

template <> inline void vapi_swap_to_be<vapi_msg_sr_policies_with_sl_index_details>(vapi_msg_sr_policies_with_sl_index_details *msg)
{
  vapi_msg_sr_policies_with_sl_index_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_policies_with_sl_index_details>(vapi_msg_sr_policies_with_sl_index_details *msg)
{
  vapi_msg_sr_policies_with_sl_index_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_policies_with_sl_index_details>()
{
  return ::vapi_msg_id_sr_policies_with_sl_index_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_policies_with_sl_index_details>>()
{
  return ::vapi_msg_id_sr_policies_with_sl_index_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_policies_with_sl_index_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_policies_with_sl_index_details>(vapi_msg_id_sr_policies_with_sl_index_details);
}

template class Msg<vapi_msg_sr_policies_with_sl_index_details>;

using Sr_policies_with_sl_index_details = Msg<vapi_msg_sr_policies_with_sl_index_details>;
template <> inline void vapi_swap_to_be<vapi_msg_sr_steering_pol_dump>(vapi_msg_sr_steering_pol_dump *msg)
{
  vapi_msg_sr_steering_pol_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_steering_pol_dump>(vapi_msg_sr_steering_pol_dump *msg)
{
  vapi_msg_sr_steering_pol_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_steering_pol_dump>()
{
  return ::vapi_msg_id_sr_steering_pol_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_steering_pol_dump>>()
{
  return ::vapi_msg_id_sr_steering_pol_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_steering_pol_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_steering_pol_dump>(vapi_msg_id_sr_steering_pol_dump);
}

template <> inline vapi_msg_sr_steering_pol_dump* vapi_alloc<vapi_msg_sr_steering_pol_dump>(Connection &con)
{
  vapi_msg_sr_steering_pol_dump* result = vapi_alloc_sr_steering_pol_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sr_steering_pol_dump>;

template class Dump<vapi_msg_sr_steering_pol_dump, vapi_msg_sr_steering_pol_details>;

using Sr_steering_pol_dump = Dump<vapi_msg_sr_steering_pol_dump, vapi_msg_sr_steering_pol_details>;

template <> inline void vapi_swap_to_be<vapi_msg_sr_steering_pol_details>(vapi_msg_sr_steering_pol_details *msg)
{
  vapi_msg_sr_steering_pol_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_steering_pol_details>(vapi_msg_sr_steering_pol_details *msg)
{
  vapi_msg_sr_steering_pol_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_steering_pol_details>()
{
  return ::vapi_msg_id_sr_steering_pol_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_steering_pol_details>>()
{
  return ::vapi_msg_id_sr_steering_pol_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_steering_pol_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_steering_pol_details>(vapi_msg_id_sr_steering_pol_details);
}

template class Msg<vapi_msg_sr_steering_pol_details>;

using Sr_steering_pol_details = Msg<vapi_msg_sr_steering_pol_details>;
}
#endif
