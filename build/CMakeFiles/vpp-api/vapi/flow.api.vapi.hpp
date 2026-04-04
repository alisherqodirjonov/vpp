#ifndef __included_hpp_flow_api_json
#define __included_hpp_flow_api_json

#include <vapi/vapi.hpp>
#include <vapi/flow.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_flow_add>(vapi_msg_flow_add *msg)
{
  vapi_msg_flow_add_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_flow_add>(vapi_msg_flow_add *msg)
{
  vapi_msg_flow_add_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_flow_add>()
{
  return ::vapi_msg_id_flow_add; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_flow_add>>()
{
  return ::vapi_msg_id_flow_add; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_flow_add()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_flow_add>(vapi_msg_id_flow_add);
}

template <> inline vapi_msg_flow_add* vapi_alloc<vapi_msg_flow_add>(Connection &con)
{
  vapi_msg_flow_add* result = vapi_alloc_flow_add(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_flow_add>;

template class Request<vapi_msg_flow_add, vapi_msg_flow_add_reply>;

using Flow_add = Request<vapi_msg_flow_add, vapi_msg_flow_add_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_flow_add_v2>(vapi_msg_flow_add_v2 *msg)
{
  vapi_msg_flow_add_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_flow_add_v2>(vapi_msg_flow_add_v2 *msg)
{
  vapi_msg_flow_add_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_flow_add_v2>()
{
  return ::vapi_msg_id_flow_add_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_flow_add_v2>>()
{
  return ::vapi_msg_id_flow_add_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_flow_add_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_flow_add_v2>(vapi_msg_id_flow_add_v2);
}

template <> inline vapi_msg_flow_add_v2* vapi_alloc<vapi_msg_flow_add_v2>(Connection &con)
{
  vapi_msg_flow_add_v2* result = vapi_alloc_flow_add_v2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_flow_add_v2>;

template class Request<vapi_msg_flow_add_v2, vapi_msg_flow_add_v2_reply>;

using Flow_add_v2 = Request<vapi_msg_flow_add_v2, vapi_msg_flow_add_v2_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_flow_add_reply>(vapi_msg_flow_add_reply *msg)
{
  vapi_msg_flow_add_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_flow_add_reply>(vapi_msg_flow_add_reply *msg)
{
  vapi_msg_flow_add_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_flow_add_reply>()
{
  return ::vapi_msg_id_flow_add_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_flow_add_reply>>()
{
  return ::vapi_msg_id_flow_add_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_flow_add_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_flow_add_reply>(vapi_msg_id_flow_add_reply);
}

template class Msg<vapi_msg_flow_add_reply>;

using Flow_add_reply = Msg<vapi_msg_flow_add_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_flow_add_v2_reply>(vapi_msg_flow_add_v2_reply *msg)
{
  vapi_msg_flow_add_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_flow_add_v2_reply>(vapi_msg_flow_add_v2_reply *msg)
{
  vapi_msg_flow_add_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_flow_add_v2_reply>()
{
  return ::vapi_msg_id_flow_add_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_flow_add_v2_reply>>()
{
  return ::vapi_msg_id_flow_add_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_flow_add_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_flow_add_v2_reply>(vapi_msg_id_flow_add_v2_reply);
}

template class Msg<vapi_msg_flow_add_v2_reply>;

using Flow_add_v2_reply = Msg<vapi_msg_flow_add_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_flow_del>(vapi_msg_flow_del *msg)
{
  vapi_msg_flow_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_flow_del>(vapi_msg_flow_del *msg)
{
  vapi_msg_flow_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_flow_del>()
{
  return ::vapi_msg_id_flow_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_flow_del>>()
{
  return ::vapi_msg_id_flow_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_flow_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_flow_del>(vapi_msg_id_flow_del);
}

template <> inline vapi_msg_flow_del* vapi_alloc<vapi_msg_flow_del>(Connection &con)
{
  vapi_msg_flow_del* result = vapi_alloc_flow_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_flow_del>;

template class Request<vapi_msg_flow_del, vapi_msg_flow_del_reply>;

using Flow_del = Request<vapi_msg_flow_del, vapi_msg_flow_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_flow_del_reply>(vapi_msg_flow_del_reply *msg)
{
  vapi_msg_flow_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_flow_del_reply>(vapi_msg_flow_del_reply *msg)
{
  vapi_msg_flow_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_flow_del_reply>()
{
  return ::vapi_msg_id_flow_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_flow_del_reply>>()
{
  return ::vapi_msg_id_flow_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_flow_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_flow_del_reply>(vapi_msg_id_flow_del_reply);
}

template class Msg<vapi_msg_flow_del_reply>;

using Flow_del_reply = Msg<vapi_msg_flow_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_flow_enable>(vapi_msg_flow_enable *msg)
{
  vapi_msg_flow_enable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_flow_enable>(vapi_msg_flow_enable *msg)
{
  vapi_msg_flow_enable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_flow_enable>()
{
  return ::vapi_msg_id_flow_enable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_flow_enable>>()
{
  return ::vapi_msg_id_flow_enable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_flow_enable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_flow_enable>(vapi_msg_id_flow_enable);
}

template <> inline vapi_msg_flow_enable* vapi_alloc<vapi_msg_flow_enable>(Connection &con)
{
  vapi_msg_flow_enable* result = vapi_alloc_flow_enable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_flow_enable>;

template class Request<vapi_msg_flow_enable, vapi_msg_flow_enable_reply>;

using Flow_enable = Request<vapi_msg_flow_enable, vapi_msg_flow_enable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_flow_enable_reply>(vapi_msg_flow_enable_reply *msg)
{
  vapi_msg_flow_enable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_flow_enable_reply>(vapi_msg_flow_enable_reply *msg)
{
  vapi_msg_flow_enable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_flow_enable_reply>()
{
  return ::vapi_msg_id_flow_enable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_flow_enable_reply>>()
{
  return ::vapi_msg_id_flow_enable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_flow_enable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_flow_enable_reply>(vapi_msg_id_flow_enable_reply);
}

template class Msg<vapi_msg_flow_enable_reply>;

using Flow_enable_reply = Msg<vapi_msg_flow_enable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_flow_disable>(vapi_msg_flow_disable *msg)
{
  vapi_msg_flow_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_flow_disable>(vapi_msg_flow_disable *msg)
{
  vapi_msg_flow_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_flow_disable>()
{
  return ::vapi_msg_id_flow_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_flow_disable>>()
{
  return ::vapi_msg_id_flow_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_flow_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_flow_disable>(vapi_msg_id_flow_disable);
}

template <> inline vapi_msg_flow_disable* vapi_alloc<vapi_msg_flow_disable>(Connection &con)
{
  vapi_msg_flow_disable* result = vapi_alloc_flow_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_flow_disable>;

template class Request<vapi_msg_flow_disable, vapi_msg_flow_disable_reply>;

using Flow_disable = Request<vapi_msg_flow_disable, vapi_msg_flow_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_flow_disable_reply>(vapi_msg_flow_disable_reply *msg)
{
  vapi_msg_flow_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_flow_disable_reply>(vapi_msg_flow_disable_reply *msg)
{
  vapi_msg_flow_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_flow_disable_reply>()
{
  return ::vapi_msg_id_flow_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_flow_disable_reply>>()
{
  return ::vapi_msg_id_flow_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_flow_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_flow_disable_reply>(vapi_msg_id_flow_disable_reply);
}

template class Msg<vapi_msg_flow_disable_reply>;

using Flow_disable_reply = Msg<vapi_msg_flow_disable_reply>;
}
#endif
