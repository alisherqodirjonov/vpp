#ifndef __included_hpp_sr_mpls_api_json
#define __included_hpp_sr_mpls_api_json

#include <vapi/vapi.hpp>
#include <vapi/sr_mpls.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_sr_mpls_policy_add>(vapi_msg_sr_mpls_policy_add *msg)
{
  vapi_msg_sr_mpls_policy_add_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_mpls_policy_add>(vapi_msg_sr_mpls_policy_add *msg)
{
  vapi_msg_sr_mpls_policy_add_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_mpls_policy_add>()
{
  return ::vapi_msg_id_sr_mpls_policy_add; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_mpls_policy_add>>()
{
  return ::vapi_msg_id_sr_mpls_policy_add; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_mpls_policy_add()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_mpls_policy_add>(vapi_msg_id_sr_mpls_policy_add);
}

template <> inline vapi_msg_sr_mpls_policy_add* vapi_alloc<vapi_msg_sr_mpls_policy_add, size_t>(Connection &con, size_t _segments_array_size)
{
  vapi_msg_sr_mpls_policy_add* result = vapi_alloc_sr_mpls_policy_add(con.vapi_ctx, _segments_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sr_mpls_policy_add>;

template class Request<vapi_msg_sr_mpls_policy_add, vapi_msg_sr_mpls_policy_add_reply, size_t>;

using Sr_mpls_policy_add = Request<vapi_msg_sr_mpls_policy_add, vapi_msg_sr_mpls_policy_add_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_sr_mpls_policy_add_reply>(vapi_msg_sr_mpls_policy_add_reply *msg)
{
  vapi_msg_sr_mpls_policy_add_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_mpls_policy_add_reply>(vapi_msg_sr_mpls_policy_add_reply *msg)
{
  vapi_msg_sr_mpls_policy_add_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_mpls_policy_add_reply>()
{
  return ::vapi_msg_id_sr_mpls_policy_add_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_mpls_policy_add_reply>>()
{
  return ::vapi_msg_id_sr_mpls_policy_add_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_mpls_policy_add_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_mpls_policy_add_reply>(vapi_msg_id_sr_mpls_policy_add_reply);
}

template class Msg<vapi_msg_sr_mpls_policy_add_reply>;

using Sr_mpls_policy_add_reply = Msg<vapi_msg_sr_mpls_policy_add_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sr_mpls_policy_mod>(vapi_msg_sr_mpls_policy_mod *msg)
{
  vapi_msg_sr_mpls_policy_mod_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_mpls_policy_mod>(vapi_msg_sr_mpls_policy_mod *msg)
{
  vapi_msg_sr_mpls_policy_mod_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_mpls_policy_mod>()
{
  return ::vapi_msg_id_sr_mpls_policy_mod; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_mpls_policy_mod>>()
{
  return ::vapi_msg_id_sr_mpls_policy_mod; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_mpls_policy_mod()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_mpls_policy_mod>(vapi_msg_id_sr_mpls_policy_mod);
}

template <> inline vapi_msg_sr_mpls_policy_mod* vapi_alloc<vapi_msg_sr_mpls_policy_mod, size_t>(Connection &con, size_t _segments_array_size)
{
  vapi_msg_sr_mpls_policy_mod* result = vapi_alloc_sr_mpls_policy_mod(con.vapi_ctx, _segments_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sr_mpls_policy_mod>;

template class Request<vapi_msg_sr_mpls_policy_mod, vapi_msg_sr_mpls_policy_mod_reply, size_t>;

using Sr_mpls_policy_mod = Request<vapi_msg_sr_mpls_policy_mod, vapi_msg_sr_mpls_policy_mod_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_sr_mpls_policy_mod_reply>(vapi_msg_sr_mpls_policy_mod_reply *msg)
{
  vapi_msg_sr_mpls_policy_mod_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_mpls_policy_mod_reply>(vapi_msg_sr_mpls_policy_mod_reply *msg)
{
  vapi_msg_sr_mpls_policy_mod_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_mpls_policy_mod_reply>()
{
  return ::vapi_msg_id_sr_mpls_policy_mod_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_mpls_policy_mod_reply>>()
{
  return ::vapi_msg_id_sr_mpls_policy_mod_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_mpls_policy_mod_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_mpls_policy_mod_reply>(vapi_msg_id_sr_mpls_policy_mod_reply);
}

template class Msg<vapi_msg_sr_mpls_policy_mod_reply>;

using Sr_mpls_policy_mod_reply = Msg<vapi_msg_sr_mpls_policy_mod_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sr_mpls_policy_del>(vapi_msg_sr_mpls_policy_del *msg)
{
  vapi_msg_sr_mpls_policy_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_mpls_policy_del>(vapi_msg_sr_mpls_policy_del *msg)
{
  vapi_msg_sr_mpls_policy_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_mpls_policy_del>()
{
  return ::vapi_msg_id_sr_mpls_policy_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_mpls_policy_del>>()
{
  return ::vapi_msg_id_sr_mpls_policy_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_mpls_policy_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_mpls_policy_del>(vapi_msg_id_sr_mpls_policy_del);
}

template <> inline vapi_msg_sr_mpls_policy_del* vapi_alloc<vapi_msg_sr_mpls_policy_del>(Connection &con)
{
  vapi_msg_sr_mpls_policy_del* result = vapi_alloc_sr_mpls_policy_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sr_mpls_policy_del>;

template class Request<vapi_msg_sr_mpls_policy_del, vapi_msg_sr_mpls_policy_del_reply>;

using Sr_mpls_policy_del = Request<vapi_msg_sr_mpls_policy_del, vapi_msg_sr_mpls_policy_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sr_mpls_policy_del_reply>(vapi_msg_sr_mpls_policy_del_reply *msg)
{
  vapi_msg_sr_mpls_policy_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_mpls_policy_del_reply>(vapi_msg_sr_mpls_policy_del_reply *msg)
{
  vapi_msg_sr_mpls_policy_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_mpls_policy_del_reply>()
{
  return ::vapi_msg_id_sr_mpls_policy_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_mpls_policy_del_reply>>()
{
  return ::vapi_msg_id_sr_mpls_policy_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_mpls_policy_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_mpls_policy_del_reply>(vapi_msg_id_sr_mpls_policy_del_reply);
}

template class Msg<vapi_msg_sr_mpls_policy_del_reply>;

using Sr_mpls_policy_del_reply = Msg<vapi_msg_sr_mpls_policy_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sr_mpls_steering_add_del>(vapi_msg_sr_mpls_steering_add_del *msg)
{
  vapi_msg_sr_mpls_steering_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_mpls_steering_add_del>(vapi_msg_sr_mpls_steering_add_del *msg)
{
  vapi_msg_sr_mpls_steering_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_mpls_steering_add_del>()
{
  return ::vapi_msg_id_sr_mpls_steering_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_mpls_steering_add_del>>()
{
  return ::vapi_msg_id_sr_mpls_steering_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_mpls_steering_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_mpls_steering_add_del>(vapi_msg_id_sr_mpls_steering_add_del);
}

template <> inline vapi_msg_sr_mpls_steering_add_del* vapi_alloc<vapi_msg_sr_mpls_steering_add_del>(Connection &con)
{
  vapi_msg_sr_mpls_steering_add_del* result = vapi_alloc_sr_mpls_steering_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sr_mpls_steering_add_del>;

template class Request<vapi_msg_sr_mpls_steering_add_del, vapi_msg_sr_mpls_steering_add_del_reply>;

using Sr_mpls_steering_add_del = Request<vapi_msg_sr_mpls_steering_add_del, vapi_msg_sr_mpls_steering_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sr_mpls_steering_add_del_reply>(vapi_msg_sr_mpls_steering_add_del_reply *msg)
{
  vapi_msg_sr_mpls_steering_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_mpls_steering_add_del_reply>(vapi_msg_sr_mpls_steering_add_del_reply *msg)
{
  vapi_msg_sr_mpls_steering_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_mpls_steering_add_del_reply>()
{
  return ::vapi_msg_id_sr_mpls_steering_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_mpls_steering_add_del_reply>>()
{
  return ::vapi_msg_id_sr_mpls_steering_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_mpls_steering_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_mpls_steering_add_del_reply>(vapi_msg_id_sr_mpls_steering_add_del_reply);
}

template class Msg<vapi_msg_sr_mpls_steering_add_del_reply>;

using Sr_mpls_steering_add_del_reply = Msg<vapi_msg_sr_mpls_steering_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sr_mpls_policy_assign_endpoint_color>(vapi_msg_sr_mpls_policy_assign_endpoint_color *msg)
{
  vapi_msg_sr_mpls_policy_assign_endpoint_color_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_mpls_policy_assign_endpoint_color>(vapi_msg_sr_mpls_policy_assign_endpoint_color *msg)
{
  vapi_msg_sr_mpls_policy_assign_endpoint_color_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_mpls_policy_assign_endpoint_color>()
{
  return ::vapi_msg_id_sr_mpls_policy_assign_endpoint_color; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_mpls_policy_assign_endpoint_color>>()
{
  return ::vapi_msg_id_sr_mpls_policy_assign_endpoint_color; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_mpls_policy_assign_endpoint_color()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_mpls_policy_assign_endpoint_color>(vapi_msg_id_sr_mpls_policy_assign_endpoint_color);
}

template <> inline vapi_msg_sr_mpls_policy_assign_endpoint_color* vapi_alloc<vapi_msg_sr_mpls_policy_assign_endpoint_color>(Connection &con)
{
  vapi_msg_sr_mpls_policy_assign_endpoint_color* result = vapi_alloc_sr_mpls_policy_assign_endpoint_color(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sr_mpls_policy_assign_endpoint_color>;

template class Request<vapi_msg_sr_mpls_policy_assign_endpoint_color, vapi_msg_sr_mpls_policy_assign_endpoint_color_reply>;

using Sr_mpls_policy_assign_endpoint_color = Request<vapi_msg_sr_mpls_policy_assign_endpoint_color, vapi_msg_sr_mpls_policy_assign_endpoint_color_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sr_mpls_policy_assign_endpoint_color_reply>(vapi_msg_sr_mpls_policy_assign_endpoint_color_reply *msg)
{
  vapi_msg_sr_mpls_policy_assign_endpoint_color_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_mpls_policy_assign_endpoint_color_reply>(vapi_msg_sr_mpls_policy_assign_endpoint_color_reply *msg)
{
  vapi_msg_sr_mpls_policy_assign_endpoint_color_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_mpls_policy_assign_endpoint_color_reply>()
{
  return ::vapi_msg_id_sr_mpls_policy_assign_endpoint_color_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_mpls_policy_assign_endpoint_color_reply>>()
{
  return ::vapi_msg_id_sr_mpls_policy_assign_endpoint_color_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_mpls_policy_assign_endpoint_color_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_mpls_policy_assign_endpoint_color_reply>(vapi_msg_id_sr_mpls_policy_assign_endpoint_color_reply);
}

template class Msg<vapi_msg_sr_mpls_policy_assign_endpoint_color_reply>;

using Sr_mpls_policy_assign_endpoint_color_reply = Msg<vapi_msg_sr_mpls_policy_assign_endpoint_color_reply>;
}
#endif
