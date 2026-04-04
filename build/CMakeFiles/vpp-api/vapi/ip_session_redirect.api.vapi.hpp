#ifndef __included_hpp_ip_session_redirect_api_json
#define __included_hpp_ip_session_redirect_api_json

#include <vapi/vapi.hpp>
#include <vapi/ip_session_redirect.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_ip_session_redirect_add>(vapi_msg_ip_session_redirect_add *msg)
{
  vapi_msg_ip_session_redirect_add_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_session_redirect_add>(vapi_msg_ip_session_redirect_add *msg)
{
  vapi_msg_ip_session_redirect_add_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_session_redirect_add>()
{
  return ::vapi_msg_id_ip_session_redirect_add; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_session_redirect_add>>()
{
  return ::vapi_msg_id_ip_session_redirect_add; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_session_redirect_add()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_session_redirect_add>(vapi_msg_id_ip_session_redirect_add);
}

template <> inline vapi_msg_ip_session_redirect_add* vapi_alloc<vapi_msg_ip_session_redirect_add, size_t>(Connection &con, size_t _paths_array_size)
{
  vapi_msg_ip_session_redirect_add* result = vapi_alloc_ip_session_redirect_add(con.vapi_ctx, _paths_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_session_redirect_add>;

template class Request<vapi_msg_ip_session_redirect_add, vapi_msg_ip_session_redirect_add_reply, size_t>;

using Ip_session_redirect_add = Request<vapi_msg_ip_session_redirect_add, vapi_msg_ip_session_redirect_add_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_session_redirect_add_reply>(vapi_msg_ip_session_redirect_add_reply *msg)
{
  vapi_msg_ip_session_redirect_add_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_session_redirect_add_reply>(vapi_msg_ip_session_redirect_add_reply *msg)
{
  vapi_msg_ip_session_redirect_add_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_session_redirect_add_reply>()
{
  return ::vapi_msg_id_ip_session_redirect_add_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_session_redirect_add_reply>>()
{
  return ::vapi_msg_id_ip_session_redirect_add_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_session_redirect_add_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_session_redirect_add_reply>(vapi_msg_id_ip_session_redirect_add_reply);
}

template class Msg<vapi_msg_ip_session_redirect_add_reply>;

using Ip_session_redirect_add_reply = Msg<vapi_msg_ip_session_redirect_add_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_session_redirect_add_v2>(vapi_msg_ip_session_redirect_add_v2 *msg)
{
  vapi_msg_ip_session_redirect_add_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_session_redirect_add_v2>(vapi_msg_ip_session_redirect_add_v2 *msg)
{
  vapi_msg_ip_session_redirect_add_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_session_redirect_add_v2>()
{
  return ::vapi_msg_id_ip_session_redirect_add_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_session_redirect_add_v2>>()
{
  return ::vapi_msg_id_ip_session_redirect_add_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_session_redirect_add_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_session_redirect_add_v2>(vapi_msg_id_ip_session_redirect_add_v2);
}

template <> inline vapi_msg_ip_session_redirect_add_v2* vapi_alloc<vapi_msg_ip_session_redirect_add_v2, size_t>(Connection &con, size_t _paths_array_size)
{
  vapi_msg_ip_session_redirect_add_v2* result = vapi_alloc_ip_session_redirect_add_v2(con.vapi_ctx, _paths_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_session_redirect_add_v2>;

template class Request<vapi_msg_ip_session_redirect_add_v2, vapi_msg_ip_session_redirect_add_v2_reply, size_t>;

using Ip_session_redirect_add_v2 = Request<vapi_msg_ip_session_redirect_add_v2, vapi_msg_ip_session_redirect_add_v2_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_session_redirect_add_v2_reply>(vapi_msg_ip_session_redirect_add_v2_reply *msg)
{
  vapi_msg_ip_session_redirect_add_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_session_redirect_add_v2_reply>(vapi_msg_ip_session_redirect_add_v2_reply *msg)
{
  vapi_msg_ip_session_redirect_add_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_session_redirect_add_v2_reply>()
{
  return ::vapi_msg_id_ip_session_redirect_add_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_session_redirect_add_v2_reply>>()
{
  return ::vapi_msg_id_ip_session_redirect_add_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_session_redirect_add_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_session_redirect_add_v2_reply>(vapi_msg_id_ip_session_redirect_add_v2_reply);
}

template class Msg<vapi_msg_ip_session_redirect_add_v2_reply>;

using Ip_session_redirect_add_v2_reply = Msg<vapi_msg_ip_session_redirect_add_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_session_redirect_del>(vapi_msg_ip_session_redirect_del *msg)
{
  vapi_msg_ip_session_redirect_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_session_redirect_del>(vapi_msg_ip_session_redirect_del *msg)
{
  vapi_msg_ip_session_redirect_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_session_redirect_del>()
{
  return ::vapi_msg_id_ip_session_redirect_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_session_redirect_del>>()
{
  return ::vapi_msg_id_ip_session_redirect_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_session_redirect_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_session_redirect_del>(vapi_msg_id_ip_session_redirect_del);
}

template <> inline vapi_msg_ip_session_redirect_del* vapi_alloc<vapi_msg_ip_session_redirect_del, size_t>(Connection &con, size_t _match_array_size)
{
  vapi_msg_ip_session_redirect_del* result = vapi_alloc_ip_session_redirect_del(con.vapi_ctx, _match_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_session_redirect_del>;

template class Request<vapi_msg_ip_session_redirect_del, vapi_msg_ip_session_redirect_del_reply, size_t>;

using Ip_session_redirect_del = Request<vapi_msg_ip_session_redirect_del, vapi_msg_ip_session_redirect_del_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_session_redirect_del_reply>(vapi_msg_ip_session_redirect_del_reply *msg)
{
  vapi_msg_ip_session_redirect_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_session_redirect_del_reply>(vapi_msg_ip_session_redirect_del_reply *msg)
{
  vapi_msg_ip_session_redirect_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_session_redirect_del_reply>()
{
  return ::vapi_msg_id_ip_session_redirect_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_session_redirect_del_reply>>()
{
  return ::vapi_msg_id_ip_session_redirect_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_session_redirect_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_session_redirect_del_reply>(vapi_msg_id_ip_session_redirect_del_reply);
}

template class Msg<vapi_msg_ip_session_redirect_del_reply>;

using Ip_session_redirect_del_reply = Msg<vapi_msg_ip_session_redirect_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_session_redirect_dump>(vapi_msg_ip_session_redirect_dump *msg)
{
  vapi_msg_ip_session_redirect_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_session_redirect_dump>(vapi_msg_ip_session_redirect_dump *msg)
{
  vapi_msg_ip_session_redirect_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_session_redirect_dump>()
{
  return ::vapi_msg_id_ip_session_redirect_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_session_redirect_dump>>()
{
  return ::vapi_msg_id_ip_session_redirect_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_session_redirect_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_session_redirect_dump>(vapi_msg_id_ip_session_redirect_dump);
}

template <> inline vapi_msg_ip_session_redirect_dump* vapi_alloc<vapi_msg_ip_session_redirect_dump>(Connection &con)
{
  vapi_msg_ip_session_redirect_dump* result = vapi_alloc_ip_session_redirect_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_session_redirect_dump>;

template class Dump<vapi_msg_ip_session_redirect_dump, vapi_msg_ip_session_redirect_details>;

using Ip_session_redirect_dump = Dump<vapi_msg_ip_session_redirect_dump, vapi_msg_ip_session_redirect_details>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_session_redirect_details>(vapi_msg_ip_session_redirect_details *msg)
{
  vapi_msg_ip_session_redirect_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_session_redirect_details>(vapi_msg_ip_session_redirect_details *msg)
{
  vapi_msg_ip_session_redirect_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_session_redirect_details>()
{
  return ::vapi_msg_id_ip_session_redirect_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_session_redirect_details>>()
{
  return ::vapi_msg_id_ip_session_redirect_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_session_redirect_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_session_redirect_details>(vapi_msg_id_ip_session_redirect_details);
}

template class Msg<vapi_msg_ip_session_redirect_details>;

using Ip_session_redirect_details = Msg<vapi_msg_ip_session_redirect_details>;
}
#endif
