#ifndef __included_hpp_lcp_api_json
#define __included_hpp_lcp_api_json

#include <vapi/vapi.hpp>
#include <vapi/lcp.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_lcp_default_ns_set>(vapi_msg_lcp_default_ns_set *msg)
{
  vapi_msg_lcp_default_ns_set_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lcp_default_ns_set>(vapi_msg_lcp_default_ns_set *msg)
{
  vapi_msg_lcp_default_ns_set_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lcp_default_ns_set>()
{
  return ::vapi_msg_id_lcp_default_ns_set; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lcp_default_ns_set>>()
{
  return ::vapi_msg_id_lcp_default_ns_set; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lcp_default_ns_set()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lcp_default_ns_set>(vapi_msg_id_lcp_default_ns_set);
}

template <> inline vapi_msg_lcp_default_ns_set* vapi_alloc<vapi_msg_lcp_default_ns_set>(Connection &con)
{
  vapi_msg_lcp_default_ns_set* result = vapi_alloc_lcp_default_ns_set(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lcp_default_ns_set>;

template class Request<vapi_msg_lcp_default_ns_set, vapi_msg_lcp_default_ns_set_reply>;

using Lcp_default_ns_set = Request<vapi_msg_lcp_default_ns_set, vapi_msg_lcp_default_ns_set_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_lcp_default_ns_set_reply>(vapi_msg_lcp_default_ns_set_reply *msg)
{
  vapi_msg_lcp_default_ns_set_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lcp_default_ns_set_reply>(vapi_msg_lcp_default_ns_set_reply *msg)
{
  vapi_msg_lcp_default_ns_set_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lcp_default_ns_set_reply>()
{
  return ::vapi_msg_id_lcp_default_ns_set_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lcp_default_ns_set_reply>>()
{
  return ::vapi_msg_id_lcp_default_ns_set_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lcp_default_ns_set_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lcp_default_ns_set_reply>(vapi_msg_id_lcp_default_ns_set_reply);
}

template class Msg<vapi_msg_lcp_default_ns_set_reply>;

using Lcp_default_ns_set_reply = Msg<vapi_msg_lcp_default_ns_set_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_lcp_default_ns_get>(vapi_msg_lcp_default_ns_get *msg)
{
  vapi_msg_lcp_default_ns_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lcp_default_ns_get>(vapi_msg_lcp_default_ns_get *msg)
{
  vapi_msg_lcp_default_ns_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lcp_default_ns_get>()
{
  return ::vapi_msg_id_lcp_default_ns_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lcp_default_ns_get>>()
{
  return ::vapi_msg_id_lcp_default_ns_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lcp_default_ns_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lcp_default_ns_get>(vapi_msg_id_lcp_default_ns_get);
}

template <> inline vapi_msg_lcp_default_ns_get* vapi_alloc<vapi_msg_lcp_default_ns_get>(Connection &con)
{
  vapi_msg_lcp_default_ns_get* result = vapi_alloc_lcp_default_ns_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lcp_default_ns_get>;

template class Request<vapi_msg_lcp_default_ns_get, vapi_msg_lcp_default_ns_get_reply>;

using Lcp_default_ns_get = Request<vapi_msg_lcp_default_ns_get, vapi_msg_lcp_default_ns_get_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_lcp_default_ns_get_reply>(vapi_msg_lcp_default_ns_get_reply *msg)
{
  vapi_msg_lcp_default_ns_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lcp_default_ns_get_reply>(vapi_msg_lcp_default_ns_get_reply *msg)
{
  vapi_msg_lcp_default_ns_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lcp_default_ns_get_reply>()
{
  return ::vapi_msg_id_lcp_default_ns_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lcp_default_ns_get_reply>>()
{
  return ::vapi_msg_id_lcp_default_ns_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lcp_default_ns_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lcp_default_ns_get_reply>(vapi_msg_id_lcp_default_ns_get_reply);
}

template class Msg<vapi_msg_lcp_default_ns_get_reply>;

using Lcp_default_ns_get_reply = Msg<vapi_msg_lcp_default_ns_get_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_lcp_itf_pair_add_del>(vapi_msg_lcp_itf_pair_add_del *msg)
{
  vapi_msg_lcp_itf_pair_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lcp_itf_pair_add_del>(vapi_msg_lcp_itf_pair_add_del *msg)
{
  vapi_msg_lcp_itf_pair_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lcp_itf_pair_add_del>()
{
  return ::vapi_msg_id_lcp_itf_pair_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lcp_itf_pair_add_del>>()
{
  return ::vapi_msg_id_lcp_itf_pair_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lcp_itf_pair_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lcp_itf_pair_add_del>(vapi_msg_id_lcp_itf_pair_add_del);
}

template <> inline vapi_msg_lcp_itf_pair_add_del* vapi_alloc<vapi_msg_lcp_itf_pair_add_del>(Connection &con)
{
  vapi_msg_lcp_itf_pair_add_del* result = vapi_alloc_lcp_itf_pair_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lcp_itf_pair_add_del>;

template class Request<vapi_msg_lcp_itf_pair_add_del, vapi_msg_lcp_itf_pair_add_del_reply>;

using Lcp_itf_pair_add_del = Request<vapi_msg_lcp_itf_pair_add_del, vapi_msg_lcp_itf_pair_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_lcp_itf_pair_add_del_reply>(vapi_msg_lcp_itf_pair_add_del_reply *msg)
{
  vapi_msg_lcp_itf_pair_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lcp_itf_pair_add_del_reply>(vapi_msg_lcp_itf_pair_add_del_reply *msg)
{
  vapi_msg_lcp_itf_pair_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lcp_itf_pair_add_del_reply>()
{
  return ::vapi_msg_id_lcp_itf_pair_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lcp_itf_pair_add_del_reply>>()
{
  return ::vapi_msg_id_lcp_itf_pair_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lcp_itf_pair_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lcp_itf_pair_add_del_reply>(vapi_msg_id_lcp_itf_pair_add_del_reply);
}

template class Msg<vapi_msg_lcp_itf_pair_add_del_reply>;

using Lcp_itf_pair_add_del_reply = Msg<vapi_msg_lcp_itf_pair_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_lcp_itf_pair_add_del_v2>(vapi_msg_lcp_itf_pair_add_del_v2 *msg)
{
  vapi_msg_lcp_itf_pair_add_del_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lcp_itf_pair_add_del_v2>(vapi_msg_lcp_itf_pair_add_del_v2 *msg)
{
  vapi_msg_lcp_itf_pair_add_del_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lcp_itf_pair_add_del_v2>()
{
  return ::vapi_msg_id_lcp_itf_pair_add_del_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lcp_itf_pair_add_del_v2>>()
{
  return ::vapi_msg_id_lcp_itf_pair_add_del_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lcp_itf_pair_add_del_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lcp_itf_pair_add_del_v2>(vapi_msg_id_lcp_itf_pair_add_del_v2);
}

template <> inline vapi_msg_lcp_itf_pair_add_del_v2* vapi_alloc<vapi_msg_lcp_itf_pair_add_del_v2>(Connection &con)
{
  vapi_msg_lcp_itf_pair_add_del_v2* result = vapi_alloc_lcp_itf_pair_add_del_v2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lcp_itf_pair_add_del_v2>;

template class Request<vapi_msg_lcp_itf_pair_add_del_v2, vapi_msg_lcp_itf_pair_add_del_v2_reply>;

using Lcp_itf_pair_add_del_v2 = Request<vapi_msg_lcp_itf_pair_add_del_v2, vapi_msg_lcp_itf_pair_add_del_v2_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_lcp_itf_pair_add_del_v2_reply>(vapi_msg_lcp_itf_pair_add_del_v2_reply *msg)
{
  vapi_msg_lcp_itf_pair_add_del_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lcp_itf_pair_add_del_v2_reply>(vapi_msg_lcp_itf_pair_add_del_v2_reply *msg)
{
  vapi_msg_lcp_itf_pair_add_del_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lcp_itf_pair_add_del_v2_reply>()
{
  return ::vapi_msg_id_lcp_itf_pair_add_del_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lcp_itf_pair_add_del_v2_reply>>()
{
  return ::vapi_msg_id_lcp_itf_pair_add_del_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lcp_itf_pair_add_del_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lcp_itf_pair_add_del_v2_reply>(vapi_msg_id_lcp_itf_pair_add_del_v2_reply);
}

template class Msg<vapi_msg_lcp_itf_pair_add_del_v2_reply>;

using Lcp_itf_pair_add_del_v2_reply = Msg<vapi_msg_lcp_itf_pair_add_del_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_lcp_itf_pair_add_del_v3>(vapi_msg_lcp_itf_pair_add_del_v3 *msg)
{
  vapi_msg_lcp_itf_pair_add_del_v3_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lcp_itf_pair_add_del_v3>(vapi_msg_lcp_itf_pair_add_del_v3 *msg)
{
  vapi_msg_lcp_itf_pair_add_del_v3_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lcp_itf_pair_add_del_v3>()
{
  return ::vapi_msg_id_lcp_itf_pair_add_del_v3; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lcp_itf_pair_add_del_v3>>()
{
  return ::vapi_msg_id_lcp_itf_pair_add_del_v3; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lcp_itf_pair_add_del_v3()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lcp_itf_pair_add_del_v3>(vapi_msg_id_lcp_itf_pair_add_del_v3);
}

template <> inline vapi_msg_lcp_itf_pair_add_del_v3* vapi_alloc<vapi_msg_lcp_itf_pair_add_del_v3>(Connection &con)
{
  vapi_msg_lcp_itf_pair_add_del_v3* result = vapi_alloc_lcp_itf_pair_add_del_v3(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lcp_itf_pair_add_del_v3>;

template class Request<vapi_msg_lcp_itf_pair_add_del_v3, vapi_msg_lcp_itf_pair_add_del_v3_reply>;

using Lcp_itf_pair_add_del_v3 = Request<vapi_msg_lcp_itf_pair_add_del_v3, vapi_msg_lcp_itf_pair_add_del_v3_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_lcp_itf_pair_add_del_v3_reply>(vapi_msg_lcp_itf_pair_add_del_v3_reply *msg)
{
  vapi_msg_lcp_itf_pair_add_del_v3_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lcp_itf_pair_add_del_v3_reply>(vapi_msg_lcp_itf_pair_add_del_v3_reply *msg)
{
  vapi_msg_lcp_itf_pair_add_del_v3_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lcp_itf_pair_add_del_v3_reply>()
{
  return ::vapi_msg_id_lcp_itf_pair_add_del_v3_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lcp_itf_pair_add_del_v3_reply>>()
{
  return ::vapi_msg_id_lcp_itf_pair_add_del_v3_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lcp_itf_pair_add_del_v3_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lcp_itf_pair_add_del_v3_reply>(vapi_msg_id_lcp_itf_pair_add_del_v3_reply);
}

template class Msg<vapi_msg_lcp_itf_pair_add_del_v3_reply>;

using Lcp_itf_pair_add_del_v3_reply = Msg<vapi_msg_lcp_itf_pair_add_del_v3_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_lcp_itf_pair_get>(vapi_msg_lcp_itf_pair_get *msg)
{
  vapi_msg_lcp_itf_pair_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lcp_itf_pair_get>(vapi_msg_lcp_itf_pair_get *msg)
{
  vapi_msg_lcp_itf_pair_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lcp_itf_pair_get>()
{
  return ::vapi_msg_id_lcp_itf_pair_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lcp_itf_pair_get>>()
{
  return ::vapi_msg_id_lcp_itf_pair_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lcp_itf_pair_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lcp_itf_pair_get>(vapi_msg_id_lcp_itf_pair_get);
}

template <> inline vapi_msg_lcp_itf_pair_get* vapi_alloc<vapi_msg_lcp_itf_pair_get>(Connection &con)
{
  vapi_msg_lcp_itf_pair_get* result = vapi_alloc_lcp_itf_pair_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lcp_itf_pair_get>;

template class Stream<vapi_msg_lcp_itf_pair_get, vapi_msg_lcp_itf_pair_get_reply, vapi_msg_lcp_itf_pair_details>;

using Lcp_itf_pair_get = Stream<vapi_msg_lcp_itf_pair_get, vapi_msg_lcp_itf_pair_get_reply, vapi_msg_lcp_itf_pair_details>;

template <> inline void vapi_swap_to_be<vapi_msg_lcp_itf_pair_get_reply>(vapi_msg_lcp_itf_pair_get_reply *msg)
{
  vapi_msg_lcp_itf_pair_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lcp_itf_pair_get_reply>(vapi_msg_lcp_itf_pair_get_reply *msg)
{
  vapi_msg_lcp_itf_pair_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lcp_itf_pair_get_reply>()
{
  return ::vapi_msg_id_lcp_itf_pair_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lcp_itf_pair_get_reply>>()
{
  return ::vapi_msg_id_lcp_itf_pair_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lcp_itf_pair_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lcp_itf_pair_get_reply>(vapi_msg_id_lcp_itf_pair_get_reply);
}

template class Msg<vapi_msg_lcp_itf_pair_get_reply>;

using Lcp_itf_pair_get_reply = Msg<vapi_msg_lcp_itf_pair_get_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_lcp_itf_pair_get_v2>(vapi_msg_lcp_itf_pair_get_v2 *msg)
{
  vapi_msg_lcp_itf_pair_get_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lcp_itf_pair_get_v2>(vapi_msg_lcp_itf_pair_get_v2 *msg)
{
  vapi_msg_lcp_itf_pair_get_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lcp_itf_pair_get_v2>()
{
  return ::vapi_msg_id_lcp_itf_pair_get_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lcp_itf_pair_get_v2>>()
{
  return ::vapi_msg_id_lcp_itf_pair_get_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lcp_itf_pair_get_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lcp_itf_pair_get_v2>(vapi_msg_id_lcp_itf_pair_get_v2);
}

template <> inline vapi_msg_lcp_itf_pair_get_v2* vapi_alloc<vapi_msg_lcp_itf_pair_get_v2>(Connection &con)
{
  vapi_msg_lcp_itf_pair_get_v2* result = vapi_alloc_lcp_itf_pair_get_v2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lcp_itf_pair_get_v2>;

template class Stream<vapi_msg_lcp_itf_pair_get_v2, vapi_msg_lcp_itf_pair_get_v2_reply, vapi_msg_lcp_itf_pair_details>;

using Lcp_itf_pair_get_v2 = Stream<vapi_msg_lcp_itf_pair_get_v2, vapi_msg_lcp_itf_pair_get_v2_reply, vapi_msg_lcp_itf_pair_details>;

template <> inline void vapi_swap_to_be<vapi_msg_lcp_itf_pair_get_v2_reply>(vapi_msg_lcp_itf_pair_get_v2_reply *msg)
{
  vapi_msg_lcp_itf_pair_get_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lcp_itf_pair_get_v2_reply>(vapi_msg_lcp_itf_pair_get_v2_reply *msg)
{
  vapi_msg_lcp_itf_pair_get_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lcp_itf_pair_get_v2_reply>()
{
  return ::vapi_msg_id_lcp_itf_pair_get_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lcp_itf_pair_get_v2_reply>>()
{
  return ::vapi_msg_id_lcp_itf_pair_get_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lcp_itf_pair_get_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lcp_itf_pair_get_v2_reply>(vapi_msg_id_lcp_itf_pair_get_v2_reply);
}

template class Msg<vapi_msg_lcp_itf_pair_get_v2_reply>;

using Lcp_itf_pair_get_v2_reply = Msg<vapi_msg_lcp_itf_pair_get_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_lcp_itf_pair_details>(vapi_msg_lcp_itf_pair_details *msg)
{
  vapi_msg_lcp_itf_pair_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lcp_itf_pair_details>(vapi_msg_lcp_itf_pair_details *msg)
{
  vapi_msg_lcp_itf_pair_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lcp_itf_pair_details>()
{
  return ::vapi_msg_id_lcp_itf_pair_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lcp_itf_pair_details>>()
{
  return ::vapi_msg_id_lcp_itf_pair_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lcp_itf_pair_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lcp_itf_pair_details>(vapi_msg_id_lcp_itf_pair_details);
}

template class Msg<vapi_msg_lcp_itf_pair_details>;

template <> inline void vapi_swap_to_be<vapi_msg_lcp_ethertype_enable>(vapi_msg_lcp_ethertype_enable *msg)
{
  vapi_msg_lcp_ethertype_enable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lcp_ethertype_enable>(vapi_msg_lcp_ethertype_enable *msg)
{
  vapi_msg_lcp_ethertype_enable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lcp_ethertype_enable>()
{
  return ::vapi_msg_id_lcp_ethertype_enable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lcp_ethertype_enable>>()
{
  return ::vapi_msg_id_lcp_ethertype_enable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lcp_ethertype_enable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lcp_ethertype_enable>(vapi_msg_id_lcp_ethertype_enable);
}

template <> inline vapi_msg_lcp_ethertype_enable* vapi_alloc<vapi_msg_lcp_ethertype_enable>(Connection &con)
{
  vapi_msg_lcp_ethertype_enable* result = vapi_alloc_lcp_ethertype_enable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lcp_ethertype_enable>;

template class Request<vapi_msg_lcp_ethertype_enable, vapi_msg_lcp_ethertype_enable_reply>;

using Lcp_ethertype_enable = Request<vapi_msg_lcp_ethertype_enable, vapi_msg_lcp_ethertype_enable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_lcp_ethertype_enable_reply>(vapi_msg_lcp_ethertype_enable_reply *msg)
{
  vapi_msg_lcp_ethertype_enable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lcp_ethertype_enable_reply>(vapi_msg_lcp_ethertype_enable_reply *msg)
{
  vapi_msg_lcp_ethertype_enable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lcp_ethertype_enable_reply>()
{
  return ::vapi_msg_id_lcp_ethertype_enable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lcp_ethertype_enable_reply>>()
{
  return ::vapi_msg_id_lcp_ethertype_enable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lcp_ethertype_enable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lcp_ethertype_enable_reply>(vapi_msg_id_lcp_ethertype_enable_reply);
}

template class Msg<vapi_msg_lcp_ethertype_enable_reply>;

using Lcp_ethertype_enable_reply = Msg<vapi_msg_lcp_ethertype_enable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_lcp_ethertype_get>(vapi_msg_lcp_ethertype_get *msg)
{
  vapi_msg_lcp_ethertype_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lcp_ethertype_get>(vapi_msg_lcp_ethertype_get *msg)
{
  vapi_msg_lcp_ethertype_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lcp_ethertype_get>()
{
  return ::vapi_msg_id_lcp_ethertype_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lcp_ethertype_get>>()
{
  return ::vapi_msg_id_lcp_ethertype_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lcp_ethertype_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lcp_ethertype_get>(vapi_msg_id_lcp_ethertype_get);
}

template <> inline vapi_msg_lcp_ethertype_get* vapi_alloc<vapi_msg_lcp_ethertype_get>(Connection &con)
{
  vapi_msg_lcp_ethertype_get* result = vapi_alloc_lcp_ethertype_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lcp_ethertype_get>;

template class Request<vapi_msg_lcp_ethertype_get, vapi_msg_lcp_ethertype_get_reply>;

using Lcp_ethertype_get = Request<vapi_msg_lcp_ethertype_get, vapi_msg_lcp_ethertype_get_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_lcp_ethertype_get_reply>(vapi_msg_lcp_ethertype_get_reply *msg)
{
  vapi_msg_lcp_ethertype_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lcp_ethertype_get_reply>(vapi_msg_lcp_ethertype_get_reply *msg)
{
  vapi_msg_lcp_ethertype_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lcp_ethertype_get_reply>()
{
  return ::vapi_msg_id_lcp_ethertype_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lcp_ethertype_get_reply>>()
{
  return ::vapi_msg_id_lcp_ethertype_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lcp_ethertype_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lcp_ethertype_get_reply>(vapi_msg_id_lcp_ethertype_get_reply);
}

template class Msg<vapi_msg_lcp_ethertype_get_reply>;

using Lcp_ethertype_get_reply = Msg<vapi_msg_lcp_ethertype_get_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_lcp_itf_pair_replace_begin>(vapi_msg_lcp_itf_pair_replace_begin *msg)
{
  vapi_msg_lcp_itf_pair_replace_begin_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lcp_itf_pair_replace_begin>(vapi_msg_lcp_itf_pair_replace_begin *msg)
{
  vapi_msg_lcp_itf_pair_replace_begin_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lcp_itf_pair_replace_begin>()
{
  return ::vapi_msg_id_lcp_itf_pair_replace_begin; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lcp_itf_pair_replace_begin>>()
{
  return ::vapi_msg_id_lcp_itf_pair_replace_begin; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lcp_itf_pair_replace_begin()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lcp_itf_pair_replace_begin>(vapi_msg_id_lcp_itf_pair_replace_begin);
}

template <> inline vapi_msg_lcp_itf_pair_replace_begin* vapi_alloc<vapi_msg_lcp_itf_pair_replace_begin>(Connection &con)
{
  vapi_msg_lcp_itf_pair_replace_begin* result = vapi_alloc_lcp_itf_pair_replace_begin(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lcp_itf_pair_replace_begin>;

template class Request<vapi_msg_lcp_itf_pair_replace_begin, vapi_msg_lcp_itf_pair_replace_begin_reply>;

using Lcp_itf_pair_replace_begin = Request<vapi_msg_lcp_itf_pair_replace_begin, vapi_msg_lcp_itf_pair_replace_begin_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_lcp_itf_pair_replace_begin_reply>(vapi_msg_lcp_itf_pair_replace_begin_reply *msg)
{
  vapi_msg_lcp_itf_pair_replace_begin_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lcp_itf_pair_replace_begin_reply>(vapi_msg_lcp_itf_pair_replace_begin_reply *msg)
{
  vapi_msg_lcp_itf_pair_replace_begin_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lcp_itf_pair_replace_begin_reply>()
{
  return ::vapi_msg_id_lcp_itf_pair_replace_begin_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lcp_itf_pair_replace_begin_reply>>()
{
  return ::vapi_msg_id_lcp_itf_pair_replace_begin_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lcp_itf_pair_replace_begin_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lcp_itf_pair_replace_begin_reply>(vapi_msg_id_lcp_itf_pair_replace_begin_reply);
}

template class Msg<vapi_msg_lcp_itf_pair_replace_begin_reply>;

using Lcp_itf_pair_replace_begin_reply = Msg<vapi_msg_lcp_itf_pair_replace_begin_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_lcp_itf_pair_replace_end>(vapi_msg_lcp_itf_pair_replace_end *msg)
{
  vapi_msg_lcp_itf_pair_replace_end_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lcp_itf_pair_replace_end>(vapi_msg_lcp_itf_pair_replace_end *msg)
{
  vapi_msg_lcp_itf_pair_replace_end_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lcp_itf_pair_replace_end>()
{
  return ::vapi_msg_id_lcp_itf_pair_replace_end; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lcp_itf_pair_replace_end>>()
{
  return ::vapi_msg_id_lcp_itf_pair_replace_end; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lcp_itf_pair_replace_end()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lcp_itf_pair_replace_end>(vapi_msg_id_lcp_itf_pair_replace_end);
}

template <> inline vapi_msg_lcp_itf_pair_replace_end* vapi_alloc<vapi_msg_lcp_itf_pair_replace_end>(Connection &con)
{
  vapi_msg_lcp_itf_pair_replace_end* result = vapi_alloc_lcp_itf_pair_replace_end(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lcp_itf_pair_replace_end>;

template class Request<vapi_msg_lcp_itf_pair_replace_end, vapi_msg_lcp_itf_pair_replace_end_reply>;

using Lcp_itf_pair_replace_end = Request<vapi_msg_lcp_itf_pair_replace_end, vapi_msg_lcp_itf_pair_replace_end_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_lcp_itf_pair_replace_end_reply>(vapi_msg_lcp_itf_pair_replace_end_reply *msg)
{
  vapi_msg_lcp_itf_pair_replace_end_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lcp_itf_pair_replace_end_reply>(vapi_msg_lcp_itf_pair_replace_end_reply *msg)
{
  vapi_msg_lcp_itf_pair_replace_end_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lcp_itf_pair_replace_end_reply>()
{
  return ::vapi_msg_id_lcp_itf_pair_replace_end_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lcp_itf_pair_replace_end_reply>>()
{
  return ::vapi_msg_id_lcp_itf_pair_replace_end_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lcp_itf_pair_replace_end_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lcp_itf_pair_replace_end_reply>(vapi_msg_id_lcp_itf_pair_replace_end_reply);
}

template class Msg<vapi_msg_lcp_itf_pair_replace_end_reply>;

using Lcp_itf_pair_replace_end_reply = Msg<vapi_msg_lcp_itf_pair_replace_end_reply>;
}
#endif
