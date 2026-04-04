#ifndef __included_hpp_gre_api_json
#define __included_hpp_gre_api_json

#include <vapi/vapi.hpp>
#include <vapi/gre.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_gre_tunnel_add_del>(vapi_msg_gre_tunnel_add_del *msg)
{
  vapi_msg_gre_tunnel_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gre_tunnel_add_del>(vapi_msg_gre_tunnel_add_del *msg)
{
  vapi_msg_gre_tunnel_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gre_tunnel_add_del>()
{
  return ::vapi_msg_id_gre_tunnel_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gre_tunnel_add_del>>()
{
  return ::vapi_msg_id_gre_tunnel_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gre_tunnel_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gre_tunnel_add_del>(vapi_msg_id_gre_tunnel_add_del);
}

template <> inline vapi_msg_gre_tunnel_add_del* vapi_alloc<vapi_msg_gre_tunnel_add_del>(Connection &con)
{
  vapi_msg_gre_tunnel_add_del* result = vapi_alloc_gre_tunnel_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_gre_tunnel_add_del>;

template class Request<vapi_msg_gre_tunnel_add_del, vapi_msg_gre_tunnel_add_del_reply>;

using Gre_tunnel_add_del = Request<vapi_msg_gre_tunnel_add_del, vapi_msg_gre_tunnel_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_gre_tunnel_add_del_reply>(vapi_msg_gre_tunnel_add_del_reply *msg)
{
  vapi_msg_gre_tunnel_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gre_tunnel_add_del_reply>(vapi_msg_gre_tunnel_add_del_reply *msg)
{
  vapi_msg_gre_tunnel_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gre_tunnel_add_del_reply>()
{
  return ::vapi_msg_id_gre_tunnel_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gre_tunnel_add_del_reply>>()
{
  return ::vapi_msg_id_gre_tunnel_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gre_tunnel_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gre_tunnel_add_del_reply>(vapi_msg_id_gre_tunnel_add_del_reply);
}

template class Msg<vapi_msg_gre_tunnel_add_del_reply>;

using Gre_tunnel_add_del_reply = Msg<vapi_msg_gre_tunnel_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_gre_tunnel_add_del_v2>(vapi_msg_gre_tunnel_add_del_v2 *msg)
{
  vapi_msg_gre_tunnel_add_del_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gre_tunnel_add_del_v2>(vapi_msg_gre_tunnel_add_del_v2 *msg)
{
  vapi_msg_gre_tunnel_add_del_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gre_tunnel_add_del_v2>()
{
  return ::vapi_msg_id_gre_tunnel_add_del_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gre_tunnel_add_del_v2>>()
{
  return ::vapi_msg_id_gre_tunnel_add_del_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gre_tunnel_add_del_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gre_tunnel_add_del_v2>(vapi_msg_id_gre_tunnel_add_del_v2);
}

template <> inline vapi_msg_gre_tunnel_add_del_v2* vapi_alloc<vapi_msg_gre_tunnel_add_del_v2>(Connection &con)
{
  vapi_msg_gre_tunnel_add_del_v2* result = vapi_alloc_gre_tunnel_add_del_v2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_gre_tunnel_add_del_v2>;

template class Request<vapi_msg_gre_tunnel_add_del_v2, vapi_msg_gre_tunnel_add_del_v2_reply>;

using Gre_tunnel_add_del_v2 = Request<vapi_msg_gre_tunnel_add_del_v2, vapi_msg_gre_tunnel_add_del_v2_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_gre_tunnel_add_del_v2_reply>(vapi_msg_gre_tunnel_add_del_v2_reply *msg)
{
  vapi_msg_gre_tunnel_add_del_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gre_tunnel_add_del_v2_reply>(vapi_msg_gre_tunnel_add_del_v2_reply *msg)
{
  vapi_msg_gre_tunnel_add_del_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gre_tunnel_add_del_v2_reply>()
{
  return ::vapi_msg_id_gre_tunnel_add_del_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gre_tunnel_add_del_v2_reply>>()
{
  return ::vapi_msg_id_gre_tunnel_add_del_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gre_tunnel_add_del_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gre_tunnel_add_del_v2_reply>(vapi_msg_id_gre_tunnel_add_del_v2_reply);
}

template class Msg<vapi_msg_gre_tunnel_add_del_v2_reply>;

using Gre_tunnel_add_del_v2_reply = Msg<vapi_msg_gre_tunnel_add_del_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_gre_tunnel_dump>(vapi_msg_gre_tunnel_dump *msg)
{
  vapi_msg_gre_tunnel_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gre_tunnel_dump>(vapi_msg_gre_tunnel_dump *msg)
{
  vapi_msg_gre_tunnel_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gre_tunnel_dump>()
{
  return ::vapi_msg_id_gre_tunnel_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gre_tunnel_dump>>()
{
  return ::vapi_msg_id_gre_tunnel_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gre_tunnel_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gre_tunnel_dump>(vapi_msg_id_gre_tunnel_dump);
}

template <> inline vapi_msg_gre_tunnel_dump* vapi_alloc<vapi_msg_gre_tunnel_dump>(Connection &con)
{
  vapi_msg_gre_tunnel_dump* result = vapi_alloc_gre_tunnel_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_gre_tunnel_dump>;

template class Request<vapi_msg_gre_tunnel_dump, vapi_msg_gre_tunnel_dump_reply>;

using Gre_tunnel_dump = Request<vapi_msg_gre_tunnel_dump, vapi_msg_gre_tunnel_dump_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_gre_tunnel_dump_reply>(vapi_msg_gre_tunnel_dump_reply *msg)
{
  vapi_msg_gre_tunnel_dump_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gre_tunnel_dump_reply>(vapi_msg_gre_tunnel_dump_reply *msg)
{
  vapi_msg_gre_tunnel_dump_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gre_tunnel_dump_reply>()
{
  return ::vapi_msg_id_gre_tunnel_dump_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gre_tunnel_dump_reply>>()
{
  return ::vapi_msg_id_gre_tunnel_dump_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gre_tunnel_dump_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gre_tunnel_dump_reply>(vapi_msg_id_gre_tunnel_dump_reply);
}

template class Msg<vapi_msg_gre_tunnel_dump_reply>;

using Gre_tunnel_dump_reply = Msg<vapi_msg_gre_tunnel_dump_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_gre_tunnel_dump_v2>(vapi_msg_gre_tunnel_dump_v2 *msg)
{
  vapi_msg_gre_tunnel_dump_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gre_tunnel_dump_v2>(vapi_msg_gre_tunnel_dump_v2 *msg)
{
  vapi_msg_gre_tunnel_dump_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gre_tunnel_dump_v2>()
{
  return ::vapi_msg_id_gre_tunnel_dump_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gre_tunnel_dump_v2>>()
{
  return ::vapi_msg_id_gre_tunnel_dump_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gre_tunnel_dump_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gre_tunnel_dump_v2>(vapi_msg_id_gre_tunnel_dump_v2);
}

template <> inline vapi_msg_gre_tunnel_dump_v2* vapi_alloc<vapi_msg_gre_tunnel_dump_v2>(Connection &con)
{
  vapi_msg_gre_tunnel_dump_v2* result = vapi_alloc_gre_tunnel_dump_v2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_gre_tunnel_dump_v2>;

template class Request<vapi_msg_gre_tunnel_dump_v2, vapi_msg_gre_tunnel_dump_v2_reply>;

using Gre_tunnel_dump_v2 = Request<vapi_msg_gre_tunnel_dump_v2, vapi_msg_gre_tunnel_dump_v2_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_gre_tunnel_dump_v2_reply>(vapi_msg_gre_tunnel_dump_v2_reply *msg)
{
  vapi_msg_gre_tunnel_dump_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gre_tunnel_dump_v2_reply>(vapi_msg_gre_tunnel_dump_v2_reply *msg)
{
  vapi_msg_gre_tunnel_dump_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gre_tunnel_dump_v2_reply>()
{
  return ::vapi_msg_id_gre_tunnel_dump_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gre_tunnel_dump_v2_reply>>()
{
  return ::vapi_msg_id_gre_tunnel_dump_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gre_tunnel_dump_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gre_tunnel_dump_v2_reply>(vapi_msg_id_gre_tunnel_dump_v2_reply);
}

template class Msg<vapi_msg_gre_tunnel_dump_v2_reply>;

using Gre_tunnel_dump_v2_reply = Msg<vapi_msg_gre_tunnel_dump_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_gre_tunnel_details>(vapi_msg_gre_tunnel_details *msg)
{
  vapi_msg_gre_tunnel_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gre_tunnel_details>(vapi_msg_gre_tunnel_details *msg)
{
  vapi_msg_gre_tunnel_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gre_tunnel_details>()
{
  return ::vapi_msg_id_gre_tunnel_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gre_tunnel_details>>()
{
  return ::vapi_msg_id_gre_tunnel_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gre_tunnel_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gre_tunnel_details>(vapi_msg_id_gre_tunnel_details);
}

template class Msg<vapi_msg_gre_tunnel_details>;

using Gre_tunnel_details = Msg<vapi_msg_gre_tunnel_details>;
template <> inline void vapi_swap_to_be<vapi_msg_gre_tunnel_details_v2>(vapi_msg_gre_tunnel_details_v2 *msg)
{
  vapi_msg_gre_tunnel_details_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gre_tunnel_details_v2>(vapi_msg_gre_tunnel_details_v2 *msg)
{
  vapi_msg_gre_tunnel_details_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gre_tunnel_details_v2>()
{
  return ::vapi_msg_id_gre_tunnel_details_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gre_tunnel_details_v2>>()
{
  return ::vapi_msg_id_gre_tunnel_details_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gre_tunnel_details_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gre_tunnel_details_v2>(vapi_msg_id_gre_tunnel_details_v2);
}

template class Msg<vapi_msg_gre_tunnel_details_v2>;

using Gre_tunnel_details_v2 = Msg<vapi_msg_gre_tunnel_details_v2>;
}
#endif
