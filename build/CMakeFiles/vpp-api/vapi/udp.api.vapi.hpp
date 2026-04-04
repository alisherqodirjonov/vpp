#ifndef __included_hpp_udp_api_json
#define __included_hpp_udp_api_json

#include <vapi/vapi.hpp>
#include <vapi/udp.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_udp_encap_add>(vapi_msg_udp_encap_add *msg)
{
  vapi_msg_udp_encap_add_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_udp_encap_add>(vapi_msg_udp_encap_add *msg)
{
  vapi_msg_udp_encap_add_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_udp_encap_add>()
{
  return ::vapi_msg_id_udp_encap_add; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_udp_encap_add>>()
{
  return ::vapi_msg_id_udp_encap_add; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_udp_encap_add()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_udp_encap_add>(vapi_msg_id_udp_encap_add);
}

template <> inline vapi_msg_udp_encap_add* vapi_alloc<vapi_msg_udp_encap_add>(Connection &con)
{
  vapi_msg_udp_encap_add* result = vapi_alloc_udp_encap_add(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_udp_encap_add>;

template class Request<vapi_msg_udp_encap_add, vapi_msg_udp_encap_add_reply>;

using Udp_encap_add = Request<vapi_msg_udp_encap_add, vapi_msg_udp_encap_add_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_udp_encap_add_reply>(vapi_msg_udp_encap_add_reply *msg)
{
  vapi_msg_udp_encap_add_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_udp_encap_add_reply>(vapi_msg_udp_encap_add_reply *msg)
{
  vapi_msg_udp_encap_add_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_udp_encap_add_reply>()
{
  return ::vapi_msg_id_udp_encap_add_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_udp_encap_add_reply>>()
{
  return ::vapi_msg_id_udp_encap_add_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_udp_encap_add_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_udp_encap_add_reply>(vapi_msg_id_udp_encap_add_reply);
}

template class Msg<vapi_msg_udp_encap_add_reply>;

using Udp_encap_add_reply = Msg<vapi_msg_udp_encap_add_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_udp_encap_del>(vapi_msg_udp_encap_del *msg)
{
  vapi_msg_udp_encap_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_udp_encap_del>(vapi_msg_udp_encap_del *msg)
{
  vapi_msg_udp_encap_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_udp_encap_del>()
{
  return ::vapi_msg_id_udp_encap_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_udp_encap_del>>()
{
  return ::vapi_msg_id_udp_encap_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_udp_encap_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_udp_encap_del>(vapi_msg_id_udp_encap_del);
}

template <> inline vapi_msg_udp_encap_del* vapi_alloc<vapi_msg_udp_encap_del>(Connection &con)
{
  vapi_msg_udp_encap_del* result = vapi_alloc_udp_encap_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_udp_encap_del>;

template class Request<vapi_msg_udp_encap_del, vapi_msg_udp_encap_del_reply>;

using Udp_encap_del = Request<vapi_msg_udp_encap_del, vapi_msg_udp_encap_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_udp_encap_del_reply>(vapi_msg_udp_encap_del_reply *msg)
{
  vapi_msg_udp_encap_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_udp_encap_del_reply>(vapi_msg_udp_encap_del_reply *msg)
{
  vapi_msg_udp_encap_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_udp_encap_del_reply>()
{
  return ::vapi_msg_id_udp_encap_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_udp_encap_del_reply>>()
{
  return ::vapi_msg_id_udp_encap_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_udp_encap_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_udp_encap_del_reply>(vapi_msg_id_udp_encap_del_reply);
}

template class Msg<vapi_msg_udp_encap_del_reply>;

using Udp_encap_del_reply = Msg<vapi_msg_udp_encap_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_udp_encap_dump>(vapi_msg_udp_encap_dump *msg)
{
  vapi_msg_udp_encap_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_udp_encap_dump>(vapi_msg_udp_encap_dump *msg)
{
  vapi_msg_udp_encap_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_udp_encap_dump>()
{
  return ::vapi_msg_id_udp_encap_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_udp_encap_dump>>()
{
  return ::vapi_msg_id_udp_encap_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_udp_encap_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_udp_encap_dump>(vapi_msg_id_udp_encap_dump);
}

template <> inline vapi_msg_udp_encap_dump* vapi_alloc<vapi_msg_udp_encap_dump>(Connection &con)
{
  vapi_msg_udp_encap_dump* result = vapi_alloc_udp_encap_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_udp_encap_dump>;

template class Dump<vapi_msg_udp_encap_dump, vapi_msg_udp_encap_details>;

using Udp_encap_dump = Dump<vapi_msg_udp_encap_dump, vapi_msg_udp_encap_details>;

template <> inline void vapi_swap_to_be<vapi_msg_udp_encap_details>(vapi_msg_udp_encap_details *msg)
{
  vapi_msg_udp_encap_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_udp_encap_details>(vapi_msg_udp_encap_details *msg)
{
  vapi_msg_udp_encap_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_udp_encap_details>()
{
  return ::vapi_msg_id_udp_encap_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_udp_encap_details>>()
{
  return ::vapi_msg_id_udp_encap_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_udp_encap_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_udp_encap_details>(vapi_msg_id_udp_encap_details);
}

template class Msg<vapi_msg_udp_encap_details>;

using Udp_encap_details = Msg<vapi_msg_udp_encap_details>;
template <> inline void vapi_swap_to_be<vapi_msg_udp_decap_add_del>(vapi_msg_udp_decap_add_del *msg)
{
  vapi_msg_udp_decap_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_udp_decap_add_del>(vapi_msg_udp_decap_add_del *msg)
{
  vapi_msg_udp_decap_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_udp_decap_add_del>()
{
  return ::vapi_msg_id_udp_decap_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_udp_decap_add_del>>()
{
  return ::vapi_msg_id_udp_decap_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_udp_decap_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_udp_decap_add_del>(vapi_msg_id_udp_decap_add_del);
}

template <> inline vapi_msg_udp_decap_add_del* vapi_alloc<vapi_msg_udp_decap_add_del>(Connection &con)
{
  vapi_msg_udp_decap_add_del* result = vapi_alloc_udp_decap_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_udp_decap_add_del>;

template class Request<vapi_msg_udp_decap_add_del, vapi_msg_udp_decap_add_del_reply>;

using Udp_decap_add_del = Request<vapi_msg_udp_decap_add_del, vapi_msg_udp_decap_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_udp_decap_add_del_reply>(vapi_msg_udp_decap_add_del_reply *msg)
{
  vapi_msg_udp_decap_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_udp_decap_add_del_reply>(vapi_msg_udp_decap_add_del_reply *msg)
{
  vapi_msg_udp_decap_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_udp_decap_add_del_reply>()
{
  return ::vapi_msg_id_udp_decap_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_udp_decap_add_del_reply>>()
{
  return ::vapi_msg_id_udp_decap_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_udp_decap_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_udp_decap_add_del_reply>(vapi_msg_id_udp_decap_add_del_reply);
}

template class Msg<vapi_msg_udp_decap_add_del_reply>;

using Udp_decap_add_del_reply = Msg<vapi_msg_udp_decap_add_del_reply>;
}
#endif
