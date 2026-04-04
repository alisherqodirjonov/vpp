#ifndef __included_hpp_pppoe_api_json
#define __included_hpp_pppoe_api_json

#include <vapi/vapi.hpp>
#include <vapi/pppoe.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_pppoe_add_del_session>(vapi_msg_pppoe_add_del_session *msg)
{
  vapi_msg_pppoe_add_del_session_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pppoe_add_del_session>(vapi_msg_pppoe_add_del_session *msg)
{
  vapi_msg_pppoe_add_del_session_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pppoe_add_del_session>()
{
  return ::vapi_msg_id_pppoe_add_del_session; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pppoe_add_del_session>>()
{
  return ::vapi_msg_id_pppoe_add_del_session; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pppoe_add_del_session()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pppoe_add_del_session>(vapi_msg_id_pppoe_add_del_session);
}

template <> inline vapi_msg_pppoe_add_del_session* vapi_alloc<vapi_msg_pppoe_add_del_session>(Connection &con)
{
  vapi_msg_pppoe_add_del_session* result = vapi_alloc_pppoe_add_del_session(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_pppoe_add_del_session>;

template class Request<vapi_msg_pppoe_add_del_session, vapi_msg_pppoe_add_del_session_reply>;

using Pppoe_add_del_session = Request<vapi_msg_pppoe_add_del_session, vapi_msg_pppoe_add_del_session_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_pppoe_add_del_session_reply>(vapi_msg_pppoe_add_del_session_reply *msg)
{
  vapi_msg_pppoe_add_del_session_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pppoe_add_del_session_reply>(vapi_msg_pppoe_add_del_session_reply *msg)
{
  vapi_msg_pppoe_add_del_session_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pppoe_add_del_session_reply>()
{
  return ::vapi_msg_id_pppoe_add_del_session_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pppoe_add_del_session_reply>>()
{
  return ::vapi_msg_id_pppoe_add_del_session_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pppoe_add_del_session_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pppoe_add_del_session_reply>(vapi_msg_id_pppoe_add_del_session_reply);
}

template class Msg<vapi_msg_pppoe_add_del_session_reply>;

using Pppoe_add_del_session_reply = Msg<vapi_msg_pppoe_add_del_session_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_pppoe_session_dump>(vapi_msg_pppoe_session_dump *msg)
{
  vapi_msg_pppoe_session_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pppoe_session_dump>(vapi_msg_pppoe_session_dump *msg)
{
  vapi_msg_pppoe_session_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pppoe_session_dump>()
{
  return ::vapi_msg_id_pppoe_session_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pppoe_session_dump>>()
{
  return ::vapi_msg_id_pppoe_session_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pppoe_session_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pppoe_session_dump>(vapi_msg_id_pppoe_session_dump);
}

template <> inline vapi_msg_pppoe_session_dump* vapi_alloc<vapi_msg_pppoe_session_dump>(Connection &con)
{
  vapi_msg_pppoe_session_dump* result = vapi_alloc_pppoe_session_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_pppoe_session_dump>;

template class Dump<vapi_msg_pppoe_session_dump, vapi_msg_pppoe_session_details>;

using Pppoe_session_dump = Dump<vapi_msg_pppoe_session_dump, vapi_msg_pppoe_session_details>;

template <> inline void vapi_swap_to_be<vapi_msg_pppoe_session_details>(vapi_msg_pppoe_session_details *msg)
{
  vapi_msg_pppoe_session_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pppoe_session_details>(vapi_msg_pppoe_session_details *msg)
{
  vapi_msg_pppoe_session_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pppoe_session_details>()
{
  return ::vapi_msg_id_pppoe_session_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pppoe_session_details>>()
{
  return ::vapi_msg_id_pppoe_session_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pppoe_session_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pppoe_session_details>(vapi_msg_id_pppoe_session_details);
}

template class Msg<vapi_msg_pppoe_session_details>;

using Pppoe_session_details = Msg<vapi_msg_pppoe_session_details>;
template <> inline void vapi_swap_to_be<vapi_msg_pppoe_add_del_cp>(vapi_msg_pppoe_add_del_cp *msg)
{
  vapi_msg_pppoe_add_del_cp_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pppoe_add_del_cp>(vapi_msg_pppoe_add_del_cp *msg)
{
  vapi_msg_pppoe_add_del_cp_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pppoe_add_del_cp>()
{
  return ::vapi_msg_id_pppoe_add_del_cp; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pppoe_add_del_cp>>()
{
  return ::vapi_msg_id_pppoe_add_del_cp; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pppoe_add_del_cp()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pppoe_add_del_cp>(vapi_msg_id_pppoe_add_del_cp);
}

template <> inline vapi_msg_pppoe_add_del_cp* vapi_alloc<vapi_msg_pppoe_add_del_cp>(Connection &con)
{
  vapi_msg_pppoe_add_del_cp* result = vapi_alloc_pppoe_add_del_cp(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_pppoe_add_del_cp>;

template class Request<vapi_msg_pppoe_add_del_cp, vapi_msg_pppoe_add_del_cp_reply>;

using Pppoe_add_del_cp = Request<vapi_msg_pppoe_add_del_cp, vapi_msg_pppoe_add_del_cp_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_pppoe_add_del_cp_reply>(vapi_msg_pppoe_add_del_cp_reply *msg)
{
  vapi_msg_pppoe_add_del_cp_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pppoe_add_del_cp_reply>(vapi_msg_pppoe_add_del_cp_reply *msg)
{
  vapi_msg_pppoe_add_del_cp_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pppoe_add_del_cp_reply>()
{
  return ::vapi_msg_id_pppoe_add_del_cp_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pppoe_add_del_cp_reply>>()
{
  return ::vapi_msg_id_pppoe_add_del_cp_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pppoe_add_del_cp_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pppoe_add_del_cp_reply>(vapi_msg_id_pppoe_add_del_cp_reply);
}

template class Msg<vapi_msg_pppoe_add_del_cp_reply>;

using Pppoe_add_del_cp_reply = Msg<vapi_msg_pppoe_add_del_cp_reply>;
}
#endif
