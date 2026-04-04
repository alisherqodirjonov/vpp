#ifndef __included_hpp_punt_api_json
#define __included_hpp_punt_api_json

#include <vapi/vapi.hpp>
#include <vapi/punt.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_set_punt>(vapi_msg_set_punt *msg)
{
  vapi_msg_set_punt_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_set_punt>(vapi_msg_set_punt *msg)
{
  vapi_msg_set_punt_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_set_punt>()
{
  return ::vapi_msg_id_set_punt; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_set_punt>>()
{
  return ::vapi_msg_id_set_punt; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_set_punt()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_set_punt>(vapi_msg_id_set_punt);
}

template <> inline vapi_msg_set_punt* vapi_alloc<vapi_msg_set_punt>(Connection &con)
{
  vapi_msg_set_punt* result = vapi_alloc_set_punt(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_set_punt>;

template class Request<vapi_msg_set_punt, vapi_msg_set_punt_reply>;

using Set_punt = Request<vapi_msg_set_punt, vapi_msg_set_punt_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_set_punt_reply>(vapi_msg_set_punt_reply *msg)
{
  vapi_msg_set_punt_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_set_punt_reply>(vapi_msg_set_punt_reply *msg)
{
  vapi_msg_set_punt_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_set_punt_reply>()
{
  return ::vapi_msg_id_set_punt_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_set_punt_reply>>()
{
  return ::vapi_msg_id_set_punt_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_set_punt_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_set_punt_reply>(vapi_msg_id_set_punt_reply);
}

template class Msg<vapi_msg_set_punt_reply>;

using Set_punt_reply = Msg<vapi_msg_set_punt_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_punt_socket_register>(vapi_msg_punt_socket_register *msg)
{
  vapi_msg_punt_socket_register_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_punt_socket_register>(vapi_msg_punt_socket_register *msg)
{
  vapi_msg_punt_socket_register_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_punt_socket_register>()
{
  return ::vapi_msg_id_punt_socket_register; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_punt_socket_register>>()
{
  return ::vapi_msg_id_punt_socket_register; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_punt_socket_register()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_punt_socket_register>(vapi_msg_id_punt_socket_register);
}

template <> inline vapi_msg_punt_socket_register* vapi_alloc<vapi_msg_punt_socket_register>(Connection &con)
{
  vapi_msg_punt_socket_register* result = vapi_alloc_punt_socket_register(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_punt_socket_register>;

template class Request<vapi_msg_punt_socket_register, vapi_msg_punt_socket_register_reply>;

using Punt_socket_register = Request<vapi_msg_punt_socket_register, vapi_msg_punt_socket_register_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_punt_socket_register_reply>(vapi_msg_punt_socket_register_reply *msg)
{
  vapi_msg_punt_socket_register_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_punt_socket_register_reply>(vapi_msg_punt_socket_register_reply *msg)
{
  vapi_msg_punt_socket_register_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_punt_socket_register_reply>()
{
  return ::vapi_msg_id_punt_socket_register_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_punt_socket_register_reply>>()
{
  return ::vapi_msg_id_punt_socket_register_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_punt_socket_register_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_punt_socket_register_reply>(vapi_msg_id_punt_socket_register_reply);
}

template class Msg<vapi_msg_punt_socket_register_reply>;

using Punt_socket_register_reply = Msg<vapi_msg_punt_socket_register_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_punt_socket_dump>(vapi_msg_punt_socket_dump *msg)
{
  vapi_msg_punt_socket_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_punt_socket_dump>(vapi_msg_punt_socket_dump *msg)
{
  vapi_msg_punt_socket_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_punt_socket_dump>()
{
  return ::vapi_msg_id_punt_socket_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_punt_socket_dump>>()
{
  return ::vapi_msg_id_punt_socket_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_punt_socket_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_punt_socket_dump>(vapi_msg_id_punt_socket_dump);
}

template <> inline vapi_msg_punt_socket_dump* vapi_alloc<vapi_msg_punt_socket_dump>(Connection &con)
{
  vapi_msg_punt_socket_dump* result = vapi_alloc_punt_socket_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_punt_socket_dump>;

template class Dump<vapi_msg_punt_socket_dump, vapi_msg_punt_socket_details>;

using Punt_socket_dump = Dump<vapi_msg_punt_socket_dump, vapi_msg_punt_socket_details>;

template <> inline void vapi_swap_to_be<vapi_msg_punt_socket_details>(vapi_msg_punt_socket_details *msg)
{
  vapi_msg_punt_socket_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_punt_socket_details>(vapi_msg_punt_socket_details *msg)
{
  vapi_msg_punt_socket_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_punt_socket_details>()
{
  return ::vapi_msg_id_punt_socket_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_punt_socket_details>>()
{
  return ::vapi_msg_id_punt_socket_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_punt_socket_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_punt_socket_details>(vapi_msg_id_punt_socket_details);
}

template class Msg<vapi_msg_punt_socket_details>;

using Punt_socket_details = Msg<vapi_msg_punt_socket_details>;
template <> inline void vapi_swap_to_be<vapi_msg_punt_socket_deregister>(vapi_msg_punt_socket_deregister *msg)
{
  vapi_msg_punt_socket_deregister_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_punt_socket_deregister>(vapi_msg_punt_socket_deregister *msg)
{
  vapi_msg_punt_socket_deregister_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_punt_socket_deregister>()
{
  return ::vapi_msg_id_punt_socket_deregister; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_punt_socket_deregister>>()
{
  return ::vapi_msg_id_punt_socket_deregister; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_punt_socket_deregister()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_punt_socket_deregister>(vapi_msg_id_punt_socket_deregister);
}

template <> inline vapi_msg_punt_socket_deregister* vapi_alloc<vapi_msg_punt_socket_deregister>(Connection &con)
{
  vapi_msg_punt_socket_deregister* result = vapi_alloc_punt_socket_deregister(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_punt_socket_deregister>;

template class Request<vapi_msg_punt_socket_deregister, vapi_msg_punt_socket_deregister_reply>;

using Punt_socket_deregister = Request<vapi_msg_punt_socket_deregister, vapi_msg_punt_socket_deregister_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_punt_socket_deregister_reply>(vapi_msg_punt_socket_deregister_reply *msg)
{
  vapi_msg_punt_socket_deregister_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_punt_socket_deregister_reply>(vapi_msg_punt_socket_deregister_reply *msg)
{
  vapi_msg_punt_socket_deregister_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_punt_socket_deregister_reply>()
{
  return ::vapi_msg_id_punt_socket_deregister_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_punt_socket_deregister_reply>>()
{
  return ::vapi_msg_id_punt_socket_deregister_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_punt_socket_deregister_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_punt_socket_deregister_reply>(vapi_msg_id_punt_socket_deregister_reply);
}

template class Msg<vapi_msg_punt_socket_deregister_reply>;

using Punt_socket_deregister_reply = Msg<vapi_msg_punt_socket_deregister_reply>;
}
#endif
