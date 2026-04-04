#ifndef __included_hpp_fib_api_json
#define __included_hpp_fib_api_json

#include <vapi/vapi.hpp>
#include <vapi/fib.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_fib_source_add>(vapi_msg_fib_source_add *msg)
{
  vapi_msg_fib_source_add_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_fib_source_add>(vapi_msg_fib_source_add *msg)
{
  vapi_msg_fib_source_add_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_fib_source_add>()
{
  return ::vapi_msg_id_fib_source_add; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_fib_source_add>>()
{
  return ::vapi_msg_id_fib_source_add; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_fib_source_add()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_fib_source_add>(vapi_msg_id_fib_source_add);
}

template <> inline vapi_msg_fib_source_add* vapi_alloc<vapi_msg_fib_source_add>(Connection &con)
{
  vapi_msg_fib_source_add* result = vapi_alloc_fib_source_add(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_fib_source_add>;

template class Request<vapi_msg_fib_source_add, vapi_msg_fib_source_add_reply>;

using Fib_source_add = Request<vapi_msg_fib_source_add, vapi_msg_fib_source_add_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_fib_source_add_reply>(vapi_msg_fib_source_add_reply *msg)
{
  vapi_msg_fib_source_add_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_fib_source_add_reply>(vapi_msg_fib_source_add_reply *msg)
{
  vapi_msg_fib_source_add_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_fib_source_add_reply>()
{
  return ::vapi_msg_id_fib_source_add_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_fib_source_add_reply>>()
{
  return ::vapi_msg_id_fib_source_add_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_fib_source_add_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_fib_source_add_reply>(vapi_msg_id_fib_source_add_reply);
}

template class Msg<vapi_msg_fib_source_add_reply>;

using Fib_source_add_reply = Msg<vapi_msg_fib_source_add_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_fib_source_dump>(vapi_msg_fib_source_dump *msg)
{
  vapi_msg_fib_source_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_fib_source_dump>(vapi_msg_fib_source_dump *msg)
{
  vapi_msg_fib_source_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_fib_source_dump>()
{
  return ::vapi_msg_id_fib_source_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_fib_source_dump>>()
{
  return ::vapi_msg_id_fib_source_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_fib_source_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_fib_source_dump>(vapi_msg_id_fib_source_dump);
}

template <> inline vapi_msg_fib_source_dump* vapi_alloc<vapi_msg_fib_source_dump>(Connection &con)
{
  vapi_msg_fib_source_dump* result = vapi_alloc_fib_source_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_fib_source_dump>;

template class Dump<vapi_msg_fib_source_dump, vapi_msg_fib_source_details>;

using Fib_source_dump = Dump<vapi_msg_fib_source_dump, vapi_msg_fib_source_details>;

template <> inline void vapi_swap_to_be<vapi_msg_fib_source_details>(vapi_msg_fib_source_details *msg)
{
  vapi_msg_fib_source_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_fib_source_details>(vapi_msg_fib_source_details *msg)
{
  vapi_msg_fib_source_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_fib_source_details>()
{
  return ::vapi_msg_id_fib_source_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_fib_source_details>>()
{
  return ::vapi_msg_id_fib_source_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_fib_source_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_fib_source_details>(vapi_msg_id_fib_source_details);
}

template class Msg<vapi_msg_fib_source_details>;

using Fib_source_details = Msg<vapi_msg_fib_source_details>;
}
#endif
