#ifndef __included_hpp_fake_api_json
#define __included_hpp_fake_api_json

#include <vapi/vapi.hpp>
#include <fake.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_test_fake_msg>(vapi_msg_test_fake_msg *msg)
{
  vapi_msg_test_fake_msg_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_test_fake_msg>(vapi_msg_test_fake_msg *msg)
{
  vapi_msg_test_fake_msg_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_test_fake_msg>()
{
  return ::vapi_msg_id_test_fake_msg; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_test_fake_msg>>()
{
  return ::vapi_msg_id_test_fake_msg; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_test_fake_msg()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_test_fake_msg>(vapi_msg_id_test_fake_msg);
}

template <> inline vapi_msg_test_fake_msg* vapi_alloc<vapi_msg_test_fake_msg>(Connection &con)
{
  vapi_msg_test_fake_msg* result = vapi_alloc_test_fake_msg(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_test_fake_msg>;

template class Request<vapi_msg_test_fake_msg, vapi_msg_test_fake_msg_reply>;

using Test_fake_msg = Request<vapi_msg_test_fake_msg, vapi_msg_test_fake_msg_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_test_fake_msg_reply>(vapi_msg_test_fake_msg_reply *msg)
{
  vapi_msg_test_fake_msg_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_test_fake_msg_reply>(vapi_msg_test_fake_msg_reply *msg)
{
  vapi_msg_test_fake_msg_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_test_fake_msg_reply>()
{
  return ::vapi_msg_id_test_fake_msg_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_test_fake_msg_reply>>()
{
  return ::vapi_msg_id_test_fake_msg_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_test_fake_msg_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_test_fake_msg_reply>(vapi_msg_id_test_fake_msg_reply);
}

template class Msg<vapi_msg_test_fake_msg_reply>;

using Test_fake_msg_reply = Msg<vapi_msg_test_fake_msg_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_test_fake_dump>(vapi_msg_test_fake_dump *msg)
{
  vapi_msg_test_fake_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_test_fake_dump>(vapi_msg_test_fake_dump *msg)
{
  vapi_msg_test_fake_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_test_fake_dump>()
{
  return ::vapi_msg_id_test_fake_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_test_fake_dump>>()
{
  return ::vapi_msg_id_test_fake_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_test_fake_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_test_fake_dump>(vapi_msg_id_test_fake_dump);
}

template <> inline vapi_msg_test_fake_dump* vapi_alloc<vapi_msg_test_fake_dump>(Connection &con)
{
  vapi_msg_test_fake_dump* result = vapi_alloc_test_fake_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_test_fake_dump>;

template class Dump<vapi_msg_test_fake_dump, vapi_msg_test_fake_details>;

using Test_fake_dump = Dump<vapi_msg_test_fake_dump, vapi_msg_test_fake_details>;

template <> inline void vapi_swap_to_be<vapi_msg_test_fake_details>(vapi_msg_test_fake_details *msg)
{
  vapi_msg_test_fake_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_test_fake_details>(vapi_msg_test_fake_details *msg)
{
  vapi_msg_test_fake_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_test_fake_details>()
{
  return ::vapi_msg_id_test_fake_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_test_fake_details>>()
{
  return ::vapi_msg_id_test_fake_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_test_fake_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_test_fake_details>(vapi_msg_id_test_fake_details);
}

template class Msg<vapi_msg_test_fake_details>;

using Test_fake_details = Msg<vapi_msg_test_fake_details>;
}
#endif
