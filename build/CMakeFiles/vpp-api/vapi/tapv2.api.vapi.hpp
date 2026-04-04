#ifndef __included_hpp_tapv2_api_json
#define __included_hpp_tapv2_api_json

#include <vapi/vapi.hpp>
#include <vapi/tapv2.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_tap_create_v3>(vapi_msg_tap_create_v3 *msg)
{
  vapi_msg_tap_create_v3_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_tap_create_v3>(vapi_msg_tap_create_v3 *msg)
{
  vapi_msg_tap_create_v3_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_tap_create_v3>()
{
  return ::vapi_msg_id_tap_create_v3; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_tap_create_v3>>()
{
  return ::vapi_msg_id_tap_create_v3; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_tap_create_v3()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_tap_create_v3>(vapi_msg_id_tap_create_v3);
}

template <> inline vapi_msg_tap_create_v3* vapi_alloc<vapi_msg_tap_create_v3, size_t>(Connection &con, size_t tag_buf_array_size)
{
  vapi_msg_tap_create_v3* result = vapi_alloc_tap_create_v3(con.vapi_ctx, tag_buf_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_tap_create_v3>;

template class Request<vapi_msg_tap_create_v3, vapi_msg_tap_create_v3_reply, size_t>;

using Tap_create_v3 = Request<vapi_msg_tap_create_v3, vapi_msg_tap_create_v3_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_tap_create_v3_reply>(vapi_msg_tap_create_v3_reply *msg)
{
  vapi_msg_tap_create_v3_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_tap_create_v3_reply>(vapi_msg_tap_create_v3_reply *msg)
{
  vapi_msg_tap_create_v3_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_tap_create_v3_reply>()
{
  return ::vapi_msg_id_tap_create_v3_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_tap_create_v3_reply>>()
{
  return ::vapi_msg_id_tap_create_v3_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_tap_create_v3_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_tap_create_v3_reply>(vapi_msg_id_tap_create_v3_reply);
}

template class Msg<vapi_msg_tap_create_v3_reply>;

using Tap_create_v3_reply = Msg<vapi_msg_tap_create_v3_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_tap_create_v2>(vapi_msg_tap_create_v2 *msg)
{
  vapi_msg_tap_create_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_tap_create_v2>(vapi_msg_tap_create_v2 *msg)
{
  vapi_msg_tap_create_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_tap_create_v2>()
{
  return ::vapi_msg_id_tap_create_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_tap_create_v2>>()
{
  return ::vapi_msg_id_tap_create_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_tap_create_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_tap_create_v2>(vapi_msg_id_tap_create_v2);
}

template <> inline vapi_msg_tap_create_v2* vapi_alloc<vapi_msg_tap_create_v2, size_t>(Connection &con, size_t tag_buf_array_size)
{
  vapi_msg_tap_create_v2* result = vapi_alloc_tap_create_v2(con.vapi_ctx, tag_buf_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_tap_create_v2>;

template class Request<vapi_msg_tap_create_v2, vapi_msg_tap_create_v2_reply, size_t>;

using Tap_create_v2 = Request<vapi_msg_tap_create_v2, vapi_msg_tap_create_v2_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_tap_create_v2_reply>(vapi_msg_tap_create_v2_reply *msg)
{
  vapi_msg_tap_create_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_tap_create_v2_reply>(vapi_msg_tap_create_v2_reply *msg)
{
  vapi_msg_tap_create_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_tap_create_v2_reply>()
{
  return ::vapi_msg_id_tap_create_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_tap_create_v2_reply>>()
{
  return ::vapi_msg_id_tap_create_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_tap_create_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_tap_create_v2_reply>(vapi_msg_id_tap_create_v2_reply);
}

template class Msg<vapi_msg_tap_create_v2_reply>;

using Tap_create_v2_reply = Msg<vapi_msg_tap_create_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_tap_delete_v2>(vapi_msg_tap_delete_v2 *msg)
{
  vapi_msg_tap_delete_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_tap_delete_v2>(vapi_msg_tap_delete_v2 *msg)
{
  vapi_msg_tap_delete_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_tap_delete_v2>()
{
  return ::vapi_msg_id_tap_delete_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_tap_delete_v2>>()
{
  return ::vapi_msg_id_tap_delete_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_tap_delete_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_tap_delete_v2>(vapi_msg_id_tap_delete_v2);
}

template <> inline vapi_msg_tap_delete_v2* vapi_alloc<vapi_msg_tap_delete_v2>(Connection &con)
{
  vapi_msg_tap_delete_v2* result = vapi_alloc_tap_delete_v2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_tap_delete_v2>;

template class Request<vapi_msg_tap_delete_v2, vapi_msg_tap_delete_v2_reply>;

using Tap_delete_v2 = Request<vapi_msg_tap_delete_v2, vapi_msg_tap_delete_v2_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_tap_delete_v2_reply>(vapi_msg_tap_delete_v2_reply *msg)
{
  vapi_msg_tap_delete_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_tap_delete_v2_reply>(vapi_msg_tap_delete_v2_reply *msg)
{
  vapi_msg_tap_delete_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_tap_delete_v2_reply>()
{
  return ::vapi_msg_id_tap_delete_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_tap_delete_v2_reply>>()
{
  return ::vapi_msg_id_tap_delete_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_tap_delete_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_tap_delete_v2_reply>(vapi_msg_id_tap_delete_v2_reply);
}

template class Msg<vapi_msg_tap_delete_v2_reply>;

using Tap_delete_v2_reply = Msg<vapi_msg_tap_delete_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_tap_v2_dump>(vapi_msg_sw_interface_tap_v2_dump *msg)
{
  vapi_msg_sw_interface_tap_v2_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_tap_v2_dump>(vapi_msg_sw_interface_tap_v2_dump *msg)
{
  vapi_msg_sw_interface_tap_v2_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_tap_v2_dump>()
{
  return ::vapi_msg_id_sw_interface_tap_v2_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_tap_v2_dump>>()
{
  return ::vapi_msg_id_sw_interface_tap_v2_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_tap_v2_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_tap_v2_dump>(vapi_msg_id_sw_interface_tap_v2_dump);
}

template <> inline vapi_msg_sw_interface_tap_v2_dump* vapi_alloc<vapi_msg_sw_interface_tap_v2_dump>(Connection &con)
{
  vapi_msg_sw_interface_tap_v2_dump* result = vapi_alloc_sw_interface_tap_v2_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_tap_v2_dump>;

template class Dump<vapi_msg_sw_interface_tap_v2_dump, vapi_msg_sw_interface_tap_v2_details>;

using Sw_interface_tap_v2_dump = Dump<vapi_msg_sw_interface_tap_v2_dump, vapi_msg_sw_interface_tap_v2_details>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_tap_v2_details>(vapi_msg_sw_interface_tap_v2_details *msg)
{
  vapi_msg_sw_interface_tap_v2_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_tap_v2_details>(vapi_msg_sw_interface_tap_v2_details *msg)
{
  vapi_msg_sw_interface_tap_v2_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_tap_v2_details>()
{
  return ::vapi_msg_id_sw_interface_tap_v2_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_tap_v2_details>>()
{
  return ::vapi_msg_id_sw_interface_tap_v2_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_tap_v2_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_tap_v2_details>(vapi_msg_id_sw_interface_tap_v2_details);
}

template class Msg<vapi_msg_sw_interface_tap_v2_details>;

using Sw_interface_tap_v2_details = Msg<vapi_msg_sw_interface_tap_v2_details>;
}
#endif
