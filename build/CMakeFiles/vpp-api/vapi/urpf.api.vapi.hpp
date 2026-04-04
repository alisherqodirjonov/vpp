#ifndef __included_hpp_urpf_api_json
#define __included_hpp_urpf_api_json

#include <vapi/vapi.hpp>
#include <vapi/urpf.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_urpf_update>(vapi_msg_urpf_update *msg)
{
  vapi_msg_urpf_update_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_urpf_update>(vapi_msg_urpf_update *msg)
{
  vapi_msg_urpf_update_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_urpf_update>()
{
  return ::vapi_msg_id_urpf_update; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_urpf_update>>()
{
  return ::vapi_msg_id_urpf_update; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_urpf_update()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_urpf_update>(vapi_msg_id_urpf_update);
}

template <> inline vapi_msg_urpf_update* vapi_alloc<vapi_msg_urpf_update>(Connection &con)
{
  vapi_msg_urpf_update* result = vapi_alloc_urpf_update(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_urpf_update>;

template class Request<vapi_msg_urpf_update, vapi_msg_urpf_update_reply>;

using Urpf_update = Request<vapi_msg_urpf_update, vapi_msg_urpf_update_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_urpf_update_reply>(vapi_msg_urpf_update_reply *msg)
{
  vapi_msg_urpf_update_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_urpf_update_reply>(vapi_msg_urpf_update_reply *msg)
{
  vapi_msg_urpf_update_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_urpf_update_reply>()
{
  return ::vapi_msg_id_urpf_update_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_urpf_update_reply>>()
{
  return ::vapi_msg_id_urpf_update_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_urpf_update_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_urpf_update_reply>(vapi_msg_id_urpf_update_reply);
}

template class Msg<vapi_msg_urpf_update_reply>;

using Urpf_update_reply = Msg<vapi_msg_urpf_update_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_urpf_update_v2>(vapi_msg_urpf_update_v2 *msg)
{
  vapi_msg_urpf_update_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_urpf_update_v2>(vapi_msg_urpf_update_v2 *msg)
{
  vapi_msg_urpf_update_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_urpf_update_v2>()
{
  return ::vapi_msg_id_urpf_update_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_urpf_update_v2>>()
{
  return ::vapi_msg_id_urpf_update_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_urpf_update_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_urpf_update_v2>(vapi_msg_id_urpf_update_v2);
}

template <> inline vapi_msg_urpf_update_v2* vapi_alloc<vapi_msg_urpf_update_v2>(Connection &con)
{
  vapi_msg_urpf_update_v2* result = vapi_alloc_urpf_update_v2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_urpf_update_v2>;

template class Request<vapi_msg_urpf_update_v2, vapi_msg_urpf_update_v2_reply>;

using Urpf_update_v2 = Request<vapi_msg_urpf_update_v2, vapi_msg_urpf_update_v2_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_urpf_update_v2_reply>(vapi_msg_urpf_update_v2_reply *msg)
{
  vapi_msg_urpf_update_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_urpf_update_v2_reply>(vapi_msg_urpf_update_v2_reply *msg)
{
  vapi_msg_urpf_update_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_urpf_update_v2_reply>()
{
  return ::vapi_msg_id_urpf_update_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_urpf_update_v2_reply>>()
{
  return ::vapi_msg_id_urpf_update_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_urpf_update_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_urpf_update_v2_reply>(vapi_msg_id_urpf_update_v2_reply);
}

template class Msg<vapi_msg_urpf_update_v2_reply>;

using Urpf_update_v2_reply = Msg<vapi_msg_urpf_update_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_urpf_interface_dump>(vapi_msg_urpf_interface_dump *msg)
{
  vapi_msg_urpf_interface_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_urpf_interface_dump>(vapi_msg_urpf_interface_dump *msg)
{
  vapi_msg_urpf_interface_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_urpf_interface_dump>()
{
  return ::vapi_msg_id_urpf_interface_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_urpf_interface_dump>>()
{
  return ::vapi_msg_id_urpf_interface_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_urpf_interface_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_urpf_interface_dump>(vapi_msg_id_urpf_interface_dump);
}

template <> inline vapi_msg_urpf_interface_dump* vapi_alloc<vapi_msg_urpf_interface_dump>(Connection &con)
{
  vapi_msg_urpf_interface_dump* result = vapi_alloc_urpf_interface_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_urpf_interface_dump>;

template class Dump<vapi_msg_urpf_interface_dump, vapi_msg_urpf_interface_details>;

using Urpf_interface_dump = Dump<vapi_msg_urpf_interface_dump, vapi_msg_urpf_interface_details>;

template <> inline void vapi_swap_to_be<vapi_msg_urpf_interface_details>(vapi_msg_urpf_interface_details *msg)
{
  vapi_msg_urpf_interface_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_urpf_interface_details>(vapi_msg_urpf_interface_details *msg)
{
  vapi_msg_urpf_interface_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_urpf_interface_details>()
{
  return ::vapi_msg_id_urpf_interface_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_urpf_interface_details>>()
{
  return ::vapi_msg_id_urpf_interface_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_urpf_interface_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_urpf_interface_details>(vapi_msg_id_urpf_interface_details);
}

template class Msg<vapi_msg_urpf_interface_details>;

using Urpf_interface_details = Msg<vapi_msg_urpf_interface_details>;
}
#endif
