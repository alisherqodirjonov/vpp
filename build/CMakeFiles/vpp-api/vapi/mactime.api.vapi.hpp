#ifndef __included_hpp_mactime_api_json
#define __included_hpp_mactime_api_json

#include <vapi/vapi.hpp>
#include <vapi/mactime.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_mactime_enable_disable>(vapi_msg_mactime_enable_disable *msg)
{
  vapi_msg_mactime_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_mactime_enable_disable>(vapi_msg_mactime_enable_disable *msg)
{
  vapi_msg_mactime_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_mactime_enable_disable>()
{
  return ::vapi_msg_id_mactime_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_mactime_enable_disable>>()
{
  return ::vapi_msg_id_mactime_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_mactime_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_mactime_enable_disable>(vapi_msg_id_mactime_enable_disable);
}

template <> inline vapi_msg_mactime_enable_disable* vapi_alloc<vapi_msg_mactime_enable_disable>(Connection &con)
{
  vapi_msg_mactime_enable_disable* result = vapi_alloc_mactime_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_mactime_enable_disable>;

template class Request<vapi_msg_mactime_enable_disable, vapi_msg_mactime_enable_disable_reply>;

using Mactime_enable_disable = Request<vapi_msg_mactime_enable_disable, vapi_msg_mactime_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_mactime_enable_disable_reply>(vapi_msg_mactime_enable_disable_reply *msg)
{
  vapi_msg_mactime_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_mactime_enable_disable_reply>(vapi_msg_mactime_enable_disable_reply *msg)
{
  vapi_msg_mactime_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_mactime_enable_disable_reply>()
{
  return ::vapi_msg_id_mactime_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_mactime_enable_disable_reply>>()
{
  return ::vapi_msg_id_mactime_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_mactime_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_mactime_enable_disable_reply>(vapi_msg_id_mactime_enable_disable_reply);
}

template class Msg<vapi_msg_mactime_enable_disable_reply>;

using Mactime_enable_disable_reply = Msg<vapi_msg_mactime_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_mactime_add_del_range>(vapi_msg_mactime_add_del_range *msg)
{
  vapi_msg_mactime_add_del_range_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_mactime_add_del_range>(vapi_msg_mactime_add_del_range *msg)
{
  vapi_msg_mactime_add_del_range_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_mactime_add_del_range>()
{
  return ::vapi_msg_id_mactime_add_del_range; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_mactime_add_del_range>>()
{
  return ::vapi_msg_id_mactime_add_del_range; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_mactime_add_del_range()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_mactime_add_del_range>(vapi_msg_id_mactime_add_del_range);
}

template <> inline vapi_msg_mactime_add_del_range* vapi_alloc<vapi_msg_mactime_add_del_range, size_t>(Connection &con, size_t _ranges_array_size)
{
  vapi_msg_mactime_add_del_range* result = vapi_alloc_mactime_add_del_range(con.vapi_ctx, _ranges_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_mactime_add_del_range>;

template class Request<vapi_msg_mactime_add_del_range, vapi_msg_mactime_add_del_range_reply, size_t>;

using Mactime_add_del_range = Request<vapi_msg_mactime_add_del_range, vapi_msg_mactime_add_del_range_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_mactime_add_del_range_reply>(vapi_msg_mactime_add_del_range_reply *msg)
{
  vapi_msg_mactime_add_del_range_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_mactime_add_del_range_reply>(vapi_msg_mactime_add_del_range_reply *msg)
{
  vapi_msg_mactime_add_del_range_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_mactime_add_del_range_reply>()
{
  return ::vapi_msg_id_mactime_add_del_range_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_mactime_add_del_range_reply>>()
{
  return ::vapi_msg_id_mactime_add_del_range_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_mactime_add_del_range_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_mactime_add_del_range_reply>(vapi_msg_id_mactime_add_del_range_reply);
}

template class Msg<vapi_msg_mactime_add_del_range_reply>;

using Mactime_add_del_range_reply = Msg<vapi_msg_mactime_add_del_range_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_mactime_dump>(vapi_msg_mactime_dump *msg)
{
  vapi_msg_mactime_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_mactime_dump>(vapi_msg_mactime_dump *msg)
{
  vapi_msg_mactime_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_mactime_dump>()
{
  return ::vapi_msg_id_mactime_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_mactime_dump>>()
{
  return ::vapi_msg_id_mactime_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_mactime_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_mactime_dump>(vapi_msg_id_mactime_dump);
}

template <> inline vapi_msg_mactime_dump* vapi_alloc<vapi_msg_mactime_dump>(Connection &con)
{
  vapi_msg_mactime_dump* result = vapi_alloc_mactime_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_mactime_dump>;

template class Dump<vapi_msg_mactime_dump, vapi_msg_mactime_details>;

using Mactime_dump = Dump<vapi_msg_mactime_dump, vapi_msg_mactime_details>;

template <> inline void vapi_swap_to_be<vapi_msg_mactime_details>(vapi_msg_mactime_details *msg)
{
  vapi_msg_mactime_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_mactime_details>(vapi_msg_mactime_details *msg)
{
  vapi_msg_mactime_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_mactime_details>()
{
  return ::vapi_msg_id_mactime_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_mactime_details>>()
{
  return ::vapi_msg_id_mactime_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_mactime_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_mactime_details>(vapi_msg_id_mactime_details);
}

template class Msg<vapi_msg_mactime_details>;

using Mactime_details = Msg<vapi_msg_mactime_details>;
}
#endif
