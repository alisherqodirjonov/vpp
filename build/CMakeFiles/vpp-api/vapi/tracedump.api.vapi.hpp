#ifndef __included_hpp_tracedump_api_json
#define __included_hpp_tracedump_api_json

#include <vapi/vapi.hpp>
#include <vapi/tracedump.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_trace_set_filters>(vapi_msg_trace_set_filters *msg)
{
  vapi_msg_trace_set_filters_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_trace_set_filters>(vapi_msg_trace_set_filters *msg)
{
  vapi_msg_trace_set_filters_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_trace_set_filters>()
{
  return ::vapi_msg_id_trace_set_filters; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_trace_set_filters>>()
{
  return ::vapi_msg_id_trace_set_filters; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_trace_set_filters()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_trace_set_filters>(vapi_msg_id_trace_set_filters);
}

template <> inline vapi_msg_trace_set_filters* vapi_alloc<vapi_msg_trace_set_filters>(Connection &con)
{
  vapi_msg_trace_set_filters* result = vapi_alloc_trace_set_filters(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_trace_set_filters>;

template class Request<vapi_msg_trace_set_filters, vapi_msg_trace_set_filters_reply>;

using Trace_set_filters = Request<vapi_msg_trace_set_filters, vapi_msg_trace_set_filters_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_trace_set_filters_reply>(vapi_msg_trace_set_filters_reply *msg)
{
  vapi_msg_trace_set_filters_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_trace_set_filters_reply>(vapi_msg_trace_set_filters_reply *msg)
{
  vapi_msg_trace_set_filters_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_trace_set_filters_reply>()
{
  return ::vapi_msg_id_trace_set_filters_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_trace_set_filters_reply>>()
{
  return ::vapi_msg_id_trace_set_filters_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_trace_set_filters_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_trace_set_filters_reply>(vapi_msg_id_trace_set_filters_reply);
}

template class Msg<vapi_msg_trace_set_filters_reply>;

using Trace_set_filters_reply = Msg<vapi_msg_trace_set_filters_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_trace_capture_packets>(vapi_msg_trace_capture_packets *msg)
{
  vapi_msg_trace_capture_packets_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_trace_capture_packets>(vapi_msg_trace_capture_packets *msg)
{
  vapi_msg_trace_capture_packets_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_trace_capture_packets>()
{
  return ::vapi_msg_id_trace_capture_packets; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_trace_capture_packets>>()
{
  return ::vapi_msg_id_trace_capture_packets; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_trace_capture_packets()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_trace_capture_packets>(vapi_msg_id_trace_capture_packets);
}

template <> inline vapi_msg_trace_capture_packets* vapi_alloc<vapi_msg_trace_capture_packets>(Connection &con)
{
  vapi_msg_trace_capture_packets* result = vapi_alloc_trace_capture_packets(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_trace_capture_packets>;

template class Request<vapi_msg_trace_capture_packets, vapi_msg_trace_capture_packets_reply>;

using Trace_capture_packets = Request<vapi_msg_trace_capture_packets, vapi_msg_trace_capture_packets_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_trace_capture_packets_reply>(vapi_msg_trace_capture_packets_reply *msg)
{
  vapi_msg_trace_capture_packets_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_trace_capture_packets_reply>(vapi_msg_trace_capture_packets_reply *msg)
{
  vapi_msg_trace_capture_packets_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_trace_capture_packets_reply>()
{
  return ::vapi_msg_id_trace_capture_packets_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_trace_capture_packets_reply>>()
{
  return ::vapi_msg_id_trace_capture_packets_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_trace_capture_packets_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_trace_capture_packets_reply>(vapi_msg_id_trace_capture_packets_reply);
}

template class Msg<vapi_msg_trace_capture_packets_reply>;

using Trace_capture_packets_reply = Msg<vapi_msg_trace_capture_packets_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_trace_clear_capture>(vapi_msg_trace_clear_capture *msg)
{
  vapi_msg_trace_clear_capture_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_trace_clear_capture>(vapi_msg_trace_clear_capture *msg)
{
  vapi_msg_trace_clear_capture_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_trace_clear_capture>()
{
  return ::vapi_msg_id_trace_clear_capture; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_trace_clear_capture>>()
{
  return ::vapi_msg_id_trace_clear_capture; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_trace_clear_capture()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_trace_clear_capture>(vapi_msg_id_trace_clear_capture);
}

template <> inline vapi_msg_trace_clear_capture* vapi_alloc<vapi_msg_trace_clear_capture>(Connection &con)
{
  vapi_msg_trace_clear_capture* result = vapi_alloc_trace_clear_capture(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_trace_clear_capture>;

template class Request<vapi_msg_trace_clear_capture, vapi_msg_trace_clear_capture_reply>;

using Trace_clear_capture = Request<vapi_msg_trace_clear_capture, vapi_msg_trace_clear_capture_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_trace_clear_capture_reply>(vapi_msg_trace_clear_capture_reply *msg)
{
  vapi_msg_trace_clear_capture_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_trace_clear_capture_reply>(vapi_msg_trace_clear_capture_reply *msg)
{
  vapi_msg_trace_clear_capture_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_trace_clear_capture_reply>()
{
  return ::vapi_msg_id_trace_clear_capture_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_trace_clear_capture_reply>>()
{
  return ::vapi_msg_id_trace_clear_capture_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_trace_clear_capture_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_trace_clear_capture_reply>(vapi_msg_id_trace_clear_capture_reply);
}

template class Msg<vapi_msg_trace_clear_capture_reply>;

using Trace_clear_capture_reply = Msg<vapi_msg_trace_clear_capture_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_trace_dump>(vapi_msg_trace_dump *msg)
{
  vapi_msg_trace_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_trace_dump>(vapi_msg_trace_dump *msg)
{
  vapi_msg_trace_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_trace_dump>()
{
  return ::vapi_msg_id_trace_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_trace_dump>>()
{
  return ::vapi_msg_id_trace_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_trace_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_trace_dump>(vapi_msg_id_trace_dump);
}

template <> inline vapi_msg_trace_dump* vapi_alloc<vapi_msg_trace_dump>(Connection &con)
{
  vapi_msg_trace_dump* result = vapi_alloc_trace_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_trace_dump>;

template class Stream<vapi_msg_trace_dump, vapi_msg_trace_dump_reply, vapi_msg_trace_details>;

using Trace_dump = Stream<vapi_msg_trace_dump, vapi_msg_trace_dump_reply, vapi_msg_trace_details>;

template <> inline void vapi_swap_to_be<vapi_msg_trace_dump_reply>(vapi_msg_trace_dump_reply *msg)
{
  vapi_msg_trace_dump_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_trace_dump_reply>(vapi_msg_trace_dump_reply *msg)
{
  vapi_msg_trace_dump_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_trace_dump_reply>()
{
  return ::vapi_msg_id_trace_dump_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_trace_dump_reply>>()
{
  return ::vapi_msg_id_trace_dump_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_trace_dump_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_trace_dump_reply>(vapi_msg_id_trace_dump_reply);
}

template class Msg<vapi_msg_trace_dump_reply>;

using Trace_dump_reply = Msg<vapi_msg_trace_dump_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_trace_details>(vapi_msg_trace_details *msg)
{
  vapi_msg_trace_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_trace_details>(vapi_msg_trace_details *msg)
{
  vapi_msg_trace_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_trace_details>()
{
  return ::vapi_msg_id_trace_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_trace_details>>()
{
  return ::vapi_msg_id_trace_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_trace_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_trace_details>(vapi_msg_id_trace_details);
}

template class Msg<vapi_msg_trace_details>;

template <> inline void vapi_swap_to_be<vapi_msg_trace_clear_cache>(vapi_msg_trace_clear_cache *msg)
{
  vapi_msg_trace_clear_cache_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_trace_clear_cache>(vapi_msg_trace_clear_cache *msg)
{
  vapi_msg_trace_clear_cache_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_trace_clear_cache>()
{
  return ::vapi_msg_id_trace_clear_cache; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_trace_clear_cache>>()
{
  return ::vapi_msg_id_trace_clear_cache; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_trace_clear_cache()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_trace_clear_cache>(vapi_msg_id_trace_clear_cache);
}

template <> inline vapi_msg_trace_clear_cache* vapi_alloc<vapi_msg_trace_clear_cache>(Connection &con)
{
  vapi_msg_trace_clear_cache* result = vapi_alloc_trace_clear_cache(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_trace_clear_cache>;

template class Request<vapi_msg_trace_clear_cache, vapi_msg_trace_clear_cache_reply>;

using Trace_clear_cache = Request<vapi_msg_trace_clear_cache, vapi_msg_trace_clear_cache_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_trace_clear_cache_reply>(vapi_msg_trace_clear_cache_reply *msg)
{
  vapi_msg_trace_clear_cache_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_trace_clear_cache_reply>(vapi_msg_trace_clear_cache_reply *msg)
{
  vapi_msg_trace_clear_cache_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_trace_clear_cache_reply>()
{
  return ::vapi_msg_id_trace_clear_cache_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_trace_clear_cache_reply>>()
{
  return ::vapi_msg_id_trace_clear_cache_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_trace_clear_cache_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_trace_clear_cache_reply>(vapi_msg_id_trace_clear_cache_reply);
}

template class Msg<vapi_msg_trace_clear_cache_reply>;

using Trace_clear_cache_reply = Msg<vapi_msg_trace_clear_cache_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_trace_v2_dump>(vapi_msg_trace_v2_dump *msg)
{
  vapi_msg_trace_v2_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_trace_v2_dump>(vapi_msg_trace_v2_dump *msg)
{
  vapi_msg_trace_v2_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_trace_v2_dump>()
{
  return ::vapi_msg_id_trace_v2_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_trace_v2_dump>>()
{
  return ::vapi_msg_id_trace_v2_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_trace_v2_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_trace_v2_dump>(vapi_msg_id_trace_v2_dump);
}

template <> inline vapi_msg_trace_v2_dump* vapi_alloc<vapi_msg_trace_v2_dump>(Connection &con)
{
  vapi_msg_trace_v2_dump* result = vapi_alloc_trace_v2_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_trace_v2_dump>;

template class Dump<vapi_msg_trace_v2_dump, vapi_msg_trace_v2_details>;

using Trace_v2_dump = Dump<vapi_msg_trace_v2_dump, vapi_msg_trace_v2_details>;

template <> inline void vapi_swap_to_be<vapi_msg_trace_v2_details>(vapi_msg_trace_v2_details *msg)
{
  vapi_msg_trace_v2_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_trace_v2_details>(vapi_msg_trace_v2_details *msg)
{
  vapi_msg_trace_v2_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_trace_v2_details>()
{
  return ::vapi_msg_id_trace_v2_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_trace_v2_details>>()
{
  return ::vapi_msg_id_trace_v2_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_trace_v2_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_trace_v2_details>(vapi_msg_id_trace_v2_details);
}

template class Msg<vapi_msg_trace_v2_details>;

using Trace_v2_details = Msg<vapi_msg_trace_v2_details>;
template <> inline void vapi_swap_to_be<vapi_msg_trace_set_filter_function>(vapi_msg_trace_set_filter_function *msg)
{
  vapi_msg_trace_set_filter_function_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_trace_set_filter_function>(vapi_msg_trace_set_filter_function *msg)
{
  vapi_msg_trace_set_filter_function_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_trace_set_filter_function>()
{
  return ::vapi_msg_id_trace_set_filter_function; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_trace_set_filter_function>>()
{
  return ::vapi_msg_id_trace_set_filter_function; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_trace_set_filter_function()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_trace_set_filter_function>(vapi_msg_id_trace_set_filter_function);
}

template <> inline vapi_msg_trace_set_filter_function* vapi_alloc<vapi_msg_trace_set_filter_function, size_t>(Connection &con, size_t filter_function_name_buf_array_size)
{
  vapi_msg_trace_set_filter_function* result = vapi_alloc_trace_set_filter_function(con.vapi_ctx, filter_function_name_buf_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_trace_set_filter_function>;

template class Request<vapi_msg_trace_set_filter_function, vapi_msg_trace_set_filter_function_reply, size_t>;

using Trace_set_filter_function = Request<vapi_msg_trace_set_filter_function, vapi_msg_trace_set_filter_function_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_trace_set_filter_function_reply>(vapi_msg_trace_set_filter_function_reply *msg)
{
  vapi_msg_trace_set_filter_function_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_trace_set_filter_function_reply>(vapi_msg_trace_set_filter_function_reply *msg)
{
  vapi_msg_trace_set_filter_function_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_trace_set_filter_function_reply>()
{
  return ::vapi_msg_id_trace_set_filter_function_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_trace_set_filter_function_reply>>()
{
  return ::vapi_msg_id_trace_set_filter_function_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_trace_set_filter_function_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_trace_set_filter_function_reply>(vapi_msg_id_trace_set_filter_function_reply);
}

template class Msg<vapi_msg_trace_set_filter_function_reply>;

using Trace_set_filter_function_reply = Msg<vapi_msg_trace_set_filter_function_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_trace_filter_function_dump>(vapi_msg_trace_filter_function_dump *msg)
{
  vapi_msg_trace_filter_function_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_trace_filter_function_dump>(vapi_msg_trace_filter_function_dump *msg)
{
  vapi_msg_trace_filter_function_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_trace_filter_function_dump>()
{
  return ::vapi_msg_id_trace_filter_function_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_trace_filter_function_dump>>()
{
  return ::vapi_msg_id_trace_filter_function_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_trace_filter_function_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_trace_filter_function_dump>(vapi_msg_id_trace_filter_function_dump);
}

template <> inline vapi_msg_trace_filter_function_dump* vapi_alloc<vapi_msg_trace_filter_function_dump>(Connection &con)
{
  vapi_msg_trace_filter_function_dump* result = vapi_alloc_trace_filter_function_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_trace_filter_function_dump>;

template class Dump<vapi_msg_trace_filter_function_dump, vapi_msg_trace_filter_function_details>;

using Trace_filter_function_dump = Dump<vapi_msg_trace_filter_function_dump, vapi_msg_trace_filter_function_details>;

template <> inline void vapi_swap_to_be<vapi_msg_trace_filter_function_details>(vapi_msg_trace_filter_function_details *msg)
{
  vapi_msg_trace_filter_function_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_trace_filter_function_details>(vapi_msg_trace_filter_function_details *msg)
{
  vapi_msg_trace_filter_function_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_trace_filter_function_details>()
{
  return ::vapi_msg_id_trace_filter_function_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_trace_filter_function_details>>()
{
  return ::vapi_msg_id_trace_filter_function_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_trace_filter_function_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_trace_filter_function_details>(vapi_msg_id_trace_filter_function_details);
}

template class Msg<vapi_msg_trace_filter_function_details>;

using Trace_filter_function_details = Msg<vapi_msg_trace_filter_function_details>;
}
#endif
