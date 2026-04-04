#ifndef __included_hpp_pg_api_json
#define __included_hpp_pg_api_json

#include <vapi/vapi.hpp>
#include <vapi/pg.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_pg_create_interface>(vapi_msg_pg_create_interface *msg)
{
  vapi_msg_pg_create_interface_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pg_create_interface>(vapi_msg_pg_create_interface *msg)
{
  vapi_msg_pg_create_interface_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pg_create_interface>()
{
  return ::vapi_msg_id_pg_create_interface; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pg_create_interface>>()
{
  return ::vapi_msg_id_pg_create_interface; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pg_create_interface()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pg_create_interface>(vapi_msg_id_pg_create_interface);
}

template <> inline vapi_msg_pg_create_interface* vapi_alloc<vapi_msg_pg_create_interface>(Connection &con)
{
  vapi_msg_pg_create_interface* result = vapi_alloc_pg_create_interface(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_pg_create_interface>;

template class Request<vapi_msg_pg_create_interface, vapi_msg_pg_create_interface_reply>;

using Pg_create_interface = Request<vapi_msg_pg_create_interface, vapi_msg_pg_create_interface_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_pg_create_interface_v2>(vapi_msg_pg_create_interface_v2 *msg)
{
  vapi_msg_pg_create_interface_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pg_create_interface_v2>(vapi_msg_pg_create_interface_v2 *msg)
{
  vapi_msg_pg_create_interface_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pg_create_interface_v2>()
{
  return ::vapi_msg_id_pg_create_interface_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pg_create_interface_v2>>()
{
  return ::vapi_msg_id_pg_create_interface_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pg_create_interface_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pg_create_interface_v2>(vapi_msg_id_pg_create_interface_v2);
}

template <> inline vapi_msg_pg_create_interface_v2* vapi_alloc<vapi_msg_pg_create_interface_v2>(Connection &con)
{
  vapi_msg_pg_create_interface_v2* result = vapi_alloc_pg_create_interface_v2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_pg_create_interface_v2>;

template class Request<vapi_msg_pg_create_interface_v2, vapi_msg_pg_create_interface_v2_reply>;

using Pg_create_interface_v2 = Request<vapi_msg_pg_create_interface_v2, vapi_msg_pg_create_interface_v2_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_pg_create_interface_v3>(vapi_msg_pg_create_interface_v3 *msg)
{
  vapi_msg_pg_create_interface_v3_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pg_create_interface_v3>(vapi_msg_pg_create_interface_v3 *msg)
{
  vapi_msg_pg_create_interface_v3_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pg_create_interface_v3>()
{
  return ::vapi_msg_id_pg_create_interface_v3; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pg_create_interface_v3>>()
{
  return ::vapi_msg_id_pg_create_interface_v3; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pg_create_interface_v3()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pg_create_interface_v3>(vapi_msg_id_pg_create_interface_v3);
}

template <> inline vapi_msg_pg_create_interface_v3* vapi_alloc<vapi_msg_pg_create_interface_v3>(Connection &con)
{
  vapi_msg_pg_create_interface_v3* result = vapi_alloc_pg_create_interface_v3(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_pg_create_interface_v3>;

template class Request<vapi_msg_pg_create_interface_v3, vapi_msg_pg_create_interface_v3_reply>;

using Pg_create_interface_v3 = Request<vapi_msg_pg_create_interface_v3, vapi_msg_pg_create_interface_v3_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_pg_create_interface_reply>(vapi_msg_pg_create_interface_reply *msg)
{
  vapi_msg_pg_create_interface_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pg_create_interface_reply>(vapi_msg_pg_create_interface_reply *msg)
{
  vapi_msg_pg_create_interface_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pg_create_interface_reply>()
{
  return ::vapi_msg_id_pg_create_interface_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pg_create_interface_reply>>()
{
  return ::vapi_msg_id_pg_create_interface_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pg_create_interface_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pg_create_interface_reply>(vapi_msg_id_pg_create_interface_reply);
}

template class Msg<vapi_msg_pg_create_interface_reply>;

using Pg_create_interface_reply = Msg<vapi_msg_pg_create_interface_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_pg_create_interface_v2_reply>(vapi_msg_pg_create_interface_v2_reply *msg)
{
  vapi_msg_pg_create_interface_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pg_create_interface_v2_reply>(vapi_msg_pg_create_interface_v2_reply *msg)
{
  vapi_msg_pg_create_interface_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pg_create_interface_v2_reply>()
{
  return ::vapi_msg_id_pg_create_interface_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pg_create_interface_v2_reply>>()
{
  return ::vapi_msg_id_pg_create_interface_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pg_create_interface_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pg_create_interface_v2_reply>(vapi_msg_id_pg_create_interface_v2_reply);
}

template class Msg<vapi_msg_pg_create_interface_v2_reply>;

using Pg_create_interface_v2_reply = Msg<vapi_msg_pg_create_interface_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_pg_create_interface_v3_reply>(vapi_msg_pg_create_interface_v3_reply *msg)
{
  vapi_msg_pg_create_interface_v3_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pg_create_interface_v3_reply>(vapi_msg_pg_create_interface_v3_reply *msg)
{
  vapi_msg_pg_create_interface_v3_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pg_create_interface_v3_reply>()
{
  return ::vapi_msg_id_pg_create_interface_v3_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pg_create_interface_v3_reply>>()
{
  return ::vapi_msg_id_pg_create_interface_v3_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pg_create_interface_v3_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pg_create_interface_v3_reply>(vapi_msg_id_pg_create_interface_v3_reply);
}

template class Msg<vapi_msg_pg_create_interface_v3_reply>;

using Pg_create_interface_v3_reply = Msg<vapi_msg_pg_create_interface_v3_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_pg_delete_interface>(vapi_msg_pg_delete_interface *msg)
{
  vapi_msg_pg_delete_interface_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pg_delete_interface>(vapi_msg_pg_delete_interface *msg)
{
  vapi_msg_pg_delete_interface_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pg_delete_interface>()
{
  return ::vapi_msg_id_pg_delete_interface; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pg_delete_interface>>()
{
  return ::vapi_msg_id_pg_delete_interface; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pg_delete_interface()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pg_delete_interface>(vapi_msg_id_pg_delete_interface);
}

template <> inline vapi_msg_pg_delete_interface* vapi_alloc<vapi_msg_pg_delete_interface>(Connection &con)
{
  vapi_msg_pg_delete_interface* result = vapi_alloc_pg_delete_interface(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_pg_delete_interface>;

template class Request<vapi_msg_pg_delete_interface, vapi_msg_pg_delete_interface_reply>;

using Pg_delete_interface = Request<vapi_msg_pg_delete_interface, vapi_msg_pg_delete_interface_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_pg_delete_interface_reply>(vapi_msg_pg_delete_interface_reply *msg)
{
  vapi_msg_pg_delete_interface_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pg_delete_interface_reply>(vapi_msg_pg_delete_interface_reply *msg)
{
  vapi_msg_pg_delete_interface_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pg_delete_interface_reply>()
{
  return ::vapi_msg_id_pg_delete_interface_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pg_delete_interface_reply>>()
{
  return ::vapi_msg_id_pg_delete_interface_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pg_delete_interface_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pg_delete_interface_reply>(vapi_msg_id_pg_delete_interface_reply);
}

template class Msg<vapi_msg_pg_delete_interface_reply>;

using Pg_delete_interface_reply = Msg<vapi_msg_pg_delete_interface_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_pg_interface_enable_disable_coalesce>(vapi_msg_pg_interface_enable_disable_coalesce *msg)
{
  vapi_msg_pg_interface_enable_disable_coalesce_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pg_interface_enable_disable_coalesce>(vapi_msg_pg_interface_enable_disable_coalesce *msg)
{
  vapi_msg_pg_interface_enable_disable_coalesce_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pg_interface_enable_disable_coalesce>()
{
  return ::vapi_msg_id_pg_interface_enable_disable_coalesce; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pg_interface_enable_disable_coalesce>>()
{
  return ::vapi_msg_id_pg_interface_enable_disable_coalesce; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pg_interface_enable_disable_coalesce()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pg_interface_enable_disable_coalesce>(vapi_msg_id_pg_interface_enable_disable_coalesce);
}

template <> inline vapi_msg_pg_interface_enable_disable_coalesce* vapi_alloc<vapi_msg_pg_interface_enable_disable_coalesce>(Connection &con)
{
  vapi_msg_pg_interface_enable_disable_coalesce* result = vapi_alloc_pg_interface_enable_disable_coalesce(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_pg_interface_enable_disable_coalesce>;

template class Request<vapi_msg_pg_interface_enable_disable_coalesce, vapi_msg_pg_interface_enable_disable_coalesce_reply>;

using Pg_interface_enable_disable_coalesce = Request<vapi_msg_pg_interface_enable_disable_coalesce, vapi_msg_pg_interface_enable_disable_coalesce_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_pg_interface_enable_disable_coalesce_reply>(vapi_msg_pg_interface_enable_disable_coalesce_reply *msg)
{
  vapi_msg_pg_interface_enable_disable_coalesce_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pg_interface_enable_disable_coalesce_reply>(vapi_msg_pg_interface_enable_disable_coalesce_reply *msg)
{
  vapi_msg_pg_interface_enable_disable_coalesce_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pg_interface_enable_disable_coalesce_reply>()
{
  return ::vapi_msg_id_pg_interface_enable_disable_coalesce_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pg_interface_enable_disable_coalesce_reply>>()
{
  return ::vapi_msg_id_pg_interface_enable_disable_coalesce_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pg_interface_enable_disable_coalesce_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pg_interface_enable_disable_coalesce_reply>(vapi_msg_id_pg_interface_enable_disable_coalesce_reply);
}

template class Msg<vapi_msg_pg_interface_enable_disable_coalesce_reply>;

using Pg_interface_enable_disable_coalesce_reply = Msg<vapi_msg_pg_interface_enable_disable_coalesce_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_pg_capture>(vapi_msg_pg_capture *msg)
{
  vapi_msg_pg_capture_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pg_capture>(vapi_msg_pg_capture *msg)
{
  vapi_msg_pg_capture_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pg_capture>()
{
  return ::vapi_msg_id_pg_capture; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pg_capture>>()
{
  return ::vapi_msg_id_pg_capture; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pg_capture()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pg_capture>(vapi_msg_id_pg_capture);
}

template <> inline vapi_msg_pg_capture* vapi_alloc<vapi_msg_pg_capture, size_t>(Connection &con, size_t pcap_file_name_buf_array_size)
{
  vapi_msg_pg_capture* result = vapi_alloc_pg_capture(con.vapi_ctx, pcap_file_name_buf_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_pg_capture>;

template class Request<vapi_msg_pg_capture, vapi_msg_pg_capture_reply, size_t>;

using Pg_capture = Request<vapi_msg_pg_capture, vapi_msg_pg_capture_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_pg_capture_reply>(vapi_msg_pg_capture_reply *msg)
{
  vapi_msg_pg_capture_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pg_capture_reply>(vapi_msg_pg_capture_reply *msg)
{
  vapi_msg_pg_capture_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pg_capture_reply>()
{
  return ::vapi_msg_id_pg_capture_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pg_capture_reply>>()
{
  return ::vapi_msg_id_pg_capture_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pg_capture_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pg_capture_reply>(vapi_msg_id_pg_capture_reply);
}

template class Msg<vapi_msg_pg_capture_reply>;

using Pg_capture_reply = Msg<vapi_msg_pg_capture_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_pg_enable_disable>(vapi_msg_pg_enable_disable *msg)
{
  vapi_msg_pg_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pg_enable_disable>(vapi_msg_pg_enable_disable *msg)
{
  vapi_msg_pg_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pg_enable_disable>()
{
  return ::vapi_msg_id_pg_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pg_enable_disable>>()
{
  return ::vapi_msg_id_pg_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pg_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pg_enable_disable>(vapi_msg_id_pg_enable_disable);
}

template <> inline vapi_msg_pg_enable_disable* vapi_alloc<vapi_msg_pg_enable_disable, size_t>(Connection &con, size_t stream_name_buf_array_size)
{
  vapi_msg_pg_enable_disable* result = vapi_alloc_pg_enable_disable(con.vapi_ctx, stream_name_buf_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_pg_enable_disable>;

template class Request<vapi_msg_pg_enable_disable, vapi_msg_pg_enable_disable_reply, size_t>;

using Pg_enable_disable = Request<vapi_msg_pg_enable_disable, vapi_msg_pg_enable_disable_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_pg_enable_disable_reply>(vapi_msg_pg_enable_disable_reply *msg)
{
  vapi_msg_pg_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pg_enable_disable_reply>(vapi_msg_pg_enable_disable_reply *msg)
{
  vapi_msg_pg_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pg_enable_disable_reply>()
{
  return ::vapi_msg_id_pg_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pg_enable_disable_reply>>()
{
  return ::vapi_msg_id_pg_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pg_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pg_enable_disable_reply>(vapi_msg_id_pg_enable_disable_reply);
}

template class Msg<vapi_msg_pg_enable_disable_reply>;

using Pg_enable_disable_reply = Msg<vapi_msg_pg_enable_disable_reply>;
}
#endif
