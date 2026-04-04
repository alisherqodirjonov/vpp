#ifndef __included_hpp_syslog_api_json
#define __included_hpp_syslog_api_json

#include <vapi/vapi.hpp>
#include <vapi/syslog.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_syslog_set_sender>(vapi_msg_syslog_set_sender *msg)
{
  vapi_msg_syslog_set_sender_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_syslog_set_sender>(vapi_msg_syslog_set_sender *msg)
{
  vapi_msg_syslog_set_sender_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_syslog_set_sender>()
{
  return ::vapi_msg_id_syslog_set_sender; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_syslog_set_sender>>()
{
  return ::vapi_msg_id_syslog_set_sender; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_syslog_set_sender()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_syslog_set_sender>(vapi_msg_id_syslog_set_sender);
}

template <> inline vapi_msg_syslog_set_sender* vapi_alloc<vapi_msg_syslog_set_sender>(Connection &con)
{
  vapi_msg_syslog_set_sender* result = vapi_alloc_syslog_set_sender(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_syslog_set_sender>;

template class Request<vapi_msg_syslog_set_sender, vapi_msg_syslog_set_sender_reply>;

using Syslog_set_sender = Request<vapi_msg_syslog_set_sender, vapi_msg_syslog_set_sender_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_syslog_set_sender_reply>(vapi_msg_syslog_set_sender_reply *msg)
{
  vapi_msg_syslog_set_sender_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_syslog_set_sender_reply>(vapi_msg_syslog_set_sender_reply *msg)
{
  vapi_msg_syslog_set_sender_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_syslog_set_sender_reply>()
{
  return ::vapi_msg_id_syslog_set_sender_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_syslog_set_sender_reply>>()
{
  return ::vapi_msg_id_syslog_set_sender_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_syslog_set_sender_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_syslog_set_sender_reply>(vapi_msg_id_syslog_set_sender_reply);
}

template class Msg<vapi_msg_syslog_set_sender_reply>;

using Syslog_set_sender_reply = Msg<vapi_msg_syslog_set_sender_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_syslog_get_sender>(vapi_msg_syslog_get_sender *msg)
{
  vapi_msg_syslog_get_sender_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_syslog_get_sender>(vapi_msg_syslog_get_sender *msg)
{
  vapi_msg_syslog_get_sender_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_syslog_get_sender>()
{
  return ::vapi_msg_id_syslog_get_sender; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_syslog_get_sender>>()
{
  return ::vapi_msg_id_syslog_get_sender; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_syslog_get_sender()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_syslog_get_sender>(vapi_msg_id_syslog_get_sender);
}

template <> inline vapi_msg_syslog_get_sender* vapi_alloc<vapi_msg_syslog_get_sender>(Connection &con)
{
  vapi_msg_syslog_get_sender* result = vapi_alloc_syslog_get_sender(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_syslog_get_sender>;

template class Request<vapi_msg_syslog_get_sender, vapi_msg_syslog_get_sender_reply>;

using Syslog_get_sender = Request<vapi_msg_syslog_get_sender, vapi_msg_syslog_get_sender_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_syslog_get_sender_reply>(vapi_msg_syslog_get_sender_reply *msg)
{
  vapi_msg_syslog_get_sender_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_syslog_get_sender_reply>(vapi_msg_syslog_get_sender_reply *msg)
{
  vapi_msg_syslog_get_sender_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_syslog_get_sender_reply>()
{
  return ::vapi_msg_id_syslog_get_sender_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_syslog_get_sender_reply>>()
{
  return ::vapi_msg_id_syslog_get_sender_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_syslog_get_sender_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_syslog_get_sender_reply>(vapi_msg_id_syslog_get_sender_reply);
}

template class Msg<vapi_msg_syslog_get_sender_reply>;

using Syslog_get_sender_reply = Msg<vapi_msg_syslog_get_sender_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_syslog_set_filter>(vapi_msg_syslog_set_filter *msg)
{
  vapi_msg_syslog_set_filter_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_syslog_set_filter>(vapi_msg_syslog_set_filter *msg)
{
  vapi_msg_syslog_set_filter_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_syslog_set_filter>()
{
  return ::vapi_msg_id_syslog_set_filter; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_syslog_set_filter>>()
{
  return ::vapi_msg_id_syslog_set_filter; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_syslog_set_filter()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_syslog_set_filter>(vapi_msg_id_syslog_set_filter);
}

template <> inline vapi_msg_syslog_set_filter* vapi_alloc<vapi_msg_syslog_set_filter>(Connection &con)
{
  vapi_msg_syslog_set_filter* result = vapi_alloc_syslog_set_filter(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_syslog_set_filter>;

template class Request<vapi_msg_syslog_set_filter, vapi_msg_syslog_set_filter_reply>;

using Syslog_set_filter = Request<vapi_msg_syslog_set_filter, vapi_msg_syslog_set_filter_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_syslog_set_filter_reply>(vapi_msg_syslog_set_filter_reply *msg)
{
  vapi_msg_syslog_set_filter_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_syslog_set_filter_reply>(vapi_msg_syslog_set_filter_reply *msg)
{
  vapi_msg_syslog_set_filter_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_syslog_set_filter_reply>()
{
  return ::vapi_msg_id_syslog_set_filter_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_syslog_set_filter_reply>>()
{
  return ::vapi_msg_id_syslog_set_filter_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_syslog_set_filter_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_syslog_set_filter_reply>(vapi_msg_id_syslog_set_filter_reply);
}

template class Msg<vapi_msg_syslog_set_filter_reply>;

using Syslog_set_filter_reply = Msg<vapi_msg_syslog_set_filter_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_syslog_get_filter>(vapi_msg_syslog_get_filter *msg)
{
  vapi_msg_syslog_get_filter_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_syslog_get_filter>(vapi_msg_syslog_get_filter *msg)
{
  vapi_msg_syslog_get_filter_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_syslog_get_filter>()
{
  return ::vapi_msg_id_syslog_get_filter; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_syslog_get_filter>>()
{
  return ::vapi_msg_id_syslog_get_filter; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_syslog_get_filter()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_syslog_get_filter>(vapi_msg_id_syslog_get_filter);
}

template <> inline vapi_msg_syslog_get_filter* vapi_alloc<vapi_msg_syslog_get_filter>(Connection &con)
{
  vapi_msg_syslog_get_filter* result = vapi_alloc_syslog_get_filter(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_syslog_get_filter>;

template class Request<vapi_msg_syslog_get_filter, vapi_msg_syslog_get_filter_reply>;

using Syslog_get_filter = Request<vapi_msg_syslog_get_filter, vapi_msg_syslog_get_filter_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_syslog_get_filter_reply>(vapi_msg_syslog_get_filter_reply *msg)
{
  vapi_msg_syslog_get_filter_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_syslog_get_filter_reply>(vapi_msg_syslog_get_filter_reply *msg)
{
  vapi_msg_syslog_get_filter_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_syslog_get_filter_reply>()
{
  return ::vapi_msg_id_syslog_get_filter_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_syslog_get_filter_reply>>()
{
  return ::vapi_msg_id_syslog_get_filter_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_syslog_get_filter_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_syslog_get_filter_reply>(vapi_msg_id_syslog_get_filter_reply);
}

template class Msg<vapi_msg_syslog_get_filter_reply>;

using Syslog_get_filter_reply = Msg<vapi_msg_syslog_get_filter_reply>;
}
#endif
