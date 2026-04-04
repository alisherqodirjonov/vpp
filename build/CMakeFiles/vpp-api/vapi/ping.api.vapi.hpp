#ifndef __included_hpp_ping_api_json
#define __included_hpp_ping_api_json

#include <vapi/vapi.hpp>
#include <vapi/ping.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_want_ping_finished_events>(vapi_msg_want_ping_finished_events *msg)
{
  vapi_msg_want_ping_finished_events_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_want_ping_finished_events>(vapi_msg_want_ping_finished_events *msg)
{
  vapi_msg_want_ping_finished_events_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_want_ping_finished_events>()
{
  return ::vapi_msg_id_want_ping_finished_events; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_want_ping_finished_events>>()
{
  return ::vapi_msg_id_want_ping_finished_events; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_want_ping_finished_events()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_want_ping_finished_events>(vapi_msg_id_want_ping_finished_events);
}

template <> inline vapi_msg_want_ping_finished_events* vapi_alloc<vapi_msg_want_ping_finished_events>(Connection &con)
{
  vapi_msg_want_ping_finished_events* result = vapi_alloc_want_ping_finished_events(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_want_ping_finished_events>;

template class Request<vapi_msg_want_ping_finished_events, vapi_msg_want_ping_finished_events_reply>;

using Want_ping_finished_events = Request<vapi_msg_want_ping_finished_events, vapi_msg_want_ping_finished_events_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_want_ping_finished_events_reply>(vapi_msg_want_ping_finished_events_reply *msg)
{
  vapi_msg_want_ping_finished_events_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_want_ping_finished_events_reply>(vapi_msg_want_ping_finished_events_reply *msg)
{
  vapi_msg_want_ping_finished_events_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_want_ping_finished_events_reply>()
{
  return ::vapi_msg_id_want_ping_finished_events_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_want_ping_finished_events_reply>>()
{
  return ::vapi_msg_id_want_ping_finished_events_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_want_ping_finished_events_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_want_ping_finished_events_reply>(vapi_msg_id_want_ping_finished_events_reply);
}

template class Msg<vapi_msg_want_ping_finished_events_reply>;

using Want_ping_finished_events_reply = Msg<vapi_msg_want_ping_finished_events_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ping_finished_event>(vapi_msg_ping_finished_event *msg)
{
  vapi_msg_ping_finished_event_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ping_finished_event>(vapi_msg_ping_finished_event *msg)
{
  vapi_msg_ping_finished_event_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ping_finished_event>()
{
  return ::vapi_msg_id_ping_finished_event; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ping_finished_event>>()
{
  return ::vapi_msg_id_ping_finished_event; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ping_finished_event()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ping_finished_event>(vapi_msg_id_ping_finished_event);
}

template class Msg<vapi_msg_ping_finished_event>;

using Ping_finished_event = Msg<vapi_msg_ping_finished_event>;
}
#endif
