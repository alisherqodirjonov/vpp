#ifndef __included_hpp_graph_api_json
#define __included_hpp_graph_api_json

#include <vapi/vapi.hpp>
#include <vapi/graph.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_graph_node_get>(vapi_msg_graph_node_get *msg)
{
  vapi_msg_graph_node_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_graph_node_get>(vapi_msg_graph_node_get *msg)
{
  vapi_msg_graph_node_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_graph_node_get>()
{
  return ::vapi_msg_id_graph_node_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_graph_node_get>>()
{
  return ::vapi_msg_id_graph_node_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_graph_node_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_graph_node_get>(vapi_msg_id_graph_node_get);
}

template <> inline vapi_msg_graph_node_get* vapi_alloc<vapi_msg_graph_node_get>(Connection &con)
{
  vapi_msg_graph_node_get* result = vapi_alloc_graph_node_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_graph_node_get>;

template class Stream<vapi_msg_graph_node_get, vapi_msg_graph_node_get_reply, vapi_msg_graph_node_details>;

using Graph_node_get = Stream<vapi_msg_graph_node_get, vapi_msg_graph_node_get_reply, vapi_msg_graph_node_details>;

template <> inline void vapi_swap_to_be<vapi_msg_graph_node_get_reply>(vapi_msg_graph_node_get_reply *msg)
{
  vapi_msg_graph_node_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_graph_node_get_reply>(vapi_msg_graph_node_get_reply *msg)
{
  vapi_msg_graph_node_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_graph_node_get_reply>()
{
  return ::vapi_msg_id_graph_node_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_graph_node_get_reply>>()
{
  return ::vapi_msg_id_graph_node_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_graph_node_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_graph_node_get_reply>(vapi_msg_id_graph_node_get_reply);
}

template class Msg<vapi_msg_graph_node_get_reply>;

using Graph_node_get_reply = Msg<vapi_msg_graph_node_get_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_graph_node_details>(vapi_msg_graph_node_details *msg)
{
  vapi_msg_graph_node_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_graph_node_details>(vapi_msg_graph_node_details *msg)
{
  vapi_msg_graph_node_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_graph_node_details>()
{
  return ::vapi_msg_id_graph_node_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_graph_node_details>>()
{
  return ::vapi_msg_id_graph_node_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_graph_node_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_graph_node_details>(vapi_msg_id_graph_node_details);
}

template class Msg<vapi_msg_graph_node_details>;

}
#endif
