#ifndef __included_hpp_vlib_api_json
#define __included_hpp_vlib_api_json

#include <vapi/vapi.hpp>
#include <vapi/vlib.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_cli>(vapi_msg_cli *msg)
{
  vapi_msg_cli_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_cli>(vapi_msg_cli *msg)
{
  vapi_msg_cli_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_cli>()
{
  return ::vapi_msg_id_cli; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_cli>>()
{
  return ::vapi_msg_id_cli; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_cli()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_cli>(vapi_msg_id_cli);
}

template <> inline vapi_msg_cli* vapi_alloc<vapi_msg_cli>(Connection &con)
{
  vapi_msg_cli* result = vapi_alloc_cli(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_cli>;

template class Request<vapi_msg_cli, vapi_msg_cli_reply>;

using Cli = Request<vapi_msg_cli, vapi_msg_cli_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_cli_inband>(vapi_msg_cli_inband *msg)
{
  vapi_msg_cli_inband_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_cli_inband>(vapi_msg_cli_inband *msg)
{
  vapi_msg_cli_inband_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_cli_inband>()
{
  return ::vapi_msg_id_cli_inband; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_cli_inband>>()
{
  return ::vapi_msg_id_cli_inband; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_cli_inband()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_cli_inband>(vapi_msg_id_cli_inband);
}

template <> inline vapi_msg_cli_inband* vapi_alloc<vapi_msg_cli_inband, size_t>(Connection &con, size_t cmd_buf_array_size)
{
  vapi_msg_cli_inband* result = vapi_alloc_cli_inband(con.vapi_ctx, cmd_buf_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_cli_inband>;

template class Request<vapi_msg_cli_inband, vapi_msg_cli_inband_reply, size_t>;

using Cli_inband = Request<vapi_msg_cli_inband, vapi_msg_cli_inband_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_cli_reply>(vapi_msg_cli_reply *msg)
{
  vapi_msg_cli_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_cli_reply>(vapi_msg_cli_reply *msg)
{
  vapi_msg_cli_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_cli_reply>()
{
  return ::vapi_msg_id_cli_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_cli_reply>>()
{
  return ::vapi_msg_id_cli_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_cli_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_cli_reply>(vapi_msg_id_cli_reply);
}

template class Msg<vapi_msg_cli_reply>;

using Cli_reply = Msg<vapi_msg_cli_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_cli_inband_reply>(vapi_msg_cli_inband_reply *msg)
{
  vapi_msg_cli_inband_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_cli_inband_reply>(vapi_msg_cli_inband_reply *msg)
{
  vapi_msg_cli_inband_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_cli_inband_reply>()
{
  return ::vapi_msg_id_cli_inband_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_cli_inband_reply>>()
{
  return ::vapi_msg_id_cli_inband_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_cli_inband_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_cli_inband_reply>(vapi_msg_id_cli_inband_reply);
}

template class Msg<vapi_msg_cli_inband_reply>;

using Cli_inband_reply = Msg<vapi_msg_cli_inband_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_get_node_index>(vapi_msg_get_node_index *msg)
{
  vapi_msg_get_node_index_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_get_node_index>(vapi_msg_get_node_index *msg)
{
  vapi_msg_get_node_index_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_get_node_index>()
{
  return ::vapi_msg_id_get_node_index; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_get_node_index>>()
{
  return ::vapi_msg_id_get_node_index; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_get_node_index()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_get_node_index>(vapi_msg_id_get_node_index);
}

template <> inline vapi_msg_get_node_index* vapi_alloc<vapi_msg_get_node_index>(Connection &con)
{
  vapi_msg_get_node_index* result = vapi_alloc_get_node_index(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_get_node_index>;

template class Request<vapi_msg_get_node_index, vapi_msg_get_node_index_reply>;

using Get_node_index = Request<vapi_msg_get_node_index, vapi_msg_get_node_index_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_get_node_index_reply>(vapi_msg_get_node_index_reply *msg)
{
  vapi_msg_get_node_index_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_get_node_index_reply>(vapi_msg_get_node_index_reply *msg)
{
  vapi_msg_get_node_index_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_get_node_index_reply>()
{
  return ::vapi_msg_id_get_node_index_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_get_node_index_reply>>()
{
  return ::vapi_msg_id_get_node_index_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_get_node_index_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_get_node_index_reply>(vapi_msg_id_get_node_index_reply);
}

template class Msg<vapi_msg_get_node_index_reply>;

using Get_node_index_reply = Msg<vapi_msg_get_node_index_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_add_node_next>(vapi_msg_add_node_next *msg)
{
  vapi_msg_add_node_next_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_add_node_next>(vapi_msg_add_node_next *msg)
{
  vapi_msg_add_node_next_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_add_node_next>()
{
  return ::vapi_msg_id_add_node_next; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_add_node_next>>()
{
  return ::vapi_msg_id_add_node_next; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_add_node_next()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_add_node_next>(vapi_msg_id_add_node_next);
}

template <> inline vapi_msg_add_node_next* vapi_alloc<vapi_msg_add_node_next>(Connection &con)
{
  vapi_msg_add_node_next* result = vapi_alloc_add_node_next(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_add_node_next>;

template class Request<vapi_msg_add_node_next, vapi_msg_add_node_next_reply>;

using Add_node_next = Request<vapi_msg_add_node_next, vapi_msg_add_node_next_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_add_node_next_reply>(vapi_msg_add_node_next_reply *msg)
{
  vapi_msg_add_node_next_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_add_node_next_reply>(vapi_msg_add_node_next_reply *msg)
{
  vapi_msg_add_node_next_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_add_node_next_reply>()
{
  return ::vapi_msg_id_add_node_next_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_add_node_next_reply>>()
{
  return ::vapi_msg_id_add_node_next_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_add_node_next_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_add_node_next_reply>(vapi_msg_id_add_node_next_reply);
}

template class Msg<vapi_msg_add_node_next_reply>;

using Add_node_next_reply = Msg<vapi_msg_add_node_next_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_show_threads>(vapi_msg_show_threads *msg)
{
  vapi_msg_show_threads_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_threads>(vapi_msg_show_threads *msg)
{
  vapi_msg_show_threads_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_threads>()
{
  return ::vapi_msg_id_show_threads; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_threads>>()
{
  return ::vapi_msg_id_show_threads; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_threads()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_threads>(vapi_msg_id_show_threads);
}

template <> inline vapi_msg_show_threads* vapi_alloc<vapi_msg_show_threads>(Connection &con)
{
  vapi_msg_show_threads* result = vapi_alloc_show_threads(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_show_threads>;

template class Request<vapi_msg_show_threads, vapi_msg_show_threads_reply>;

using Show_threads = Request<vapi_msg_show_threads, vapi_msg_show_threads_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_show_threads_reply>(vapi_msg_show_threads_reply *msg)
{
  vapi_msg_show_threads_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_threads_reply>(vapi_msg_show_threads_reply *msg)
{
  vapi_msg_show_threads_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_threads_reply>()
{
  return ::vapi_msg_id_show_threads_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_threads_reply>>()
{
  return ::vapi_msg_id_show_threads_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_threads_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_threads_reply>(vapi_msg_id_show_threads_reply);
}

template class Msg<vapi_msg_show_threads_reply>;

using Show_threads_reply = Msg<vapi_msg_show_threads_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_get_node_graph>(vapi_msg_get_node_graph *msg)
{
  vapi_msg_get_node_graph_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_get_node_graph>(vapi_msg_get_node_graph *msg)
{
  vapi_msg_get_node_graph_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_get_node_graph>()
{
  return ::vapi_msg_id_get_node_graph; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_get_node_graph>>()
{
  return ::vapi_msg_id_get_node_graph; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_get_node_graph()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_get_node_graph>(vapi_msg_id_get_node_graph);
}

template <> inline vapi_msg_get_node_graph* vapi_alloc<vapi_msg_get_node_graph>(Connection &con)
{
  vapi_msg_get_node_graph* result = vapi_alloc_get_node_graph(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_get_node_graph>;

template class Request<vapi_msg_get_node_graph, vapi_msg_get_node_graph_reply>;

using Get_node_graph = Request<vapi_msg_get_node_graph, vapi_msg_get_node_graph_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_get_node_graph_reply>(vapi_msg_get_node_graph_reply *msg)
{
  vapi_msg_get_node_graph_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_get_node_graph_reply>(vapi_msg_get_node_graph_reply *msg)
{
  vapi_msg_get_node_graph_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_get_node_graph_reply>()
{
  return ::vapi_msg_id_get_node_graph_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_get_node_graph_reply>>()
{
  return ::vapi_msg_id_get_node_graph_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_get_node_graph_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_get_node_graph_reply>(vapi_msg_id_get_node_graph_reply);
}

template class Msg<vapi_msg_get_node_graph_reply>;

using Get_node_graph_reply = Msg<vapi_msg_get_node_graph_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_get_next_index>(vapi_msg_get_next_index *msg)
{
  vapi_msg_get_next_index_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_get_next_index>(vapi_msg_get_next_index *msg)
{
  vapi_msg_get_next_index_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_get_next_index>()
{
  return ::vapi_msg_id_get_next_index; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_get_next_index>>()
{
  return ::vapi_msg_id_get_next_index; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_get_next_index()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_get_next_index>(vapi_msg_id_get_next_index);
}

template <> inline vapi_msg_get_next_index* vapi_alloc<vapi_msg_get_next_index>(Connection &con)
{
  vapi_msg_get_next_index* result = vapi_alloc_get_next_index(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_get_next_index>;

template class Request<vapi_msg_get_next_index, vapi_msg_get_next_index_reply>;

using Get_next_index = Request<vapi_msg_get_next_index, vapi_msg_get_next_index_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_get_next_index_reply>(vapi_msg_get_next_index_reply *msg)
{
  vapi_msg_get_next_index_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_get_next_index_reply>(vapi_msg_get_next_index_reply *msg)
{
  vapi_msg_get_next_index_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_get_next_index_reply>()
{
  return ::vapi_msg_id_get_next_index_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_get_next_index_reply>>()
{
  return ::vapi_msg_id_get_next_index_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_get_next_index_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_get_next_index_reply>(vapi_msg_id_get_next_index_reply);
}

template class Msg<vapi_msg_get_next_index_reply>;

using Get_next_index_reply = Msg<vapi_msg_get_next_index_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_get_f64_endian_value>(vapi_msg_get_f64_endian_value *msg)
{
  vapi_msg_get_f64_endian_value_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_get_f64_endian_value>(vapi_msg_get_f64_endian_value *msg)
{
  vapi_msg_get_f64_endian_value_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_get_f64_endian_value>()
{
  return ::vapi_msg_id_get_f64_endian_value; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_get_f64_endian_value>>()
{
  return ::vapi_msg_id_get_f64_endian_value; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_get_f64_endian_value()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_get_f64_endian_value>(vapi_msg_id_get_f64_endian_value);
}

template <> inline vapi_msg_get_f64_endian_value* vapi_alloc<vapi_msg_get_f64_endian_value>(Connection &con)
{
  vapi_msg_get_f64_endian_value* result = vapi_alloc_get_f64_endian_value(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_get_f64_endian_value>;

template class Request<vapi_msg_get_f64_endian_value, vapi_msg_get_f64_endian_value_reply>;

using Get_f64_endian_value = Request<vapi_msg_get_f64_endian_value, vapi_msg_get_f64_endian_value_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_get_f64_endian_value_reply>(vapi_msg_get_f64_endian_value_reply *msg)
{
  vapi_msg_get_f64_endian_value_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_get_f64_endian_value_reply>(vapi_msg_get_f64_endian_value_reply *msg)
{
  vapi_msg_get_f64_endian_value_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_get_f64_endian_value_reply>()
{
  return ::vapi_msg_id_get_f64_endian_value_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_get_f64_endian_value_reply>>()
{
  return ::vapi_msg_id_get_f64_endian_value_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_get_f64_endian_value_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_get_f64_endian_value_reply>(vapi_msg_id_get_f64_endian_value_reply);
}

template class Msg<vapi_msg_get_f64_endian_value_reply>;

using Get_f64_endian_value_reply = Msg<vapi_msg_get_f64_endian_value_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_get_f64_increment_by_one>(vapi_msg_get_f64_increment_by_one *msg)
{
  vapi_msg_get_f64_increment_by_one_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_get_f64_increment_by_one>(vapi_msg_get_f64_increment_by_one *msg)
{
  vapi_msg_get_f64_increment_by_one_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_get_f64_increment_by_one>()
{
  return ::vapi_msg_id_get_f64_increment_by_one; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_get_f64_increment_by_one>>()
{
  return ::vapi_msg_id_get_f64_increment_by_one; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_get_f64_increment_by_one()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_get_f64_increment_by_one>(vapi_msg_id_get_f64_increment_by_one);
}

template <> inline vapi_msg_get_f64_increment_by_one* vapi_alloc<vapi_msg_get_f64_increment_by_one>(Connection &con)
{
  vapi_msg_get_f64_increment_by_one* result = vapi_alloc_get_f64_increment_by_one(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_get_f64_increment_by_one>;

template class Request<vapi_msg_get_f64_increment_by_one, vapi_msg_get_f64_increment_by_one_reply>;

using Get_f64_increment_by_one = Request<vapi_msg_get_f64_increment_by_one, vapi_msg_get_f64_increment_by_one_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_get_f64_increment_by_one_reply>(vapi_msg_get_f64_increment_by_one_reply *msg)
{
  vapi_msg_get_f64_increment_by_one_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_get_f64_increment_by_one_reply>(vapi_msg_get_f64_increment_by_one_reply *msg)
{
  vapi_msg_get_f64_increment_by_one_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_get_f64_increment_by_one_reply>()
{
  return ::vapi_msg_id_get_f64_increment_by_one_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_get_f64_increment_by_one_reply>>()
{
  return ::vapi_msg_id_get_f64_increment_by_one_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_get_f64_increment_by_one_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_get_f64_increment_by_one_reply>(vapi_msg_id_get_f64_increment_by_one_reply);
}

template class Msg<vapi_msg_get_f64_increment_by_one_reply>;

using Get_f64_increment_by_one_reply = Msg<vapi_msg_get_f64_increment_by_one_reply>;
}
#endif
