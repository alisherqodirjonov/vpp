#ifndef __included_hpp_det44_api_json
#define __included_hpp_det44_api_json

#include <vapi/vapi.hpp>
#include <vapi/det44.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_det44_plugin_enable_disable>(vapi_msg_det44_plugin_enable_disable *msg)
{
  vapi_msg_det44_plugin_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_det44_plugin_enable_disable>(vapi_msg_det44_plugin_enable_disable *msg)
{
  vapi_msg_det44_plugin_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_det44_plugin_enable_disable>()
{
  return ::vapi_msg_id_det44_plugin_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_det44_plugin_enable_disable>>()
{
  return ::vapi_msg_id_det44_plugin_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_det44_plugin_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_det44_plugin_enable_disable>(vapi_msg_id_det44_plugin_enable_disable);
}

template <> inline vapi_msg_det44_plugin_enable_disable* vapi_alloc<vapi_msg_det44_plugin_enable_disable>(Connection &con)
{
  vapi_msg_det44_plugin_enable_disable* result = vapi_alloc_det44_plugin_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_det44_plugin_enable_disable>;

template class Request<vapi_msg_det44_plugin_enable_disable, vapi_msg_det44_plugin_enable_disable_reply>;

using Det44_plugin_enable_disable = Request<vapi_msg_det44_plugin_enable_disable, vapi_msg_det44_plugin_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_det44_plugin_enable_disable_reply>(vapi_msg_det44_plugin_enable_disable_reply *msg)
{
  vapi_msg_det44_plugin_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_det44_plugin_enable_disable_reply>(vapi_msg_det44_plugin_enable_disable_reply *msg)
{
  vapi_msg_det44_plugin_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_det44_plugin_enable_disable_reply>()
{
  return ::vapi_msg_id_det44_plugin_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_det44_plugin_enable_disable_reply>>()
{
  return ::vapi_msg_id_det44_plugin_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_det44_plugin_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_det44_plugin_enable_disable_reply>(vapi_msg_id_det44_plugin_enable_disable_reply);
}

template class Msg<vapi_msg_det44_plugin_enable_disable_reply>;

using Det44_plugin_enable_disable_reply = Msg<vapi_msg_det44_plugin_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_det44_interface_add_del_feature>(vapi_msg_det44_interface_add_del_feature *msg)
{
  vapi_msg_det44_interface_add_del_feature_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_det44_interface_add_del_feature>(vapi_msg_det44_interface_add_del_feature *msg)
{
  vapi_msg_det44_interface_add_del_feature_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_det44_interface_add_del_feature>()
{
  return ::vapi_msg_id_det44_interface_add_del_feature; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_det44_interface_add_del_feature>>()
{
  return ::vapi_msg_id_det44_interface_add_del_feature; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_det44_interface_add_del_feature()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_det44_interface_add_del_feature>(vapi_msg_id_det44_interface_add_del_feature);
}

template <> inline vapi_msg_det44_interface_add_del_feature* vapi_alloc<vapi_msg_det44_interface_add_del_feature>(Connection &con)
{
  vapi_msg_det44_interface_add_del_feature* result = vapi_alloc_det44_interface_add_del_feature(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_det44_interface_add_del_feature>;

template class Request<vapi_msg_det44_interface_add_del_feature, vapi_msg_det44_interface_add_del_feature_reply>;

using Det44_interface_add_del_feature = Request<vapi_msg_det44_interface_add_del_feature, vapi_msg_det44_interface_add_del_feature_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_det44_interface_add_del_feature_reply>(vapi_msg_det44_interface_add_del_feature_reply *msg)
{
  vapi_msg_det44_interface_add_del_feature_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_det44_interface_add_del_feature_reply>(vapi_msg_det44_interface_add_del_feature_reply *msg)
{
  vapi_msg_det44_interface_add_del_feature_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_det44_interface_add_del_feature_reply>()
{
  return ::vapi_msg_id_det44_interface_add_del_feature_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_det44_interface_add_del_feature_reply>>()
{
  return ::vapi_msg_id_det44_interface_add_del_feature_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_det44_interface_add_del_feature_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_det44_interface_add_del_feature_reply>(vapi_msg_id_det44_interface_add_del_feature_reply);
}

template class Msg<vapi_msg_det44_interface_add_del_feature_reply>;

using Det44_interface_add_del_feature_reply = Msg<vapi_msg_det44_interface_add_del_feature_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_det44_interface_dump>(vapi_msg_det44_interface_dump *msg)
{
  vapi_msg_det44_interface_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_det44_interface_dump>(vapi_msg_det44_interface_dump *msg)
{
  vapi_msg_det44_interface_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_det44_interface_dump>()
{
  return ::vapi_msg_id_det44_interface_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_det44_interface_dump>>()
{
  return ::vapi_msg_id_det44_interface_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_det44_interface_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_det44_interface_dump>(vapi_msg_id_det44_interface_dump);
}

template <> inline vapi_msg_det44_interface_dump* vapi_alloc<vapi_msg_det44_interface_dump>(Connection &con)
{
  vapi_msg_det44_interface_dump* result = vapi_alloc_det44_interface_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_det44_interface_dump>;

template class Dump<vapi_msg_det44_interface_dump, vapi_msg_det44_interface_details>;

using Det44_interface_dump = Dump<vapi_msg_det44_interface_dump, vapi_msg_det44_interface_details>;

template <> inline void vapi_swap_to_be<vapi_msg_det44_interface_details>(vapi_msg_det44_interface_details *msg)
{
  vapi_msg_det44_interface_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_det44_interface_details>(vapi_msg_det44_interface_details *msg)
{
  vapi_msg_det44_interface_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_det44_interface_details>()
{
  return ::vapi_msg_id_det44_interface_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_det44_interface_details>>()
{
  return ::vapi_msg_id_det44_interface_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_det44_interface_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_det44_interface_details>(vapi_msg_id_det44_interface_details);
}

template class Msg<vapi_msg_det44_interface_details>;

using Det44_interface_details = Msg<vapi_msg_det44_interface_details>;
template <> inline void vapi_swap_to_be<vapi_msg_det44_add_del_map>(vapi_msg_det44_add_del_map *msg)
{
  vapi_msg_det44_add_del_map_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_det44_add_del_map>(vapi_msg_det44_add_del_map *msg)
{
  vapi_msg_det44_add_del_map_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_det44_add_del_map>()
{
  return ::vapi_msg_id_det44_add_del_map; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_det44_add_del_map>>()
{
  return ::vapi_msg_id_det44_add_del_map; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_det44_add_del_map()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_det44_add_del_map>(vapi_msg_id_det44_add_del_map);
}

template <> inline vapi_msg_det44_add_del_map* vapi_alloc<vapi_msg_det44_add_del_map>(Connection &con)
{
  vapi_msg_det44_add_del_map* result = vapi_alloc_det44_add_del_map(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_det44_add_del_map>;

template class Request<vapi_msg_det44_add_del_map, vapi_msg_det44_add_del_map_reply>;

using Det44_add_del_map = Request<vapi_msg_det44_add_del_map, vapi_msg_det44_add_del_map_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_det44_add_del_map_reply>(vapi_msg_det44_add_del_map_reply *msg)
{
  vapi_msg_det44_add_del_map_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_det44_add_del_map_reply>(vapi_msg_det44_add_del_map_reply *msg)
{
  vapi_msg_det44_add_del_map_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_det44_add_del_map_reply>()
{
  return ::vapi_msg_id_det44_add_del_map_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_det44_add_del_map_reply>>()
{
  return ::vapi_msg_id_det44_add_del_map_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_det44_add_del_map_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_det44_add_del_map_reply>(vapi_msg_id_det44_add_del_map_reply);
}

template class Msg<vapi_msg_det44_add_del_map_reply>;

using Det44_add_del_map_reply = Msg<vapi_msg_det44_add_del_map_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_det44_forward>(vapi_msg_det44_forward *msg)
{
  vapi_msg_det44_forward_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_det44_forward>(vapi_msg_det44_forward *msg)
{
  vapi_msg_det44_forward_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_det44_forward>()
{
  return ::vapi_msg_id_det44_forward; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_det44_forward>>()
{
  return ::vapi_msg_id_det44_forward; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_det44_forward()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_det44_forward>(vapi_msg_id_det44_forward);
}

template <> inline vapi_msg_det44_forward* vapi_alloc<vapi_msg_det44_forward>(Connection &con)
{
  vapi_msg_det44_forward* result = vapi_alloc_det44_forward(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_det44_forward>;

template class Request<vapi_msg_det44_forward, vapi_msg_det44_forward_reply>;

using Det44_forward = Request<vapi_msg_det44_forward, vapi_msg_det44_forward_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_det44_forward_reply>(vapi_msg_det44_forward_reply *msg)
{
  vapi_msg_det44_forward_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_det44_forward_reply>(vapi_msg_det44_forward_reply *msg)
{
  vapi_msg_det44_forward_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_det44_forward_reply>()
{
  return ::vapi_msg_id_det44_forward_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_det44_forward_reply>>()
{
  return ::vapi_msg_id_det44_forward_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_det44_forward_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_det44_forward_reply>(vapi_msg_id_det44_forward_reply);
}

template class Msg<vapi_msg_det44_forward_reply>;

using Det44_forward_reply = Msg<vapi_msg_det44_forward_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_det44_reverse>(vapi_msg_det44_reverse *msg)
{
  vapi_msg_det44_reverse_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_det44_reverse>(vapi_msg_det44_reverse *msg)
{
  vapi_msg_det44_reverse_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_det44_reverse>()
{
  return ::vapi_msg_id_det44_reverse; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_det44_reverse>>()
{
  return ::vapi_msg_id_det44_reverse; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_det44_reverse()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_det44_reverse>(vapi_msg_id_det44_reverse);
}

template <> inline vapi_msg_det44_reverse* vapi_alloc<vapi_msg_det44_reverse>(Connection &con)
{
  vapi_msg_det44_reverse* result = vapi_alloc_det44_reverse(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_det44_reverse>;

template class Request<vapi_msg_det44_reverse, vapi_msg_det44_reverse_reply>;

using Det44_reverse = Request<vapi_msg_det44_reverse, vapi_msg_det44_reverse_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_det44_reverse_reply>(vapi_msg_det44_reverse_reply *msg)
{
  vapi_msg_det44_reverse_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_det44_reverse_reply>(vapi_msg_det44_reverse_reply *msg)
{
  vapi_msg_det44_reverse_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_det44_reverse_reply>()
{
  return ::vapi_msg_id_det44_reverse_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_det44_reverse_reply>>()
{
  return ::vapi_msg_id_det44_reverse_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_det44_reverse_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_det44_reverse_reply>(vapi_msg_id_det44_reverse_reply);
}

template class Msg<vapi_msg_det44_reverse_reply>;

using Det44_reverse_reply = Msg<vapi_msg_det44_reverse_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_det44_map_dump>(vapi_msg_det44_map_dump *msg)
{
  vapi_msg_det44_map_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_det44_map_dump>(vapi_msg_det44_map_dump *msg)
{
  vapi_msg_det44_map_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_det44_map_dump>()
{
  return ::vapi_msg_id_det44_map_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_det44_map_dump>>()
{
  return ::vapi_msg_id_det44_map_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_det44_map_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_det44_map_dump>(vapi_msg_id_det44_map_dump);
}

template <> inline vapi_msg_det44_map_dump* vapi_alloc<vapi_msg_det44_map_dump>(Connection &con)
{
  vapi_msg_det44_map_dump* result = vapi_alloc_det44_map_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_det44_map_dump>;

template class Dump<vapi_msg_det44_map_dump, vapi_msg_det44_map_details>;

using Det44_map_dump = Dump<vapi_msg_det44_map_dump, vapi_msg_det44_map_details>;

template <> inline void vapi_swap_to_be<vapi_msg_det44_map_details>(vapi_msg_det44_map_details *msg)
{
  vapi_msg_det44_map_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_det44_map_details>(vapi_msg_det44_map_details *msg)
{
  vapi_msg_det44_map_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_det44_map_details>()
{
  return ::vapi_msg_id_det44_map_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_det44_map_details>>()
{
  return ::vapi_msg_id_det44_map_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_det44_map_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_det44_map_details>(vapi_msg_id_det44_map_details);
}

template class Msg<vapi_msg_det44_map_details>;

using Det44_map_details = Msg<vapi_msg_det44_map_details>;
template <> inline void vapi_swap_to_be<vapi_msg_det44_close_session_out>(vapi_msg_det44_close_session_out *msg)
{
  vapi_msg_det44_close_session_out_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_det44_close_session_out>(vapi_msg_det44_close_session_out *msg)
{
  vapi_msg_det44_close_session_out_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_det44_close_session_out>()
{
  return ::vapi_msg_id_det44_close_session_out; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_det44_close_session_out>>()
{
  return ::vapi_msg_id_det44_close_session_out; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_det44_close_session_out()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_det44_close_session_out>(vapi_msg_id_det44_close_session_out);
}

template <> inline vapi_msg_det44_close_session_out* vapi_alloc<vapi_msg_det44_close_session_out>(Connection &con)
{
  vapi_msg_det44_close_session_out* result = vapi_alloc_det44_close_session_out(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_det44_close_session_out>;

template class Request<vapi_msg_det44_close_session_out, vapi_msg_det44_close_session_out_reply>;

using Det44_close_session_out = Request<vapi_msg_det44_close_session_out, vapi_msg_det44_close_session_out_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_det44_close_session_out_reply>(vapi_msg_det44_close_session_out_reply *msg)
{
  vapi_msg_det44_close_session_out_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_det44_close_session_out_reply>(vapi_msg_det44_close_session_out_reply *msg)
{
  vapi_msg_det44_close_session_out_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_det44_close_session_out_reply>()
{
  return ::vapi_msg_id_det44_close_session_out_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_det44_close_session_out_reply>>()
{
  return ::vapi_msg_id_det44_close_session_out_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_det44_close_session_out_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_det44_close_session_out_reply>(vapi_msg_id_det44_close_session_out_reply);
}

template class Msg<vapi_msg_det44_close_session_out_reply>;

using Det44_close_session_out_reply = Msg<vapi_msg_det44_close_session_out_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_det44_close_session_in>(vapi_msg_det44_close_session_in *msg)
{
  vapi_msg_det44_close_session_in_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_det44_close_session_in>(vapi_msg_det44_close_session_in *msg)
{
  vapi_msg_det44_close_session_in_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_det44_close_session_in>()
{
  return ::vapi_msg_id_det44_close_session_in; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_det44_close_session_in>>()
{
  return ::vapi_msg_id_det44_close_session_in; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_det44_close_session_in()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_det44_close_session_in>(vapi_msg_id_det44_close_session_in);
}

template <> inline vapi_msg_det44_close_session_in* vapi_alloc<vapi_msg_det44_close_session_in>(Connection &con)
{
  vapi_msg_det44_close_session_in* result = vapi_alloc_det44_close_session_in(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_det44_close_session_in>;

template class Request<vapi_msg_det44_close_session_in, vapi_msg_det44_close_session_in_reply>;

using Det44_close_session_in = Request<vapi_msg_det44_close_session_in, vapi_msg_det44_close_session_in_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_det44_close_session_in_reply>(vapi_msg_det44_close_session_in_reply *msg)
{
  vapi_msg_det44_close_session_in_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_det44_close_session_in_reply>(vapi_msg_det44_close_session_in_reply *msg)
{
  vapi_msg_det44_close_session_in_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_det44_close_session_in_reply>()
{
  return ::vapi_msg_id_det44_close_session_in_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_det44_close_session_in_reply>>()
{
  return ::vapi_msg_id_det44_close_session_in_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_det44_close_session_in_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_det44_close_session_in_reply>(vapi_msg_id_det44_close_session_in_reply);
}

template class Msg<vapi_msg_det44_close_session_in_reply>;

using Det44_close_session_in_reply = Msg<vapi_msg_det44_close_session_in_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_det44_session_dump>(vapi_msg_det44_session_dump *msg)
{
  vapi_msg_det44_session_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_det44_session_dump>(vapi_msg_det44_session_dump *msg)
{
  vapi_msg_det44_session_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_det44_session_dump>()
{
  return ::vapi_msg_id_det44_session_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_det44_session_dump>>()
{
  return ::vapi_msg_id_det44_session_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_det44_session_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_det44_session_dump>(vapi_msg_id_det44_session_dump);
}

template <> inline vapi_msg_det44_session_dump* vapi_alloc<vapi_msg_det44_session_dump>(Connection &con)
{
  vapi_msg_det44_session_dump* result = vapi_alloc_det44_session_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_det44_session_dump>;

template class Dump<vapi_msg_det44_session_dump, vapi_msg_det44_session_details>;

using Det44_session_dump = Dump<vapi_msg_det44_session_dump, vapi_msg_det44_session_details>;

template <> inline void vapi_swap_to_be<vapi_msg_det44_session_details>(vapi_msg_det44_session_details *msg)
{
  vapi_msg_det44_session_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_det44_session_details>(vapi_msg_det44_session_details *msg)
{
  vapi_msg_det44_session_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_det44_session_details>()
{
  return ::vapi_msg_id_det44_session_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_det44_session_details>>()
{
  return ::vapi_msg_id_det44_session_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_det44_session_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_det44_session_details>(vapi_msg_id_det44_session_details);
}

template class Msg<vapi_msg_det44_session_details>;

using Det44_session_details = Msg<vapi_msg_det44_session_details>;
template <> inline void vapi_swap_to_be<vapi_msg_det44_set_timeouts>(vapi_msg_det44_set_timeouts *msg)
{
  vapi_msg_det44_set_timeouts_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_det44_set_timeouts>(vapi_msg_det44_set_timeouts *msg)
{
  vapi_msg_det44_set_timeouts_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_det44_set_timeouts>()
{
  return ::vapi_msg_id_det44_set_timeouts; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_det44_set_timeouts>>()
{
  return ::vapi_msg_id_det44_set_timeouts; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_det44_set_timeouts()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_det44_set_timeouts>(vapi_msg_id_det44_set_timeouts);
}

template <> inline vapi_msg_det44_set_timeouts* vapi_alloc<vapi_msg_det44_set_timeouts>(Connection &con)
{
  vapi_msg_det44_set_timeouts* result = vapi_alloc_det44_set_timeouts(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_det44_set_timeouts>;

template class Request<vapi_msg_det44_set_timeouts, vapi_msg_det44_set_timeouts_reply>;

using Det44_set_timeouts = Request<vapi_msg_det44_set_timeouts, vapi_msg_det44_set_timeouts_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_det44_set_timeouts_reply>(vapi_msg_det44_set_timeouts_reply *msg)
{
  vapi_msg_det44_set_timeouts_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_det44_set_timeouts_reply>(vapi_msg_det44_set_timeouts_reply *msg)
{
  vapi_msg_det44_set_timeouts_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_det44_set_timeouts_reply>()
{
  return ::vapi_msg_id_det44_set_timeouts_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_det44_set_timeouts_reply>>()
{
  return ::vapi_msg_id_det44_set_timeouts_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_det44_set_timeouts_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_det44_set_timeouts_reply>(vapi_msg_id_det44_set_timeouts_reply);
}

template class Msg<vapi_msg_det44_set_timeouts_reply>;

using Det44_set_timeouts_reply = Msg<vapi_msg_det44_set_timeouts_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_det44_get_timeouts>(vapi_msg_det44_get_timeouts *msg)
{
  vapi_msg_det44_get_timeouts_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_det44_get_timeouts>(vapi_msg_det44_get_timeouts *msg)
{
  vapi_msg_det44_get_timeouts_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_det44_get_timeouts>()
{
  return ::vapi_msg_id_det44_get_timeouts; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_det44_get_timeouts>>()
{
  return ::vapi_msg_id_det44_get_timeouts; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_det44_get_timeouts()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_det44_get_timeouts>(vapi_msg_id_det44_get_timeouts);
}

template <> inline vapi_msg_det44_get_timeouts* vapi_alloc<vapi_msg_det44_get_timeouts>(Connection &con)
{
  vapi_msg_det44_get_timeouts* result = vapi_alloc_det44_get_timeouts(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_det44_get_timeouts>;

template class Request<vapi_msg_det44_get_timeouts, vapi_msg_det44_get_timeouts_reply>;

using Det44_get_timeouts = Request<vapi_msg_det44_get_timeouts, vapi_msg_det44_get_timeouts_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_det44_get_timeouts_reply>(vapi_msg_det44_get_timeouts_reply *msg)
{
  vapi_msg_det44_get_timeouts_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_det44_get_timeouts_reply>(vapi_msg_det44_get_timeouts_reply *msg)
{
  vapi_msg_det44_get_timeouts_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_det44_get_timeouts_reply>()
{
  return ::vapi_msg_id_det44_get_timeouts_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_det44_get_timeouts_reply>>()
{
  return ::vapi_msg_id_det44_get_timeouts_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_det44_get_timeouts_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_det44_get_timeouts_reply>(vapi_msg_id_det44_get_timeouts_reply);
}

template class Msg<vapi_msg_det44_get_timeouts_reply>;

using Det44_get_timeouts_reply = Msg<vapi_msg_det44_get_timeouts_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat_det_add_del_map>(vapi_msg_nat_det_add_del_map *msg)
{
  vapi_msg_nat_det_add_del_map_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat_det_add_del_map>(vapi_msg_nat_det_add_del_map *msg)
{
  vapi_msg_nat_det_add_del_map_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat_det_add_del_map>()
{
  return ::vapi_msg_id_nat_det_add_del_map; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat_det_add_del_map>>()
{
  return ::vapi_msg_id_nat_det_add_del_map; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat_det_add_del_map()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat_det_add_del_map>(vapi_msg_id_nat_det_add_del_map);
}

template <> inline vapi_msg_nat_det_add_del_map* vapi_alloc<vapi_msg_nat_det_add_del_map>(Connection &con)
{
  vapi_msg_nat_det_add_del_map* result = vapi_alloc_nat_det_add_del_map(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat_det_add_del_map>;

template class Request<vapi_msg_nat_det_add_del_map, vapi_msg_nat_det_add_del_map_reply>;

using Nat_det_add_del_map = Request<vapi_msg_nat_det_add_del_map, vapi_msg_nat_det_add_del_map_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat_det_add_del_map_reply>(vapi_msg_nat_det_add_del_map_reply *msg)
{
  vapi_msg_nat_det_add_del_map_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat_det_add_del_map_reply>(vapi_msg_nat_det_add_del_map_reply *msg)
{
  vapi_msg_nat_det_add_del_map_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat_det_add_del_map_reply>()
{
  return ::vapi_msg_id_nat_det_add_del_map_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat_det_add_del_map_reply>>()
{
  return ::vapi_msg_id_nat_det_add_del_map_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat_det_add_del_map_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat_det_add_del_map_reply>(vapi_msg_id_nat_det_add_del_map_reply);
}

template class Msg<vapi_msg_nat_det_add_del_map_reply>;

using Nat_det_add_del_map_reply = Msg<vapi_msg_nat_det_add_del_map_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat_det_forward>(vapi_msg_nat_det_forward *msg)
{
  vapi_msg_nat_det_forward_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat_det_forward>(vapi_msg_nat_det_forward *msg)
{
  vapi_msg_nat_det_forward_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat_det_forward>()
{
  return ::vapi_msg_id_nat_det_forward; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat_det_forward>>()
{
  return ::vapi_msg_id_nat_det_forward; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat_det_forward()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat_det_forward>(vapi_msg_id_nat_det_forward);
}

template <> inline vapi_msg_nat_det_forward* vapi_alloc<vapi_msg_nat_det_forward>(Connection &con)
{
  vapi_msg_nat_det_forward* result = vapi_alloc_nat_det_forward(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat_det_forward>;

template class Request<vapi_msg_nat_det_forward, vapi_msg_nat_det_forward_reply>;

using Nat_det_forward = Request<vapi_msg_nat_det_forward, vapi_msg_nat_det_forward_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat_det_forward_reply>(vapi_msg_nat_det_forward_reply *msg)
{
  vapi_msg_nat_det_forward_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat_det_forward_reply>(vapi_msg_nat_det_forward_reply *msg)
{
  vapi_msg_nat_det_forward_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat_det_forward_reply>()
{
  return ::vapi_msg_id_nat_det_forward_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat_det_forward_reply>>()
{
  return ::vapi_msg_id_nat_det_forward_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat_det_forward_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat_det_forward_reply>(vapi_msg_id_nat_det_forward_reply);
}

template class Msg<vapi_msg_nat_det_forward_reply>;

using Nat_det_forward_reply = Msg<vapi_msg_nat_det_forward_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat_det_reverse>(vapi_msg_nat_det_reverse *msg)
{
  vapi_msg_nat_det_reverse_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat_det_reverse>(vapi_msg_nat_det_reverse *msg)
{
  vapi_msg_nat_det_reverse_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat_det_reverse>()
{
  return ::vapi_msg_id_nat_det_reverse; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat_det_reverse>>()
{
  return ::vapi_msg_id_nat_det_reverse; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat_det_reverse()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat_det_reverse>(vapi_msg_id_nat_det_reverse);
}

template <> inline vapi_msg_nat_det_reverse* vapi_alloc<vapi_msg_nat_det_reverse>(Connection &con)
{
  vapi_msg_nat_det_reverse* result = vapi_alloc_nat_det_reverse(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat_det_reverse>;

template class Request<vapi_msg_nat_det_reverse, vapi_msg_nat_det_reverse_reply>;

using Nat_det_reverse = Request<vapi_msg_nat_det_reverse, vapi_msg_nat_det_reverse_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat_det_reverse_reply>(vapi_msg_nat_det_reverse_reply *msg)
{
  vapi_msg_nat_det_reverse_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat_det_reverse_reply>(vapi_msg_nat_det_reverse_reply *msg)
{
  vapi_msg_nat_det_reverse_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat_det_reverse_reply>()
{
  return ::vapi_msg_id_nat_det_reverse_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat_det_reverse_reply>>()
{
  return ::vapi_msg_id_nat_det_reverse_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat_det_reverse_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat_det_reverse_reply>(vapi_msg_id_nat_det_reverse_reply);
}

template class Msg<vapi_msg_nat_det_reverse_reply>;

using Nat_det_reverse_reply = Msg<vapi_msg_nat_det_reverse_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat_det_map_dump>(vapi_msg_nat_det_map_dump *msg)
{
  vapi_msg_nat_det_map_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat_det_map_dump>(vapi_msg_nat_det_map_dump *msg)
{
  vapi_msg_nat_det_map_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat_det_map_dump>()
{
  return ::vapi_msg_id_nat_det_map_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat_det_map_dump>>()
{
  return ::vapi_msg_id_nat_det_map_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat_det_map_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat_det_map_dump>(vapi_msg_id_nat_det_map_dump);
}

template <> inline vapi_msg_nat_det_map_dump* vapi_alloc<vapi_msg_nat_det_map_dump>(Connection &con)
{
  vapi_msg_nat_det_map_dump* result = vapi_alloc_nat_det_map_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat_det_map_dump>;

template class Dump<vapi_msg_nat_det_map_dump, vapi_msg_nat_det_map_details>;

using Nat_det_map_dump = Dump<vapi_msg_nat_det_map_dump, vapi_msg_nat_det_map_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nat_det_map_details>(vapi_msg_nat_det_map_details *msg)
{
  vapi_msg_nat_det_map_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat_det_map_details>(vapi_msg_nat_det_map_details *msg)
{
  vapi_msg_nat_det_map_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat_det_map_details>()
{
  return ::vapi_msg_id_nat_det_map_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat_det_map_details>>()
{
  return ::vapi_msg_id_nat_det_map_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat_det_map_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat_det_map_details>(vapi_msg_id_nat_det_map_details);
}

template class Msg<vapi_msg_nat_det_map_details>;

using Nat_det_map_details = Msg<vapi_msg_nat_det_map_details>;
template <> inline void vapi_swap_to_be<vapi_msg_nat_det_close_session_out>(vapi_msg_nat_det_close_session_out *msg)
{
  vapi_msg_nat_det_close_session_out_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat_det_close_session_out>(vapi_msg_nat_det_close_session_out *msg)
{
  vapi_msg_nat_det_close_session_out_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat_det_close_session_out>()
{
  return ::vapi_msg_id_nat_det_close_session_out; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat_det_close_session_out>>()
{
  return ::vapi_msg_id_nat_det_close_session_out; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat_det_close_session_out()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat_det_close_session_out>(vapi_msg_id_nat_det_close_session_out);
}

template <> inline vapi_msg_nat_det_close_session_out* vapi_alloc<vapi_msg_nat_det_close_session_out>(Connection &con)
{
  vapi_msg_nat_det_close_session_out* result = vapi_alloc_nat_det_close_session_out(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat_det_close_session_out>;

template class Request<vapi_msg_nat_det_close_session_out, vapi_msg_nat_det_close_session_out_reply>;

using Nat_det_close_session_out = Request<vapi_msg_nat_det_close_session_out, vapi_msg_nat_det_close_session_out_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat_det_close_session_out_reply>(vapi_msg_nat_det_close_session_out_reply *msg)
{
  vapi_msg_nat_det_close_session_out_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat_det_close_session_out_reply>(vapi_msg_nat_det_close_session_out_reply *msg)
{
  vapi_msg_nat_det_close_session_out_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat_det_close_session_out_reply>()
{
  return ::vapi_msg_id_nat_det_close_session_out_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat_det_close_session_out_reply>>()
{
  return ::vapi_msg_id_nat_det_close_session_out_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat_det_close_session_out_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat_det_close_session_out_reply>(vapi_msg_id_nat_det_close_session_out_reply);
}

template class Msg<vapi_msg_nat_det_close_session_out_reply>;

using Nat_det_close_session_out_reply = Msg<vapi_msg_nat_det_close_session_out_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat_det_close_session_in>(vapi_msg_nat_det_close_session_in *msg)
{
  vapi_msg_nat_det_close_session_in_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat_det_close_session_in>(vapi_msg_nat_det_close_session_in *msg)
{
  vapi_msg_nat_det_close_session_in_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat_det_close_session_in>()
{
  return ::vapi_msg_id_nat_det_close_session_in; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat_det_close_session_in>>()
{
  return ::vapi_msg_id_nat_det_close_session_in; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat_det_close_session_in()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat_det_close_session_in>(vapi_msg_id_nat_det_close_session_in);
}

template <> inline vapi_msg_nat_det_close_session_in* vapi_alloc<vapi_msg_nat_det_close_session_in>(Connection &con)
{
  vapi_msg_nat_det_close_session_in* result = vapi_alloc_nat_det_close_session_in(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat_det_close_session_in>;

template class Request<vapi_msg_nat_det_close_session_in, vapi_msg_nat_det_close_session_in_reply>;

using Nat_det_close_session_in = Request<vapi_msg_nat_det_close_session_in, vapi_msg_nat_det_close_session_in_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat_det_close_session_in_reply>(vapi_msg_nat_det_close_session_in_reply *msg)
{
  vapi_msg_nat_det_close_session_in_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat_det_close_session_in_reply>(vapi_msg_nat_det_close_session_in_reply *msg)
{
  vapi_msg_nat_det_close_session_in_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat_det_close_session_in_reply>()
{
  return ::vapi_msg_id_nat_det_close_session_in_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat_det_close_session_in_reply>>()
{
  return ::vapi_msg_id_nat_det_close_session_in_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat_det_close_session_in_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat_det_close_session_in_reply>(vapi_msg_id_nat_det_close_session_in_reply);
}

template class Msg<vapi_msg_nat_det_close_session_in_reply>;

using Nat_det_close_session_in_reply = Msg<vapi_msg_nat_det_close_session_in_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat_det_session_dump>(vapi_msg_nat_det_session_dump *msg)
{
  vapi_msg_nat_det_session_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat_det_session_dump>(vapi_msg_nat_det_session_dump *msg)
{
  vapi_msg_nat_det_session_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat_det_session_dump>()
{
  return ::vapi_msg_id_nat_det_session_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat_det_session_dump>>()
{
  return ::vapi_msg_id_nat_det_session_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat_det_session_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat_det_session_dump>(vapi_msg_id_nat_det_session_dump);
}

template <> inline vapi_msg_nat_det_session_dump* vapi_alloc<vapi_msg_nat_det_session_dump>(Connection &con)
{
  vapi_msg_nat_det_session_dump* result = vapi_alloc_nat_det_session_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat_det_session_dump>;

template class Dump<vapi_msg_nat_det_session_dump, vapi_msg_nat_det_session_details>;

using Nat_det_session_dump = Dump<vapi_msg_nat_det_session_dump, vapi_msg_nat_det_session_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nat_det_session_details>(vapi_msg_nat_det_session_details *msg)
{
  vapi_msg_nat_det_session_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat_det_session_details>(vapi_msg_nat_det_session_details *msg)
{
  vapi_msg_nat_det_session_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat_det_session_details>()
{
  return ::vapi_msg_id_nat_det_session_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat_det_session_details>>()
{
  return ::vapi_msg_id_nat_det_session_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat_det_session_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat_det_session_details>(vapi_msg_id_nat_det_session_details);
}

template class Msg<vapi_msg_nat_det_session_details>;

using Nat_det_session_details = Msg<vapi_msg_nat_det_session_details>;
}
#endif
