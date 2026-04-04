#ifndef __included_hpp_flowprobe_api_json
#define __included_hpp_flowprobe_api_json

#include <vapi/vapi.hpp>
#include <vapi/flowprobe.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_flowprobe_tx_interface_add_del>(vapi_msg_flowprobe_tx_interface_add_del *msg)
{
  vapi_msg_flowprobe_tx_interface_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_flowprobe_tx_interface_add_del>(vapi_msg_flowprobe_tx_interface_add_del *msg)
{
  vapi_msg_flowprobe_tx_interface_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_flowprobe_tx_interface_add_del>()
{
  return ::vapi_msg_id_flowprobe_tx_interface_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_flowprobe_tx_interface_add_del>>()
{
  return ::vapi_msg_id_flowprobe_tx_interface_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_flowprobe_tx_interface_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_flowprobe_tx_interface_add_del>(vapi_msg_id_flowprobe_tx_interface_add_del);
}

template <> inline vapi_msg_flowprobe_tx_interface_add_del* vapi_alloc<vapi_msg_flowprobe_tx_interface_add_del>(Connection &con)
{
  vapi_msg_flowprobe_tx_interface_add_del* result = vapi_alloc_flowprobe_tx_interface_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_flowprobe_tx_interface_add_del>;

template class Request<vapi_msg_flowprobe_tx_interface_add_del, vapi_msg_flowprobe_tx_interface_add_del_reply>;

using Flowprobe_tx_interface_add_del = Request<vapi_msg_flowprobe_tx_interface_add_del, vapi_msg_flowprobe_tx_interface_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_flowprobe_tx_interface_add_del_reply>(vapi_msg_flowprobe_tx_interface_add_del_reply *msg)
{
  vapi_msg_flowprobe_tx_interface_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_flowprobe_tx_interface_add_del_reply>(vapi_msg_flowprobe_tx_interface_add_del_reply *msg)
{
  vapi_msg_flowprobe_tx_interface_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_flowprobe_tx_interface_add_del_reply>()
{
  return ::vapi_msg_id_flowprobe_tx_interface_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_flowprobe_tx_interface_add_del_reply>>()
{
  return ::vapi_msg_id_flowprobe_tx_interface_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_flowprobe_tx_interface_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_flowprobe_tx_interface_add_del_reply>(vapi_msg_id_flowprobe_tx_interface_add_del_reply);
}

template class Msg<vapi_msg_flowprobe_tx_interface_add_del_reply>;

using Flowprobe_tx_interface_add_del_reply = Msg<vapi_msg_flowprobe_tx_interface_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_flowprobe_interface_add_del>(vapi_msg_flowprobe_interface_add_del *msg)
{
  vapi_msg_flowprobe_interface_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_flowprobe_interface_add_del>(vapi_msg_flowprobe_interface_add_del *msg)
{
  vapi_msg_flowprobe_interface_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_flowprobe_interface_add_del>()
{
  return ::vapi_msg_id_flowprobe_interface_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_flowprobe_interface_add_del>>()
{
  return ::vapi_msg_id_flowprobe_interface_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_flowprobe_interface_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_flowprobe_interface_add_del>(vapi_msg_id_flowprobe_interface_add_del);
}

template <> inline vapi_msg_flowprobe_interface_add_del* vapi_alloc<vapi_msg_flowprobe_interface_add_del>(Connection &con)
{
  vapi_msg_flowprobe_interface_add_del* result = vapi_alloc_flowprobe_interface_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_flowprobe_interface_add_del>;

template class Request<vapi_msg_flowprobe_interface_add_del, vapi_msg_flowprobe_interface_add_del_reply>;

using Flowprobe_interface_add_del = Request<vapi_msg_flowprobe_interface_add_del, vapi_msg_flowprobe_interface_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_flowprobe_interface_add_del_reply>(vapi_msg_flowprobe_interface_add_del_reply *msg)
{
  vapi_msg_flowprobe_interface_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_flowprobe_interface_add_del_reply>(vapi_msg_flowprobe_interface_add_del_reply *msg)
{
  vapi_msg_flowprobe_interface_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_flowprobe_interface_add_del_reply>()
{
  return ::vapi_msg_id_flowprobe_interface_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_flowprobe_interface_add_del_reply>>()
{
  return ::vapi_msg_id_flowprobe_interface_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_flowprobe_interface_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_flowprobe_interface_add_del_reply>(vapi_msg_id_flowprobe_interface_add_del_reply);
}

template class Msg<vapi_msg_flowprobe_interface_add_del_reply>;

using Flowprobe_interface_add_del_reply = Msg<vapi_msg_flowprobe_interface_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_flowprobe_interface_dump>(vapi_msg_flowprobe_interface_dump *msg)
{
  vapi_msg_flowprobe_interface_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_flowprobe_interface_dump>(vapi_msg_flowprobe_interface_dump *msg)
{
  vapi_msg_flowprobe_interface_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_flowprobe_interface_dump>()
{
  return ::vapi_msg_id_flowprobe_interface_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_flowprobe_interface_dump>>()
{
  return ::vapi_msg_id_flowprobe_interface_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_flowprobe_interface_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_flowprobe_interface_dump>(vapi_msg_id_flowprobe_interface_dump);
}

template <> inline vapi_msg_flowprobe_interface_dump* vapi_alloc<vapi_msg_flowprobe_interface_dump>(Connection &con)
{
  vapi_msg_flowprobe_interface_dump* result = vapi_alloc_flowprobe_interface_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_flowprobe_interface_dump>;

template class Dump<vapi_msg_flowprobe_interface_dump, vapi_msg_flowprobe_interface_details>;

using Flowprobe_interface_dump = Dump<vapi_msg_flowprobe_interface_dump, vapi_msg_flowprobe_interface_details>;

template <> inline void vapi_swap_to_be<vapi_msg_flowprobe_interface_details>(vapi_msg_flowprobe_interface_details *msg)
{
  vapi_msg_flowprobe_interface_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_flowprobe_interface_details>(vapi_msg_flowprobe_interface_details *msg)
{
  vapi_msg_flowprobe_interface_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_flowprobe_interface_details>()
{
  return ::vapi_msg_id_flowprobe_interface_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_flowprobe_interface_details>>()
{
  return ::vapi_msg_id_flowprobe_interface_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_flowprobe_interface_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_flowprobe_interface_details>(vapi_msg_id_flowprobe_interface_details);
}

template class Msg<vapi_msg_flowprobe_interface_details>;

using Flowprobe_interface_details = Msg<vapi_msg_flowprobe_interface_details>;
template <> inline void vapi_swap_to_be<vapi_msg_flowprobe_params>(vapi_msg_flowprobe_params *msg)
{
  vapi_msg_flowprobe_params_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_flowprobe_params>(vapi_msg_flowprobe_params *msg)
{
  vapi_msg_flowprobe_params_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_flowprobe_params>()
{
  return ::vapi_msg_id_flowprobe_params; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_flowprobe_params>>()
{
  return ::vapi_msg_id_flowprobe_params; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_flowprobe_params()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_flowprobe_params>(vapi_msg_id_flowprobe_params);
}

template <> inline vapi_msg_flowprobe_params* vapi_alloc<vapi_msg_flowprobe_params>(Connection &con)
{
  vapi_msg_flowprobe_params* result = vapi_alloc_flowprobe_params(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_flowprobe_params>;

template class Request<vapi_msg_flowprobe_params, vapi_msg_flowprobe_params_reply>;

using Flowprobe_params = Request<vapi_msg_flowprobe_params, vapi_msg_flowprobe_params_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_flowprobe_params_reply>(vapi_msg_flowprobe_params_reply *msg)
{
  vapi_msg_flowprobe_params_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_flowprobe_params_reply>(vapi_msg_flowprobe_params_reply *msg)
{
  vapi_msg_flowprobe_params_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_flowprobe_params_reply>()
{
  return ::vapi_msg_id_flowprobe_params_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_flowprobe_params_reply>>()
{
  return ::vapi_msg_id_flowprobe_params_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_flowprobe_params_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_flowprobe_params_reply>(vapi_msg_id_flowprobe_params_reply);
}

template class Msg<vapi_msg_flowprobe_params_reply>;

using Flowprobe_params_reply = Msg<vapi_msg_flowprobe_params_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_flowprobe_set_params>(vapi_msg_flowprobe_set_params *msg)
{
  vapi_msg_flowprobe_set_params_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_flowprobe_set_params>(vapi_msg_flowprobe_set_params *msg)
{
  vapi_msg_flowprobe_set_params_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_flowprobe_set_params>()
{
  return ::vapi_msg_id_flowprobe_set_params; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_flowprobe_set_params>>()
{
  return ::vapi_msg_id_flowprobe_set_params; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_flowprobe_set_params()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_flowprobe_set_params>(vapi_msg_id_flowprobe_set_params);
}

template <> inline vapi_msg_flowprobe_set_params* vapi_alloc<vapi_msg_flowprobe_set_params>(Connection &con)
{
  vapi_msg_flowprobe_set_params* result = vapi_alloc_flowprobe_set_params(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_flowprobe_set_params>;

template class Request<vapi_msg_flowprobe_set_params, vapi_msg_flowprobe_set_params_reply>;

using Flowprobe_set_params = Request<vapi_msg_flowprobe_set_params, vapi_msg_flowprobe_set_params_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_flowprobe_set_params_reply>(vapi_msg_flowprobe_set_params_reply *msg)
{
  vapi_msg_flowprobe_set_params_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_flowprobe_set_params_reply>(vapi_msg_flowprobe_set_params_reply *msg)
{
  vapi_msg_flowprobe_set_params_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_flowprobe_set_params_reply>()
{
  return ::vapi_msg_id_flowprobe_set_params_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_flowprobe_set_params_reply>>()
{
  return ::vapi_msg_id_flowprobe_set_params_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_flowprobe_set_params_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_flowprobe_set_params_reply>(vapi_msg_id_flowprobe_set_params_reply);
}

template class Msg<vapi_msg_flowprobe_set_params_reply>;

using Flowprobe_set_params_reply = Msg<vapi_msg_flowprobe_set_params_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_flowprobe_get_params>(vapi_msg_flowprobe_get_params *msg)
{
  vapi_msg_flowprobe_get_params_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_flowprobe_get_params>(vapi_msg_flowprobe_get_params *msg)
{
  vapi_msg_flowprobe_get_params_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_flowprobe_get_params>()
{
  return ::vapi_msg_id_flowprobe_get_params; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_flowprobe_get_params>>()
{
  return ::vapi_msg_id_flowprobe_get_params; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_flowprobe_get_params()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_flowprobe_get_params>(vapi_msg_id_flowprobe_get_params);
}

template <> inline vapi_msg_flowprobe_get_params* vapi_alloc<vapi_msg_flowprobe_get_params>(Connection &con)
{
  vapi_msg_flowprobe_get_params* result = vapi_alloc_flowprobe_get_params(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_flowprobe_get_params>;

template class Request<vapi_msg_flowprobe_get_params, vapi_msg_flowprobe_get_params_reply>;

using Flowprobe_get_params = Request<vapi_msg_flowprobe_get_params, vapi_msg_flowprobe_get_params_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_flowprobe_get_params_reply>(vapi_msg_flowprobe_get_params_reply *msg)
{
  vapi_msg_flowprobe_get_params_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_flowprobe_get_params_reply>(vapi_msg_flowprobe_get_params_reply *msg)
{
  vapi_msg_flowprobe_get_params_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_flowprobe_get_params_reply>()
{
  return ::vapi_msg_id_flowprobe_get_params_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_flowprobe_get_params_reply>>()
{
  return ::vapi_msg_id_flowprobe_get_params_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_flowprobe_get_params_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_flowprobe_get_params_reply>(vapi_msg_id_flowprobe_get_params_reply);
}

template class Msg<vapi_msg_flowprobe_get_params_reply>;

using Flowprobe_get_params_reply = Msg<vapi_msg_flowprobe_get_params_reply>;
}
#endif
