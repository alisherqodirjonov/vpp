#ifndef __included_hpp_lldp_api_json
#define __included_hpp_lldp_api_json

#include <vapi/vapi.hpp>
#include <vapi/lldp.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_lldp_config>(vapi_msg_lldp_config *msg)
{
  vapi_msg_lldp_config_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lldp_config>(vapi_msg_lldp_config *msg)
{
  vapi_msg_lldp_config_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lldp_config>()
{
  return ::vapi_msg_id_lldp_config; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lldp_config>>()
{
  return ::vapi_msg_id_lldp_config; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lldp_config()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lldp_config>(vapi_msg_id_lldp_config);
}

template <> inline vapi_msg_lldp_config* vapi_alloc<vapi_msg_lldp_config, size_t>(Connection &con, size_t system_name_buf_array_size)
{
  vapi_msg_lldp_config* result = vapi_alloc_lldp_config(con.vapi_ctx, system_name_buf_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lldp_config>;

template class Request<vapi_msg_lldp_config, vapi_msg_lldp_config_reply, size_t>;

using Lldp_config = Request<vapi_msg_lldp_config, vapi_msg_lldp_config_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_lldp_config_reply>(vapi_msg_lldp_config_reply *msg)
{
  vapi_msg_lldp_config_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lldp_config_reply>(vapi_msg_lldp_config_reply *msg)
{
  vapi_msg_lldp_config_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lldp_config_reply>()
{
  return ::vapi_msg_id_lldp_config_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lldp_config_reply>>()
{
  return ::vapi_msg_id_lldp_config_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lldp_config_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lldp_config_reply>(vapi_msg_id_lldp_config_reply);
}

template class Msg<vapi_msg_lldp_config_reply>;

using Lldp_config_reply = Msg<vapi_msg_lldp_config_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_lldp>(vapi_msg_sw_interface_set_lldp *msg)
{
  vapi_msg_sw_interface_set_lldp_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_lldp>(vapi_msg_sw_interface_set_lldp *msg)
{
  vapi_msg_sw_interface_set_lldp_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_lldp>()
{
  return ::vapi_msg_id_sw_interface_set_lldp; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_lldp>>()
{
  return ::vapi_msg_id_sw_interface_set_lldp; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_lldp()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_lldp>(vapi_msg_id_sw_interface_set_lldp);
}

template <> inline vapi_msg_sw_interface_set_lldp* vapi_alloc<vapi_msg_sw_interface_set_lldp, size_t>(Connection &con, size_t port_desc_buf_array_size)
{
  vapi_msg_sw_interface_set_lldp* result = vapi_alloc_sw_interface_set_lldp(con.vapi_ctx, port_desc_buf_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_set_lldp>;

template class Request<vapi_msg_sw_interface_set_lldp, vapi_msg_sw_interface_set_lldp_reply, size_t>;

using Sw_interface_set_lldp = Request<vapi_msg_sw_interface_set_lldp, vapi_msg_sw_interface_set_lldp_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_lldp_reply>(vapi_msg_sw_interface_set_lldp_reply *msg)
{
  vapi_msg_sw_interface_set_lldp_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_lldp_reply>(vapi_msg_sw_interface_set_lldp_reply *msg)
{
  vapi_msg_sw_interface_set_lldp_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_lldp_reply>()
{
  return ::vapi_msg_id_sw_interface_set_lldp_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_lldp_reply>>()
{
  return ::vapi_msg_id_sw_interface_set_lldp_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_lldp_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_lldp_reply>(vapi_msg_id_sw_interface_set_lldp_reply);
}

template class Msg<vapi_msg_sw_interface_set_lldp_reply>;

using Sw_interface_set_lldp_reply = Msg<vapi_msg_sw_interface_set_lldp_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_lldp_dump>(vapi_msg_lldp_dump *msg)
{
  vapi_msg_lldp_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lldp_dump>(vapi_msg_lldp_dump *msg)
{
  vapi_msg_lldp_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lldp_dump>()
{
  return ::vapi_msg_id_lldp_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lldp_dump>>()
{
  return ::vapi_msg_id_lldp_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lldp_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lldp_dump>(vapi_msg_id_lldp_dump);
}

template <> inline vapi_msg_lldp_dump* vapi_alloc<vapi_msg_lldp_dump>(Connection &con)
{
  vapi_msg_lldp_dump* result = vapi_alloc_lldp_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lldp_dump>;

template class Stream<vapi_msg_lldp_dump, vapi_msg_lldp_dump_reply, vapi_msg_lldp_details>;

using Lldp_dump = Stream<vapi_msg_lldp_dump, vapi_msg_lldp_dump_reply, vapi_msg_lldp_details>;

template <> inline void vapi_swap_to_be<vapi_msg_lldp_dump_reply>(vapi_msg_lldp_dump_reply *msg)
{
  vapi_msg_lldp_dump_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lldp_dump_reply>(vapi_msg_lldp_dump_reply *msg)
{
  vapi_msg_lldp_dump_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lldp_dump_reply>()
{
  return ::vapi_msg_id_lldp_dump_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lldp_dump_reply>>()
{
  return ::vapi_msg_id_lldp_dump_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lldp_dump_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lldp_dump_reply>(vapi_msg_id_lldp_dump_reply);
}

template class Msg<vapi_msg_lldp_dump_reply>;

using Lldp_dump_reply = Msg<vapi_msg_lldp_dump_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_lldp_details>(vapi_msg_lldp_details *msg)
{
  vapi_msg_lldp_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lldp_details>(vapi_msg_lldp_details *msg)
{
  vapi_msg_lldp_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lldp_details>()
{
  return ::vapi_msg_id_lldp_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lldp_details>>()
{
  return ::vapi_msg_id_lldp_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lldp_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lldp_details>(vapi_msg_id_lldp_details);
}

template class Msg<vapi_msg_lldp_details>;

}
#endif
