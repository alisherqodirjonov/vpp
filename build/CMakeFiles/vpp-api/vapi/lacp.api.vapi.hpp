#ifndef __included_hpp_lacp_api_json
#define __included_hpp_lacp_api_json

#include <vapi/vapi.hpp>
#include <vapi/lacp.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_lacp_dump>(vapi_msg_sw_interface_lacp_dump *msg)
{
  vapi_msg_sw_interface_lacp_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_lacp_dump>(vapi_msg_sw_interface_lacp_dump *msg)
{
  vapi_msg_sw_interface_lacp_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_lacp_dump>()
{
  return ::vapi_msg_id_sw_interface_lacp_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_lacp_dump>>()
{
  return ::vapi_msg_id_sw_interface_lacp_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_lacp_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_lacp_dump>(vapi_msg_id_sw_interface_lacp_dump);
}

template <> inline vapi_msg_sw_interface_lacp_dump* vapi_alloc<vapi_msg_sw_interface_lacp_dump>(Connection &con)
{
  vapi_msg_sw_interface_lacp_dump* result = vapi_alloc_sw_interface_lacp_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_lacp_dump>;

template class Dump<vapi_msg_sw_interface_lacp_dump, vapi_msg_sw_interface_lacp_details>;

using Sw_interface_lacp_dump = Dump<vapi_msg_sw_interface_lacp_dump, vapi_msg_sw_interface_lacp_details>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_lacp_details>(vapi_msg_sw_interface_lacp_details *msg)
{
  vapi_msg_sw_interface_lacp_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_lacp_details>(vapi_msg_sw_interface_lacp_details *msg)
{
  vapi_msg_sw_interface_lacp_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_lacp_details>()
{
  return ::vapi_msg_id_sw_interface_lacp_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_lacp_details>>()
{
  return ::vapi_msg_id_sw_interface_lacp_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_lacp_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_lacp_details>(vapi_msg_id_sw_interface_lacp_details);
}

template class Msg<vapi_msg_sw_interface_lacp_details>;

using Sw_interface_lacp_details = Msg<vapi_msg_sw_interface_lacp_details>;
}
#endif
