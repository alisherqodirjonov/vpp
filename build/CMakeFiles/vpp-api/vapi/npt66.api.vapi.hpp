#ifndef __included_hpp_npt66_api_json
#define __included_hpp_npt66_api_json

#include <vapi/vapi.hpp>
#include <vapi/npt66.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_npt66_binding_add_del>(vapi_msg_npt66_binding_add_del *msg)
{
  vapi_msg_npt66_binding_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_npt66_binding_add_del>(vapi_msg_npt66_binding_add_del *msg)
{
  vapi_msg_npt66_binding_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_npt66_binding_add_del>()
{
  return ::vapi_msg_id_npt66_binding_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_npt66_binding_add_del>>()
{
  return ::vapi_msg_id_npt66_binding_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_npt66_binding_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_npt66_binding_add_del>(vapi_msg_id_npt66_binding_add_del);
}

template <> inline vapi_msg_npt66_binding_add_del* vapi_alloc<vapi_msg_npt66_binding_add_del>(Connection &con)
{
  vapi_msg_npt66_binding_add_del* result = vapi_alloc_npt66_binding_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_npt66_binding_add_del>;

template class Request<vapi_msg_npt66_binding_add_del, vapi_msg_npt66_binding_add_del_reply>;

using Npt66_binding_add_del = Request<vapi_msg_npt66_binding_add_del, vapi_msg_npt66_binding_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_npt66_binding_add_del_reply>(vapi_msg_npt66_binding_add_del_reply *msg)
{
  vapi_msg_npt66_binding_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_npt66_binding_add_del_reply>(vapi_msg_npt66_binding_add_del_reply *msg)
{
  vapi_msg_npt66_binding_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_npt66_binding_add_del_reply>()
{
  return ::vapi_msg_id_npt66_binding_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_npt66_binding_add_del_reply>>()
{
  return ::vapi_msg_id_npt66_binding_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_npt66_binding_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_npt66_binding_add_del_reply>(vapi_msg_id_npt66_binding_add_del_reply);
}

template class Msg<vapi_msg_npt66_binding_add_del_reply>;

using Npt66_binding_add_del_reply = Msg<vapi_msg_npt66_binding_add_del_reply>;
}
#endif
