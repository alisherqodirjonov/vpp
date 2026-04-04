#ifndef __included_hpp_session_api_json
#define __included_hpp_session_api_json

#include <vapi/vapi.hpp>
#include <vapi/session.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_app_attach>(vapi_msg_app_attach *msg)
{
  vapi_msg_app_attach_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_app_attach>(vapi_msg_app_attach *msg)
{
  vapi_msg_app_attach_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_app_attach>()
{
  return ::vapi_msg_id_app_attach; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_app_attach>>()
{
  return ::vapi_msg_id_app_attach; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_app_attach()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_app_attach>(vapi_msg_id_app_attach);
}

template <> inline vapi_msg_app_attach* vapi_alloc<vapi_msg_app_attach, size_t>(Connection &con, size_t namespace_id_buf_array_size)
{
  vapi_msg_app_attach* result = vapi_alloc_app_attach(con.vapi_ctx, namespace_id_buf_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_app_attach>;

template class Request<vapi_msg_app_attach, vapi_msg_app_attach_reply, size_t>;

using App_attach = Request<vapi_msg_app_attach, vapi_msg_app_attach_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_app_attach_reply>(vapi_msg_app_attach_reply *msg)
{
  vapi_msg_app_attach_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_app_attach_reply>(vapi_msg_app_attach_reply *msg)
{
  vapi_msg_app_attach_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_app_attach_reply>()
{
  return ::vapi_msg_id_app_attach_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_app_attach_reply>>()
{
  return ::vapi_msg_id_app_attach_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_app_attach_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_app_attach_reply>(vapi_msg_id_app_attach_reply);
}

template class Msg<vapi_msg_app_attach_reply>;

using App_attach_reply = Msg<vapi_msg_app_attach_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_application_detach>(vapi_msg_application_detach *msg)
{
  vapi_msg_application_detach_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_application_detach>(vapi_msg_application_detach *msg)
{
  vapi_msg_application_detach_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_application_detach>()
{
  return ::vapi_msg_id_application_detach; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_application_detach>>()
{
  return ::vapi_msg_id_application_detach; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_application_detach()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_application_detach>(vapi_msg_id_application_detach);
}

template <> inline vapi_msg_application_detach* vapi_alloc<vapi_msg_application_detach>(Connection &con)
{
  vapi_msg_application_detach* result = vapi_alloc_application_detach(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_application_detach>;

template class Request<vapi_msg_application_detach, vapi_msg_application_detach_reply>;

using Application_detach = Request<vapi_msg_application_detach, vapi_msg_application_detach_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_application_detach_reply>(vapi_msg_application_detach_reply *msg)
{
  vapi_msg_application_detach_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_application_detach_reply>(vapi_msg_application_detach_reply *msg)
{
  vapi_msg_application_detach_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_application_detach_reply>()
{
  return ::vapi_msg_id_application_detach_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_application_detach_reply>>()
{
  return ::vapi_msg_id_application_detach_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_application_detach_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_application_detach_reply>(vapi_msg_id_application_detach_reply);
}

template class Msg<vapi_msg_application_detach_reply>;

using Application_detach_reply = Msg<vapi_msg_application_detach_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_app_add_cert_key_pair>(vapi_msg_app_add_cert_key_pair *msg)
{
  vapi_msg_app_add_cert_key_pair_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_app_add_cert_key_pair>(vapi_msg_app_add_cert_key_pair *msg)
{
  vapi_msg_app_add_cert_key_pair_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_app_add_cert_key_pair>()
{
  return ::vapi_msg_id_app_add_cert_key_pair; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_app_add_cert_key_pair>>()
{
  return ::vapi_msg_id_app_add_cert_key_pair; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_app_add_cert_key_pair()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_app_add_cert_key_pair>(vapi_msg_id_app_add_cert_key_pair);
}

template <> inline vapi_msg_app_add_cert_key_pair* vapi_alloc<vapi_msg_app_add_cert_key_pair, size_t>(Connection &con, size_t _certkey_array_size)
{
  vapi_msg_app_add_cert_key_pair* result = vapi_alloc_app_add_cert_key_pair(con.vapi_ctx, _certkey_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_app_add_cert_key_pair>;

template class Request<vapi_msg_app_add_cert_key_pair, vapi_msg_app_add_cert_key_pair_reply, size_t>;

using App_add_cert_key_pair = Request<vapi_msg_app_add_cert_key_pair, vapi_msg_app_add_cert_key_pair_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_app_add_cert_key_pair_reply>(vapi_msg_app_add_cert_key_pair_reply *msg)
{
  vapi_msg_app_add_cert_key_pair_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_app_add_cert_key_pair_reply>(vapi_msg_app_add_cert_key_pair_reply *msg)
{
  vapi_msg_app_add_cert_key_pair_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_app_add_cert_key_pair_reply>()
{
  return ::vapi_msg_id_app_add_cert_key_pair_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_app_add_cert_key_pair_reply>>()
{
  return ::vapi_msg_id_app_add_cert_key_pair_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_app_add_cert_key_pair_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_app_add_cert_key_pair_reply>(vapi_msg_id_app_add_cert_key_pair_reply);
}

template class Msg<vapi_msg_app_add_cert_key_pair_reply>;

using App_add_cert_key_pair_reply = Msg<vapi_msg_app_add_cert_key_pair_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_app_del_cert_key_pair>(vapi_msg_app_del_cert_key_pair *msg)
{
  vapi_msg_app_del_cert_key_pair_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_app_del_cert_key_pair>(vapi_msg_app_del_cert_key_pair *msg)
{
  vapi_msg_app_del_cert_key_pair_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_app_del_cert_key_pair>()
{
  return ::vapi_msg_id_app_del_cert_key_pair; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_app_del_cert_key_pair>>()
{
  return ::vapi_msg_id_app_del_cert_key_pair; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_app_del_cert_key_pair()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_app_del_cert_key_pair>(vapi_msg_id_app_del_cert_key_pair);
}

template <> inline vapi_msg_app_del_cert_key_pair* vapi_alloc<vapi_msg_app_del_cert_key_pair>(Connection &con)
{
  vapi_msg_app_del_cert_key_pair* result = vapi_alloc_app_del_cert_key_pair(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_app_del_cert_key_pair>;

template class Request<vapi_msg_app_del_cert_key_pair, vapi_msg_app_del_cert_key_pair_reply>;

using App_del_cert_key_pair = Request<vapi_msg_app_del_cert_key_pair, vapi_msg_app_del_cert_key_pair_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_app_del_cert_key_pair_reply>(vapi_msg_app_del_cert_key_pair_reply *msg)
{
  vapi_msg_app_del_cert_key_pair_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_app_del_cert_key_pair_reply>(vapi_msg_app_del_cert_key_pair_reply *msg)
{
  vapi_msg_app_del_cert_key_pair_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_app_del_cert_key_pair_reply>()
{
  return ::vapi_msg_id_app_del_cert_key_pair_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_app_del_cert_key_pair_reply>>()
{
  return ::vapi_msg_id_app_del_cert_key_pair_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_app_del_cert_key_pair_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_app_del_cert_key_pair_reply>(vapi_msg_id_app_del_cert_key_pair_reply);
}

template class Msg<vapi_msg_app_del_cert_key_pair_reply>;

using App_del_cert_key_pair_reply = Msg<vapi_msg_app_del_cert_key_pair_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_app_worker_add_del>(vapi_msg_app_worker_add_del *msg)
{
  vapi_msg_app_worker_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_app_worker_add_del>(vapi_msg_app_worker_add_del *msg)
{
  vapi_msg_app_worker_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_app_worker_add_del>()
{
  return ::vapi_msg_id_app_worker_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_app_worker_add_del>>()
{
  return ::vapi_msg_id_app_worker_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_app_worker_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_app_worker_add_del>(vapi_msg_id_app_worker_add_del);
}

template <> inline vapi_msg_app_worker_add_del* vapi_alloc<vapi_msg_app_worker_add_del>(Connection &con)
{
  vapi_msg_app_worker_add_del* result = vapi_alloc_app_worker_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_app_worker_add_del>;

template class Request<vapi_msg_app_worker_add_del, vapi_msg_app_worker_add_del_reply>;

using App_worker_add_del = Request<vapi_msg_app_worker_add_del, vapi_msg_app_worker_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_app_worker_add_del_reply>(vapi_msg_app_worker_add_del_reply *msg)
{
  vapi_msg_app_worker_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_app_worker_add_del_reply>(vapi_msg_app_worker_add_del_reply *msg)
{
  vapi_msg_app_worker_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_app_worker_add_del_reply>()
{
  return ::vapi_msg_id_app_worker_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_app_worker_add_del_reply>>()
{
  return ::vapi_msg_id_app_worker_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_app_worker_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_app_worker_add_del_reply>(vapi_msg_id_app_worker_add_del_reply);
}

template class Msg<vapi_msg_app_worker_add_del_reply>;

using App_worker_add_del_reply = Msg<vapi_msg_app_worker_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_session_enable_disable>(vapi_msg_session_enable_disable *msg)
{
  vapi_msg_session_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_session_enable_disable>(vapi_msg_session_enable_disable *msg)
{
  vapi_msg_session_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_session_enable_disable>()
{
  return ::vapi_msg_id_session_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_session_enable_disable>>()
{
  return ::vapi_msg_id_session_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_session_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_session_enable_disable>(vapi_msg_id_session_enable_disable);
}

template <> inline vapi_msg_session_enable_disable* vapi_alloc<vapi_msg_session_enable_disable>(Connection &con)
{
  vapi_msg_session_enable_disable* result = vapi_alloc_session_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_session_enable_disable>;

template class Request<vapi_msg_session_enable_disable, vapi_msg_session_enable_disable_reply>;

using Session_enable_disable = Request<vapi_msg_session_enable_disable, vapi_msg_session_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_session_enable_disable_reply>(vapi_msg_session_enable_disable_reply *msg)
{
  vapi_msg_session_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_session_enable_disable_reply>(vapi_msg_session_enable_disable_reply *msg)
{
  vapi_msg_session_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_session_enable_disable_reply>()
{
  return ::vapi_msg_id_session_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_session_enable_disable_reply>>()
{
  return ::vapi_msg_id_session_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_session_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_session_enable_disable_reply>(vapi_msg_id_session_enable_disable_reply);
}

template class Msg<vapi_msg_session_enable_disable_reply>;

using Session_enable_disable_reply = Msg<vapi_msg_session_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_session_enable_disable_v2>(vapi_msg_session_enable_disable_v2 *msg)
{
  vapi_msg_session_enable_disable_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_session_enable_disable_v2>(vapi_msg_session_enable_disable_v2 *msg)
{
  vapi_msg_session_enable_disable_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_session_enable_disable_v2>()
{
  return ::vapi_msg_id_session_enable_disable_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_session_enable_disable_v2>>()
{
  return ::vapi_msg_id_session_enable_disable_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_session_enable_disable_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_session_enable_disable_v2>(vapi_msg_id_session_enable_disable_v2);
}

template <> inline vapi_msg_session_enable_disable_v2* vapi_alloc<vapi_msg_session_enable_disable_v2>(Connection &con)
{
  vapi_msg_session_enable_disable_v2* result = vapi_alloc_session_enable_disable_v2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_session_enable_disable_v2>;

template class Request<vapi_msg_session_enable_disable_v2, vapi_msg_session_enable_disable_v2_reply>;

using Session_enable_disable_v2 = Request<vapi_msg_session_enable_disable_v2, vapi_msg_session_enable_disable_v2_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_session_enable_disable_v2_reply>(vapi_msg_session_enable_disable_v2_reply *msg)
{
  vapi_msg_session_enable_disable_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_session_enable_disable_v2_reply>(vapi_msg_session_enable_disable_v2_reply *msg)
{
  vapi_msg_session_enable_disable_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_session_enable_disable_v2_reply>()
{
  return ::vapi_msg_id_session_enable_disable_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_session_enable_disable_v2_reply>>()
{
  return ::vapi_msg_id_session_enable_disable_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_session_enable_disable_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_session_enable_disable_v2_reply>(vapi_msg_id_session_enable_disable_v2_reply);
}

template class Msg<vapi_msg_session_enable_disable_v2_reply>;

using Session_enable_disable_v2_reply = Msg<vapi_msg_session_enable_disable_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_session_sapi_enable_disable>(vapi_msg_session_sapi_enable_disable *msg)
{
  vapi_msg_session_sapi_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_session_sapi_enable_disable>(vapi_msg_session_sapi_enable_disable *msg)
{
  vapi_msg_session_sapi_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_session_sapi_enable_disable>()
{
  return ::vapi_msg_id_session_sapi_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_session_sapi_enable_disable>>()
{
  return ::vapi_msg_id_session_sapi_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_session_sapi_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_session_sapi_enable_disable>(vapi_msg_id_session_sapi_enable_disable);
}

template <> inline vapi_msg_session_sapi_enable_disable* vapi_alloc<vapi_msg_session_sapi_enable_disable>(Connection &con)
{
  vapi_msg_session_sapi_enable_disable* result = vapi_alloc_session_sapi_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_session_sapi_enable_disable>;

template class Request<vapi_msg_session_sapi_enable_disable, vapi_msg_session_sapi_enable_disable_reply>;

using Session_sapi_enable_disable = Request<vapi_msg_session_sapi_enable_disable, vapi_msg_session_sapi_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_session_sapi_enable_disable_reply>(vapi_msg_session_sapi_enable_disable_reply *msg)
{
  vapi_msg_session_sapi_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_session_sapi_enable_disable_reply>(vapi_msg_session_sapi_enable_disable_reply *msg)
{
  vapi_msg_session_sapi_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_session_sapi_enable_disable_reply>()
{
  return ::vapi_msg_id_session_sapi_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_session_sapi_enable_disable_reply>>()
{
  return ::vapi_msg_id_session_sapi_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_session_sapi_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_session_sapi_enable_disable_reply>(vapi_msg_id_session_sapi_enable_disable_reply);
}

template class Msg<vapi_msg_session_sapi_enable_disable_reply>;

using Session_sapi_enable_disable_reply = Msg<vapi_msg_session_sapi_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_app_namespace_add_del>(vapi_msg_app_namespace_add_del *msg)
{
  vapi_msg_app_namespace_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_app_namespace_add_del>(vapi_msg_app_namespace_add_del *msg)
{
  vapi_msg_app_namespace_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_app_namespace_add_del>()
{
  return ::vapi_msg_id_app_namespace_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_app_namespace_add_del>>()
{
  return ::vapi_msg_id_app_namespace_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_app_namespace_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_app_namespace_add_del>(vapi_msg_id_app_namespace_add_del);
}

template <> inline vapi_msg_app_namespace_add_del* vapi_alloc<vapi_msg_app_namespace_add_del, size_t>(Connection &con, size_t namespace_id_buf_array_size)
{
  vapi_msg_app_namespace_add_del* result = vapi_alloc_app_namespace_add_del(con.vapi_ctx, namespace_id_buf_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_app_namespace_add_del>;

template class Request<vapi_msg_app_namespace_add_del, vapi_msg_app_namespace_add_del_reply, size_t>;

using App_namespace_add_del = Request<vapi_msg_app_namespace_add_del, vapi_msg_app_namespace_add_del_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_app_namespace_add_del_v4>(vapi_msg_app_namespace_add_del_v4 *msg)
{
  vapi_msg_app_namespace_add_del_v4_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_app_namespace_add_del_v4>(vapi_msg_app_namespace_add_del_v4 *msg)
{
  vapi_msg_app_namespace_add_del_v4_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_app_namespace_add_del_v4>()
{
  return ::vapi_msg_id_app_namespace_add_del_v4; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_app_namespace_add_del_v4>>()
{
  return ::vapi_msg_id_app_namespace_add_del_v4; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_app_namespace_add_del_v4()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_app_namespace_add_del_v4>(vapi_msg_id_app_namespace_add_del_v4);
}

template <> inline vapi_msg_app_namespace_add_del_v4* vapi_alloc<vapi_msg_app_namespace_add_del_v4, size_t>(Connection &con, size_t sock_name_buf_array_size)
{
  vapi_msg_app_namespace_add_del_v4* result = vapi_alloc_app_namespace_add_del_v4(con.vapi_ctx, sock_name_buf_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_app_namespace_add_del_v4>;

template class Request<vapi_msg_app_namespace_add_del_v4, vapi_msg_app_namespace_add_del_v4_reply, size_t>;

using App_namespace_add_del_v4 = Request<vapi_msg_app_namespace_add_del_v4, vapi_msg_app_namespace_add_del_v4_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_app_namespace_add_del_v4_reply>(vapi_msg_app_namespace_add_del_v4_reply *msg)
{
  vapi_msg_app_namespace_add_del_v4_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_app_namespace_add_del_v4_reply>(vapi_msg_app_namespace_add_del_v4_reply *msg)
{
  vapi_msg_app_namespace_add_del_v4_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_app_namespace_add_del_v4_reply>()
{
  return ::vapi_msg_id_app_namespace_add_del_v4_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_app_namespace_add_del_v4_reply>>()
{
  return ::vapi_msg_id_app_namespace_add_del_v4_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_app_namespace_add_del_v4_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_app_namespace_add_del_v4_reply>(vapi_msg_id_app_namespace_add_del_v4_reply);
}

template class Msg<vapi_msg_app_namespace_add_del_v4_reply>;

using App_namespace_add_del_v4_reply = Msg<vapi_msg_app_namespace_add_del_v4_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_app_namespace_add_del_v2>(vapi_msg_app_namespace_add_del_v2 *msg)
{
  vapi_msg_app_namespace_add_del_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_app_namespace_add_del_v2>(vapi_msg_app_namespace_add_del_v2 *msg)
{
  vapi_msg_app_namespace_add_del_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_app_namespace_add_del_v2>()
{
  return ::vapi_msg_id_app_namespace_add_del_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_app_namespace_add_del_v2>>()
{
  return ::vapi_msg_id_app_namespace_add_del_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_app_namespace_add_del_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_app_namespace_add_del_v2>(vapi_msg_id_app_namespace_add_del_v2);
}

template <> inline vapi_msg_app_namespace_add_del_v2* vapi_alloc<vapi_msg_app_namespace_add_del_v2>(Connection &con)
{
  vapi_msg_app_namespace_add_del_v2* result = vapi_alloc_app_namespace_add_del_v2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_app_namespace_add_del_v2>;

template class Request<vapi_msg_app_namespace_add_del_v2, vapi_msg_app_namespace_add_del_v2_reply>;

using App_namespace_add_del_v2 = Request<vapi_msg_app_namespace_add_del_v2, vapi_msg_app_namespace_add_del_v2_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_app_namespace_add_del_v3>(vapi_msg_app_namespace_add_del_v3 *msg)
{
  vapi_msg_app_namespace_add_del_v3_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_app_namespace_add_del_v3>(vapi_msg_app_namespace_add_del_v3 *msg)
{
  vapi_msg_app_namespace_add_del_v3_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_app_namespace_add_del_v3>()
{
  return ::vapi_msg_id_app_namespace_add_del_v3; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_app_namespace_add_del_v3>>()
{
  return ::vapi_msg_id_app_namespace_add_del_v3; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_app_namespace_add_del_v3()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_app_namespace_add_del_v3>(vapi_msg_id_app_namespace_add_del_v3);
}

template <> inline vapi_msg_app_namespace_add_del_v3* vapi_alloc<vapi_msg_app_namespace_add_del_v3, size_t>(Connection &con, size_t sock_name_buf_array_size)
{
  vapi_msg_app_namespace_add_del_v3* result = vapi_alloc_app_namespace_add_del_v3(con.vapi_ctx, sock_name_buf_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_app_namespace_add_del_v3>;

template class Request<vapi_msg_app_namespace_add_del_v3, vapi_msg_app_namespace_add_del_v3_reply, size_t>;

using App_namespace_add_del_v3 = Request<vapi_msg_app_namespace_add_del_v3, vapi_msg_app_namespace_add_del_v3_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_app_namespace_add_del_reply>(vapi_msg_app_namespace_add_del_reply *msg)
{
  vapi_msg_app_namespace_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_app_namespace_add_del_reply>(vapi_msg_app_namespace_add_del_reply *msg)
{
  vapi_msg_app_namespace_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_app_namespace_add_del_reply>()
{
  return ::vapi_msg_id_app_namespace_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_app_namespace_add_del_reply>>()
{
  return ::vapi_msg_id_app_namespace_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_app_namespace_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_app_namespace_add_del_reply>(vapi_msg_id_app_namespace_add_del_reply);
}

template class Msg<vapi_msg_app_namespace_add_del_reply>;

using App_namespace_add_del_reply = Msg<vapi_msg_app_namespace_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_app_namespace_add_del_v2_reply>(vapi_msg_app_namespace_add_del_v2_reply *msg)
{
  vapi_msg_app_namespace_add_del_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_app_namespace_add_del_v2_reply>(vapi_msg_app_namespace_add_del_v2_reply *msg)
{
  vapi_msg_app_namespace_add_del_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_app_namespace_add_del_v2_reply>()
{
  return ::vapi_msg_id_app_namespace_add_del_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_app_namespace_add_del_v2_reply>>()
{
  return ::vapi_msg_id_app_namespace_add_del_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_app_namespace_add_del_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_app_namespace_add_del_v2_reply>(vapi_msg_id_app_namespace_add_del_v2_reply);
}

template class Msg<vapi_msg_app_namespace_add_del_v2_reply>;

using App_namespace_add_del_v2_reply = Msg<vapi_msg_app_namespace_add_del_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_app_namespace_add_del_v3_reply>(vapi_msg_app_namespace_add_del_v3_reply *msg)
{
  vapi_msg_app_namespace_add_del_v3_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_app_namespace_add_del_v3_reply>(vapi_msg_app_namespace_add_del_v3_reply *msg)
{
  vapi_msg_app_namespace_add_del_v3_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_app_namespace_add_del_v3_reply>()
{
  return ::vapi_msg_id_app_namespace_add_del_v3_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_app_namespace_add_del_v3_reply>>()
{
  return ::vapi_msg_id_app_namespace_add_del_v3_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_app_namespace_add_del_v3_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_app_namespace_add_del_v3_reply>(vapi_msg_id_app_namespace_add_del_v3_reply);
}

template class Msg<vapi_msg_app_namespace_add_del_v3_reply>;

using App_namespace_add_del_v3_reply = Msg<vapi_msg_app_namespace_add_del_v3_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_session_rule_add_del>(vapi_msg_session_rule_add_del *msg)
{
  vapi_msg_session_rule_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_session_rule_add_del>(vapi_msg_session_rule_add_del *msg)
{
  vapi_msg_session_rule_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_session_rule_add_del>()
{
  return ::vapi_msg_id_session_rule_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_session_rule_add_del>>()
{
  return ::vapi_msg_id_session_rule_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_session_rule_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_session_rule_add_del>(vapi_msg_id_session_rule_add_del);
}

template <> inline vapi_msg_session_rule_add_del* vapi_alloc<vapi_msg_session_rule_add_del>(Connection &con)
{
  vapi_msg_session_rule_add_del* result = vapi_alloc_session_rule_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_session_rule_add_del>;

template class Request<vapi_msg_session_rule_add_del, vapi_msg_session_rule_add_del_reply>;

using Session_rule_add_del = Request<vapi_msg_session_rule_add_del, vapi_msg_session_rule_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_session_rule_add_del_reply>(vapi_msg_session_rule_add_del_reply *msg)
{
  vapi_msg_session_rule_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_session_rule_add_del_reply>(vapi_msg_session_rule_add_del_reply *msg)
{
  vapi_msg_session_rule_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_session_rule_add_del_reply>()
{
  return ::vapi_msg_id_session_rule_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_session_rule_add_del_reply>>()
{
  return ::vapi_msg_id_session_rule_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_session_rule_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_session_rule_add_del_reply>(vapi_msg_id_session_rule_add_del_reply);
}

template class Msg<vapi_msg_session_rule_add_del_reply>;

using Session_rule_add_del_reply = Msg<vapi_msg_session_rule_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_session_rules_dump>(vapi_msg_session_rules_dump *msg)
{
  vapi_msg_session_rules_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_session_rules_dump>(vapi_msg_session_rules_dump *msg)
{
  vapi_msg_session_rules_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_session_rules_dump>()
{
  return ::vapi_msg_id_session_rules_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_session_rules_dump>>()
{
  return ::vapi_msg_id_session_rules_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_session_rules_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_session_rules_dump>(vapi_msg_id_session_rules_dump);
}

template <> inline vapi_msg_session_rules_dump* vapi_alloc<vapi_msg_session_rules_dump>(Connection &con)
{
  vapi_msg_session_rules_dump* result = vapi_alloc_session_rules_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_session_rules_dump>;

template class Dump<vapi_msg_session_rules_dump, vapi_msg_session_rules_details>;

using Session_rules_dump = Dump<vapi_msg_session_rules_dump, vapi_msg_session_rules_details>;

template <> inline void vapi_swap_to_be<vapi_msg_session_rules_details>(vapi_msg_session_rules_details *msg)
{
  vapi_msg_session_rules_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_session_rules_details>(vapi_msg_session_rules_details *msg)
{
  vapi_msg_session_rules_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_session_rules_details>()
{
  return ::vapi_msg_id_session_rules_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_session_rules_details>>()
{
  return ::vapi_msg_id_session_rules_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_session_rules_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_session_rules_details>(vapi_msg_id_session_rules_details);
}

template class Msg<vapi_msg_session_rules_details>;

using Session_rules_details = Msg<vapi_msg_session_rules_details>;
template <> inline void vapi_swap_to_be<vapi_msg_session_rules_v2_dump>(vapi_msg_session_rules_v2_dump *msg)
{
  vapi_msg_session_rules_v2_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_session_rules_v2_dump>(vapi_msg_session_rules_v2_dump *msg)
{
  vapi_msg_session_rules_v2_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_session_rules_v2_dump>()
{
  return ::vapi_msg_id_session_rules_v2_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_session_rules_v2_dump>>()
{
  return ::vapi_msg_id_session_rules_v2_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_session_rules_v2_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_session_rules_v2_dump>(vapi_msg_id_session_rules_v2_dump);
}

template <> inline vapi_msg_session_rules_v2_dump* vapi_alloc<vapi_msg_session_rules_v2_dump>(Connection &con)
{
  vapi_msg_session_rules_v2_dump* result = vapi_alloc_session_rules_v2_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_session_rules_v2_dump>;

template class Dump<vapi_msg_session_rules_v2_dump, vapi_msg_session_rules_v2_details>;

using Session_rules_v2_dump = Dump<vapi_msg_session_rules_v2_dump, vapi_msg_session_rules_v2_details>;

template <> inline void vapi_swap_to_be<vapi_msg_session_rules_v2_details>(vapi_msg_session_rules_v2_details *msg)
{
  vapi_msg_session_rules_v2_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_session_rules_v2_details>(vapi_msg_session_rules_v2_details *msg)
{
  vapi_msg_session_rules_v2_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_session_rules_v2_details>()
{
  return ::vapi_msg_id_session_rules_v2_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_session_rules_v2_details>>()
{
  return ::vapi_msg_id_session_rules_v2_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_session_rules_v2_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_session_rules_v2_details>(vapi_msg_id_session_rules_v2_details);
}

template class Msg<vapi_msg_session_rules_v2_details>;

using Session_rules_v2_details = Msg<vapi_msg_session_rules_v2_details>;
template <> inline void vapi_swap_to_be<vapi_msg_session_sdl_add_del>(vapi_msg_session_sdl_add_del *msg)
{
  vapi_msg_session_sdl_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_session_sdl_add_del>(vapi_msg_session_sdl_add_del *msg)
{
  vapi_msg_session_sdl_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_session_sdl_add_del>()
{
  return ::vapi_msg_id_session_sdl_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_session_sdl_add_del>>()
{
  return ::vapi_msg_id_session_sdl_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_session_sdl_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_session_sdl_add_del>(vapi_msg_id_session_sdl_add_del);
}

template <> inline vapi_msg_session_sdl_add_del* vapi_alloc<vapi_msg_session_sdl_add_del, size_t>(Connection &con, size_t _r_array_size)
{
  vapi_msg_session_sdl_add_del* result = vapi_alloc_session_sdl_add_del(con.vapi_ctx, _r_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_session_sdl_add_del>;

template class Request<vapi_msg_session_sdl_add_del, vapi_msg_session_sdl_add_del_reply, size_t>;

using Session_sdl_add_del = Request<vapi_msg_session_sdl_add_del, vapi_msg_session_sdl_add_del_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_session_sdl_add_del_reply>(vapi_msg_session_sdl_add_del_reply *msg)
{
  vapi_msg_session_sdl_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_session_sdl_add_del_reply>(vapi_msg_session_sdl_add_del_reply *msg)
{
  vapi_msg_session_sdl_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_session_sdl_add_del_reply>()
{
  return ::vapi_msg_id_session_sdl_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_session_sdl_add_del_reply>>()
{
  return ::vapi_msg_id_session_sdl_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_session_sdl_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_session_sdl_add_del_reply>(vapi_msg_id_session_sdl_add_del_reply);
}

template class Msg<vapi_msg_session_sdl_add_del_reply>;

using Session_sdl_add_del_reply = Msg<vapi_msg_session_sdl_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_session_sdl_add_del_v2>(vapi_msg_session_sdl_add_del_v2 *msg)
{
  vapi_msg_session_sdl_add_del_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_session_sdl_add_del_v2>(vapi_msg_session_sdl_add_del_v2 *msg)
{
  vapi_msg_session_sdl_add_del_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_session_sdl_add_del_v2>()
{
  return ::vapi_msg_id_session_sdl_add_del_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_session_sdl_add_del_v2>>()
{
  return ::vapi_msg_id_session_sdl_add_del_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_session_sdl_add_del_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_session_sdl_add_del_v2>(vapi_msg_id_session_sdl_add_del_v2);
}

template <> inline vapi_msg_session_sdl_add_del_v2* vapi_alloc<vapi_msg_session_sdl_add_del_v2, size_t>(Connection &con, size_t _r_array_size)
{
  vapi_msg_session_sdl_add_del_v2* result = vapi_alloc_session_sdl_add_del_v2(con.vapi_ctx, _r_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_session_sdl_add_del_v2>;

template class Request<vapi_msg_session_sdl_add_del_v2, vapi_msg_session_sdl_add_del_v2_reply, size_t>;

using Session_sdl_add_del_v2 = Request<vapi_msg_session_sdl_add_del_v2, vapi_msg_session_sdl_add_del_v2_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_session_sdl_add_del_v2_reply>(vapi_msg_session_sdl_add_del_v2_reply *msg)
{
  vapi_msg_session_sdl_add_del_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_session_sdl_add_del_v2_reply>(vapi_msg_session_sdl_add_del_v2_reply *msg)
{
  vapi_msg_session_sdl_add_del_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_session_sdl_add_del_v2_reply>()
{
  return ::vapi_msg_id_session_sdl_add_del_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_session_sdl_add_del_v2_reply>>()
{
  return ::vapi_msg_id_session_sdl_add_del_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_session_sdl_add_del_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_session_sdl_add_del_v2_reply>(vapi_msg_id_session_sdl_add_del_v2_reply);
}

template class Msg<vapi_msg_session_sdl_add_del_v2_reply>;

using Session_sdl_add_del_v2_reply = Msg<vapi_msg_session_sdl_add_del_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_session_sdl_dump>(vapi_msg_session_sdl_dump *msg)
{
  vapi_msg_session_sdl_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_session_sdl_dump>(vapi_msg_session_sdl_dump *msg)
{
  vapi_msg_session_sdl_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_session_sdl_dump>()
{
  return ::vapi_msg_id_session_sdl_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_session_sdl_dump>>()
{
  return ::vapi_msg_id_session_sdl_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_session_sdl_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_session_sdl_dump>(vapi_msg_id_session_sdl_dump);
}

template <> inline vapi_msg_session_sdl_dump* vapi_alloc<vapi_msg_session_sdl_dump>(Connection &con)
{
  vapi_msg_session_sdl_dump* result = vapi_alloc_session_sdl_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_session_sdl_dump>;

template class Dump<vapi_msg_session_sdl_dump, vapi_msg_session_sdl_details>;

using Session_sdl_dump = Dump<vapi_msg_session_sdl_dump, vapi_msg_session_sdl_details>;

template <> inline void vapi_swap_to_be<vapi_msg_session_sdl_details>(vapi_msg_session_sdl_details *msg)
{
  vapi_msg_session_sdl_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_session_sdl_details>(vapi_msg_session_sdl_details *msg)
{
  vapi_msg_session_sdl_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_session_sdl_details>()
{
  return ::vapi_msg_id_session_sdl_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_session_sdl_details>>()
{
  return ::vapi_msg_id_session_sdl_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_session_sdl_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_session_sdl_details>(vapi_msg_id_session_sdl_details);
}

template class Msg<vapi_msg_session_sdl_details>;

using Session_sdl_details = Msg<vapi_msg_session_sdl_details>;
template <> inline void vapi_swap_to_be<vapi_msg_session_sdl_v2_dump>(vapi_msg_session_sdl_v2_dump *msg)
{
  vapi_msg_session_sdl_v2_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_session_sdl_v2_dump>(vapi_msg_session_sdl_v2_dump *msg)
{
  vapi_msg_session_sdl_v2_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_session_sdl_v2_dump>()
{
  return ::vapi_msg_id_session_sdl_v2_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_session_sdl_v2_dump>>()
{
  return ::vapi_msg_id_session_sdl_v2_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_session_sdl_v2_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_session_sdl_v2_dump>(vapi_msg_id_session_sdl_v2_dump);
}

template <> inline vapi_msg_session_sdl_v2_dump* vapi_alloc<vapi_msg_session_sdl_v2_dump>(Connection &con)
{
  vapi_msg_session_sdl_v2_dump* result = vapi_alloc_session_sdl_v2_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_session_sdl_v2_dump>;

template class Dump<vapi_msg_session_sdl_v2_dump, vapi_msg_session_sdl_v2_details>;

using Session_sdl_v2_dump = Dump<vapi_msg_session_sdl_v2_dump, vapi_msg_session_sdl_v2_details>;

template <> inline void vapi_swap_to_be<vapi_msg_session_sdl_v2_details>(vapi_msg_session_sdl_v2_details *msg)
{
  vapi_msg_session_sdl_v2_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_session_sdl_v2_details>(vapi_msg_session_sdl_v2_details *msg)
{
  vapi_msg_session_sdl_v2_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_session_sdl_v2_details>()
{
  return ::vapi_msg_id_session_sdl_v2_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_session_sdl_v2_details>>()
{
  return ::vapi_msg_id_session_sdl_v2_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_session_sdl_v2_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_session_sdl_v2_details>(vapi_msg_id_session_sdl_v2_details);
}

template class Msg<vapi_msg_session_sdl_v2_details>;

using Session_sdl_v2_details = Msg<vapi_msg_session_sdl_v2_details>;
template <> inline void vapi_swap_to_be<vapi_msg_session_sdl_v3_dump>(vapi_msg_session_sdl_v3_dump *msg)
{
  vapi_msg_session_sdl_v3_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_session_sdl_v3_dump>(vapi_msg_session_sdl_v3_dump *msg)
{
  vapi_msg_session_sdl_v3_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_session_sdl_v3_dump>()
{
  return ::vapi_msg_id_session_sdl_v3_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_session_sdl_v3_dump>>()
{
  return ::vapi_msg_id_session_sdl_v3_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_session_sdl_v3_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_session_sdl_v3_dump>(vapi_msg_id_session_sdl_v3_dump);
}

template <> inline vapi_msg_session_sdl_v3_dump* vapi_alloc<vapi_msg_session_sdl_v3_dump>(Connection &con)
{
  vapi_msg_session_sdl_v3_dump* result = vapi_alloc_session_sdl_v3_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_session_sdl_v3_dump>;

template class Dump<vapi_msg_session_sdl_v3_dump, vapi_msg_session_sdl_v3_details>;

using Session_sdl_v3_dump = Dump<vapi_msg_session_sdl_v3_dump, vapi_msg_session_sdl_v3_details>;

template <> inline void vapi_swap_to_be<vapi_msg_session_sdl_v3_details>(vapi_msg_session_sdl_v3_details *msg)
{
  vapi_msg_session_sdl_v3_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_session_sdl_v3_details>(vapi_msg_session_sdl_v3_details *msg)
{
  vapi_msg_session_sdl_v3_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_session_sdl_v3_details>()
{
  return ::vapi_msg_id_session_sdl_v3_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_session_sdl_v3_details>>()
{
  return ::vapi_msg_id_session_sdl_v3_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_session_sdl_v3_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_session_sdl_v3_details>(vapi_msg_id_session_sdl_v3_details);
}

template class Msg<vapi_msg_session_sdl_v3_details>;

using Session_sdl_v3_details = Msg<vapi_msg_session_sdl_v3_details>;
}
#endif
