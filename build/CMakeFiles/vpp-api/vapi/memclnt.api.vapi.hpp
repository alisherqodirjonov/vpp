#ifndef __included_hpp_memclnt_api_json
#define __included_hpp_memclnt_api_json

#include <vapi/vapi.hpp>
#include <vapi/memclnt.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_memclnt_create>(vapi_msg_memclnt_create *msg)
{
  vapi_msg_memclnt_create_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_memclnt_create>(vapi_msg_memclnt_create *msg)
{
  vapi_msg_memclnt_create_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_memclnt_create>()
{
  return ::vapi_msg_id_memclnt_create; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_memclnt_create>>()
{
  return ::vapi_msg_id_memclnt_create; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_memclnt_create()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_memclnt_create>(vapi_msg_id_memclnt_create);
}

template <> inline vapi_msg_memclnt_create* vapi_alloc<vapi_msg_memclnt_create>(Connection &con)
{
  vapi_msg_memclnt_create* result = vapi_alloc_memclnt_create(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_memclnt_create>;

template class Request<vapi_msg_memclnt_create, vapi_msg_memclnt_create_reply>;

using Memclnt_create = Request<vapi_msg_memclnt_create, vapi_msg_memclnt_create_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_memclnt_create_reply>(vapi_msg_memclnt_create_reply *msg)
{
  vapi_msg_memclnt_create_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_memclnt_create_reply>(vapi_msg_memclnt_create_reply *msg)
{
  vapi_msg_memclnt_create_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_memclnt_create_reply>()
{
  return ::vapi_msg_id_memclnt_create_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_memclnt_create_reply>>()
{
  return ::vapi_msg_id_memclnt_create_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_memclnt_create_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_memclnt_create_reply>(vapi_msg_id_memclnt_create_reply);
}

template class Msg<vapi_msg_memclnt_create_reply>;

using Memclnt_create_reply = Msg<vapi_msg_memclnt_create_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_memclnt_delete_reply>(vapi_msg_memclnt_delete_reply *msg)
{
  vapi_msg_memclnt_delete_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_memclnt_delete_reply>(vapi_msg_memclnt_delete_reply *msg)
{
  vapi_msg_memclnt_delete_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_memclnt_delete_reply>()
{
  return ::vapi_msg_id_memclnt_delete_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_memclnt_delete_reply>>()
{
  return ::vapi_msg_id_memclnt_delete_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_memclnt_delete_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_memclnt_delete_reply>(vapi_msg_id_memclnt_delete_reply);
}

template class Msg<vapi_msg_memclnt_delete_reply>;

using Memclnt_delete_reply = Msg<vapi_msg_memclnt_delete_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_rpc_call>(vapi_msg_rpc_call *msg)
{
  vapi_msg_rpc_call_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_rpc_call>(vapi_msg_rpc_call *msg)
{
  vapi_msg_rpc_call_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_rpc_call>()
{
  return ::vapi_msg_id_rpc_call; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_rpc_call>>()
{
  return ::vapi_msg_id_rpc_call; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_rpc_call()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_rpc_call>(vapi_msg_id_rpc_call);
}

template <> inline vapi_msg_rpc_call* vapi_alloc<vapi_msg_rpc_call, size_t>(Connection &con, size_t _data_array_size)
{
  vapi_msg_rpc_call* result = vapi_alloc_rpc_call(con.vapi_ctx, _data_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_rpc_call>;

template class Request<vapi_msg_rpc_call, vapi_msg_rpc_call_reply, size_t>;

using Rpc_call = Request<vapi_msg_rpc_call, vapi_msg_rpc_call_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_rpc_call_reply>(vapi_msg_rpc_call_reply *msg)
{
  vapi_msg_rpc_call_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_rpc_call_reply>(vapi_msg_rpc_call_reply *msg)
{
  vapi_msg_rpc_call_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_rpc_call_reply>()
{
  return ::vapi_msg_id_rpc_call_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_rpc_call_reply>>()
{
  return ::vapi_msg_id_rpc_call_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_rpc_call_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_rpc_call_reply>(vapi_msg_id_rpc_call_reply);
}

template class Msg<vapi_msg_rpc_call_reply>;

using Rpc_call_reply = Msg<vapi_msg_rpc_call_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_get_first_msg_id>(vapi_msg_get_first_msg_id *msg)
{
  vapi_msg_get_first_msg_id_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_get_first_msg_id>(vapi_msg_get_first_msg_id *msg)
{
  vapi_msg_get_first_msg_id_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_get_first_msg_id>()
{
  return ::vapi_msg_id_get_first_msg_id; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_get_first_msg_id>>()
{
  return ::vapi_msg_id_get_first_msg_id; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_get_first_msg_id()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_get_first_msg_id>(vapi_msg_id_get_first_msg_id);
}

template <> inline vapi_msg_get_first_msg_id* vapi_alloc<vapi_msg_get_first_msg_id>(Connection &con)
{
  vapi_msg_get_first_msg_id* result = vapi_alloc_get_first_msg_id(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_get_first_msg_id>;

template class Request<vapi_msg_get_first_msg_id, vapi_msg_get_first_msg_id_reply>;

using Get_first_msg_id = Request<vapi_msg_get_first_msg_id, vapi_msg_get_first_msg_id_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_get_first_msg_id_reply>(vapi_msg_get_first_msg_id_reply *msg)
{
  vapi_msg_get_first_msg_id_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_get_first_msg_id_reply>(vapi_msg_get_first_msg_id_reply *msg)
{
  vapi_msg_get_first_msg_id_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_get_first_msg_id_reply>()
{
  return ::vapi_msg_id_get_first_msg_id_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_get_first_msg_id_reply>>()
{
  return ::vapi_msg_id_get_first_msg_id_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_get_first_msg_id_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_get_first_msg_id_reply>(vapi_msg_id_get_first_msg_id_reply);
}

template class Msg<vapi_msg_get_first_msg_id_reply>;

using Get_first_msg_id_reply = Msg<vapi_msg_get_first_msg_id_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_api_versions>(vapi_msg_api_versions *msg)
{
  vapi_msg_api_versions_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_api_versions>(vapi_msg_api_versions *msg)
{
  vapi_msg_api_versions_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_api_versions>()
{
  return ::vapi_msg_id_api_versions; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_api_versions>>()
{
  return ::vapi_msg_id_api_versions; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_api_versions()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_api_versions>(vapi_msg_id_api_versions);
}

template <> inline vapi_msg_api_versions* vapi_alloc<vapi_msg_api_versions>(Connection &con)
{
  vapi_msg_api_versions* result = vapi_alloc_api_versions(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_api_versions>;

template class Request<vapi_msg_api_versions, vapi_msg_api_versions_reply>;

using Api_versions = Request<vapi_msg_api_versions, vapi_msg_api_versions_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_api_versions_reply>(vapi_msg_api_versions_reply *msg)
{
  vapi_msg_api_versions_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_api_versions_reply>(vapi_msg_api_versions_reply *msg)
{
  vapi_msg_api_versions_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_api_versions_reply>()
{
  return ::vapi_msg_id_api_versions_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_api_versions_reply>>()
{
  return ::vapi_msg_id_api_versions_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_api_versions_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_api_versions_reply>(vapi_msg_id_api_versions_reply);
}

template class Msg<vapi_msg_api_versions_reply>;

using Api_versions_reply = Msg<vapi_msg_api_versions_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sockclnt_create>(vapi_msg_sockclnt_create *msg)
{
  vapi_msg_sockclnt_create_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sockclnt_create>(vapi_msg_sockclnt_create *msg)
{
  vapi_msg_sockclnt_create_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sockclnt_create>()
{
  return ::vapi_msg_id_sockclnt_create; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sockclnt_create>>()
{
  return ::vapi_msg_id_sockclnt_create; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sockclnt_create()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sockclnt_create>(vapi_msg_id_sockclnt_create);
}

template <> inline vapi_msg_sockclnt_create* vapi_alloc<vapi_msg_sockclnt_create>(Connection &con)
{
  vapi_msg_sockclnt_create* result = vapi_alloc_sockclnt_create(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sockclnt_create>;

template class Request<vapi_msg_sockclnt_create, vapi_msg_sockclnt_create_reply>;

using Sockclnt_create = Request<vapi_msg_sockclnt_create, vapi_msg_sockclnt_create_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sockclnt_create_reply>(vapi_msg_sockclnt_create_reply *msg)
{
  vapi_msg_sockclnt_create_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sockclnt_create_reply>(vapi_msg_sockclnt_create_reply *msg)
{
  vapi_msg_sockclnt_create_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sockclnt_create_reply>()
{
  return ::vapi_msg_id_sockclnt_create_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sockclnt_create_reply>>()
{
  return ::vapi_msg_id_sockclnt_create_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sockclnt_create_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sockclnt_create_reply>(vapi_msg_id_sockclnt_create_reply);
}

template class Msg<vapi_msg_sockclnt_create_reply>;

using Sockclnt_create_reply = Msg<vapi_msg_sockclnt_create_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sockclnt_delete>(vapi_msg_sockclnt_delete *msg)
{
  vapi_msg_sockclnt_delete_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sockclnt_delete>(vapi_msg_sockclnt_delete *msg)
{
  vapi_msg_sockclnt_delete_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sockclnt_delete>()
{
  return ::vapi_msg_id_sockclnt_delete; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sockclnt_delete>>()
{
  return ::vapi_msg_id_sockclnt_delete; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sockclnt_delete()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sockclnt_delete>(vapi_msg_id_sockclnt_delete);
}

template <> inline vapi_msg_sockclnt_delete* vapi_alloc<vapi_msg_sockclnt_delete>(Connection &con)
{
  vapi_msg_sockclnt_delete* result = vapi_alloc_sockclnt_delete(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sockclnt_delete>;

template class Request<vapi_msg_sockclnt_delete, vapi_msg_sockclnt_delete_reply>;

using Sockclnt_delete = Request<vapi_msg_sockclnt_delete, vapi_msg_sockclnt_delete_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sockclnt_delete_reply>(vapi_msg_sockclnt_delete_reply *msg)
{
  vapi_msg_sockclnt_delete_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sockclnt_delete_reply>(vapi_msg_sockclnt_delete_reply *msg)
{
  vapi_msg_sockclnt_delete_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sockclnt_delete_reply>()
{
  return ::vapi_msg_id_sockclnt_delete_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sockclnt_delete_reply>>()
{
  return ::vapi_msg_id_sockclnt_delete_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sockclnt_delete_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sockclnt_delete_reply>(vapi_msg_id_sockclnt_delete_reply);
}

template class Msg<vapi_msg_sockclnt_delete_reply>;

using Sockclnt_delete_reply = Msg<vapi_msg_sockclnt_delete_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sock_init_shm>(vapi_msg_sock_init_shm *msg)
{
  vapi_msg_sock_init_shm_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sock_init_shm>(vapi_msg_sock_init_shm *msg)
{
  vapi_msg_sock_init_shm_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sock_init_shm>()
{
  return ::vapi_msg_id_sock_init_shm; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sock_init_shm>>()
{
  return ::vapi_msg_id_sock_init_shm; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sock_init_shm()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sock_init_shm>(vapi_msg_id_sock_init_shm);
}

template <> inline vapi_msg_sock_init_shm* vapi_alloc<vapi_msg_sock_init_shm, size_t>(Connection &con, size_t _configs_array_size)
{
  vapi_msg_sock_init_shm* result = vapi_alloc_sock_init_shm(con.vapi_ctx, _configs_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sock_init_shm>;

template class Request<vapi_msg_sock_init_shm, vapi_msg_sock_init_shm_reply, size_t>;

using Sock_init_shm = Request<vapi_msg_sock_init_shm, vapi_msg_sock_init_shm_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_sock_init_shm_reply>(vapi_msg_sock_init_shm_reply *msg)
{
  vapi_msg_sock_init_shm_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sock_init_shm_reply>(vapi_msg_sock_init_shm_reply *msg)
{
  vapi_msg_sock_init_shm_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sock_init_shm_reply>()
{
  return ::vapi_msg_id_sock_init_shm_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sock_init_shm_reply>>()
{
  return ::vapi_msg_id_sock_init_shm_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sock_init_shm_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sock_init_shm_reply>(vapi_msg_id_sock_init_shm_reply);
}

template class Msg<vapi_msg_sock_init_shm_reply>;

using Sock_init_shm_reply = Msg<vapi_msg_sock_init_shm_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_memclnt_keepalive>(vapi_msg_memclnt_keepalive *msg)
{
  vapi_msg_memclnt_keepalive_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_memclnt_keepalive>(vapi_msg_memclnt_keepalive *msg)
{
  vapi_msg_memclnt_keepalive_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_memclnt_keepalive>()
{
  return ::vapi_msg_id_memclnt_keepalive; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_memclnt_keepalive>>()
{
  return ::vapi_msg_id_memclnt_keepalive; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_memclnt_keepalive()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_memclnt_keepalive>(vapi_msg_id_memclnt_keepalive);
}

template <> inline vapi_msg_memclnt_keepalive* vapi_alloc<vapi_msg_memclnt_keepalive>(Connection &con)
{
  vapi_msg_memclnt_keepalive* result = vapi_alloc_memclnt_keepalive(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_memclnt_keepalive>;

template class Request<vapi_msg_memclnt_keepalive, vapi_msg_memclnt_keepalive_reply>;

using Memclnt_keepalive = Request<vapi_msg_memclnt_keepalive, vapi_msg_memclnt_keepalive_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_memclnt_keepalive_reply>(vapi_msg_memclnt_keepalive_reply *msg)
{
  vapi_msg_memclnt_keepalive_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_memclnt_keepalive_reply>(vapi_msg_memclnt_keepalive_reply *msg)
{
  vapi_msg_memclnt_keepalive_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_memclnt_keepalive_reply>()
{
  return ::vapi_msg_id_memclnt_keepalive_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_memclnt_keepalive_reply>>()
{
  return ::vapi_msg_id_memclnt_keepalive_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_memclnt_keepalive_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_memclnt_keepalive_reply>(vapi_msg_id_memclnt_keepalive_reply);
}

template class Msg<vapi_msg_memclnt_keepalive_reply>;

using Memclnt_keepalive_reply = Msg<vapi_msg_memclnt_keepalive_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_control_ping>(vapi_msg_control_ping *msg)
{
  vapi_msg_control_ping_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_control_ping>(vapi_msg_control_ping *msg)
{
  vapi_msg_control_ping_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_control_ping>()
{
  return ::vapi_msg_id_control_ping; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_control_ping>>()
{
  return ::vapi_msg_id_control_ping; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_control_ping()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_control_ping>(vapi_msg_id_control_ping);
}

template <> inline vapi_msg_control_ping* vapi_alloc<vapi_msg_control_ping>(Connection &con)
{
  vapi_msg_control_ping* result = vapi_alloc_control_ping(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_control_ping>;

template class Request<vapi_msg_control_ping, vapi_msg_control_ping_reply>;

using Control_ping = Request<vapi_msg_control_ping, vapi_msg_control_ping_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_control_ping_reply>(vapi_msg_control_ping_reply *msg)
{
  vapi_msg_control_ping_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_control_ping_reply>(vapi_msg_control_ping_reply *msg)
{
  vapi_msg_control_ping_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_control_ping_reply>()
{
  return ::vapi_msg_id_control_ping_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_control_ping_reply>>()
{
  return ::vapi_msg_id_control_ping_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_control_ping_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_control_ping_reply>(vapi_msg_id_control_ping_reply);
}

template class Msg<vapi_msg_control_ping_reply>;

using Control_ping_reply = Msg<vapi_msg_control_ping_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_memclnt_create_v2>(vapi_msg_memclnt_create_v2 *msg)
{
  vapi_msg_memclnt_create_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_memclnt_create_v2>(vapi_msg_memclnt_create_v2 *msg)
{
  vapi_msg_memclnt_create_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_memclnt_create_v2>()
{
  return ::vapi_msg_id_memclnt_create_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_memclnt_create_v2>>()
{
  return ::vapi_msg_id_memclnt_create_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_memclnt_create_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_memclnt_create_v2>(vapi_msg_id_memclnt_create_v2);
}

template <> inline vapi_msg_memclnt_create_v2* vapi_alloc<vapi_msg_memclnt_create_v2>(Connection &con)
{
  vapi_msg_memclnt_create_v2* result = vapi_alloc_memclnt_create_v2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_memclnt_create_v2>;

template class Request<vapi_msg_memclnt_create_v2, vapi_msg_memclnt_create_v2_reply>;

using Memclnt_create_v2 = Request<vapi_msg_memclnt_create_v2, vapi_msg_memclnt_create_v2_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_memclnt_create_v2_reply>(vapi_msg_memclnt_create_v2_reply *msg)
{
  vapi_msg_memclnt_create_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_memclnt_create_v2_reply>(vapi_msg_memclnt_create_v2_reply *msg)
{
  vapi_msg_memclnt_create_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_memclnt_create_v2_reply>()
{
  return ::vapi_msg_id_memclnt_create_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_memclnt_create_v2_reply>>()
{
  return ::vapi_msg_id_memclnt_create_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_memclnt_create_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_memclnt_create_v2_reply>(vapi_msg_id_memclnt_create_v2_reply);
}

template class Msg<vapi_msg_memclnt_create_v2_reply>;

using Memclnt_create_v2_reply = Msg<vapi_msg_memclnt_create_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_get_api_json>(vapi_msg_get_api_json *msg)
{
  vapi_msg_get_api_json_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_get_api_json>(vapi_msg_get_api_json *msg)
{
  vapi_msg_get_api_json_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_get_api_json>()
{
  return ::vapi_msg_id_get_api_json; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_get_api_json>>()
{
  return ::vapi_msg_id_get_api_json; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_get_api_json()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_get_api_json>(vapi_msg_id_get_api_json);
}

template <> inline vapi_msg_get_api_json* vapi_alloc<vapi_msg_get_api_json>(Connection &con)
{
  vapi_msg_get_api_json* result = vapi_alloc_get_api_json(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_get_api_json>;

template class Request<vapi_msg_get_api_json, vapi_msg_get_api_json_reply>;

using Get_api_json = Request<vapi_msg_get_api_json, vapi_msg_get_api_json_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_get_api_json_reply>(vapi_msg_get_api_json_reply *msg)
{
  vapi_msg_get_api_json_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_get_api_json_reply>(vapi_msg_get_api_json_reply *msg)
{
  vapi_msg_get_api_json_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_get_api_json_reply>()
{
  return ::vapi_msg_id_get_api_json_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_get_api_json_reply>>()
{
  return ::vapi_msg_id_get_api_json_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_get_api_json_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_get_api_json_reply>(vapi_msg_id_get_api_json_reply);
}

template class Msg<vapi_msg_get_api_json_reply>;

using Get_api_json_reply = Msg<vapi_msg_get_api_json_reply>;
}
#endif
