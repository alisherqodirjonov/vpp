#ifndef __included_hpp_one_api_json
#define __included_hpp_one_api_json

#include <vapi/vapi.hpp>
#include <vapi/one.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_one_add_del_locator_set>(vapi_msg_one_add_del_locator_set *msg)
{
  vapi_msg_one_add_del_locator_set_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_add_del_locator_set>(vapi_msg_one_add_del_locator_set *msg)
{
  vapi_msg_one_add_del_locator_set_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_add_del_locator_set>()
{
  return ::vapi_msg_id_one_add_del_locator_set; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_add_del_locator_set>>()
{
  return ::vapi_msg_id_one_add_del_locator_set; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_add_del_locator_set()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_add_del_locator_set>(vapi_msg_id_one_add_del_locator_set);
}

template <> inline vapi_msg_one_add_del_locator_set* vapi_alloc<vapi_msg_one_add_del_locator_set, size_t>(Connection &con, size_t _locators_array_size)
{
  vapi_msg_one_add_del_locator_set* result = vapi_alloc_one_add_del_locator_set(con.vapi_ctx, _locators_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_add_del_locator_set>;

template class Request<vapi_msg_one_add_del_locator_set, vapi_msg_one_add_del_locator_set_reply, size_t>;

using One_add_del_locator_set = Request<vapi_msg_one_add_del_locator_set, vapi_msg_one_add_del_locator_set_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_one_add_del_locator_set_reply>(vapi_msg_one_add_del_locator_set_reply *msg)
{
  vapi_msg_one_add_del_locator_set_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_add_del_locator_set_reply>(vapi_msg_one_add_del_locator_set_reply *msg)
{
  vapi_msg_one_add_del_locator_set_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_add_del_locator_set_reply>()
{
  return ::vapi_msg_id_one_add_del_locator_set_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_add_del_locator_set_reply>>()
{
  return ::vapi_msg_id_one_add_del_locator_set_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_add_del_locator_set_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_add_del_locator_set_reply>(vapi_msg_id_one_add_del_locator_set_reply);
}

template class Msg<vapi_msg_one_add_del_locator_set_reply>;

using One_add_del_locator_set_reply = Msg<vapi_msg_one_add_del_locator_set_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_one_add_del_locator>(vapi_msg_one_add_del_locator *msg)
{
  vapi_msg_one_add_del_locator_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_add_del_locator>(vapi_msg_one_add_del_locator *msg)
{
  vapi_msg_one_add_del_locator_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_add_del_locator>()
{
  return ::vapi_msg_id_one_add_del_locator; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_add_del_locator>>()
{
  return ::vapi_msg_id_one_add_del_locator; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_add_del_locator()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_add_del_locator>(vapi_msg_id_one_add_del_locator);
}

template <> inline vapi_msg_one_add_del_locator* vapi_alloc<vapi_msg_one_add_del_locator>(Connection &con)
{
  vapi_msg_one_add_del_locator* result = vapi_alloc_one_add_del_locator(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_add_del_locator>;

template class Request<vapi_msg_one_add_del_locator, vapi_msg_one_add_del_locator_reply>;

using One_add_del_locator = Request<vapi_msg_one_add_del_locator, vapi_msg_one_add_del_locator_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_one_add_del_locator_reply>(vapi_msg_one_add_del_locator_reply *msg)
{
  vapi_msg_one_add_del_locator_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_add_del_locator_reply>(vapi_msg_one_add_del_locator_reply *msg)
{
  vapi_msg_one_add_del_locator_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_add_del_locator_reply>()
{
  return ::vapi_msg_id_one_add_del_locator_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_add_del_locator_reply>>()
{
  return ::vapi_msg_id_one_add_del_locator_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_add_del_locator_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_add_del_locator_reply>(vapi_msg_id_one_add_del_locator_reply);
}

template class Msg<vapi_msg_one_add_del_locator_reply>;

using One_add_del_locator_reply = Msg<vapi_msg_one_add_del_locator_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_one_add_del_local_eid>(vapi_msg_one_add_del_local_eid *msg)
{
  vapi_msg_one_add_del_local_eid_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_add_del_local_eid>(vapi_msg_one_add_del_local_eid *msg)
{
  vapi_msg_one_add_del_local_eid_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_add_del_local_eid>()
{
  return ::vapi_msg_id_one_add_del_local_eid; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_add_del_local_eid>>()
{
  return ::vapi_msg_id_one_add_del_local_eid; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_add_del_local_eid()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_add_del_local_eid>(vapi_msg_id_one_add_del_local_eid);
}

template <> inline vapi_msg_one_add_del_local_eid* vapi_alloc<vapi_msg_one_add_del_local_eid>(Connection &con)
{
  vapi_msg_one_add_del_local_eid* result = vapi_alloc_one_add_del_local_eid(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_add_del_local_eid>;

template class Request<vapi_msg_one_add_del_local_eid, vapi_msg_one_add_del_local_eid_reply>;

using One_add_del_local_eid = Request<vapi_msg_one_add_del_local_eid, vapi_msg_one_add_del_local_eid_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_one_add_del_local_eid_reply>(vapi_msg_one_add_del_local_eid_reply *msg)
{
  vapi_msg_one_add_del_local_eid_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_add_del_local_eid_reply>(vapi_msg_one_add_del_local_eid_reply *msg)
{
  vapi_msg_one_add_del_local_eid_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_add_del_local_eid_reply>()
{
  return ::vapi_msg_id_one_add_del_local_eid_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_add_del_local_eid_reply>>()
{
  return ::vapi_msg_id_one_add_del_local_eid_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_add_del_local_eid_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_add_del_local_eid_reply>(vapi_msg_id_one_add_del_local_eid_reply);
}

template class Msg<vapi_msg_one_add_del_local_eid_reply>;

using One_add_del_local_eid_reply = Msg<vapi_msg_one_add_del_local_eid_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_one_map_register_set_ttl>(vapi_msg_one_map_register_set_ttl *msg)
{
  vapi_msg_one_map_register_set_ttl_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_map_register_set_ttl>(vapi_msg_one_map_register_set_ttl *msg)
{
  vapi_msg_one_map_register_set_ttl_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_map_register_set_ttl>()
{
  return ::vapi_msg_id_one_map_register_set_ttl; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_map_register_set_ttl>>()
{
  return ::vapi_msg_id_one_map_register_set_ttl; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_map_register_set_ttl()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_map_register_set_ttl>(vapi_msg_id_one_map_register_set_ttl);
}

template <> inline vapi_msg_one_map_register_set_ttl* vapi_alloc<vapi_msg_one_map_register_set_ttl>(Connection &con)
{
  vapi_msg_one_map_register_set_ttl* result = vapi_alloc_one_map_register_set_ttl(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_map_register_set_ttl>;

template class Request<vapi_msg_one_map_register_set_ttl, vapi_msg_one_map_register_set_ttl_reply>;

using One_map_register_set_ttl = Request<vapi_msg_one_map_register_set_ttl, vapi_msg_one_map_register_set_ttl_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_one_map_register_set_ttl_reply>(vapi_msg_one_map_register_set_ttl_reply *msg)
{
  vapi_msg_one_map_register_set_ttl_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_map_register_set_ttl_reply>(vapi_msg_one_map_register_set_ttl_reply *msg)
{
  vapi_msg_one_map_register_set_ttl_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_map_register_set_ttl_reply>()
{
  return ::vapi_msg_id_one_map_register_set_ttl_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_map_register_set_ttl_reply>>()
{
  return ::vapi_msg_id_one_map_register_set_ttl_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_map_register_set_ttl_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_map_register_set_ttl_reply>(vapi_msg_id_one_map_register_set_ttl_reply);
}

template class Msg<vapi_msg_one_map_register_set_ttl_reply>;

using One_map_register_set_ttl_reply = Msg<vapi_msg_one_map_register_set_ttl_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_show_one_map_register_ttl>(vapi_msg_show_one_map_register_ttl *msg)
{
  vapi_msg_show_one_map_register_ttl_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_one_map_register_ttl>(vapi_msg_show_one_map_register_ttl *msg)
{
  vapi_msg_show_one_map_register_ttl_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_one_map_register_ttl>()
{
  return ::vapi_msg_id_show_one_map_register_ttl; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_one_map_register_ttl>>()
{
  return ::vapi_msg_id_show_one_map_register_ttl; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_one_map_register_ttl()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_one_map_register_ttl>(vapi_msg_id_show_one_map_register_ttl);
}

template <> inline vapi_msg_show_one_map_register_ttl* vapi_alloc<vapi_msg_show_one_map_register_ttl>(Connection &con)
{
  vapi_msg_show_one_map_register_ttl* result = vapi_alloc_show_one_map_register_ttl(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_show_one_map_register_ttl>;

template class Request<vapi_msg_show_one_map_register_ttl, vapi_msg_show_one_map_register_ttl_reply>;

using Show_one_map_register_ttl = Request<vapi_msg_show_one_map_register_ttl, vapi_msg_show_one_map_register_ttl_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_show_one_map_register_ttl_reply>(vapi_msg_show_one_map_register_ttl_reply *msg)
{
  vapi_msg_show_one_map_register_ttl_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_one_map_register_ttl_reply>(vapi_msg_show_one_map_register_ttl_reply *msg)
{
  vapi_msg_show_one_map_register_ttl_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_one_map_register_ttl_reply>()
{
  return ::vapi_msg_id_show_one_map_register_ttl_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_one_map_register_ttl_reply>>()
{
  return ::vapi_msg_id_show_one_map_register_ttl_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_one_map_register_ttl_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_one_map_register_ttl_reply>(vapi_msg_id_show_one_map_register_ttl_reply);
}

template class Msg<vapi_msg_show_one_map_register_ttl_reply>;

using Show_one_map_register_ttl_reply = Msg<vapi_msg_show_one_map_register_ttl_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_one_add_del_map_server>(vapi_msg_one_add_del_map_server *msg)
{
  vapi_msg_one_add_del_map_server_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_add_del_map_server>(vapi_msg_one_add_del_map_server *msg)
{
  vapi_msg_one_add_del_map_server_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_add_del_map_server>()
{
  return ::vapi_msg_id_one_add_del_map_server; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_add_del_map_server>>()
{
  return ::vapi_msg_id_one_add_del_map_server; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_add_del_map_server()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_add_del_map_server>(vapi_msg_id_one_add_del_map_server);
}

template <> inline vapi_msg_one_add_del_map_server* vapi_alloc<vapi_msg_one_add_del_map_server>(Connection &con)
{
  vapi_msg_one_add_del_map_server* result = vapi_alloc_one_add_del_map_server(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_add_del_map_server>;

template class Request<vapi_msg_one_add_del_map_server, vapi_msg_one_add_del_map_server_reply>;

using One_add_del_map_server = Request<vapi_msg_one_add_del_map_server, vapi_msg_one_add_del_map_server_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_one_add_del_map_server_reply>(vapi_msg_one_add_del_map_server_reply *msg)
{
  vapi_msg_one_add_del_map_server_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_add_del_map_server_reply>(vapi_msg_one_add_del_map_server_reply *msg)
{
  vapi_msg_one_add_del_map_server_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_add_del_map_server_reply>()
{
  return ::vapi_msg_id_one_add_del_map_server_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_add_del_map_server_reply>>()
{
  return ::vapi_msg_id_one_add_del_map_server_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_add_del_map_server_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_add_del_map_server_reply>(vapi_msg_id_one_add_del_map_server_reply);
}

template class Msg<vapi_msg_one_add_del_map_server_reply>;

using One_add_del_map_server_reply = Msg<vapi_msg_one_add_del_map_server_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_one_add_del_map_resolver>(vapi_msg_one_add_del_map_resolver *msg)
{
  vapi_msg_one_add_del_map_resolver_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_add_del_map_resolver>(vapi_msg_one_add_del_map_resolver *msg)
{
  vapi_msg_one_add_del_map_resolver_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_add_del_map_resolver>()
{
  return ::vapi_msg_id_one_add_del_map_resolver; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_add_del_map_resolver>>()
{
  return ::vapi_msg_id_one_add_del_map_resolver; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_add_del_map_resolver()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_add_del_map_resolver>(vapi_msg_id_one_add_del_map_resolver);
}

template <> inline vapi_msg_one_add_del_map_resolver* vapi_alloc<vapi_msg_one_add_del_map_resolver>(Connection &con)
{
  vapi_msg_one_add_del_map_resolver* result = vapi_alloc_one_add_del_map_resolver(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_add_del_map_resolver>;

template class Request<vapi_msg_one_add_del_map_resolver, vapi_msg_one_add_del_map_resolver_reply>;

using One_add_del_map_resolver = Request<vapi_msg_one_add_del_map_resolver, vapi_msg_one_add_del_map_resolver_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_one_add_del_map_resolver_reply>(vapi_msg_one_add_del_map_resolver_reply *msg)
{
  vapi_msg_one_add_del_map_resolver_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_add_del_map_resolver_reply>(vapi_msg_one_add_del_map_resolver_reply *msg)
{
  vapi_msg_one_add_del_map_resolver_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_add_del_map_resolver_reply>()
{
  return ::vapi_msg_id_one_add_del_map_resolver_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_add_del_map_resolver_reply>>()
{
  return ::vapi_msg_id_one_add_del_map_resolver_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_add_del_map_resolver_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_add_del_map_resolver_reply>(vapi_msg_id_one_add_del_map_resolver_reply);
}

template class Msg<vapi_msg_one_add_del_map_resolver_reply>;

using One_add_del_map_resolver_reply = Msg<vapi_msg_one_add_del_map_resolver_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_one_enable_disable>(vapi_msg_one_enable_disable *msg)
{
  vapi_msg_one_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_enable_disable>(vapi_msg_one_enable_disable *msg)
{
  vapi_msg_one_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_enable_disable>()
{
  return ::vapi_msg_id_one_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_enable_disable>>()
{
  return ::vapi_msg_id_one_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_enable_disable>(vapi_msg_id_one_enable_disable);
}

template <> inline vapi_msg_one_enable_disable* vapi_alloc<vapi_msg_one_enable_disable>(Connection &con)
{
  vapi_msg_one_enable_disable* result = vapi_alloc_one_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_enable_disable>;

template class Request<vapi_msg_one_enable_disable, vapi_msg_one_enable_disable_reply>;

using One_enable_disable = Request<vapi_msg_one_enable_disable, vapi_msg_one_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_one_enable_disable_reply>(vapi_msg_one_enable_disable_reply *msg)
{
  vapi_msg_one_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_enable_disable_reply>(vapi_msg_one_enable_disable_reply *msg)
{
  vapi_msg_one_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_enable_disable_reply>()
{
  return ::vapi_msg_id_one_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_enable_disable_reply>>()
{
  return ::vapi_msg_id_one_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_enable_disable_reply>(vapi_msg_id_one_enable_disable_reply);
}

template class Msg<vapi_msg_one_enable_disable_reply>;

using One_enable_disable_reply = Msg<vapi_msg_one_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_one_nsh_set_locator_set>(vapi_msg_one_nsh_set_locator_set *msg)
{
  vapi_msg_one_nsh_set_locator_set_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_nsh_set_locator_set>(vapi_msg_one_nsh_set_locator_set *msg)
{
  vapi_msg_one_nsh_set_locator_set_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_nsh_set_locator_set>()
{
  return ::vapi_msg_id_one_nsh_set_locator_set; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_nsh_set_locator_set>>()
{
  return ::vapi_msg_id_one_nsh_set_locator_set; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_nsh_set_locator_set()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_nsh_set_locator_set>(vapi_msg_id_one_nsh_set_locator_set);
}

template <> inline vapi_msg_one_nsh_set_locator_set* vapi_alloc<vapi_msg_one_nsh_set_locator_set>(Connection &con)
{
  vapi_msg_one_nsh_set_locator_set* result = vapi_alloc_one_nsh_set_locator_set(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_nsh_set_locator_set>;

template class Request<vapi_msg_one_nsh_set_locator_set, vapi_msg_one_nsh_set_locator_set_reply>;

using One_nsh_set_locator_set = Request<vapi_msg_one_nsh_set_locator_set, vapi_msg_one_nsh_set_locator_set_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_one_nsh_set_locator_set_reply>(vapi_msg_one_nsh_set_locator_set_reply *msg)
{
  vapi_msg_one_nsh_set_locator_set_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_nsh_set_locator_set_reply>(vapi_msg_one_nsh_set_locator_set_reply *msg)
{
  vapi_msg_one_nsh_set_locator_set_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_nsh_set_locator_set_reply>()
{
  return ::vapi_msg_id_one_nsh_set_locator_set_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_nsh_set_locator_set_reply>>()
{
  return ::vapi_msg_id_one_nsh_set_locator_set_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_nsh_set_locator_set_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_nsh_set_locator_set_reply>(vapi_msg_id_one_nsh_set_locator_set_reply);
}

template class Msg<vapi_msg_one_nsh_set_locator_set_reply>;

using One_nsh_set_locator_set_reply = Msg<vapi_msg_one_nsh_set_locator_set_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_one_pitr_set_locator_set>(vapi_msg_one_pitr_set_locator_set *msg)
{
  vapi_msg_one_pitr_set_locator_set_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_pitr_set_locator_set>(vapi_msg_one_pitr_set_locator_set *msg)
{
  vapi_msg_one_pitr_set_locator_set_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_pitr_set_locator_set>()
{
  return ::vapi_msg_id_one_pitr_set_locator_set; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_pitr_set_locator_set>>()
{
  return ::vapi_msg_id_one_pitr_set_locator_set; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_pitr_set_locator_set()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_pitr_set_locator_set>(vapi_msg_id_one_pitr_set_locator_set);
}

template <> inline vapi_msg_one_pitr_set_locator_set* vapi_alloc<vapi_msg_one_pitr_set_locator_set>(Connection &con)
{
  vapi_msg_one_pitr_set_locator_set* result = vapi_alloc_one_pitr_set_locator_set(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_pitr_set_locator_set>;

template class Request<vapi_msg_one_pitr_set_locator_set, vapi_msg_one_pitr_set_locator_set_reply>;

using One_pitr_set_locator_set = Request<vapi_msg_one_pitr_set_locator_set, vapi_msg_one_pitr_set_locator_set_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_one_pitr_set_locator_set_reply>(vapi_msg_one_pitr_set_locator_set_reply *msg)
{
  vapi_msg_one_pitr_set_locator_set_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_pitr_set_locator_set_reply>(vapi_msg_one_pitr_set_locator_set_reply *msg)
{
  vapi_msg_one_pitr_set_locator_set_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_pitr_set_locator_set_reply>()
{
  return ::vapi_msg_id_one_pitr_set_locator_set_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_pitr_set_locator_set_reply>>()
{
  return ::vapi_msg_id_one_pitr_set_locator_set_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_pitr_set_locator_set_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_pitr_set_locator_set_reply>(vapi_msg_id_one_pitr_set_locator_set_reply);
}

template class Msg<vapi_msg_one_pitr_set_locator_set_reply>;

using One_pitr_set_locator_set_reply = Msg<vapi_msg_one_pitr_set_locator_set_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_one_use_petr>(vapi_msg_one_use_petr *msg)
{
  vapi_msg_one_use_petr_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_use_petr>(vapi_msg_one_use_petr *msg)
{
  vapi_msg_one_use_petr_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_use_petr>()
{
  return ::vapi_msg_id_one_use_petr; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_use_petr>>()
{
  return ::vapi_msg_id_one_use_petr; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_use_petr()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_use_petr>(vapi_msg_id_one_use_petr);
}

template <> inline vapi_msg_one_use_petr* vapi_alloc<vapi_msg_one_use_petr>(Connection &con)
{
  vapi_msg_one_use_petr* result = vapi_alloc_one_use_petr(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_use_petr>;

template class Request<vapi_msg_one_use_petr, vapi_msg_one_use_petr_reply>;

using One_use_petr = Request<vapi_msg_one_use_petr, vapi_msg_one_use_petr_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_one_use_petr_reply>(vapi_msg_one_use_petr_reply *msg)
{
  vapi_msg_one_use_petr_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_use_petr_reply>(vapi_msg_one_use_petr_reply *msg)
{
  vapi_msg_one_use_petr_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_use_petr_reply>()
{
  return ::vapi_msg_id_one_use_petr_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_use_petr_reply>>()
{
  return ::vapi_msg_id_one_use_petr_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_use_petr_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_use_petr_reply>(vapi_msg_id_one_use_petr_reply);
}

template class Msg<vapi_msg_one_use_petr_reply>;

using One_use_petr_reply = Msg<vapi_msg_one_use_petr_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_show_one_use_petr>(vapi_msg_show_one_use_petr *msg)
{
  vapi_msg_show_one_use_petr_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_one_use_petr>(vapi_msg_show_one_use_petr *msg)
{
  vapi_msg_show_one_use_petr_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_one_use_petr>()
{
  return ::vapi_msg_id_show_one_use_petr; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_one_use_petr>>()
{
  return ::vapi_msg_id_show_one_use_petr; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_one_use_petr()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_one_use_petr>(vapi_msg_id_show_one_use_petr);
}

template <> inline vapi_msg_show_one_use_petr* vapi_alloc<vapi_msg_show_one_use_petr>(Connection &con)
{
  vapi_msg_show_one_use_petr* result = vapi_alloc_show_one_use_petr(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_show_one_use_petr>;

template class Request<vapi_msg_show_one_use_petr, vapi_msg_show_one_use_petr_reply>;

using Show_one_use_petr = Request<vapi_msg_show_one_use_petr, vapi_msg_show_one_use_petr_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_show_one_use_petr_reply>(vapi_msg_show_one_use_petr_reply *msg)
{
  vapi_msg_show_one_use_petr_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_one_use_petr_reply>(vapi_msg_show_one_use_petr_reply *msg)
{
  vapi_msg_show_one_use_petr_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_one_use_petr_reply>()
{
  return ::vapi_msg_id_show_one_use_petr_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_one_use_petr_reply>>()
{
  return ::vapi_msg_id_show_one_use_petr_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_one_use_petr_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_one_use_petr_reply>(vapi_msg_id_show_one_use_petr_reply);
}

template class Msg<vapi_msg_show_one_use_petr_reply>;

using Show_one_use_petr_reply = Msg<vapi_msg_show_one_use_petr_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_show_one_rloc_probe_state>(vapi_msg_show_one_rloc_probe_state *msg)
{
  vapi_msg_show_one_rloc_probe_state_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_one_rloc_probe_state>(vapi_msg_show_one_rloc_probe_state *msg)
{
  vapi_msg_show_one_rloc_probe_state_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_one_rloc_probe_state>()
{
  return ::vapi_msg_id_show_one_rloc_probe_state; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_one_rloc_probe_state>>()
{
  return ::vapi_msg_id_show_one_rloc_probe_state; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_one_rloc_probe_state()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_one_rloc_probe_state>(vapi_msg_id_show_one_rloc_probe_state);
}

template <> inline vapi_msg_show_one_rloc_probe_state* vapi_alloc<vapi_msg_show_one_rloc_probe_state>(Connection &con)
{
  vapi_msg_show_one_rloc_probe_state* result = vapi_alloc_show_one_rloc_probe_state(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_show_one_rloc_probe_state>;

template class Request<vapi_msg_show_one_rloc_probe_state, vapi_msg_show_one_rloc_probe_state_reply>;

using Show_one_rloc_probe_state = Request<vapi_msg_show_one_rloc_probe_state, vapi_msg_show_one_rloc_probe_state_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_show_one_rloc_probe_state_reply>(vapi_msg_show_one_rloc_probe_state_reply *msg)
{
  vapi_msg_show_one_rloc_probe_state_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_one_rloc_probe_state_reply>(vapi_msg_show_one_rloc_probe_state_reply *msg)
{
  vapi_msg_show_one_rloc_probe_state_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_one_rloc_probe_state_reply>()
{
  return ::vapi_msg_id_show_one_rloc_probe_state_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_one_rloc_probe_state_reply>>()
{
  return ::vapi_msg_id_show_one_rloc_probe_state_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_one_rloc_probe_state_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_one_rloc_probe_state_reply>(vapi_msg_id_show_one_rloc_probe_state_reply);
}

template class Msg<vapi_msg_show_one_rloc_probe_state_reply>;

using Show_one_rloc_probe_state_reply = Msg<vapi_msg_show_one_rloc_probe_state_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_one_rloc_probe_enable_disable>(vapi_msg_one_rloc_probe_enable_disable *msg)
{
  vapi_msg_one_rloc_probe_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_rloc_probe_enable_disable>(vapi_msg_one_rloc_probe_enable_disable *msg)
{
  vapi_msg_one_rloc_probe_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_rloc_probe_enable_disable>()
{
  return ::vapi_msg_id_one_rloc_probe_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_rloc_probe_enable_disable>>()
{
  return ::vapi_msg_id_one_rloc_probe_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_rloc_probe_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_rloc_probe_enable_disable>(vapi_msg_id_one_rloc_probe_enable_disable);
}

template <> inline vapi_msg_one_rloc_probe_enable_disable* vapi_alloc<vapi_msg_one_rloc_probe_enable_disable>(Connection &con)
{
  vapi_msg_one_rloc_probe_enable_disable* result = vapi_alloc_one_rloc_probe_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_rloc_probe_enable_disable>;

template class Request<vapi_msg_one_rloc_probe_enable_disable, vapi_msg_one_rloc_probe_enable_disable_reply>;

using One_rloc_probe_enable_disable = Request<vapi_msg_one_rloc_probe_enable_disable, vapi_msg_one_rloc_probe_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_one_rloc_probe_enable_disable_reply>(vapi_msg_one_rloc_probe_enable_disable_reply *msg)
{
  vapi_msg_one_rloc_probe_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_rloc_probe_enable_disable_reply>(vapi_msg_one_rloc_probe_enable_disable_reply *msg)
{
  vapi_msg_one_rloc_probe_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_rloc_probe_enable_disable_reply>()
{
  return ::vapi_msg_id_one_rloc_probe_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_rloc_probe_enable_disable_reply>>()
{
  return ::vapi_msg_id_one_rloc_probe_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_rloc_probe_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_rloc_probe_enable_disable_reply>(vapi_msg_id_one_rloc_probe_enable_disable_reply);
}

template class Msg<vapi_msg_one_rloc_probe_enable_disable_reply>;

using One_rloc_probe_enable_disable_reply = Msg<vapi_msg_one_rloc_probe_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_one_map_register_enable_disable>(vapi_msg_one_map_register_enable_disable *msg)
{
  vapi_msg_one_map_register_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_map_register_enable_disable>(vapi_msg_one_map_register_enable_disable *msg)
{
  vapi_msg_one_map_register_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_map_register_enable_disable>()
{
  return ::vapi_msg_id_one_map_register_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_map_register_enable_disable>>()
{
  return ::vapi_msg_id_one_map_register_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_map_register_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_map_register_enable_disable>(vapi_msg_id_one_map_register_enable_disable);
}

template <> inline vapi_msg_one_map_register_enable_disable* vapi_alloc<vapi_msg_one_map_register_enable_disable>(Connection &con)
{
  vapi_msg_one_map_register_enable_disable* result = vapi_alloc_one_map_register_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_map_register_enable_disable>;

template class Request<vapi_msg_one_map_register_enable_disable, vapi_msg_one_map_register_enable_disable_reply>;

using One_map_register_enable_disable = Request<vapi_msg_one_map_register_enable_disable, vapi_msg_one_map_register_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_one_map_register_enable_disable_reply>(vapi_msg_one_map_register_enable_disable_reply *msg)
{
  vapi_msg_one_map_register_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_map_register_enable_disable_reply>(vapi_msg_one_map_register_enable_disable_reply *msg)
{
  vapi_msg_one_map_register_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_map_register_enable_disable_reply>()
{
  return ::vapi_msg_id_one_map_register_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_map_register_enable_disable_reply>>()
{
  return ::vapi_msg_id_one_map_register_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_map_register_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_map_register_enable_disable_reply>(vapi_msg_id_one_map_register_enable_disable_reply);
}

template class Msg<vapi_msg_one_map_register_enable_disable_reply>;

using One_map_register_enable_disable_reply = Msg<vapi_msg_one_map_register_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_show_one_map_register_state>(vapi_msg_show_one_map_register_state *msg)
{
  vapi_msg_show_one_map_register_state_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_one_map_register_state>(vapi_msg_show_one_map_register_state *msg)
{
  vapi_msg_show_one_map_register_state_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_one_map_register_state>()
{
  return ::vapi_msg_id_show_one_map_register_state; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_one_map_register_state>>()
{
  return ::vapi_msg_id_show_one_map_register_state; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_one_map_register_state()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_one_map_register_state>(vapi_msg_id_show_one_map_register_state);
}

template <> inline vapi_msg_show_one_map_register_state* vapi_alloc<vapi_msg_show_one_map_register_state>(Connection &con)
{
  vapi_msg_show_one_map_register_state* result = vapi_alloc_show_one_map_register_state(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_show_one_map_register_state>;

template class Request<vapi_msg_show_one_map_register_state, vapi_msg_show_one_map_register_state_reply>;

using Show_one_map_register_state = Request<vapi_msg_show_one_map_register_state, vapi_msg_show_one_map_register_state_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_show_one_map_register_state_reply>(vapi_msg_show_one_map_register_state_reply *msg)
{
  vapi_msg_show_one_map_register_state_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_one_map_register_state_reply>(vapi_msg_show_one_map_register_state_reply *msg)
{
  vapi_msg_show_one_map_register_state_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_one_map_register_state_reply>()
{
  return ::vapi_msg_id_show_one_map_register_state_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_one_map_register_state_reply>>()
{
  return ::vapi_msg_id_show_one_map_register_state_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_one_map_register_state_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_one_map_register_state_reply>(vapi_msg_id_show_one_map_register_state_reply);
}

template class Msg<vapi_msg_show_one_map_register_state_reply>;

using Show_one_map_register_state_reply = Msg<vapi_msg_show_one_map_register_state_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_one_map_request_mode>(vapi_msg_one_map_request_mode *msg)
{
  vapi_msg_one_map_request_mode_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_map_request_mode>(vapi_msg_one_map_request_mode *msg)
{
  vapi_msg_one_map_request_mode_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_map_request_mode>()
{
  return ::vapi_msg_id_one_map_request_mode; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_map_request_mode>>()
{
  return ::vapi_msg_id_one_map_request_mode; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_map_request_mode()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_map_request_mode>(vapi_msg_id_one_map_request_mode);
}

template <> inline vapi_msg_one_map_request_mode* vapi_alloc<vapi_msg_one_map_request_mode>(Connection &con)
{
  vapi_msg_one_map_request_mode* result = vapi_alloc_one_map_request_mode(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_map_request_mode>;

template class Request<vapi_msg_one_map_request_mode, vapi_msg_one_map_request_mode_reply>;

using One_map_request_mode = Request<vapi_msg_one_map_request_mode, vapi_msg_one_map_request_mode_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_one_map_request_mode_reply>(vapi_msg_one_map_request_mode_reply *msg)
{
  vapi_msg_one_map_request_mode_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_map_request_mode_reply>(vapi_msg_one_map_request_mode_reply *msg)
{
  vapi_msg_one_map_request_mode_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_map_request_mode_reply>()
{
  return ::vapi_msg_id_one_map_request_mode_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_map_request_mode_reply>>()
{
  return ::vapi_msg_id_one_map_request_mode_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_map_request_mode_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_map_request_mode_reply>(vapi_msg_id_one_map_request_mode_reply);
}

template class Msg<vapi_msg_one_map_request_mode_reply>;

using One_map_request_mode_reply = Msg<vapi_msg_one_map_request_mode_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_show_one_map_request_mode>(vapi_msg_show_one_map_request_mode *msg)
{
  vapi_msg_show_one_map_request_mode_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_one_map_request_mode>(vapi_msg_show_one_map_request_mode *msg)
{
  vapi_msg_show_one_map_request_mode_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_one_map_request_mode>()
{
  return ::vapi_msg_id_show_one_map_request_mode; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_one_map_request_mode>>()
{
  return ::vapi_msg_id_show_one_map_request_mode; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_one_map_request_mode()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_one_map_request_mode>(vapi_msg_id_show_one_map_request_mode);
}

template <> inline vapi_msg_show_one_map_request_mode* vapi_alloc<vapi_msg_show_one_map_request_mode>(Connection &con)
{
  vapi_msg_show_one_map_request_mode* result = vapi_alloc_show_one_map_request_mode(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_show_one_map_request_mode>;

template class Request<vapi_msg_show_one_map_request_mode, vapi_msg_show_one_map_request_mode_reply>;

using Show_one_map_request_mode = Request<vapi_msg_show_one_map_request_mode, vapi_msg_show_one_map_request_mode_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_show_one_map_request_mode_reply>(vapi_msg_show_one_map_request_mode_reply *msg)
{
  vapi_msg_show_one_map_request_mode_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_one_map_request_mode_reply>(vapi_msg_show_one_map_request_mode_reply *msg)
{
  vapi_msg_show_one_map_request_mode_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_one_map_request_mode_reply>()
{
  return ::vapi_msg_id_show_one_map_request_mode_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_one_map_request_mode_reply>>()
{
  return ::vapi_msg_id_show_one_map_request_mode_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_one_map_request_mode_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_one_map_request_mode_reply>(vapi_msg_id_show_one_map_request_mode_reply);
}

template class Msg<vapi_msg_show_one_map_request_mode_reply>;

using Show_one_map_request_mode_reply = Msg<vapi_msg_show_one_map_request_mode_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_one_add_del_remote_mapping>(vapi_msg_one_add_del_remote_mapping *msg)
{
  vapi_msg_one_add_del_remote_mapping_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_add_del_remote_mapping>(vapi_msg_one_add_del_remote_mapping *msg)
{
  vapi_msg_one_add_del_remote_mapping_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_add_del_remote_mapping>()
{
  return ::vapi_msg_id_one_add_del_remote_mapping; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_add_del_remote_mapping>>()
{
  return ::vapi_msg_id_one_add_del_remote_mapping; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_add_del_remote_mapping()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_add_del_remote_mapping>(vapi_msg_id_one_add_del_remote_mapping);
}

template <> inline vapi_msg_one_add_del_remote_mapping* vapi_alloc<vapi_msg_one_add_del_remote_mapping, size_t>(Connection &con, size_t _rlocs_array_size)
{
  vapi_msg_one_add_del_remote_mapping* result = vapi_alloc_one_add_del_remote_mapping(con.vapi_ctx, _rlocs_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_add_del_remote_mapping>;

template class Request<vapi_msg_one_add_del_remote_mapping, vapi_msg_one_add_del_remote_mapping_reply, size_t>;

using One_add_del_remote_mapping = Request<vapi_msg_one_add_del_remote_mapping, vapi_msg_one_add_del_remote_mapping_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_one_add_del_remote_mapping_reply>(vapi_msg_one_add_del_remote_mapping_reply *msg)
{
  vapi_msg_one_add_del_remote_mapping_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_add_del_remote_mapping_reply>(vapi_msg_one_add_del_remote_mapping_reply *msg)
{
  vapi_msg_one_add_del_remote_mapping_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_add_del_remote_mapping_reply>()
{
  return ::vapi_msg_id_one_add_del_remote_mapping_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_add_del_remote_mapping_reply>>()
{
  return ::vapi_msg_id_one_add_del_remote_mapping_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_add_del_remote_mapping_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_add_del_remote_mapping_reply>(vapi_msg_id_one_add_del_remote_mapping_reply);
}

template class Msg<vapi_msg_one_add_del_remote_mapping_reply>;

using One_add_del_remote_mapping_reply = Msg<vapi_msg_one_add_del_remote_mapping_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_one_add_del_l2_arp_entry>(vapi_msg_one_add_del_l2_arp_entry *msg)
{
  vapi_msg_one_add_del_l2_arp_entry_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_add_del_l2_arp_entry>(vapi_msg_one_add_del_l2_arp_entry *msg)
{
  vapi_msg_one_add_del_l2_arp_entry_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_add_del_l2_arp_entry>()
{
  return ::vapi_msg_id_one_add_del_l2_arp_entry; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_add_del_l2_arp_entry>>()
{
  return ::vapi_msg_id_one_add_del_l2_arp_entry; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_add_del_l2_arp_entry()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_add_del_l2_arp_entry>(vapi_msg_id_one_add_del_l2_arp_entry);
}

template <> inline vapi_msg_one_add_del_l2_arp_entry* vapi_alloc<vapi_msg_one_add_del_l2_arp_entry>(Connection &con)
{
  vapi_msg_one_add_del_l2_arp_entry* result = vapi_alloc_one_add_del_l2_arp_entry(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_add_del_l2_arp_entry>;

template class Request<vapi_msg_one_add_del_l2_arp_entry, vapi_msg_one_add_del_l2_arp_entry_reply>;

using One_add_del_l2_arp_entry = Request<vapi_msg_one_add_del_l2_arp_entry, vapi_msg_one_add_del_l2_arp_entry_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_one_add_del_l2_arp_entry_reply>(vapi_msg_one_add_del_l2_arp_entry_reply *msg)
{
  vapi_msg_one_add_del_l2_arp_entry_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_add_del_l2_arp_entry_reply>(vapi_msg_one_add_del_l2_arp_entry_reply *msg)
{
  vapi_msg_one_add_del_l2_arp_entry_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_add_del_l2_arp_entry_reply>()
{
  return ::vapi_msg_id_one_add_del_l2_arp_entry_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_add_del_l2_arp_entry_reply>>()
{
  return ::vapi_msg_id_one_add_del_l2_arp_entry_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_add_del_l2_arp_entry_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_add_del_l2_arp_entry_reply>(vapi_msg_id_one_add_del_l2_arp_entry_reply);
}

template class Msg<vapi_msg_one_add_del_l2_arp_entry_reply>;

using One_add_del_l2_arp_entry_reply = Msg<vapi_msg_one_add_del_l2_arp_entry_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_one_l2_arp_entries_get>(vapi_msg_one_l2_arp_entries_get *msg)
{
  vapi_msg_one_l2_arp_entries_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_l2_arp_entries_get>(vapi_msg_one_l2_arp_entries_get *msg)
{
  vapi_msg_one_l2_arp_entries_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_l2_arp_entries_get>()
{
  return ::vapi_msg_id_one_l2_arp_entries_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_l2_arp_entries_get>>()
{
  return ::vapi_msg_id_one_l2_arp_entries_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_l2_arp_entries_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_l2_arp_entries_get>(vapi_msg_id_one_l2_arp_entries_get);
}

template <> inline vapi_msg_one_l2_arp_entries_get* vapi_alloc<vapi_msg_one_l2_arp_entries_get>(Connection &con)
{
  vapi_msg_one_l2_arp_entries_get* result = vapi_alloc_one_l2_arp_entries_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_l2_arp_entries_get>;

template class Request<vapi_msg_one_l2_arp_entries_get, vapi_msg_one_l2_arp_entries_get_reply>;

using One_l2_arp_entries_get = Request<vapi_msg_one_l2_arp_entries_get, vapi_msg_one_l2_arp_entries_get_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_one_l2_arp_entries_get_reply>(vapi_msg_one_l2_arp_entries_get_reply *msg)
{
  vapi_msg_one_l2_arp_entries_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_l2_arp_entries_get_reply>(vapi_msg_one_l2_arp_entries_get_reply *msg)
{
  vapi_msg_one_l2_arp_entries_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_l2_arp_entries_get_reply>()
{
  return ::vapi_msg_id_one_l2_arp_entries_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_l2_arp_entries_get_reply>>()
{
  return ::vapi_msg_id_one_l2_arp_entries_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_l2_arp_entries_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_l2_arp_entries_get_reply>(vapi_msg_id_one_l2_arp_entries_get_reply);
}

template class Msg<vapi_msg_one_l2_arp_entries_get_reply>;

using One_l2_arp_entries_get_reply = Msg<vapi_msg_one_l2_arp_entries_get_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_one_add_del_ndp_entry>(vapi_msg_one_add_del_ndp_entry *msg)
{
  vapi_msg_one_add_del_ndp_entry_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_add_del_ndp_entry>(vapi_msg_one_add_del_ndp_entry *msg)
{
  vapi_msg_one_add_del_ndp_entry_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_add_del_ndp_entry>()
{
  return ::vapi_msg_id_one_add_del_ndp_entry; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_add_del_ndp_entry>>()
{
  return ::vapi_msg_id_one_add_del_ndp_entry; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_add_del_ndp_entry()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_add_del_ndp_entry>(vapi_msg_id_one_add_del_ndp_entry);
}

template <> inline vapi_msg_one_add_del_ndp_entry* vapi_alloc<vapi_msg_one_add_del_ndp_entry>(Connection &con)
{
  vapi_msg_one_add_del_ndp_entry* result = vapi_alloc_one_add_del_ndp_entry(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_add_del_ndp_entry>;

template class Request<vapi_msg_one_add_del_ndp_entry, vapi_msg_one_add_del_ndp_entry_reply>;

using One_add_del_ndp_entry = Request<vapi_msg_one_add_del_ndp_entry, vapi_msg_one_add_del_ndp_entry_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_one_add_del_ndp_entry_reply>(vapi_msg_one_add_del_ndp_entry_reply *msg)
{
  vapi_msg_one_add_del_ndp_entry_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_add_del_ndp_entry_reply>(vapi_msg_one_add_del_ndp_entry_reply *msg)
{
  vapi_msg_one_add_del_ndp_entry_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_add_del_ndp_entry_reply>()
{
  return ::vapi_msg_id_one_add_del_ndp_entry_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_add_del_ndp_entry_reply>>()
{
  return ::vapi_msg_id_one_add_del_ndp_entry_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_add_del_ndp_entry_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_add_del_ndp_entry_reply>(vapi_msg_id_one_add_del_ndp_entry_reply);
}

template class Msg<vapi_msg_one_add_del_ndp_entry_reply>;

using One_add_del_ndp_entry_reply = Msg<vapi_msg_one_add_del_ndp_entry_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_one_ndp_entries_get>(vapi_msg_one_ndp_entries_get *msg)
{
  vapi_msg_one_ndp_entries_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_ndp_entries_get>(vapi_msg_one_ndp_entries_get *msg)
{
  vapi_msg_one_ndp_entries_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_ndp_entries_get>()
{
  return ::vapi_msg_id_one_ndp_entries_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_ndp_entries_get>>()
{
  return ::vapi_msg_id_one_ndp_entries_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_ndp_entries_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_ndp_entries_get>(vapi_msg_id_one_ndp_entries_get);
}

template <> inline vapi_msg_one_ndp_entries_get* vapi_alloc<vapi_msg_one_ndp_entries_get>(Connection &con)
{
  vapi_msg_one_ndp_entries_get* result = vapi_alloc_one_ndp_entries_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_ndp_entries_get>;

template class Request<vapi_msg_one_ndp_entries_get, vapi_msg_one_ndp_entries_get_reply>;

using One_ndp_entries_get = Request<vapi_msg_one_ndp_entries_get, vapi_msg_one_ndp_entries_get_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_one_ndp_entries_get_reply>(vapi_msg_one_ndp_entries_get_reply *msg)
{
  vapi_msg_one_ndp_entries_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_ndp_entries_get_reply>(vapi_msg_one_ndp_entries_get_reply *msg)
{
  vapi_msg_one_ndp_entries_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_ndp_entries_get_reply>()
{
  return ::vapi_msg_id_one_ndp_entries_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_ndp_entries_get_reply>>()
{
  return ::vapi_msg_id_one_ndp_entries_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_ndp_entries_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_ndp_entries_get_reply>(vapi_msg_id_one_ndp_entries_get_reply);
}

template class Msg<vapi_msg_one_ndp_entries_get_reply>;

using One_ndp_entries_get_reply = Msg<vapi_msg_one_ndp_entries_get_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_one_set_transport_protocol>(vapi_msg_one_set_transport_protocol *msg)
{
  vapi_msg_one_set_transport_protocol_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_set_transport_protocol>(vapi_msg_one_set_transport_protocol *msg)
{
  vapi_msg_one_set_transport_protocol_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_set_transport_protocol>()
{
  return ::vapi_msg_id_one_set_transport_protocol; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_set_transport_protocol>>()
{
  return ::vapi_msg_id_one_set_transport_protocol; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_set_transport_protocol()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_set_transport_protocol>(vapi_msg_id_one_set_transport_protocol);
}

template <> inline vapi_msg_one_set_transport_protocol* vapi_alloc<vapi_msg_one_set_transport_protocol>(Connection &con)
{
  vapi_msg_one_set_transport_protocol* result = vapi_alloc_one_set_transport_protocol(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_set_transport_protocol>;

template class Request<vapi_msg_one_set_transport_protocol, vapi_msg_one_set_transport_protocol_reply>;

using One_set_transport_protocol = Request<vapi_msg_one_set_transport_protocol, vapi_msg_one_set_transport_protocol_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_one_set_transport_protocol_reply>(vapi_msg_one_set_transport_protocol_reply *msg)
{
  vapi_msg_one_set_transport_protocol_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_set_transport_protocol_reply>(vapi_msg_one_set_transport_protocol_reply *msg)
{
  vapi_msg_one_set_transport_protocol_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_set_transport_protocol_reply>()
{
  return ::vapi_msg_id_one_set_transport_protocol_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_set_transport_protocol_reply>>()
{
  return ::vapi_msg_id_one_set_transport_protocol_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_set_transport_protocol_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_set_transport_protocol_reply>(vapi_msg_id_one_set_transport_protocol_reply);
}

template class Msg<vapi_msg_one_set_transport_protocol_reply>;

using One_set_transport_protocol_reply = Msg<vapi_msg_one_set_transport_protocol_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_one_get_transport_protocol>(vapi_msg_one_get_transport_protocol *msg)
{
  vapi_msg_one_get_transport_protocol_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_get_transport_protocol>(vapi_msg_one_get_transport_protocol *msg)
{
  vapi_msg_one_get_transport_protocol_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_get_transport_protocol>()
{
  return ::vapi_msg_id_one_get_transport_protocol; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_get_transport_protocol>>()
{
  return ::vapi_msg_id_one_get_transport_protocol; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_get_transport_protocol()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_get_transport_protocol>(vapi_msg_id_one_get_transport_protocol);
}

template <> inline vapi_msg_one_get_transport_protocol* vapi_alloc<vapi_msg_one_get_transport_protocol>(Connection &con)
{
  vapi_msg_one_get_transport_protocol* result = vapi_alloc_one_get_transport_protocol(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_get_transport_protocol>;

template class Request<vapi_msg_one_get_transport_protocol, vapi_msg_one_get_transport_protocol_reply>;

using One_get_transport_protocol = Request<vapi_msg_one_get_transport_protocol, vapi_msg_one_get_transport_protocol_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_one_get_transport_protocol_reply>(vapi_msg_one_get_transport_protocol_reply *msg)
{
  vapi_msg_one_get_transport_protocol_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_get_transport_protocol_reply>(vapi_msg_one_get_transport_protocol_reply *msg)
{
  vapi_msg_one_get_transport_protocol_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_get_transport_protocol_reply>()
{
  return ::vapi_msg_id_one_get_transport_protocol_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_get_transport_protocol_reply>>()
{
  return ::vapi_msg_id_one_get_transport_protocol_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_get_transport_protocol_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_get_transport_protocol_reply>(vapi_msg_id_one_get_transport_protocol_reply);
}

template class Msg<vapi_msg_one_get_transport_protocol_reply>;

using One_get_transport_protocol_reply = Msg<vapi_msg_one_get_transport_protocol_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_one_ndp_bd_get>(vapi_msg_one_ndp_bd_get *msg)
{
  vapi_msg_one_ndp_bd_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_ndp_bd_get>(vapi_msg_one_ndp_bd_get *msg)
{
  vapi_msg_one_ndp_bd_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_ndp_bd_get>()
{
  return ::vapi_msg_id_one_ndp_bd_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_ndp_bd_get>>()
{
  return ::vapi_msg_id_one_ndp_bd_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_ndp_bd_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_ndp_bd_get>(vapi_msg_id_one_ndp_bd_get);
}

template <> inline vapi_msg_one_ndp_bd_get* vapi_alloc<vapi_msg_one_ndp_bd_get>(Connection &con)
{
  vapi_msg_one_ndp_bd_get* result = vapi_alloc_one_ndp_bd_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_ndp_bd_get>;

template class Request<vapi_msg_one_ndp_bd_get, vapi_msg_one_ndp_bd_get_reply>;

using One_ndp_bd_get = Request<vapi_msg_one_ndp_bd_get, vapi_msg_one_ndp_bd_get_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_one_ndp_bd_get_reply>(vapi_msg_one_ndp_bd_get_reply *msg)
{
  vapi_msg_one_ndp_bd_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_ndp_bd_get_reply>(vapi_msg_one_ndp_bd_get_reply *msg)
{
  vapi_msg_one_ndp_bd_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_ndp_bd_get_reply>()
{
  return ::vapi_msg_id_one_ndp_bd_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_ndp_bd_get_reply>>()
{
  return ::vapi_msg_id_one_ndp_bd_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_ndp_bd_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_ndp_bd_get_reply>(vapi_msg_id_one_ndp_bd_get_reply);
}

template class Msg<vapi_msg_one_ndp_bd_get_reply>;

using One_ndp_bd_get_reply = Msg<vapi_msg_one_ndp_bd_get_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_one_l2_arp_bd_get>(vapi_msg_one_l2_arp_bd_get *msg)
{
  vapi_msg_one_l2_arp_bd_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_l2_arp_bd_get>(vapi_msg_one_l2_arp_bd_get *msg)
{
  vapi_msg_one_l2_arp_bd_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_l2_arp_bd_get>()
{
  return ::vapi_msg_id_one_l2_arp_bd_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_l2_arp_bd_get>>()
{
  return ::vapi_msg_id_one_l2_arp_bd_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_l2_arp_bd_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_l2_arp_bd_get>(vapi_msg_id_one_l2_arp_bd_get);
}

template <> inline vapi_msg_one_l2_arp_bd_get* vapi_alloc<vapi_msg_one_l2_arp_bd_get>(Connection &con)
{
  vapi_msg_one_l2_arp_bd_get* result = vapi_alloc_one_l2_arp_bd_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_l2_arp_bd_get>;

template class Request<vapi_msg_one_l2_arp_bd_get, vapi_msg_one_l2_arp_bd_get_reply>;

using One_l2_arp_bd_get = Request<vapi_msg_one_l2_arp_bd_get, vapi_msg_one_l2_arp_bd_get_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_one_l2_arp_bd_get_reply>(vapi_msg_one_l2_arp_bd_get_reply *msg)
{
  vapi_msg_one_l2_arp_bd_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_l2_arp_bd_get_reply>(vapi_msg_one_l2_arp_bd_get_reply *msg)
{
  vapi_msg_one_l2_arp_bd_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_l2_arp_bd_get_reply>()
{
  return ::vapi_msg_id_one_l2_arp_bd_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_l2_arp_bd_get_reply>>()
{
  return ::vapi_msg_id_one_l2_arp_bd_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_l2_arp_bd_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_l2_arp_bd_get_reply>(vapi_msg_id_one_l2_arp_bd_get_reply);
}

template class Msg<vapi_msg_one_l2_arp_bd_get_reply>;

using One_l2_arp_bd_get_reply = Msg<vapi_msg_one_l2_arp_bd_get_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_one_add_del_adjacency>(vapi_msg_one_add_del_adjacency *msg)
{
  vapi_msg_one_add_del_adjacency_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_add_del_adjacency>(vapi_msg_one_add_del_adjacency *msg)
{
  vapi_msg_one_add_del_adjacency_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_add_del_adjacency>()
{
  return ::vapi_msg_id_one_add_del_adjacency; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_add_del_adjacency>>()
{
  return ::vapi_msg_id_one_add_del_adjacency; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_add_del_adjacency()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_add_del_adjacency>(vapi_msg_id_one_add_del_adjacency);
}

template <> inline vapi_msg_one_add_del_adjacency* vapi_alloc<vapi_msg_one_add_del_adjacency>(Connection &con)
{
  vapi_msg_one_add_del_adjacency* result = vapi_alloc_one_add_del_adjacency(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_add_del_adjacency>;

template class Request<vapi_msg_one_add_del_adjacency, vapi_msg_one_add_del_adjacency_reply>;

using One_add_del_adjacency = Request<vapi_msg_one_add_del_adjacency, vapi_msg_one_add_del_adjacency_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_one_add_del_adjacency_reply>(vapi_msg_one_add_del_adjacency_reply *msg)
{
  vapi_msg_one_add_del_adjacency_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_add_del_adjacency_reply>(vapi_msg_one_add_del_adjacency_reply *msg)
{
  vapi_msg_one_add_del_adjacency_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_add_del_adjacency_reply>()
{
  return ::vapi_msg_id_one_add_del_adjacency_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_add_del_adjacency_reply>>()
{
  return ::vapi_msg_id_one_add_del_adjacency_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_add_del_adjacency_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_add_del_adjacency_reply>(vapi_msg_id_one_add_del_adjacency_reply);
}

template class Msg<vapi_msg_one_add_del_adjacency_reply>;

using One_add_del_adjacency_reply = Msg<vapi_msg_one_add_del_adjacency_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_one_add_del_map_request_itr_rlocs>(vapi_msg_one_add_del_map_request_itr_rlocs *msg)
{
  vapi_msg_one_add_del_map_request_itr_rlocs_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_add_del_map_request_itr_rlocs>(vapi_msg_one_add_del_map_request_itr_rlocs *msg)
{
  vapi_msg_one_add_del_map_request_itr_rlocs_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_add_del_map_request_itr_rlocs>()
{
  return ::vapi_msg_id_one_add_del_map_request_itr_rlocs; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_add_del_map_request_itr_rlocs>>()
{
  return ::vapi_msg_id_one_add_del_map_request_itr_rlocs; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_add_del_map_request_itr_rlocs()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_add_del_map_request_itr_rlocs>(vapi_msg_id_one_add_del_map_request_itr_rlocs);
}

template <> inline vapi_msg_one_add_del_map_request_itr_rlocs* vapi_alloc<vapi_msg_one_add_del_map_request_itr_rlocs>(Connection &con)
{
  vapi_msg_one_add_del_map_request_itr_rlocs* result = vapi_alloc_one_add_del_map_request_itr_rlocs(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_add_del_map_request_itr_rlocs>;

template class Request<vapi_msg_one_add_del_map_request_itr_rlocs, vapi_msg_one_add_del_map_request_itr_rlocs_reply>;

using One_add_del_map_request_itr_rlocs = Request<vapi_msg_one_add_del_map_request_itr_rlocs, vapi_msg_one_add_del_map_request_itr_rlocs_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_one_add_del_map_request_itr_rlocs_reply>(vapi_msg_one_add_del_map_request_itr_rlocs_reply *msg)
{
  vapi_msg_one_add_del_map_request_itr_rlocs_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_add_del_map_request_itr_rlocs_reply>(vapi_msg_one_add_del_map_request_itr_rlocs_reply *msg)
{
  vapi_msg_one_add_del_map_request_itr_rlocs_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_add_del_map_request_itr_rlocs_reply>()
{
  return ::vapi_msg_id_one_add_del_map_request_itr_rlocs_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_add_del_map_request_itr_rlocs_reply>>()
{
  return ::vapi_msg_id_one_add_del_map_request_itr_rlocs_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_add_del_map_request_itr_rlocs_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_add_del_map_request_itr_rlocs_reply>(vapi_msg_id_one_add_del_map_request_itr_rlocs_reply);
}

template class Msg<vapi_msg_one_add_del_map_request_itr_rlocs_reply>;

using One_add_del_map_request_itr_rlocs_reply = Msg<vapi_msg_one_add_del_map_request_itr_rlocs_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_one_eid_table_add_del_map>(vapi_msg_one_eid_table_add_del_map *msg)
{
  vapi_msg_one_eid_table_add_del_map_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_eid_table_add_del_map>(vapi_msg_one_eid_table_add_del_map *msg)
{
  vapi_msg_one_eid_table_add_del_map_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_eid_table_add_del_map>()
{
  return ::vapi_msg_id_one_eid_table_add_del_map; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_eid_table_add_del_map>>()
{
  return ::vapi_msg_id_one_eid_table_add_del_map; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_eid_table_add_del_map()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_eid_table_add_del_map>(vapi_msg_id_one_eid_table_add_del_map);
}

template <> inline vapi_msg_one_eid_table_add_del_map* vapi_alloc<vapi_msg_one_eid_table_add_del_map>(Connection &con)
{
  vapi_msg_one_eid_table_add_del_map* result = vapi_alloc_one_eid_table_add_del_map(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_eid_table_add_del_map>;

template class Request<vapi_msg_one_eid_table_add_del_map, vapi_msg_one_eid_table_add_del_map_reply>;

using One_eid_table_add_del_map = Request<vapi_msg_one_eid_table_add_del_map, vapi_msg_one_eid_table_add_del_map_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_one_eid_table_add_del_map_reply>(vapi_msg_one_eid_table_add_del_map_reply *msg)
{
  vapi_msg_one_eid_table_add_del_map_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_eid_table_add_del_map_reply>(vapi_msg_one_eid_table_add_del_map_reply *msg)
{
  vapi_msg_one_eid_table_add_del_map_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_eid_table_add_del_map_reply>()
{
  return ::vapi_msg_id_one_eid_table_add_del_map_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_eid_table_add_del_map_reply>>()
{
  return ::vapi_msg_id_one_eid_table_add_del_map_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_eid_table_add_del_map_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_eid_table_add_del_map_reply>(vapi_msg_id_one_eid_table_add_del_map_reply);
}

template class Msg<vapi_msg_one_eid_table_add_del_map_reply>;

using One_eid_table_add_del_map_reply = Msg<vapi_msg_one_eid_table_add_del_map_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_one_locator_dump>(vapi_msg_one_locator_dump *msg)
{
  vapi_msg_one_locator_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_locator_dump>(vapi_msg_one_locator_dump *msg)
{
  vapi_msg_one_locator_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_locator_dump>()
{
  return ::vapi_msg_id_one_locator_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_locator_dump>>()
{
  return ::vapi_msg_id_one_locator_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_locator_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_locator_dump>(vapi_msg_id_one_locator_dump);
}

template <> inline vapi_msg_one_locator_dump* vapi_alloc<vapi_msg_one_locator_dump>(Connection &con)
{
  vapi_msg_one_locator_dump* result = vapi_alloc_one_locator_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_locator_dump>;

template class Dump<vapi_msg_one_locator_dump, vapi_msg_one_locator_details>;

using One_locator_dump = Dump<vapi_msg_one_locator_dump, vapi_msg_one_locator_details>;

template <> inline void vapi_swap_to_be<vapi_msg_one_locator_details>(vapi_msg_one_locator_details *msg)
{
  vapi_msg_one_locator_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_locator_details>(vapi_msg_one_locator_details *msg)
{
  vapi_msg_one_locator_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_locator_details>()
{
  return ::vapi_msg_id_one_locator_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_locator_details>>()
{
  return ::vapi_msg_id_one_locator_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_locator_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_locator_details>(vapi_msg_id_one_locator_details);
}

template class Msg<vapi_msg_one_locator_details>;

using One_locator_details = Msg<vapi_msg_one_locator_details>;
template <> inline void vapi_swap_to_be<vapi_msg_one_locator_set_details>(vapi_msg_one_locator_set_details *msg)
{
  vapi_msg_one_locator_set_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_locator_set_details>(vapi_msg_one_locator_set_details *msg)
{
  vapi_msg_one_locator_set_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_locator_set_details>()
{
  return ::vapi_msg_id_one_locator_set_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_locator_set_details>>()
{
  return ::vapi_msg_id_one_locator_set_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_locator_set_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_locator_set_details>(vapi_msg_id_one_locator_set_details);
}

template class Msg<vapi_msg_one_locator_set_details>;

using One_locator_set_details = Msg<vapi_msg_one_locator_set_details>;
template <> inline void vapi_swap_to_be<vapi_msg_one_locator_set_dump>(vapi_msg_one_locator_set_dump *msg)
{
  vapi_msg_one_locator_set_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_locator_set_dump>(vapi_msg_one_locator_set_dump *msg)
{
  vapi_msg_one_locator_set_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_locator_set_dump>()
{
  return ::vapi_msg_id_one_locator_set_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_locator_set_dump>>()
{
  return ::vapi_msg_id_one_locator_set_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_locator_set_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_locator_set_dump>(vapi_msg_id_one_locator_set_dump);
}

template <> inline vapi_msg_one_locator_set_dump* vapi_alloc<vapi_msg_one_locator_set_dump>(Connection &con)
{
  vapi_msg_one_locator_set_dump* result = vapi_alloc_one_locator_set_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_locator_set_dump>;

template class Dump<vapi_msg_one_locator_set_dump, vapi_msg_one_locator_set_details>;

using One_locator_set_dump = Dump<vapi_msg_one_locator_set_dump, vapi_msg_one_locator_set_details>;

template <> inline void vapi_swap_to_be<vapi_msg_one_eid_table_details>(vapi_msg_one_eid_table_details *msg)
{
  vapi_msg_one_eid_table_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_eid_table_details>(vapi_msg_one_eid_table_details *msg)
{
  vapi_msg_one_eid_table_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_eid_table_details>()
{
  return ::vapi_msg_id_one_eid_table_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_eid_table_details>>()
{
  return ::vapi_msg_id_one_eid_table_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_eid_table_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_eid_table_details>(vapi_msg_id_one_eid_table_details);
}

template class Msg<vapi_msg_one_eid_table_details>;

using One_eid_table_details = Msg<vapi_msg_one_eid_table_details>;
template <> inline void vapi_swap_to_be<vapi_msg_one_eid_table_dump>(vapi_msg_one_eid_table_dump *msg)
{
  vapi_msg_one_eid_table_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_eid_table_dump>(vapi_msg_one_eid_table_dump *msg)
{
  vapi_msg_one_eid_table_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_eid_table_dump>()
{
  return ::vapi_msg_id_one_eid_table_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_eid_table_dump>>()
{
  return ::vapi_msg_id_one_eid_table_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_eid_table_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_eid_table_dump>(vapi_msg_id_one_eid_table_dump);
}

template <> inline vapi_msg_one_eid_table_dump* vapi_alloc<vapi_msg_one_eid_table_dump>(Connection &con)
{
  vapi_msg_one_eid_table_dump* result = vapi_alloc_one_eid_table_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_eid_table_dump>;

template class Dump<vapi_msg_one_eid_table_dump, vapi_msg_one_eid_table_details>;

using One_eid_table_dump = Dump<vapi_msg_one_eid_table_dump, vapi_msg_one_eid_table_details>;

template <> inline void vapi_swap_to_be<vapi_msg_one_adjacencies_get_reply>(vapi_msg_one_adjacencies_get_reply *msg)
{
  vapi_msg_one_adjacencies_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_adjacencies_get_reply>(vapi_msg_one_adjacencies_get_reply *msg)
{
  vapi_msg_one_adjacencies_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_adjacencies_get_reply>()
{
  return ::vapi_msg_id_one_adjacencies_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_adjacencies_get_reply>>()
{
  return ::vapi_msg_id_one_adjacencies_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_adjacencies_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_adjacencies_get_reply>(vapi_msg_id_one_adjacencies_get_reply);
}

template class Msg<vapi_msg_one_adjacencies_get_reply>;

using One_adjacencies_get_reply = Msg<vapi_msg_one_adjacencies_get_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_one_adjacencies_get>(vapi_msg_one_adjacencies_get *msg)
{
  vapi_msg_one_adjacencies_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_adjacencies_get>(vapi_msg_one_adjacencies_get *msg)
{
  vapi_msg_one_adjacencies_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_adjacencies_get>()
{
  return ::vapi_msg_id_one_adjacencies_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_adjacencies_get>>()
{
  return ::vapi_msg_id_one_adjacencies_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_adjacencies_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_adjacencies_get>(vapi_msg_id_one_adjacencies_get);
}

template <> inline vapi_msg_one_adjacencies_get* vapi_alloc<vapi_msg_one_adjacencies_get>(Connection &con)
{
  vapi_msg_one_adjacencies_get* result = vapi_alloc_one_adjacencies_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_adjacencies_get>;

template class Request<vapi_msg_one_adjacencies_get, vapi_msg_one_adjacencies_get_reply>;

using One_adjacencies_get = Request<vapi_msg_one_adjacencies_get, vapi_msg_one_adjacencies_get_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_one_eid_table_map_details>(vapi_msg_one_eid_table_map_details *msg)
{
  vapi_msg_one_eid_table_map_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_eid_table_map_details>(vapi_msg_one_eid_table_map_details *msg)
{
  vapi_msg_one_eid_table_map_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_eid_table_map_details>()
{
  return ::vapi_msg_id_one_eid_table_map_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_eid_table_map_details>>()
{
  return ::vapi_msg_id_one_eid_table_map_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_eid_table_map_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_eid_table_map_details>(vapi_msg_id_one_eid_table_map_details);
}

template class Msg<vapi_msg_one_eid_table_map_details>;

using One_eid_table_map_details = Msg<vapi_msg_one_eid_table_map_details>;
template <> inline void vapi_swap_to_be<vapi_msg_one_eid_table_map_dump>(vapi_msg_one_eid_table_map_dump *msg)
{
  vapi_msg_one_eid_table_map_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_eid_table_map_dump>(vapi_msg_one_eid_table_map_dump *msg)
{
  vapi_msg_one_eid_table_map_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_eid_table_map_dump>()
{
  return ::vapi_msg_id_one_eid_table_map_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_eid_table_map_dump>>()
{
  return ::vapi_msg_id_one_eid_table_map_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_eid_table_map_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_eid_table_map_dump>(vapi_msg_id_one_eid_table_map_dump);
}

template <> inline vapi_msg_one_eid_table_map_dump* vapi_alloc<vapi_msg_one_eid_table_map_dump>(Connection &con)
{
  vapi_msg_one_eid_table_map_dump* result = vapi_alloc_one_eid_table_map_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_eid_table_map_dump>;

template class Dump<vapi_msg_one_eid_table_map_dump, vapi_msg_one_eid_table_map_details>;

using One_eid_table_map_dump = Dump<vapi_msg_one_eid_table_map_dump, vapi_msg_one_eid_table_map_details>;

template <> inline void vapi_swap_to_be<vapi_msg_one_eid_table_vni_dump>(vapi_msg_one_eid_table_vni_dump *msg)
{
  vapi_msg_one_eid_table_vni_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_eid_table_vni_dump>(vapi_msg_one_eid_table_vni_dump *msg)
{
  vapi_msg_one_eid_table_vni_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_eid_table_vni_dump>()
{
  return ::vapi_msg_id_one_eid_table_vni_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_eid_table_vni_dump>>()
{
  return ::vapi_msg_id_one_eid_table_vni_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_eid_table_vni_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_eid_table_vni_dump>(vapi_msg_id_one_eid_table_vni_dump);
}

template <> inline vapi_msg_one_eid_table_vni_dump* vapi_alloc<vapi_msg_one_eid_table_vni_dump>(Connection &con)
{
  vapi_msg_one_eid_table_vni_dump* result = vapi_alloc_one_eid_table_vni_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_eid_table_vni_dump>;

template class Dump<vapi_msg_one_eid_table_vni_dump, vapi_msg_one_eid_table_vni_details>;

using One_eid_table_vni_dump = Dump<vapi_msg_one_eid_table_vni_dump, vapi_msg_one_eid_table_vni_details>;

template <> inline void vapi_swap_to_be<vapi_msg_one_eid_table_vni_details>(vapi_msg_one_eid_table_vni_details *msg)
{
  vapi_msg_one_eid_table_vni_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_eid_table_vni_details>(vapi_msg_one_eid_table_vni_details *msg)
{
  vapi_msg_one_eid_table_vni_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_eid_table_vni_details>()
{
  return ::vapi_msg_id_one_eid_table_vni_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_eid_table_vni_details>>()
{
  return ::vapi_msg_id_one_eid_table_vni_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_eid_table_vni_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_eid_table_vni_details>(vapi_msg_id_one_eid_table_vni_details);
}

template class Msg<vapi_msg_one_eid_table_vni_details>;

using One_eid_table_vni_details = Msg<vapi_msg_one_eid_table_vni_details>;
template <> inline void vapi_swap_to_be<vapi_msg_one_map_resolver_details>(vapi_msg_one_map_resolver_details *msg)
{
  vapi_msg_one_map_resolver_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_map_resolver_details>(vapi_msg_one_map_resolver_details *msg)
{
  vapi_msg_one_map_resolver_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_map_resolver_details>()
{
  return ::vapi_msg_id_one_map_resolver_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_map_resolver_details>>()
{
  return ::vapi_msg_id_one_map_resolver_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_map_resolver_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_map_resolver_details>(vapi_msg_id_one_map_resolver_details);
}

template class Msg<vapi_msg_one_map_resolver_details>;

using One_map_resolver_details = Msg<vapi_msg_one_map_resolver_details>;
template <> inline void vapi_swap_to_be<vapi_msg_one_map_resolver_dump>(vapi_msg_one_map_resolver_dump *msg)
{
  vapi_msg_one_map_resolver_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_map_resolver_dump>(vapi_msg_one_map_resolver_dump *msg)
{
  vapi_msg_one_map_resolver_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_map_resolver_dump>()
{
  return ::vapi_msg_id_one_map_resolver_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_map_resolver_dump>>()
{
  return ::vapi_msg_id_one_map_resolver_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_map_resolver_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_map_resolver_dump>(vapi_msg_id_one_map_resolver_dump);
}

template <> inline vapi_msg_one_map_resolver_dump* vapi_alloc<vapi_msg_one_map_resolver_dump>(Connection &con)
{
  vapi_msg_one_map_resolver_dump* result = vapi_alloc_one_map_resolver_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_map_resolver_dump>;

template class Dump<vapi_msg_one_map_resolver_dump, vapi_msg_one_map_resolver_details>;

using One_map_resolver_dump = Dump<vapi_msg_one_map_resolver_dump, vapi_msg_one_map_resolver_details>;

template <> inline void vapi_swap_to_be<vapi_msg_one_map_server_details>(vapi_msg_one_map_server_details *msg)
{
  vapi_msg_one_map_server_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_map_server_details>(vapi_msg_one_map_server_details *msg)
{
  vapi_msg_one_map_server_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_map_server_details>()
{
  return ::vapi_msg_id_one_map_server_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_map_server_details>>()
{
  return ::vapi_msg_id_one_map_server_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_map_server_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_map_server_details>(vapi_msg_id_one_map_server_details);
}

template class Msg<vapi_msg_one_map_server_details>;

using One_map_server_details = Msg<vapi_msg_one_map_server_details>;
template <> inline void vapi_swap_to_be<vapi_msg_one_map_server_dump>(vapi_msg_one_map_server_dump *msg)
{
  vapi_msg_one_map_server_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_map_server_dump>(vapi_msg_one_map_server_dump *msg)
{
  vapi_msg_one_map_server_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_map_server_dump>()
{
  return ::vapi_msg_id_one_map_server_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_map_server_dump>>()
{
  return ::vapi_msg_id_one_map_server_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_map_server_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_map_server_dump>(vapi_msg_id_one_map_server_dump);
}

template <> inline vapi_msg_one_map_server_dump* vapi_alloc<vapi_msg_one_map_server_dump>(Connection &con)
{
  vapi_msg_one_map_server_dump* result = vapi_alloc_one_map_server_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_map_server_dump>;

template class Dump<vapi_msg_one_map_server_dump, vapi_msg_one_map_server_details>;

using One_map_server_dump = Dump<vapi_msg_one_map_server_dump, vapi_msg_one_map_server_details>;

template <> inline void vapi_swap_to_be<vapi_msg_show_one_status>(vapi_msg_show_one_status *msg)
{
  vapi_msg_show_one_status_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_one_status>(vapi_msg_show_one_status *msg)
{
  vapi_msg_show_one_status_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_one_status>()
{
  return ::vapi_msg_id_show_one_status; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_one_status>>()
{
  return ::vapi_msg_id_show_one_status; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_one_status()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_one_status>(vapi_msg_id_show_one_status);
}

template <> inline vapi_msg_show_one_status* vapi_alloc<vapi_msg_show_one_status>(Connection &con)
{
  vapi_msg_show_one_status* result = vapi_alloc_show_one_status(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_show_one_status>;

template class Request<vapi_msg_show_one_status, vapi_msg_show_one_status_reply>;

using Show_one_status = Request<vapi_msg_show_one_status, vapi_msg_show_one_status_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_show_one_status_reply>(vapi_msg_show_one_status_reply *msg)
{
  vapi_msg_show_one_status_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_one_status_reply>(vapi_msg_show_one_status_reply *msg)
{
  vapi_msg_show_one_status_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_one_status_reply>()
{
  return ::vapi_msg_id_show_one_status_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_one_status_reply>>()
{
  return ::vapi_msg_id_show_one_status_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_one_status_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_one_status_reply>(vapi_msg_id_show_one_status_reply);
}

template class Msg<vapi_msg_show_one_status_reply>;

using Show_one_status_reply = Msg<vapi_msg_show_one_status_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_one_get_map_request_itr_rlocs>(vapi_msg_one_get_map_request_itr_rlocs *msg)
{
  vapi_msg_one_get_map_request_itr_rlocs_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_get_map_request_itr_rlocs>(vapi_msg_one_get_map_request_itr_rlocs *msg)
{
  vapi_msg_one_get_map_request_itr_rlocs_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_get_map_request_itr_rlocs>()
{
  return ::vapi_msg_id_one_get_map_request_itr_rlocs; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_get_map_request_itr_rlocs>>()
{
  return ::vapi_msg_id_one_get_map_request_itr_rlocs; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_get_map_request_itr_rlocs()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_get_map_request_itr_rlocs>(vapi_msg_id_one_get_map_request_itr_rlocs);
}

template <> inline vapi_msg_one_get_map_request_itr_rlocs* vapi_alloc<vapi_msg_one_get_map_request_itr_rlocs>(Connection &con)
{
  vapi_msg_one_get_map_request_itr_rlocs* result = vapi_alloc_one_get_map_request_itr_rlocs(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_get_map_request_itr_rlocs>;

template class Request<vapi_msg_one_get_map_request_itr_rlocs, vapi_msg_one_get_map_request_itr_rlocs_reply>;

using One_get_map_request_itr_rlocs = Request<vapi_msg_one_get_map_request_itr_rlocs, vapi_msg_one_get_map_request_itr_rlocs_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_one_get_map_request_itr_rlocs_reply>(vapi_msg_one_get_map_request_itr_rlocs_reply *msg)
{
  vapi_msg_one_get_map_request_itr_rlocs_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_get_map_request_itr_rlocs_reply>(vapi_msg_one_get_map_request_itr_rlocs_reply *msg)
{
  vapi_msg_one_get_map_request_itr_rlocs_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_get_map_request_itr_rlocs_reply>()
{
  return ::vapi_msg_id_one_get_map_request_itr_rlocs_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_get_map_request_itr_rlocs_reply>>()
{
  return ::vapi_msg_id_one_get_map_request_itr_rlocs_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_get_map_request_itr_rlocs_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_get_map_request_itr_rlocs_reply>(vapi_msg_id_one_get_map_request_itr_rlocs_reply);
}

template class Msg<vapi_msg_one_get_map_request_itr_rlocs_reply>;

using One_get_map_request_itr_rlocs_reply = Msg<vapi_msg_one_get_map_request_itr_rlocs_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_show_one_nsh_mapping>(vapi_msg_show_one_nsh_mapping *msg)
{
  vapi_msg_show_one_nsh_mapping_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_one_nsh_mapping>(vapi_msg_show_one_nsh_mapping *msg)
{
  vapi_msg_show_one_nsh_mapping_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_one_nsh_mapping>()
{
  return ::vapi_msg_id_show_one_nsh_mapping; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_one_nsh_mapping>>()
{
  return ::vapi_msg_id_show_one_nsh_mapping; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_one_nsh_mapping()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_one_nsh_mapping>(vapi_msg_id_show_one_nsh_mapping);
}

template <> inline vapi_msg_show_one_nsh_mapping* vapi_alloc<vapi_msg_show_one_nsh_mapping>(Connection &con)
{
  vapi_msg_show_one_nsh_mapping* result = vapi_alloc_show_one_nsh_mapping(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_show_one_nsh_mapping>;

template class Request<vapi_msg_show_one_nsh_mapping, vapi_msg_show_one_nsh_mapping_reply>;

using Show_one_nsh_mapping = Request<vapi_msg_show_one_nsh_mapping, vapi_msg_show_one_nsh_mapping_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_show_one_nsh_mapping_reply>(vapi_msg_show_one_nsh_mapping_reply *msg)
{
  vapi_msg_show_one_nsh_mapping_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_one_nsh_mapping_reply>(vapi_msg_show_one_nsh_mapping_reply *msg)
{
  vapi_msg_show_one_nsh_mapping_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_one_nsh_mapping_reply>()
{
  return ::vapi_msg_id_show_one_nsh_mapping_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_one_nsh_mapping_reply>>()
{
  return ::vapi_msg_id_show_one_nsh_mapping_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_one_nsh_mapping_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_one_nsh_mapping_reply>(vapi_msg_id_show_one_nsh_mapping_reply);
}

template class Msg<vapi_msg_show_one_nsh_mapping_reply>;

using Show_one_nsh_mapping_reply = Msg<vapi_msg_show_one_nsh_mapping_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_show_one_pitr>(vapi_msg_show_one_pitr *msg)
{
  vapi_msg_show_one_pitr_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_one_pitr>(vapi_msg_show_one_pitr *msg)
{
  vapi_msg_show_one_pitr_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_one_pitr>()
{
  return ::vapi_msg_id_show_one_pitr; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_one_pitr>>()
{
  return ::vapi_msg_id_show_one_pitr; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_one_pitr()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_one_pitr>(vapi_msg_id_show_one_pitr);
}

template <> inline vapi_msg_show_one_pitr* vapi_alloc<vapi_msg_show_one_pitr>(Connection &con)
{
  vapi_msg_show_one_pitr* result = vapi_alloc_show_one_pitr(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_show_one_pitr>;

template class Request<vapi_msg_show_one_pitr, vapi_msg_show_one_pitr_reply>;

using Show_one_pitr = Request<vapi_msg_show_one_pitr, vapi_msg_show_one_pitr_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_show_one_pitr_reply>(vapi_msg_show_one_pitr_reply *msg)
{
  vapi_msg_show_one_pitr_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_one_pitr_reply>(vapi_msg_show_one_pitr_reply *msg)
{
  vapi_msg_show_one_pitr_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_one_pitr_reply>()
{
  return ::vapi_msg_id_show_one_pitr_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_one_pitr_reply>>()
{
  return ::vapi_msg_id_show_one_pitr_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_one_pitr_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_one_pitr_reply>(vapi_msg_id_show_one_pitr_reply);
}

template class Msg<vapi_msg_show_one_pitr_reply>;

using Show_one_pitr_reply = Msg<vapi_msg_show_one_pitr_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_one_stats_dump>(vapi_msg_one_stats_dump *msg)
{
  vapi_msg_one_stats_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_stats_dump>(vapi_msg_one_stats_dump *msg)
{
  vapi_msg_one_stats_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_stats_dump>()
{
  return ::vapi_msg_id_one_stats_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_stats_dump>>()
{
  return ::vapi_msg_id_one_stats_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_stats_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_stats_dump>(vapi_msg_id_one_stats_dump);
}

template <> inline vapi_msg_one_stats_dump* vapi_alloc<vapi_msg_one_stats_dump>(Connection &con)
{
  vapi_msg_one_stats_dump* result = vapi_alloc_one_stats_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_stats_dump>;

template class Dump<vapi_msg_one_stats_dump, vapi_msg_one_stats_details>;

using One_stats_dump = Dump<vapi_msg_one_stats_dump, vapi_msg_one_stats_details>;

template <> inline void vapi_swap_to_be<vapi_msg_one_stats_details>(vapi_msg_one_stats_details *msg)
{
  vapi_msg_one_stats_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_stats_details>(vapi_msg_one_stats_details *msg)
{
  vapi_msg_one_stats_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_stats_details>()
{
  return ::vapi_msg_id_one_stats_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_stats_details>>()
{
  return ::vapi_msg_id_one_stats_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_stats_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_stats_details>(vapi_msg_id_one_stats_details);
}

template class Msg<vapi_msg_one_stats_details>;

using One_stats_details = Msg<vapi_msg_one_stats_details>;
template <> inline void vapi_swap_to_be<vapi_msg_one_stats_flush>(vapi_msg_one_stats_flush *msg)
{
  vapi_msg_one_stats_flush_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_stats_flush>(vapi_msg_one_stats_flush *msg)
{
  vapi_msg_one_stats_flush_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_stats_flush>()
{
  return ::vapi_msg_id_one_stats_flush; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_stats_flush>>()
{
  return ::vapi_msg_id_one_stats_flush; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_stats_flush()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_stats_flush>(vapi_msg_id_one_stats_flush);
}

template <> inline vapi_msg_one_stats_flush* vapi_alloc<vapi_msg_one_stats_flush>(Connection &con)
{
  vapi_msg_one_stats_flush* result = vapi_alloc_one_stats_flush(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_stats_flush>;

template class Request<vapi_msg_one_stats_flush, vapi_msg_one_stats_flush_reply>;

using One_stats_flush = Request<vapi_msg_one_stats_flush, vapi_msg_one_stats_flush_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_one_stats_flush_reply>(vapi_msg_one_stats_flush_reply *msg)
{
  vapi_msg_one_stats_flush_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_stats_flush_reply>(vapi_msg_one_stats_flush_reply *msg)
{
  vapi_msg_one_stats_flush_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_stats_flush_reply>()
{
  return ::vapi_msg_id_one_stats_flush_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_stats_flush_reply>>()
{
  return ::vapi_msg_id_one_stats_flush_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_stats_flush_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_stats_flush_reply>(vapi_msg_id_one_stats_flush_reply);
}

template class Msg<vapi_msg_one_stats_flush_reply>;

using One_stats_flush_reply = Msg<vapi_msg_one_stats_flush_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_one_stats_enable_disable>(vapi_msg_one_stats_enable_disable *msg)
{
  vapi_msg_one_stats_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_stats_enable_disable>(vapi_msg_one_stats_enable_disable *msg)
{
  vapi_msg_one_stats_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_stats_enable_disable>()
{
  return ::vapi_msg_id_one_stats_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_stats_enable_disable>>()
{
  return ::vapi_msg_id_one_stats_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_stats_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_stats_enable_disable>(vapi_msg_id_one_stats_enable_disable);
}

template <> inline vapi_msg_one_stats_enable_disable* vapi_alloc<vapi_msg_one_stats_enable_disable>(Connection &con)
{
  vapi_msg_one_stats_enable_disable* result = vapi_alloc_one_stats_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_stats_enable_disable>;

template class Request<vapi_msg_one_stats_enable_disable, vapi_msg_one_stats_enable_disable_reply>;

using One_stats_enable_disable = Request<vapi_msg_one_stats_enable_disable, vapi_msg_one_stats_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_one_stats_enable_disable_reply>(vapi_msg_one_stats_enable_disable_reply *msg)
{
  vapi_msg_one_stats_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_stats_enable_disable_reply>(vapi_msg_one_stats_enable_disable_reply *msg)
{
  vapi_msg_one_stats_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_stats_enable_disable_reply>()
{
  return ::vapi_msg_id_one_stats_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_stats_enable_disable_reply>>()
{
  return ::vapi_msg_id_one_stats_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_stats_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_stats_enable_disable_reply>(vapi_msg_id_one_stats_enable_disable_reply);
}

template class Msg<vapi_msg_one_stats_enable_disable_reply>;

using One_stats_enable_disable_reply = Msg<vapi_msg_one_stats_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_show_one_stats_enable_disable>(vapi_msg_show_one_stats_enable_disable *msg)
{
  vapi_msg_show_one_stats_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_one_stats_enable_disable>(vapi_msg_show_one_stats_enable_disable *msg)
{
  vapi_msg_show_one_stats_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_one_stats_enable_disable>()
{
  return ::vapi_msg_id_show_one_stats_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_one_stats_enable_disable>>()
{
  return ::vapi_msg_id_show_one_stats_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_one_stats_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_one_stats_enable_disable>(vapi_msg_id_show_one_stats_enable_disable);
}

template <> inline vapi_msg_show_one_stats_enable_disable* vapi_alloc<vapi_msg_show_one_stats_enable_disable>(Connection &con)
{
  vapi_msg_show_one_stats_enable_disable* result = vapi_alloc_show_one_stats_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_show_one_stats_enable_disable>;

template class Request<vapi_msg_show_one_stats_enable_disable, vapi_msg_show_one_stats_enable_disable_reply>;

using Show_one_stats_enable_disable = Request<vapi_msg_show_one_stats_enable_disable, vapi_msg_show_one_stats_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_show_one_stats_enable_disable_reply>(vapi_msg_show_one_stats_enable_disable_reply *msg)
{
  vapi_msg_show_one_stats_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_one_stats_enable_disable_reply>(vapi_msg_show_one_stats_enable_disable_reply *msg)
{
  vapi_msg_show_one_stats_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_one_stats_enable_disable_reply>()
{
  return ::vapi_msg_id_show_one_stats_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_one_stats_enable_disable_reply>>()
{
  return ::vapi_msg_id_show_one_stats_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_one_stats_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_one_stats_enable_disable_reply>(vapi_msg_id_show_one_stats_enable_disable_reply);
}

template class Msg<vapi_msg_show_one_stats_enable_disable_reply>;

using Show_one_stats_enable_disable_reply = Msg<vapi_msg_show_one_stats_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_one_map_register_fallback_threshold>(vapi_msg_one_map_register_fallback_threshold *msg)
{
  vapi_msg_one_map_register_fallback_threshold_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_map_register_fallback_threshold>(vapi_msg_one_map_register_fallback_threshold *msg)
{
  vapi_msg_one_map_register_fallback_threshold_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_map_register_fallback_threshold>()
{
  return ::vapi_msg_id_one_map_register_fallback_threshold; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_map_register_fallback_threshold>>()
{
  return ::vapi_msg_id_one_map_register_fallback_threshold; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_map_register_fallback_threshold()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_map_register_fallback_threshold>(vapi_msg_id_one_map_register_fallback_threshold);
}

template <> inline vapi_msg_one_map_register_fallback_threshold* vapi_alloc<vapi_msg_one_map_register_fallback_threshold>(Connection &con)
{
  vapi_msg_one_map_register_fallback_threshold* result = vapi_alloc_one_map_register_fallback_threshold(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_map_register_fallback_threshold>;

template class Request<vapi_msg_one_map_register_fallback_threshold, vapi_msg_one_map_register_fallback_threshold_reply>;

using One_map_register_fallback_threshold = Request<vapi_msg_one_map_register_fallback_threshold, vapi_msg_one_map_register_fallback_threshold_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_one_map_register_fallback_threshold_reply>(vapi_msg_one_map_register_fallback_threshold_reply *msg)
{
  vapi_msg_one_map_register_fallback_threshold_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_map_register_fallback_threshold_reply>(vapi_msg_one_map_register_fallback_threshold_reply *msg)
{
  vapi_msg_one_map_register_fallback_threshold_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_map_register_fallback_threshold_reply>()
{
  return ::vapi_msg_id_one_map_register_fallback_threshold_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_map_register_fallback_threshold_reply>>()
{
  return ::vapi_msg_id_one_map_register_fallback_threshold_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_map_register_fallback_threshold_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_map_register_fallback_threshold_reply>(vapi_msg_id_one_map_register_fallback_threshold_reply);
}

template class Msg<vapi_msg_one_map_register_fallback_threshold_reply>;

using One_map_register_fallback_threshold_reply = Msg<vapi_msg_one_map_register_fallback_threshold_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_show_one_map_register_fallback_threshold>(vapi_msg_show_one_map_register_fallback_threshold *msg)
{
  vapi_msg_show_one_map_register_fallback_threshold_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_one_map_register_fallback_threshold>(vapi_msg_show_one_map_register_fallback_threshold *msg)
{
  vapi_msg_show_one_map_register_fallback_threshold_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_one_map_register_fallback_threshold>()
{
  return ::vapi_msg_id_show_one_map_register_fallback_threshold; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_one_map_register_fallback_threshold>>()
{
  return ::vapi_msg_id_show_one_map_register_fallback_threshold; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_one_map_register_fallback_threshold()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_one_map_register_fallback_threshold>(vapi_msg_id_show_one_map_register_fallback_threshold);
}

template <> inline vapi_msg_show_one_map_register_fallback_threshold* vapi_alloc<vapi_msg_show_one_map_register_fallback_threshold>(Connection &con)
{
  vapi_msg_show_one_map_register_fallback_threshold* result = vapi_alloc_show_one_map_register_fallback_threshold(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_show_one_map_register_fallback_threshold>;

template class Request<vapi_msg_show_one_map_register_fallback_threshold, vapi_msg_show_one_map_register_fallback_threshold_reply>;

using Show_one_map_register_fallback_threshold = Request<vapi_msg_show_one_map_register_fallback_threshold, vapi_msg_show_one_map_register_fallback_threshold_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_show_one_map_register_fallback_threshold_reply>(vapi_msg_show_one_map_register_fallback_threshold_reply *msg)
{
  vapi_msg_show_one_map_register_fallback_threshold_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_one_map_register_fallback_threshold_reply>(vapi_msg_show_one_map_register_fallback_threshold_reply *msg)
{
  vapi_msg_show_one_map_register_fallback_threshold_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_one_map_register_fallback_threshold_reply>()
{
  return ::vapi_msg_id_show_one_map_register_fallback_threshold_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_one_map_register_fallback_threshold_reply>>()
{
  return ::vapi_msg_id_show_one_map_register_fallback_threshold_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_one_map_register_fallback_threshold_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_one_map_register_fallback_threshold_reply>(vapi_msg_id_show_one_map_register_fallback_threshold_reply);
}

template class Msg<vapi_msg_show_one_map_register_fallback_threshold_reply>;

using Show_one_map_register_fallback_threshold_reply = Msg<vapi_msg_show_one_map_register_fallback_threshold_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_one_enable_disable_xtr_mode>(vapi_msg_one_enable_disable_xtr_mode *msg)
{
  vapi_msg_one_enable_disable_xtr_mode_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_enable_disable_xtr_mode>(vapi_msg_one_enable_disable_xtr_mode *msg)
{
  vapi_msg_one_enable_disable_xtr_mode_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_enable_disable_xtr_mode>()
{
  return ::vapi_msg_id_one_enable_disable_xtr_mode; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_enable_disable_xtr_mode>>()
{
  return ::vapi_msg_id_one_enable_disable_xtr_mode; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_enable_disable_xtr_mode()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_enable_disable_xtr_mode>(vapi_msg_id_one_enable_disable_xtr_mode);
}

template <> inline vapi_msg_one_enable_disable_xtr_mode* vapi_alloc<vapi_msg_one_enable_disable_xtr_mode>(Connection &con)
{
  vapi_msg_one_enable_disable_xtr_mode* result = vapi_alloc_one_enable_disable_xtr_mode(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_enable_disable_xtr_mode>;

template class Request<vapi_msg_one_enable_disable_xtr_mode, vapi_msg_one_enable_disable_xtr_mode_reply>;

using One_enable_disable_xtr_mode = Request<vapi_msg_one_enable_disable_xtr_mode, vapi_msg_one_enable_disable_xtr_mode_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_one_enable_disable_xtr_mode_reply>(vapi_msg_one_enable_disable_xtr_mode_reply *msg)
{
  vapi_msg_one_enable_disable_xtr_mode_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_enable_disable_xtr_mode_reply>(vapi_msg_one_enable_disable_xtr_mode_reply *msg)
{
  vapi_msg_one_enable_disable_xtr_mode_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_enable_disable_xtr_mode_reply>()
{
  return ::vapi_msg_id_one_enable_disable_xtr_mode_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_enable_disable_xtr_mode_reply>>()
{
  return ::vapi_msg_id_one_enable_disable_xtr_mode_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_enable_disable_xtr_mode_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_enable_disable_xtr_mode_reply>(vapi_msg_id_one_enable_disable_xtr_mode_reply);
}

template class Msg<vapi_msg_one_enable_disable_xtr_mode_reply>;

using One_enable_disable_xtr_mode_reply = Msg<vapi_msg_one_enable_disable_xtr_mode_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_one_show_xtr_mode>(vapi_msg_one_show_xtr_mode *msg)
{
  vapi_msg_one_show_xtr_mode_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_show_xtr_mode>(vapi_msg_one_show_xtr_mode *msg)
{
  vapi_msg_one_show_xtr_mode_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_show_xtr_mode>()
{
  return ::vapi_msg_id_one_show_xtr_mode; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_show_xtr_mode>>()
{
  return ::vapi_msg_id_one_show_xtr_mode; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_show_xtr_mode()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_show_xtr_mode>(vapi_msg_id_one_show_xtr_mode);
}

template <> inline vapi_msg_one_show_xtr_mode* vapi_alloc<vapi_msg_one_show_xtr_mode>(Connection &con)
{
  vapi_msg_one_show_xtr_mode* result = vapi_alloc_one_show_xtr_mode(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_show_xtr_mode>;

template class Request<vapi_msg_one_show_xtr_mode, vapi_msg_one_show_xtr_mode_reply>;

using One_show_xtr_mode = Request<vapi_msg_one_show_xtr_mode, vapi_msg_one_show_xtr_mode_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_one_show_xtr_mode_reply>(vapi_msg_one_show_xtr_mode_reply *msg)
{
  vapi_msg_one_show_xtr_mode_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_show_xtr_mode_reply>(vapi_msg_one_show_xtr_mode_reply *msg)
{
  vapi_msg_one_show_xtr_mode_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_show_xtr_mode_reply>()
{
  return ::vapi_msg_id_one_show_xtr_mode_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_show_xtr_mode_reply>>()
{
  return ::vapi_msg_id_one_show_xtr_mode_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_show_xtr_mode_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_show_xtr_mode_reply>(vapi_msg_id_one_show_xtr_mode_reply);
}

template class Msg<vapi_msg_one_show_xtr_mode_reply>;

using One_show_xtr_mode_reply = Msg<vapi_msg_one_show_xtr_mode_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_one_enable_disable_petr_mode>(vapi_msg_one_enable_disable_petr_mode *msg)
{
  vapi_msg_one_enable_disable_petr_mode_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_enable_disable_petr_mode>(vapi_msg_one_enable_disable_petr_mode *msg)
{
  vapi_msg_one_enable_disable_petr_mode_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_enable_disable_petr_mode>()
{
  return ::vapi_msg_id_one_enable_disable_petr_mode; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_enable_disable_petr_mode>>()
{
  return ::vapi_msg_id_one_enable_disable_petr_mode; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_enable_disable_petr_mode()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_enable_disable_petr_mode>(vapi_msg_id_one_enable_disable_petr_mode);
}

template <> inline vapi_msg_one_enable_disable_petr_mode* vapi_alloc<vapi_msg_one_enable_disable_petr_mode>(Connection &con)
{
  vapi_msg_one_enable_disable_petr_mode* result = vapi_alloc_one_enable_disable_petr_mode(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_enable_disable_petr_mode>;

template class Request<vapi_msg_one_enable_disable_petr_mode, vapi_msg_one_enable_disable_petr_mode_reply>;

using One_enable_disable_petr_mode = Request<vapi_msg_one_enable_disable_petr_mode, vapi_msg_one_enable_disable_petr_mode_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_one_enable_disable_petr_mode_reply>(vapi_msg_one_enable_disable_petr_mode_reply *msg)
{
  vapi_msg_one_enable_disable_petr_mode_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_enable_disable_petr_mode_reply>(vapi_msg_one_enable_disable_petr_mode_reply *msg)
{
  vapi_msg_one_enable_disable_petr_mode_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_enable_disable_petr_mode_reply>()
{
  return ::vapi_msg_id_one_enable_disable_petr_mode_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_enable_disable_petr_mode_reply>>()
{
  return ::vapi_msg_id_one_enable_disable_petr_mode_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_enable_disable_petr_mode_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_enable_disable_petr_mode_reply>(vapi_msg_id_one_enable_disable_petr_mode_reply);
}

template class Msg<vapi_msg_one_enable_disable_petr_mode_reply>;

using One_enable_disable_petr_mode_reply = Msg<vapi_msg_one_enable_disable_petr_mode_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_one_show_petr_mode>(vapi_msg_one_show_petr_mode *msg)
{
  vapi_msg_one_show_petr_mode_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_show_petr_mode>(vapi_msg_one_show_petr_mode *msg)
{
  vapi_msg_one_show_petr_mode_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_show_petr_mode>()
{
  return ::vapi_msg_id_one_show_petr_mode; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_show_petr_mode>>()
{
  return ::vapi_msg_id_one_show_petr_mode; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_show_petr_mode()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_show_petr_mode>(vapi_msg_id_one_show_petr_mode);
}

template <> inline vapi_msg_one_show_petr_mode* vapi_alloc<vapi_msg_one_show_petr_mode>(Connection &con)
{
  vapi_msg_one_show_petr_mode* result = vapi_alloc_one_show_petr_mode(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_show_petr_mode>;

template class Request<vapi_msg_one_show_petr_mode, vapi_msg_one_show_petr_mode_reply>;

using One_show_petr_mode = Request<vapi_msg_one_show_petr_mode, vapi_msg_one_show_petr_mode_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_one_show_petr_mode_reply>(vapi_msg_one_show_petr_mode_reply *msg)
{
  vapi_msg_one_show_petr_mode_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_show_petr_mode_reply>(vapi_msg_one_show_petr_mode_reply *msg)
{
  vapi_msg_one_show_petr_mode_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_show_petr_mode_reply>()
{
  return ::vapi_msg_id_one_show_petr_mode_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_show_petr_mode_reply>>()
{
  return ::vapi_msg_id_one_show_petr_mode_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_show_petr_mode_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_show_petr_mode_reply>(vapi_msg_id_one_show_petr_mode_reply);
}

template class Msg<vapi_msg_one_show_petr_mode_reply>;

using One_show_petr_mode_reply = Msg<vapi_msg_one_show_petr_mode_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_one_enable_disable_pitr_mode>(vapi_msg_one_enable_disable_pitr_mode *msg)
{
  vapi_msg_one_enable_disable_pitr_mode_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_enable_disable_pitr_mode>(vapi_msg_one_enable_disable_pitr_mode *msg)
{
  vapi_msg_one_enable_disable_pitr_mode_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_enable_disable_pitr_mode>()
{
  return ::vapi_msg_id_one_enable_disable_pitr_mode; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_enable_disable_pitr_mode>>()
{
  return ::vapi_msg_id_one_enable_disable_pitr_mode; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_enable_disable_pitr_mode()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_enable_disable_pitr_mode>(vapi_msg_id_one_enable_disable_pitr_mode);
}

template <> inline vapi_msg_one_enable_disable_pitr_mode* vapi_alloc<vapi_msg_one_enable_disable_pitr_mode>(Connection &con)
{
  vapi_msg_one_enable_disable_pitr_mode* result = vapi_alloc_one_enable_disable_pitr_mode(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_enable_disable_pitr_mode>;

template class Request<vapi_msg_one_enable_disable_pitr_mode, vapi_msg_one_enable_disable_pitr_mode_reply>;

using One_enable_disable_pitr_mode = Request<vapi_msg_one_enable_disable_pitr_mode, vapi_msg_one_enable_disable_pitr_mode_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_one_enable_disable_pitr_mode_reply>(vapi_msg_one_enable_disable_pitr_mode_reply *msg)
{
  vapi_msg_one_enable_disable_pitr_mode_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_enable_disable_pitr_mode_reply>(vapi_msg_one_enable_disable_pitr_mode_reply *msg)
{
  vapi_msg_one_enable_disable_pitr_mode_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_enable_disable_pitr_mode_reply>()
{
  return ::vapi_msg_id_one_enable_disable_pitr_mode_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_enable_disable_pitr_mode_reply>>()
{
  return ::vapi_msg_id_one_enable_disable_pitr_mode_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_enable_disable_pitr_mode_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_enable_disable_pitr_mode_reply>(vapi_msg_id_one_enable_disable_pitr_mode_reply);
}

template class Msg<vapi_msg_one_enable_disable_pitr_mode_reply>;

using One_enable_disable_pitr_mode_reply = Msg<vapi_msg_one_enable_disable_pitr_mode_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_one_show_pitr_mode>(vapi_msg_one_show_pitr_mode *msg)
{
  vapi_msg_one_show_pitr_mode_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_show_pitr_mode>(vapi_msg_one_show_pitr_mode *msg)
{
  vapi_msg_one_show_pitr_mode_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_show_pitr_mode>()
{
  return ::vapi_msg_id_one_show_pitr_mode; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_show_pitr_mode>>()
{
  return ::vapi_msg_id_one_show_pitr_mode; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_show_pitr_mode()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_show_pitr_mode>(vapi_msg_id_one_show_pitr_mode);
}

template <> inline vapi_msg_one_show_pitr_mode* vapi_alloc<vapi_msg_one_show_pitr_mode>(Connection &con)
{
  vapi_msg_one_show_pitr_mode* result = vapi_alloc_one_show_pitr_mode(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_one_show_pitr_mode>;

template class Request<vapi_msg_one_show_pitr_mode, vapi_msg_one_show_pitr_mode_reply>;

using One_show_pitr_mode = Request<vapi_msg_one_show_pitr_mode, vapi_msg_one_show_pitr_mode_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_one_show_pitr_mode_reply>(vapi_msg_one_show_pitr_mode_reply *msg)
{
  vapi_msg_one_show_pitr_mode_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_one_show_pitr_mode_reply>(vapi_msg_one_show_pitr_mode_reply *msg)
{
  vapi_msg_one_show_pitr_mode_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_one_show_pitr_mode_reply>()
{
  return ::vapi_msg_id_one_show_pitr_mode_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_one_show_pitr_mode_reply>>()
{
  return ::vapi_msg_id_one_show_pitr_mode_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_one_show_pitr_mode_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_one_show_pitr_mode_reply>(vapi_msg_id_one_show_pitr_mode_reply);
}

template class Msg<vapi_msg_one_show_pitr_mode_reply>;

using One_show_pitr_mode_reply = Msg<vapi_msg_one_show_pitr_mode_reply>;
}
#endif
