#ifndef __included_hpp_lisp_api_json
#define __included_hpp_lisp_api_json

#include <vapi/vapi.hpp>
#include <vapi/lisp.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_lisp_add_del_locator_set>(vapi_msg_lisp_add_del_locator_set *msg)
{
  vapi_msg_lisp_add_del_locator_set_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_add_del_locator_set>(vapi_msg_lisp_add_del_locator_set *msg)
{
  vapi_msg_lisp_add_del_locator_set_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_add_del_locator_set>()
{
  return ::vapi_msg_id_lisp_add_del_locator_set; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_add_del_locator_set>>()
{
  return ::vapi_msg_id_lisp_add_del_locator_set; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_add_del_locator_set()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_add_del_locator_set>(vapi_msg_id_lisp_add_del_locator_set);
}

template <> inline vapi_msg_lisp_add_del_locator_set* vapi_alloc<vapi_msg_lisp_add_del_locator_set, size_t>(Connection &con, size_t _locators_array_size)
{
  vapi_msg_lisp_add_del_locator_set* result = vapi_alloc_lisp_add_del_locator_set(con.vapi_ctx, _locators_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lisp_add_del_locator_set>;

template class Request<vapi_msg_lisp_add_del_locator_set, vapi_msg_lisp_add_del_locator_set_reply, size_t>;

using Lisp_add_del_locator_set = Request<vapi_msg_lisp_add_del_locator_set, vapi_msg_lisp_add_del_locator_set_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_lisp_add_del_locator_set_reply>(vapi_msg_lisp_add_del_locator_set_reply *msg)
{
  vapi_msg_lisp_add_del_locator_set_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_add_del_locator_set_reply>(vapi_msg_lisp_add_del_locator_set_reply *msg)
{
  vapi_msg_lisp_add_del_locator_set_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_add_del_locator_set_reply>()
{
  return ::vapi_msg_id_lisp_add_del_locator_set_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_add_del_locator_set_reply>>()
{
  return ::vapi_msg_id_lisp_add_del_locator_set_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_add_del_locator_set_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_add_del_locator_set_reply>(vapi_msg_id_lisp_add_del_locator_set_reply);
}

template class Msg<vapi_msg_lisp_add_del_locator_set_reply>;

using Lisp_add_del_locator_set_reply = Msg<vapi_msg_lisp_add_del_locator_set_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_lisp_add_del_locator>(vapi_msg_lisp_add_del_locator *msg)
{
  vapi_msg_lisp_add_del_locator_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_add_del_locator>(vapi_msg_lisp_add_del_locator *msg)
{
  vapi_msg_lisp_add_del_locator_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_add_del_locator>()
{
  return ::vapi_msg_id_lisp_add_del_locator; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_add_del_locator>>()
{
  return ::vapi_msg_id_lisp_add_del_locator; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_add_del_locator()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_add_del_locator>(vapi_msg_id_lisp_add_del_locator);
}

template <> inline vapi_msg_lisp_add_del_locator* vapi_alloc<vapi_msg_lisp_add_del_locator>(Connection &con)
{
  vapi_msg_lisp_add_del_locator* result = vapi_alloc_lisp_add_del_locator(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lisp_add_del_locator>;

template class Request<vapi_msg_lisp_add_del_locator, vapi_msg_lisp_add_del_locator_reply>;

using Lisp_add_del_locator = Request<vapi_msg_lisp_add_del_locator, vapi_msg_lisp_add_del_locator_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_lisp_add_del_locator_reply>(vapi_msg_lisp_add_del_locator_reply *msg)
{
  vapi_msg_lisp_add_del_locator_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_add_del_locator_reply>(vapi_msg_lisp_add_del_locator_reply *msg)
{
  vapi_msg_lisp_add_del_locator_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_add_del_locator_reply>()
{
  return ::vapi_msg_id_lisp_add_del_locator_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_add_del_locator_reply>>()
{
  return ::vapi_msg_id_lisp_add_del_locator_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_add_del_locator_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_add_del_locator_reply>(vapi_msg_id_lisp_add_del_locator_reply);
}

template class Msg<vapi_msg_lisp_add_del_locator_reply>;

using Lisp_add_del_locator_reply = Msg<vapi_msg_lisp_add_del_locator_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_lisp_add_del_local_eid>(vapi_msg_lisp_add_del_local_eid *msg)
{
  vapi_msg_lisp_add_del_local_eid_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_add_del_local_eid>(vapi_msg_lisp_add_del_local_eid *msg)
{
  vapi_msg_lisp_add_del_local_eid_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_add_del_local_eid>()
{
  return ::vapi_msg_id_lisp_add_del_local_eid; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_add_del_local_eid>>()
{
  return ::vapi_msg_id_lisp_add_del_local_eid; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_add_del_local_eid()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_add_del_local_eid>(vapi_msg_id_lisp_add_del_local_eid);
}

template <> inline vapi_msg_lisp_add_del_local_eid* vapi_alloc<vapi_msg_lisp_add_del_local_eid>(Connection &con)
{
  vapi_msg_lisp_add_del_local_eid* result = vapi_alloc_lisp_add_del_local_eid(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lisp_add_del_local_eid>;

template class Request<vapi_msg_lisp_add_del_local_eid, vapi_msg_lisp_add_del_local_eid_reply>;

using Lisp_add_del_local_eid = Request<vapi_msg_lisp_add_del_local_eid, vapi_msg_lisp_add_del_local_eid_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_lisp_add_del_local_eid_reply>(vapi_msg_lisp_add_del_local_eid_reply *msg)
{
  vapi_msg_lisp_add_del_local_eid_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_add_del_local_eid_reply>(vapi_msg_lisp_add_del_local_eid_reply *msg)
{
  vapi_msg_lisp_add_del_local_eid_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_add_del_local_eid_reply>()
{
  return ::vapi_msg_id_lisp_add_del_local_eid_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_add_del_local_eid_reply>>()
{
  return ::vapi_msg_id_lisp_add_del_local_eid_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_add_del_local_eid_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_add_del_local_eid_reply>(vapi_msg_id_lisp_add_del_local_eid_reply);
}

template class Msg<vapi_msg_lisp_add_del_local_eid_reply>;

using Lisp_add_del_local_eid_reply = Msg<vapi_msg_lisp_add_del_local_eid_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_lisp_add_del_map_server>(vapi_msg_lisp_add_del_map_server *msg)
{
  vapi_msg_lisp_add_del_map_server_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_add_del_map_server>(vapi_msg_lisp_add_del_map_server *msg)
{
  vapi_msg_lisp_add_del_map_server_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_add_del_map_server>()
{
  return ::vapi_msg_id_lisp_add_del_map_server; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_add_del_map_server>>()
{
  return ::vapi_msg_id_lisp_add_del_map_server; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_add_del_map_server()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_add_del_map_server>(vapi_msg_id_lisp_add_del_map_server);
}

template <> inline vapi_msg_lisp_add_del_map_server* vapi_alloc<vapi_msg_lisp_add_del_map_server>(Connection &con)
{
  vapi_msg_lisp_add_del_map_server* result = vapi_alloc_lisp_add_del_map_server(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lisp_add_del_map_server>;

template class Request<vapi_msg_lisp_add_del_map_server, vapi_msg_lisp_add_del_map_server_reply>;

using Lisp_add_del_map_server = Request<vapi_msg_lisp_add_del_map_server, vapi_msg_lisp_add_del_map_server_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_lisp_add_del_map_server_reply>(vapi_msg_lisp_add_del_map_server_reply *msg)
{
  vapi_msg_lisp_add_del_map_server_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_add_del_map_server_reply>(vapi_msg_lisp_add_del_map_server_reply *msg)
{
  vapi_msg_lisp_add_del_map_server_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_add_del_map_server_reply>()
{
  return ::vapi_msg_id_lisp_add_del_map_server_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_add_del_map_server_reply>>()
{
  return ::vapi_msg_id_lisp_add_del_map_server_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_add_del_map_server_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_add_del_map_server_reply>(vapi_msg_id_lisp_add_del_map_server_reply);
}

template class Msg<vapi_msg_lisp_add_del_map_server_reply>;

using Lisp_add_del_map_server_reply = Msg<vapi_msg_lisp_add_del_map_server_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_lisp_add_del_map_resolver>(vapi_msg_lisp_add_del_map_resolver *msg)
{
  vapi_msg_lisp_add_del_map_resolver_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_add_del_map_resolver>(vapi_msg_lisp_add_del_map_resolver *msg)
{
  vapi_msg_lisp_add_del_map_resolver_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_add_del_map_resolver>()
{
  return ::vapi_msg_id_lisp_add_del_map_resolver; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_add_del_map_resolver>>()
{
  return ::vapi_msg_id_lisp_add_del_map_resolver; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_add_del_map_resolver()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_add_del_map_resolver>(vapi_msg_id_lisp_add_del_map_resolver);
}

template <> inline vapi_msg_lisp_add_del_map_resolver* vapi_alloc<vapi_msg_lisp_add_del_map_resolver>(Connection &con)
{
  vapi_msg_lisp_add_del_map_resolver* result = vapi_alloc_lisp_add_del_map_resolver(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lisp_add_del_map_resolver>;

template class Request<vapi_msg_lisp_add_del_map_resolver, vapi_msg_lisp_add_del_map_resolver_reply>;

using Lisp_add_del_map_resolver = Request<vapi_msg_lisp_add_del_map_resolver, vapi_msg_lisp_add_del_map_resolver_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_lisp_add_del_map_resolver_reply>(vapi_msg_lisp_add_del_map_resolver_reply *msg)
{
  vapi_msg_lisp_add_del_map_resolver_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_add_del_map_resolver_reply>(vapi_msg_lisp_add_del_map_resolver_reply *msg)
{
  vapi_msg_lisp_add_del_map_resolver_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_add_del_map_resolver_reply>()
{
  return ::vapi_msg_id_lisp_add_del_map_resolver_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_add_del_map_resolver_reply>>()
{
  return ::vapi_msg_id_lisp_add_del_map_resolver_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_add_del_map_resolver_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_add_del_map_resolver_reply>(vapi_msg_id_lisp_add_del_map_resolver_reply);
}

template class Msg<vapi_msg_lisp_add_del_map_resolver_reply>;

using Lisp_add_del_map_resolver_reply = Msg<vapi_msg_lisp_add_del_map_resolver_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_lisp_enable_disable>(vapi_msg_lisp_enable_disable *msg)
{
  vapi_msg_lisp_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_enable_disable>(vapi_msg_lisp_enable_disable *msg)
{
  vapi_msg_lisp_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_enable_disable>()
{
  return ::vapi_msg_id_lisp_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_enable_disable>>()
{
  return ::vapi_msg_id_lisp_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_enable_disable>(vapi_msg_id_lisp_enable_disable);
}

template <> inline vapi_msg_lisp_enable_disable* vapi_alloc<vapi_msg_lisp_enable_disable>(Connection &con)
{
  vapi_msg_lisp_enable_disable* result = vapi_alloc_lisp_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lisp_enable_disable>;

template class Request<vapi_msg_lisp_enable_disable, vapi_msg_lisp_enable_disable_reply>;

using Lisp_enable_disable = Request<vapi_msg_lisp_enable_disable, vapi_msg_lisp_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_lisp_enable_disable_reply>(vapi_msg_lisp_enable_disable_reply *msg)
{
  vapi_msg_lisp_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_enable_disable_reply>(vapi_msg_lisp_enable_disable_reply *msg)
{
  vapi_msg_lisp_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_enable_disable_reply>()
{
  return ::vapi_msg_id_lisp_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_enable_disable_reply>>()
{
  return ::vapi_msg_id_lisp_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_enable_disable_reply>(vapi_msg_id_lisp_enable_disable_reply);
}

template class Msg<vapi_msg_lisp_enable_disable_reply>;

using Lisp_enable_disable_reply = Msg<vapi_msg_lisp_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_lisp_pitr_set_locator_set>(vapi_msg_lisp_pitr_set_locator_set *msg)
{
  vapi_msg_lisp_pitr_set_locator_set_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_pitr_set_locator_set>(vapi_msg_lisp_pitr_set_locator_set *msg)
{
  vapi_msg_lisp_pitr_set_locator_set_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_pitr_set_locator_set>()
{
  return ::vapi_msg_id_lisp_pitr_set_locator_set; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_pitr_set_locator_set>>()
{
  return ::vapi_msg_id_lisp_pitr_set_locator_set; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_pitr_set_locator_set()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_pitr_set_locator_set>(vapi_msg_id_lisp_pitr_set_locator_set);
}

template <> inline vapi_msg_lisp_pitr_set_locator_set* vapi_alloc<vapi_msg_lisp_pitr_set_locator_set>(Connection &con)
{
  vapi_msg_lisp_pitr_set_locator_set* result = vapi_alloc_lisp_pitr_set_locator_set(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lisp_pitr_set_locator_set>;

template class Request<vapi_msg_lisp_pitr_set_locator_set, vapi_msg_lisp_pitr_set_locator_set_reply>;

using Lisp_pitr_set_locator_set = Request<vapi_msg_lisp_pitr_set_locator_set, vapi_msg_lisp_pitr_set_locator_set_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_lisp_pitr_set_locator_set_reply>(vapi_msg_lisp_pitr_set_locator_set_reply *msg)
{
  vapi_msg_lisp_pitr_set_locator_set_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_pitr_set_locator_set_reply>(vapi_msg_lisp_pitr_set_locator_set_reply *msg)
{
  vapi_msg_lisp_pitr_set_locator_set_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_pitr_set_locator_set_reply>()
{
  return ::vapi_msg_id_lisp_pitr_set_locator_set_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_pitr_set_locator_set_reply>>()
{
  return ::vapi_msg_id_lisp_pitr_set_locator_set_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_pitr_set_locator_set_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_pitr_set_locator_set_reply>(vapi_msg_id_lisp_pitr_set_locator_set_reply);
}

template class Msg<vapi_msg_lisp_pitr_set_locator_set_reply>;

using Lisp_pitr_set_locator_set_reply = Msg<vapi_msg_lisp_pitr_set_locator_set_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_lisp_use_petr>(vapi_msg_lisp_use_petr *msg)
{
  vapi_msg_lisp_use_petr_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_use_petr>(vapi_msg_lisp_use_petr *msg)
{
  vapi_msg_lisp_use_petr_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_use_petr>()
{
  return ::vapi_msg_id_lisp_use_petr; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_use_petr>>()
{
  return ::vapi_msg_id_lisp_use_petr; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_use_petr()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_use_petr>(vapi_msg_id_lisp_use_petr);
}

template <> inline vapi_msg_lisp_use_petr* vapi_alloc<vapi_msg_lisp_use_petr>(Connection &con)
{
  vapi_msg_lisp_use_petr* result = vapi_alloc_lisp_use_petr(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lisp_use_petr>;

template class Request<vapi_msg_lisp_use_petr, vapi_msg_lisp_use_petr_reply>;

using Lisp_use_petr = Request<vapi_msg_lisp_use_petr, vapi_msg_lisp_use_petr_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_lisp_use_petr_reply>(vapi_msg_lisp_use_petr_reply *msg)
{
  vapi_msg_lisp_use_petr_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_use_petr_reply>(vapi_msg_lisp_use_petr_reply *msg)
{
  vapi_msg_lisp_use_petr_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_use_petr_reply>()
{
  return ::vapi_msg_id_lisp_use_petr_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_use_petr_reply>>()
{
  return ::vapi_msg_id_lisp_use_petr_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_use_petr_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_use_petr_reply>(vapi_msg_id_lisp_use_petr_reply);
}

template class Msg<vapi_msg_lisp_use_petr_reply>;

using Lisp_use_petr_reply = Msg<vapi_msg_lisp_use_petr_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_show_lisp_use_petr>(vapi_msg_show_lisp_use_petr *msg)
{
  vapi_msg_show_lisp_use_petr_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_lisp_use_petr>(vapi_msg_show_lisp_use_petr *msg)
{
  vapi_msg_show_lisp_use_petr_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_lisp_use_petr>()
{
  return ::vapi_msg_id_show_lisp_use_petr; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_lisp_use_petr>>()
{
  return ::vapi_msg_id_show_lisp_use_petr; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_lisp_use_petr()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_lisp_use_petr>(vapi_msg_id_show_lisp_use_petr);
}

template <> inline vapi_msg_show_lisp_use_petr* vapi_alloc<vapi_msg_show_lisp_use_petr>(Connection &con)
{
  vapi_msg_show_lisp_use_petr* result = vapi_alloc_show_lisp_use_petr(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_show_lisp_use_petr>;

template class Request<vapi_msg_show_lisp_use_petr, vapi_msg_show_lisp_use_petr_reply>;

using Show_lisp_use_petr = Request<vapi_msg_show_lisp_use_petr, vapi_msg_show_lisp_use_petr_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_show_lisp_use_petr_reply>(vapi_msg_show_lisp_use_petr_reply *msg)
{
  vapi_msg_show_lisp_use_petr_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_lisp_use_petr_reply>(vapi_msg_show_lisp_use_petr_reply *msg)
{
  vapi_msg_show_lisp_use_petr_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_lisp_use_petr_reply>()
{
  return ::vapi_msg_id_show_lisp_use_petr_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_lisp_use_petr_reply>>()
{
  return ::vapi_msg_id_show_lisp_use_petr_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_lisp_use_petr_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_lisp_use_petr_reply>(vapi_msg_id_show_lisp_use_petr_reply);
}

template class Msg<vapi_msg_show_lisp_use_petr_reply>;

using Show_lisp_use_petr_reply = Msg<vapi_msg_show_lisp_use_petr_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_show_lisp_rloc_probe_state>(vapi_msg_show_lisp_rloc_probe_state *msg)
{
  vapi_msg_show_lisp_rloc_probe_state_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_lisp_rloc_probe_state>(vapi_msg_show_lisp_rloc_probe_state *msg)
{
  vapi_msg_show_lisp_rloc_probe_state_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_lisp_rloc_probe_state>()
{
  return ::vapi_msg_id_show_lisp_rloc_probe_state; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_lisp_rloc_probe_state>>()
{
  return ::vapi_msg_id_show_lisp_rloc_probe_state; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_lisp_rloc_probe_state()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_lisp_rloc_probe_state>(vapi_msg_id_show_lisp_rloc_probe_state);
}

template <> inline vapi_msg_show_lisp_rloc_probe_state* vapi_alloc<vapi_msg_show_lisp_rloc_probe_state>(Connection &con)
{
  vapi_msg_show_lisp_rloc_probe_state* result = vapi_alloc_show_lisp_rloc_probe_state(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_show_lisp_rloc_probe_state>;

template class Request<vapi_msg_show_lisp_rloc_probe_state, vapi_msg_show_lisp_rloc_probe_state_reply>;

using Show_lisp_rloc_probe_state = Request<vapi_msg_show_lisp_rloc_probe_state, vapi_msg_show_lisp_rloc_probe_state_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_show_lisp_rloc_probe_state_reply>(vapi_msg_show_lisp_rloc_probe_state_reply *msg)
{
  vapi_msg_show_lisp_rloc_probe_state_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_lisp_rloc_probe_state_reply>(vapi_msg_show_lisp_rloc_probe_state_reply *msg)
{
  vapi_msg_show_lisp_rloc_probe_state_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_lisp_rloc_probe_state_reply>()
{
  return ::vapi_msg_id_show_lisp_rloc_probe_state_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_lisp_rloc_probe_state_reply>>()
{
  return ::vapi_msg_id_show_lisp_rloc_probe_state_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_lisp_rloc_probe_state_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_lisp_rloc_probe_state_reply>(vapi_msg_id_show_lisp_rloc_probe_state_reply);
}

template class Msg<vapi_msg_show_lisp_rloc_probe_state_reply>;

using Show_lisp_rloc_probe_state_reply = Msg<vapi_msg_show_lisp_rloc_probe_state_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_lisp_rloc_probe_enable_disable>(vapi_msg_lisp_rloc_probe_enable_disable *msg)
{
  vapi_msg_lisp_rloc_probe_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_rloc_probe_enable_disable>(vapi_msg_lisp_rloc_probe_enable_disable *msg)
{
  vapi_msg_lisp_rloc_probe_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_rloc_probe_enable_disable>()
{
  return ::vapi_msg_id_lisp_rloc_probe_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_rloc_probe_enable_disable>>()
{
  return ::vapi_msg_id_lisp_rloc_probe_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_rloc_probe_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_rloc_probe_enable_disable>(vapi_msg_id_lisp_rloc_probe_enable_disable);
}

template <> inline vapi_msg_lisp_rloc_probe_enable_disable* vapi_alloc<vapi_msg_lisp_rloc_probe_enable_disable>(Connection &con)
{
  vapi_msg_lisp_rloc_probe_enable_disable* result = vapi_alloc_lisp_rloc_probe_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lisp_rloc_probe_enable_disable>;

template class Request<vapi_msg_lisp_rloc_probe_enable_disable, vapi_msg_lisp_rloc_probe_enable_disable_reply>;

using Lisp_rloc_probe_enable_disable = Request<vapi_msg_lisp_rloc_probe_enable_disable, vapi_msg_lisp_rloc_probe_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_lisp_rloc_probe_enable_disable_reply>(vapi_msg_lisp_rloc_probe_enable_disable_reply *msg)
{
  vapi_msg_lisp_rloc_probe_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_rloc_probe_enable_disable_reply>(vapi_msg_lisp_rloc_probe_enable_disable_reply *msg)
{
  vapi_msg_lisp_rloc_probe_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_rloc_probe_enable_disable_reply>()
{
  return ::vapi_msg_id_lisp_rloc_probe_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_rloc_probe_enable_disable_reply>>()
{
  return ::vapi_msg_id_lisp_rloc_probe_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_rloc_probe_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_rloc_probe_enable_disable_reply>(vapi_msg_id_lisp_rloc_probe_enable_disable_reply);
}

template class Msg<vapi_msg_lisp_rloc_probe_enable_disable_reply>;

using Lisp_rloc_probe_enable_disable_reply = Msg<vapi_msg_lisp_rloc_probe_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_lisp_map_register_enable_disable>(vapi_msg_lisp_map_register_enable_disable *msg)
{
  vapi_msg_lisp_map_register_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_map_register_enable_disable>(vapi_msg_lisp_map_register_enable_disable *msg)
{
  vapi_msg_lisp_map_register_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_map_register_enable_disable>()
{
  return ::vapi_msg_id_lisp_map_register_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_map_register_enable_disable>>()
{
  return ::vapi_msg_id_lisp_map_register_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_map_register_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_map_register_enable_disable>(vapi_msg_id_lisp_map_register_enable_disable);
}

template <> inline vapi_msg_lisp_map_register_enable_disable* vapi_alloc<vapi_msg_lisp_map_register_enable_disable>(Connection &con)
{
  vapi_msg_lisp_map_register_enable_disable* result = vapi_alloc_lisp_map_register_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lisp_map_register_enable_disable>;

template class Request<vapi_msg_lisp_map_register_enable_disable, vapi_msg_lisp_map_register_enable_disable_reply>;

using Lisp_map_register_enable_disable = Request<vapi_msg_lisp_map_register_enable_disable, vapi_msg_lisp_map_register_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_lisp_map_register_enable_disable_reply>(vapi_msg_lisp_map_register_enable_disable_reply *msg)
{
  vapi_msg_lisp_map_register_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_map_register_enable_disable_reply>(vapi_msg_lisp_map_register_enable_disable_reply *msg)
{
  vapi_msg_lisp_map_register_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_map_register_enable_disable_reply>()
{
  return ::vapi_msg_id_lisp_map_register_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_map_register_enable_disable_reply>>()
{
  return ::vapi_msg_id_lisp_map_register_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_map_register_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_map_register_enable_disable_reply>(vapi_msg_id_lisp_map_register_enable_disable_reply);
}

template class Msg<vapi_msg_lisp_map_register_enable_disable_reply>;

using Lisp_map_register_enable_disable_reply = Msg<vapi_msg_lisp_map_register_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_show_lisp_map_register_state>(vapi_msg_show_lisp_map_register_state *msg)
{
  vapi_msg_show_lisp_map_register_state_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_lisp_map_register_state>(vapi_msg_show_lisp_map_register_state *msg)
{
  vapi_msg_show_lisp_map_register_state_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_lisp_map_register_state>()
{
  return ::vapi_msg_id_show_lisp_map_register_state; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_lisp_map_register_state>>()
{
  return ::vapi_msg_id_show_lisp_map_register_state; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_lisp_map_register_state()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_lisp_map_register_state>(vapi_msg_id_show_lisp_map_register_state);
}

template <> inline vapi_msg_show_lisp_map_register_state* vapi_alloc<vapi_msg_show_lisp_map_register_state>(Connection &con)
{
  vapi_msg_show_lisp_map_register_state* result = vapi_alloc_show_lisp_map_register_state(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_show_lisp_map_register_state>;

template class Request<vapi_msg_show_lisp_map_register_state, vapi_msg_show_lisp_map_register_state_reply>;

using Show_lisp_map_register_state = Request<vapi_msg_show_lisp_map_register_state, vapi_msg_show_lisp_map_register_state_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_show_lisp_map_register_state_reply>(vapi_msg_show_lisp_map_register_state_reply *msg)
{
  vapi_msg_show_lisp_map_register_state_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_lisp_map_register_state_reply>(vapi_msg_show_lisp_map_register_state_reply *msg)
{
  vapi_msg_show_lisp_map_register_state_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_lisp_map_register_state_reply>()
{
  return ::vapi_msg_id_show_lisp_map_register_state_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_lisp_map_register_state_reply>>()
{
  return ::vapi_msg_id_show_lisp_map_register_state_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_lisp_map_register_state_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_lisp_map_register_state_reply>(vapi_msg_id_show_lisp_map_register_state_reply);
}

template class Msg<vapi_msg_show_lisp_map_register_state_reply>;

using Show_lisp_map_register_state_reply = Msg<vapi_msg_show_lisp_map_register_state_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_lisp_map_request_mode>(vapi_msg_lisp_map_request_mode *msg)
{
  vapi_msg_lisp_map_request_mode_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_map_request_mode>(vapi_msg_lisp_map_request_mode *msg)
{
  vapi_msg_lisp_map_request_mode_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_map_request_mode>()
{
  return ::vapi_msg_id_lisp_map_request_mode; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_map_request_mode>>()
{
  return ::vapi_msg_id_lisp_map_request_mode; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_map_request_mode()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_map_request_mode>(vapi_msg_id_lisp_map_request_mode);
}

template <> inline vapi_msg_lisp_map_request_mode* vapi_alloc<vapi_msg_lisp_map_request_mode>(Connection &con)
{
  vapi_msg_lisp_map_request_mode* result = vapi_alloc_lisp_map_request_mode(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lisp_map_request_mode>;

template class Request<vapi_msg_lisp_map_request_mode, vapi_msg_lisp_map_request_mode_reply>;

using Lisp_map_request_mode = Request<vapi_msg_lisp_map_request_mode, vapi_msg_lisp_map_request_mode_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_lisp_map_request_mode_reply>(vapi_msg_lisp_map_request_mode_reply *msg)
{
  vapi_msg_lisp_map_request_mode_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_map_request_mode_reply>(vapi_msg_lisp_map_request_mode_reply *msg)
{
  vapi_msg_lisp_map_request_mode_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_map_request_mode_reply>()
{
  return ::vapi_msg_id_lisp_map_request_mode_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_map_request_mode_reply>>()
{
  return ::vapi_msg_id_lisp_map_request_mode_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_map_request_mode_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_map_request_mode_reply>(vapi_msg_id_lisp_map_request_mode_reply);
}

template class Msg<vapi_msg_lisp_map_request_mode_reply>;

using Lisp_map_request_mode_reply = Msg<vapi_msg_lisp_map_request_mode_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_show_lisp_map_request_mode>(vapi_msg_show_lisp_map_request_mode *msg)
{
  vapi_msg_show_lisp_map_request_mode_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_lisp_map_request_mode>(vapi_msg_show_lisp_map_request_mode *msg)
{
  vapi_msg_show_lisp_map_request_mode_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_lisp_map_request_mode>()
{
  return ::vapi_msg_id_show_lisp_map_request_mode; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_lisp_map_request_mode>>()
{
  return ::vapi_msg_id_show_lisp_map_request_mode; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_lisp_map_request_mode()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_lisp_map_request_mode>(vapi_msg_id_show_lisp_map_request_mode);
}

template <> inline vapi_msg_show_lisp_map_request_mode* vapi_alloc<vapi_msg_show_lisp_map_request_mode>(Connection &con)
{
  vapi_msg_show_lisp_map_request_mode* result = vapi_alloc_show_lisp_map_request_mode(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_show_lisp_map_request_mode>;

template class Request<vapi_msg_show_lisp_map_request_mode, vapi_msg_show_lisp_map_request_mode_reply>;

using Show_lisp_map_request_mode = Request<vapi_msg_show_lisp_map_request_mode, vapi_msg_show_lisp_map_request_mode_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_show_lisp_map_request_mode_reply>(vapi_msg_show_lisp_map_request_mode_reply *msg)
{
  vapi_msg_show_lisp_map_request_mode_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_lisp_map_request_mode_reply>(vapi_msg_show_lisp_map_request_mode_reply *msg)
{
  vapi_msg_show_lisp_map_request_mode_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_lisp_map_request_mode_reply>()
{
  return ::vapi_msg_id_show_lisp_map_request_mode_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_lisp_map_request_mode_reply>>()
{
  return ::vapi_msg_id_show_lisp_map_request_mode_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_lisp_map_request_mode_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_lisp_map_request_mode_reply>(vapi_msg_id_show_lisp_map_request_mode_reply);
}

template class Msg<vapi_msg_show_lisp_map_request_mode_reply>;

using Show_lisp_map_request_mode_reply = Msg<vapi_msg_show_lisp_map_request_mode_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_lisp_add_del_remote_mapping>(vapi_msg_lisp_add_del_remote_mapping *msg)
{
  vapi_msg_lisp_add_del_remote_mapping_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_add_del_remote_mapping>(vapi_msg_lisp_add_del_remote_mapping *msg)
{
  vapi_msg_lisp_add_del_remote_mapping_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_add_del_remote_mapping>()
{
  return ::vapi_msg_id_lisp_add_del_remote_mapping; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_add_del_remote_mapping>>()
{
  return ::vapi_msg_id_lisp_add_del_remote_mapping; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_add_del_remote_mapping()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_add_del_remote_mapping>(vapi_msg_id_lisp_add_del_remote_mapping);
}

template <> inline vapi_msg_lisp_add_del_remote_mapping* vapi_alloc<vapi_msg_lisp_add_del_remote_mapping, size_t>(Connection &con, size_t _rlocs_array_size)
{
  vapi_msg_lisp_add_del_remote_mapping* result = vapi_alloc_lisp_add_del_remote_mapping(con.vapi_ctx, _rlocs_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lisp_add_del_remote_mapping>;

template class Request<vapi_msg_lisp_add_del_remote_mapping, vapi_msg_lisp_add_del_remote_mapping_reply, size_t>;

using Lisp_add_del_remote_mapping = Request<vapi_msg_lisp_add_del_remote_mapping, vapi_msg_lisp_add_del_remote_mapping_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_lisp_add_del_remote_mapping_reply>(vapi_msg_lisp_add_del_remote_mapping_reply *msg)
{
  vapi_msg_lisp_add_del_remote_mapping_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_add_del_remote_mapping_reply>(vapi_msg_lisp_add_del_remote_mapping_reply *msg)
{
  vapi_msg_lisp_add_del_remote_mapping_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_add_del_remote_mapping_reply>()
{
  return ::vapi_msg_id_lisp_add_del_remote_mapping_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_add_del_remote_mapping_reply>>()
{
  return ::vapi_msg_id_lisp_add_del_remote_mapping_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_add_del_remote_mapping_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_add_del_remote_mapping_reply>(vapi_msg_id_lisp_add_del_remote_mapping_reply);
}

template class Msg<vapi_msg_lisp_add_del_remote_mapping_reply>;

using Lisp_add_del_remote_mapping_reply = Msg<vapi_msg_lisp_add_del_remote_mapping_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_lisp_add_del_adjacency>(vapi_msg_lisp_add_del_adjacency *msg)
{
  vapi_msg_lisp_add_del_adjacency_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_add_del_adjacency>(vapi_msg_lisp_add_del_adjacency *msg)
{
  vapi_msg_lisp_add_del_adjacency_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_add_del_adjacency>()
{
  return ::vapi_msg_id_lisp_add_del_adjacency; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_add_del_adjacency>>()
{
  return ::vapi_msg_id_lisp_add_del_adjacency; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_add_del_adjacency()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_add_del_adjacency>(vapi_msg_id_lisp_add_del_adjacency);
}

template <> inline vapi_msg_lisp_add_del_adjacency* vapi_alloc<vapi_msg_lisp_add_del_adjacency>(Connection &con)
{
  vapi_msg_lisp_add_del_adjacency* result = vapi_alloc_lisp_add_del_adjacency(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lisp_add_del_adjacency>;

template class Request<vapi_msg_lisp_add_del_adjacency, vapi_msg_lisp_add_del_adjacency_reply>;

using Lisp_add_del_adjacency = Request<vapi_msg_lisp_add_del_adjacency, vapi_msg_lisp_add_del_adjacency_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_lisp_add_del_adjacency_reply>(vapi_msg_lisp_add_del_adjacency_reply *msg)
{
  vapi_msg_lisp_add_del_adjacency_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_add_del_adjacency_reply>(vapi_msg_lisp_add_del_adjacency_reply *msg)
{
  vapi_msg_lisp_add_del_adjacency_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_add_del_adjacency_reply>()
{
  return ::vapi_msg_id_lisp_add_del_adjacency_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_add_del_adjacency_reply>>()
{
  return ::vapi_msg_id_lisp_add_del_adjacency_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_add_del_adjacency_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_add_del_adjacency_reply>(vapi_msg_id_lisp_add_del_adjacency_reply);
}

template class Msg<vapi_msg_lisp_add_del_adjacency_reply>;

using Lisp_add_del_adjacency_reply = Msg<vapi_msg_lisp_add_del_adjacency_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_lisp_add_del_map_request_itr_rlocs>(vapi_msg_lisp_add_del_map_request_itr_rlocs *msg)
{
  vapi_msg_lisp_add_del_map_request_itr_rlocs_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_add_del_map_request_itr_rlocs>(vapi_msg_lisp_add_del_map_request_itr_rlocs *msg)
{
  vapi_msg_lisp_add_del_map_request_itr_rlocs_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_add_del_map_request_itr_rlocs>()
{
  return ::vapi_msg_id_lisp_add_del_map_request_itr_rlocs; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_add_del_map_request_itr_rlocs>>()
{
  return ::vapi_msg_id_lisp_add_del_map_request_itr_rlocs; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_add_del_map_request_itr_rlocs()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_add_del_map_request_itr_rlocs>(vapi_msg_id_lisp_add_del_map_request_itr_rlocs);
}

template <> inline vapi_msg_lisp_add_del_map_request_itr_rlocs* vapi_alloc<vapi_msg_lisp_add_del_map_request_itr_rlocs>(Connection &con)
{
  vapi_msg_lisp_add_del_map_request_itr_rlocs* result = vapi_alloc_lisp_add_del_map_request_itr_rlocs(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lisp_add_del_map_request_itr_rlocs>;

template class Request<vapi_msg_lisp_add_del_map_request_itr_rlocs, vapi_msg_lisp_add_del_map_request_itr_rlocs_reply>;

using Lisp_add_del_map_request_itr_rlocs = Request<vapi_msg_lisp_add_del_map_request_itr_rlocs, vapi_msg_lisp_add_del_map_request_itr_rlocs_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_lisp_add_del_map_request_itr_rlocs_reply>(vapi_msg_lisp_add_del_map_request_itr_rlocs_reply *msg)
{
  vapi_msg_lisp_add_del_map_request_itr_rlocs_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_add_del_map_request_itr_rlocs_reply>(vapi_msg_lisp_add_del_map_request_itr_rlocs_reply *msg)
{
  vapi_msg_lisp_add_del_map_request_itr_rlocs_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_add_del_map_request_itr_rlocs_reply>()
{
  return ::vapi_msg_id_lisp_add_del_map_request_itr_rlocs_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_add_del_map_request_itr_rlocs_reply>>()
{
  return ::vapi_msg_id_lisp_add_del_map_request_itr_rlocs_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_add_del_map_request_itr_rlocs_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_add_del_map_request_itr_rlocs_reply>(vapi_msg_id_lisp_add_del_map_request_itr_rlocs_reply);
}

template class Msg<vapi_msg_lisp_add_del_map_request_itr_rlocs_reply>;

using Lisp_add_del_map_request_itr_rlocs_reply = Msg<vapi_msg_lisp_add_del_map_request_itr_rlocs_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_lisp_eid_table_add_del_map>(vapi_msg_lisp_eid_table_add_del_map *msg)
{
  vapi_msg_lisp_eid_table_add_del_map_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_eid_table_add_del_map>(vapi_msg_lisp_eid_table_add_del_map *msg)
{
  vapi_msg_lisp_eid_table_add_del_map_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_eid_table_add_del_map>()
{
  return ::vapi_msg_id_lisp_eid_table_add_del_map; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_eid_table_add_del_map>>()
{
  return ::vapi_msg_id_lisp_eid_table_add_del_map; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_eid_table_add_del_map()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_eid_table_add_del_map>(vapi_msg_id_lisp_eid_table_add_del_map);
}

template <> inline vapi_msg_lisp_eid_table_add_del_map* vapi_alloc<vapi_msg_lisp_eid_table_add_del_map>(Connection &con)
{
  vapi_msg_lisp_eid_table_add_del_map* result = vapi_alloc_lisp_eid_table_add_del_map(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lisp_eid_table_add_del_map>;

template class Request<vapi_msg_lisp_eid_table_add_del_map, vapi_msg_lisp_eid_table_add_del_map_reply>;

using Lisp_eid_table_add_del_map = Request<vapi_msg_lisp_eid_table_add_del_map, vapi_msg_lisp_eid_table_add_del_map_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_lisp_eid_table_add_del_map_reply>(vapi_msg_lisp_eid_table_add_del_map_reply *msg)
{
  vapi_msg_lisp_eid_table_add_del_map_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_eid_table_add_del_map_reply>(vapi_msg_lisp_eid_table_add_del_map_reply *msg)
{
  vapi_msg_lisp_eid_table_add_del_map_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_eid_table_add_del_map_reply>()
{
  return ::vapi_msg_id_lisp_eid_table_add_del_map_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_eid_table_add_del_map_reply>>()
{
  return ::vapi_msg_id_lisp_eid_table_add_del_map_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_eid_table_add_del_map_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_eid_table_add_del_map_reply>(vapi_msg_id_lisp_eid_table_add_del_map_reply);
}

template class Msg<vapi_msg_lisp_eid_table_add_del_map_reply>;

using Lisp_eid_table_add_del_map_reply = Msg<vapi_msg_lisp_eid_table_add_del_map_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_lisp_locator_dump>(vapi_msg_lisp_locator_dump *msg)
{
  vapi_msg_lisp_locator_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_locator_dump>(vapi_msg_lisp_locator_dump *msg)
{
  vapi_msg_lisp_locator_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_locator_dump>()
{
  return ::vapi_msg_id_lisp_locator_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_locator_dump>>()
{
  return ::vapi_msg_id_lisp_locator_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_locator_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_locator_dump>(vapi_msg_id_lisp_locator_dump);
}

template <> inline vapi_msg_lisp_locator_dump* vapi_alloc<vapi_msg_lisp_locator_dump>(Connection &con)
{
  vapi_msg_lisp_locator_dump* result = vapi_alloc_lisp_locator_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lisp_locator_dump>;

template class Dump<vapi_msg_lisp_locator_dump, vapi_msg_lisp_locator_details>;

using Lisp_locator_dump = Dump<vapi_msg_lisp_locator_dump, vapi_msg_lisp_locator_details>;

template <> inline void vapi_swap_to_be<vapi_msg_lisp_locator_details>(vapi_msg_lisp_locator_details *msg)
{
  vapi_msg_lisp_locator_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_locator_details>(vapi_msg_lisp_locator_details *msg)
{
  vapi_msg_lisp_locator_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_locator_details>()
{
  return ::vapi_msg_id_lisp_locator_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_locator_details>>()
{
  return ::vapi_msg_id_lisp_locator_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_locator_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_locator_details>(vapi_msg_id_lisp_locator_details);
}

template class Msg<vapi_msg_lisp_locator_details>;

using Lisp_locator_details = Msg<vapi_msg_lisp_locator_details>;
template <> inline void vapi_swap_to_be<vapi_msg_lisp_locator_set_details>(vapi_msg_lisp_locator_set_details *msg)
{
  vapi_msg_lisp_locator_set_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_locator_set_details>(vapi_msg_lisp_locator_set_details *msg)
{
  vapi_msg_lisp_locator_set_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_locator_set_details>()
{
  return ::vapi_msg_id_lisp_locator_set_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_locator_set_details>>()
{
  return ::vapi_msg_id_lisp_locator_set_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_locator_set_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_locator_set_details>(vapi_msg_id_lisp_locator_set_details);
}

template class Msg<vapi_msg_lisp_locator_set_details>;

using Lisp_locator_set_details = Msg<vapi_msg_lisp_locator_set_details>;
template <> inline void vapi_swap_to_be<vapi_msg_lisp_locator_set_dump>(vapi_msg_lisp_locator_set_dump *msg)
{
  vapi_msg_lisp_locator_set_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_locator_set_dump>(vapi_msg_lisp_locator_set_dump *msg)
{
  vapi_msg_lisp_locator_set_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_locator_set_dump>()
{
  return ::vapi_msg_id_lisp_locator_set_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_locator_set_dump>>()
{
  return ::vapi_msg_id_lisp_locator_set_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_locator_set_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_locator_set_dump>(vapi_msg_id_lisp_locator_set_dump);
}

template <> inline vapi_msg_lisp_locator_set_dump* vapi_alloc<vapi_msg_lisp_locator_set_dump>(Connection &con)
{
  vapi_msg_lisp_locator_set_dump* result = vapi_alloc_lisp_locator_set_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lisp_locator_set_dump>;

template class Dump<vapi_msg_lisp_locator_set_dump, vapi_msg_lisp_locator_set_details>;

using Lisp_locator_set_dump = Dump<vapi_msg_lisp_locator_set_dump, vapi_msg_lisp_locator_set_details>;

template <> inline void vapi_swap_to_be<vapi_msg_lisp_eid_table_details>(vapi_msg_lisp_eid_table_details *msg)
{
  vapi_msg_lisp_eid_table_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_eid_table_details>(vapi_msg_lisp_eid_table_details *msg)
{
  vapi_msg_lisp_eid_table_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_eid_table_details>()
{
  return ::vapi_msg_id_lisp_eid_table_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_eid_table_details>>()
{
  return ::vapi_msg_id_lisp_eid_table_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_eid_table_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_eid_table_details>(vapi_msg_id_lisp_eid_table_details);
}

template class Msg<vapi_msg_lisp_eid_table_details>;

using Lisp_eid_table_details = Msg<vapi_msg_lisp_eid_table_details>;
template <> inline void vapi_swap_to_be<vapi_msg_lisp_eid_table_dump>(vapi_msg_lisp_eid_table_dump *msg)
{
  vapi_msg_lisp_eid_table_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_eid_table_dump>(vapi_msg_lisp_eid_table_dump *msg)
{
  vapi_msg_lisp_eid_table_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_eid_table_dump>()
{
  return ::vapi_msg_id_lisp_eid_table_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_eid_table_dump>>()
{
  return ::vapi_msg_id_lisp_eid_table_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_eid_table_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_eid_table_dump>(vapi_msg_id_lisp_eid_table_dump);
}

template <> inline vapi_msg_lisp_eid_table_dump* vapi_alloc<vapi_msg_lisp_eid_table_dump>(Connection &con)
{
  vapi_msg_lisp_eid_table_dump* result = vapi_alloc_lisp_eid_table_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lisp_eid_table_dump>;

template class Dump<vapi_msg_lisp_eid_table_dump, vapi_msg_lisp_eid_table_details>;

using Lisp_eid_table_dump = Dump<vapi_msg_lisp_eid_table_dump, vapi_msg_lisp_eid_table_details>;

template <> inline void vapi_swap_to_be<vapi_msg_lisp_adjacencies_get_reply>(vapi_msg_lisp_adjacencies_get_reply *msg)
{
  vapi_msg_lisp_adjacencies_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_adjacencies_get_reply>(vapi_msg_lisp_adjacencies_get_reply *msg)
{
  vapi_msg_lisp_adjacencies_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_adjacencies_get_reply>()
{
  return ::vapi_msg_id_lisp_adjacencies_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_adjacencies_get_reply>>()
{
  return ::vapi_msg_id_lisp_adjacencies_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_adjacencies_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_adjacencies_get_reply>(vapi_msg_id_lisp_adjacencies_get_reply);
}

template class Msg<vapi_msg_lisp_adjacencies_get_reply>;

using Lisp_adjacencies_get_reply = Msg<vapi_msg_lisp_adjacencies_get_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_lisp_adjacencies_get>(vapi_msg_lisp_adjacencies_get *msg)
{
  vapi_msg_lisp_adjacencies_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_adjacencies_get>(vapi_msg_lisp_adjacencies_get *msg)
{
  vapi_msg_lisp_adjacencies_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_adjacencies_get>()
{
  return ::vapi_msg_id_lisp_adjacencies_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_adjacencies_get>>()
{
  return ::vapi_msg_id_lisp_adjacencies_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_adjacencies_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_adjacencies_get>(vapi_msg_id_lisp_adjacencies_get);
}

template <> inline vapi_msg_lisp_adjacencies_get* vapi_alloc<vapi_msg_lisp_adjacencies_get>(Connection &con)
{
  vapi_msg_lisp_adjacencies_get* result = vapi_alloc_lisp_adjacencies_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lisp_adjacencies_get>;

template class Request<vapi_msg_lisp_adjacencies_get, vapi_msg_lisp_adjacencies_get_reply>;

using Lisp_adjacencies_get = Request<vapi_msg_lisp_adjacencies_get, vapi_msg_lisp_adjacencies_get_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_lisp_eid_table_map_details>(vapi_msg_lisp_eid_table_map_details *msg)
{
  vapi_msg_lisp_eid_table_map_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_eid_table_map_details>(vapi_msg_lisp_eid_table_map_details *msg)
{
  vapi_msg_lisp_eid_table_map_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_eid_table_map_details>()
{
  return ::vapi_msg_id_lisp_eid_table_map_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_eid_table_map_details>>()
{
  return ::vapi_msg_id_lisp_eid_table_map_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_eid_table_map_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_eid_table_map_details>(vapi_msg_id_lisp_eid_table_map_details);
}

template class Msg<vapi_msg_lisp_eid_table_map_details>;

using Lisp_eid_table_map_details = Msg<vapi_msg_lisp_eid_table_map_details>;
template <> inline void vapi_swap_to_be<vapi_msg_lisp_eid_table_map_dump>(vapi_msg_lisp_eid_table_map_dump *msg)
{
  vapi_msg_lisp_eid_table_map_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_eid_table_map_dump>(vapi_msg_lisp_eid_table_map_dump *msg)
{
  vapi_msg_lisp_eid_table_map_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_eid_table_map_dump>()
{
  return ::vapi_msg_id_lisp_eid_table_map_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_eid_table_map_dump>>()
{
  return ::vapi_msg_id_lisp_eid_table_map_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_eid_table_map_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_eid_table_map_dump>(vapi_msg_id_lisp_eid_table_map_dump);
}

template <> inline vapi_msg_lisp_eid_table_map_dump* vapi_alloc<vapi_msg_lisp_eid_table_map_dump>(Connection &con)
{
  vapi_msg_lisp_eid_table_map_dump* result = vapi_alloc_lisp_eid_table_map_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lisp_eid_table_map_dump>;

template class Dump<vapi_msg_lisp_eid_table_map_dump, vapi_msg_lisp_eid_table_map_details>;

using Lisp_eid_table_map_dump = Dump<vapi_msg_lisp_eid_table_map_dump, vapi_msg_lisp_eid_table_map_details>;

template <> inline void vapi_swap_to_be<vapi_msg_lisp_eid_table_vni_dump>(vapi_msg_lisp_eid_table_vni_dump *msg)
{
  vapi_msg_lisp_eid_table_vni_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_eid_table_vni_dump>(vapi_msg_lisp_eid_table_vni_dump *msg)
{
  vapi_msg_lisp_eid_table_vni_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_eid_table_vni_dump>()
{
  return ::vapi_msg_id_lisp_eid_table_vni_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_eid_table_vni_dump>>()
{
  return ::vapi_msg_id_lisp_eid_table_vni_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_eid_table_vni_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_eid_table_vni_dump>(vapi_msg_id_lisp_eid_table_vni_dump);
}

template <> inline vapi_msg_lisp_eid_table_vni_dump* vapi_alloc<vapi_msg_lisp_eid_table_vni_dump>(Connection &con)
{
  vapi_msg_lisp_eid_table_vni_dump* result = vapi_alloc_lisp_eid_table_vni_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lisp_eid_table_vni_dump>;

template class Dump<vapi_msg_lisp_eid_table_vni_dump, vapi_msg_lisp_eid_table_vni_details>;

using Lisp_eid_table_vni_dump = Dump<vapi_msg_lisp_eid_table_vni_dump, vapi_msg_lisp_eid_table_vni_details>;

template <> inline void vapi_swap_to_be<vapi_msg_lisp_eid_table_vni_details>(vapi_msg_lisp_eid_table_vni_details *msg)
{
  vapi_msg_lisp_eid_table_vni_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_eid_table_vni_details>(vapi_msg_lisp_eid_table_vni_details *msg)
{
  vapi_msg_lisp_eid_table_vni_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_eid_table_vni_details>()
{
  return ::vapi_msg_id_lisp_eid_table_vni_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_eid_table_vni_details>>()
{
  return ::vapi_msg_id_lisp_eid_table_vni_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_eid_table_vni_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_eid_table_vni_details>(vapi_msg_id_lisp_eid_table_vni_details);
}

template class Msg<vapi_msg_lisp_eid_table_vni_details>;

using Lisp_eid_table_vni_details = Msg<vapi_msg_lisp_eid_table_vni_details>;
template <> inline void vapi_swap_to_be<vapi_msg_lisp_map_resolver_details>(vapi_msg_lisp_map_resolver_details *msg)
{
  vapi_msg_lisp_map_resolver_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_map_resolver_details>(vapi_msg_lisp_map_resolver_details *msg)
{
  vapi_msg_lisp_map_resolver_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_map_resolver_details>()
{
  return ::vapi_msg_id_lisp_map_resolver_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_map_resolver_details>>()
{
  return ::vapi_msg_id_lisp_map_resolver_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_map_resolver_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_map_resolver_details>(vapi_msg_id_lisp_map_resolver_details);
}

template class Msg<vapi_msg_lisp_map_resolver_details>;

using Lisp_map_resolver_details = Msg<vapi_msg_lisp_map_resolver_details>;
template <> inline void vapi_swap_to_be<vapi_msg_lisp_map_resolver_dump>(vapi_msg_lisp_map_resolver_dump *msg)
{
  vapi_msg_lisp_map_resolver_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_map_resolver_dump>(vapi_msg_lisp_map_resolver_dump *msg)
{
  vapi_msg_lisp_map_resolver_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_map_resolver_dump>()
{
  return ::vapi_msg_id_lisp_map_resolver_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_map_resolver_dump>>()
{
  return ::vapi_msg_id_lisp_map_resolver_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_map_resolver_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_map_resolver_dump>(vapi_msg_id_lisp_map_resolver_dump);
}

template <> inline vapi_msg_lisp_map_resolver_dump* vapi_alloc<vapi_msg_lisp_map_resolver_dump>(Connection &con)
{
  vapi_msg_lisp_map_resolver_dump* result = vapi_alloc_lisp_map_resolver_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lisp_map_resolver_dump>;

template class Dump<vapi_msg_lisp_map_resolver_dump, vapi_msg_lisp_map_resolver_details>;

using Lisp_map_resolver_dump = Dump<vapi_msg_lisp_map_resolver_dump, vapi_msg_lisp_map_resolver_details>;

template <> inline void vapi_swap_to_be<vapi_msg_lisp_map_server_details>(vapi_msg_lisp_map_server_details *msg)
{
  vapi_msg_lisp_map_server_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_map_server_details>(vapi_msg_lisp_map_server_details *msg)
{
  vapi_msg_lisp_map_server_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_map_server_details>()
{
  return ::vapi_msg_id_lisp_map_server_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_map_server_details>>()
{
  return ::vapi_msg_id_lisp_map_server_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_map_server_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_map_server_details>(vapi_msg_id_lisp_map_server_details);
}

template class Msg<vapi_msg_lisp_map_server_details>;

using Lisp_map_server_details = Msg<vapi_msg_lisp_map_server_details>;
template <> inline void vapi_swap_to_be<vapi_msg_lisp_map_server_dump>(vapi_msg_lisp_map_server_dump *msg)
{
  vapi_msg_lisp_map_server_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_map_server_dump>(vapi_msg_lisp_map_server_dump *msg)
{
  vapi_msg_lisp_map_server_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_map_server_dump>()
{
  return ::vapi_msg_id_lisp_map_server_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_map_server_dump>>()
{
  return ::vapi_msg_id_lisp_map_server_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_map_server_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_map_server_dump>(vapi_msg_id_lisp_map_server_dump);
}

template <> inline vapi_msg_lisp_map_server_dump* vapi_alloc<vapi_msg_lisp_map_server_dump>(Connection &con)
{
  vapi_msg_lisp_map_server_dump* result = vapi_alloc_lisp_map_server_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lisp_map_server_dump>;

template class Dump<vapi_msg_lisp_map_server_dump, vapi_msg_lisp_map_server_details>;

using Lisp_map_server_dump = Dump<vapi_msg_lisp_map_server_dump, vapi_msg_lisp_map_server_details>;

template <> inline void vapi_swap_to_be<vapi_msg_show_lisp_status>(vapi_msg_show_lisp_status *msg)
{
  vapi_msg_show_lisp_status_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_lisp_status>(vapi_msg_show_lisp_status *msg)
{
  vapi_msg_show_lisp_status_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_lisp_status>()
{
  return ::vapi_msg_id_show_lisp_status; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_lisp_status>>()
{
  return ::vapi_msg_id_show_lisp_status; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_lisp_status()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_lisp_status>(vapi_msg_id_show_lisp_status);
}

template <> inline vapi_msg_show_lisp_status* vapi_alloc<vapi_msg_show_lisp_status>(Connection &con)
{
  vapi_msg_show_lisp_status* result = vapi_alloc_show_lisp_status(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_show_lisp_status>;

template class Request<vapi_msg_show_lisp_status, vapi_msg_show_lisp_status_reply>;

using Show_lisp_status = Request<vapi_msg_show_lisp_status, vapi_msg_show_lisp_status_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_show_lisp_status_reply>(vapi_msg_show_lisp_status_reply *msg)
{
  vapi_msg_show_lisp_status_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_lisp_status_reply>(vapi_msg_show_lisp_status_reply *msg)
{
  vapi_msg_show_lisp_status_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_lisp_status_reply>()
{
  return ::vapi_msg_id_show_lisp_status_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_lisp_status_reply>>()
{
  return ::vapi_msg_id_show_lisp_status_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_lisp_status_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_lisp_status_reply>(vapi_msg_id_show_lisp_status_reply);
}

template class Msg<vapi_msg_show_lisp_status_reply>;

using Show_lisp_status_reply = Msg<vapi_msg_show_lisp_status_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_lisp_get_map_request_itr_rlocs>(vapi_msg_lisp_get_map_request_itr_rlocs *msg)
{
  vapi_msg_lisp_get_map_request_itr_rlocs_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_get_map_request_itr_rlocs>(vapi_msg_lisp_get_map_request_itr_rlocs *msg)
{
  vapi_msg_lisp_get_map_request_itr_rlocs_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_get_map_request_itr_rlocs>()
{
  return ::vapi_msg_id_lisp_get_map_request_itr_rlocs; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_get_map_request_itr_rlocs>>()
{
  return ::vapi_msg_id_lisp_get_map_request_itr_rlocs; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_get_map_request_itr_rlocs()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_get_map_request_itr_rlocs>(vapi_msg_id_lisp_get_map_request_itr_rlocs);
}

template <> inline vapi_msg_lisp_get_map_request_itr_rlocs* vapi_alloc<vapi_msg_lisp_get_map_request_itr_rlocs>(Connection &con)
{
  vapi_msg_lisp_get_map_request_itr_rlocs* result = vapi_alloc_lisp_get_map_request_itr_rlocs(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lisp_get_map_request_itr_rlocs>;

template class Request<vapi_msg_lisp_get_map_request_itr_rlocs, vapi_msg_lisp_get_map_request_itr_rlocs_reply>;

using Lisp_get_map_request_itr_rlocs = Request<vapi_msg_lisp_get_map_request_itr_rlocs, vapi_msg_lisp_get_map_request_itr_rlocs_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_lisp_get_map_request_itr_rlocs_reply>(vapi_msg_lisp_get_map_request_itr_rlocs_reply *msg)
{
  vapi_msg_lisp_get_map_request_itr_rlocs_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lisp_get_map_request_itr_rlocs_reply>(vapi_msg_lisp_get_map_request_itr_rlocs_reply *msg)
{
  vapi_msg_lisp_get_map_request_itr_rlocs_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lisp_get_map_request_itr_rlocs_reply>()
{
  return ::vapi_msg_id_lisp_get_map_request_itr_rlocs_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lisp_get_map_request_itr_rlocs_reply>>()
{
  return ::vapi_msg_id_lisp_get_map_request_itr_rlocs_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lisp_get_map_request_itr_rlocs_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lisp_get_map_request_itr_rlocs_reply>(vapi_msg_id_lisp_get_map_request_itr_rlocs_reply);
}

template class Msg<vapi_msg_lisp_get_map_request_itr_rlocs_reply>;

using Lisp_get_map_request_itr_rlocs_reply = Msg<vapi_msg_lisp_get_map_request_itr_rlocs_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_show_lisp_pitr>(vapi_msg_show_lisp_pitr *msg)
{
  vapi_msg_show_lisp_pitr_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_lisp_pitr>(vapi_msg_show_lisp_pitr *msg)
{
  vapi_msg_show_lisp_pitr_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_lisp_pitr>()
{
  return ::vapi_msg_id_show_lisp_pitr; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_lisp_pitr>>()
{
  return ::vapi_msg_id_show_lisp_pitr; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_lisp_pitr()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_lisp_pitr>(vapi_msg_id_show_lisp_pitr);
}

template <> inline vapi_msg_show_lisp_pitr* vapi_alloc<vapi_msg_show_lisp_pitr>(Connection &con)
{
  vapi_msg_show_lisp_pitr* result = vapi_alloc_show_lisp_pitr(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_show_lisp_pitr>;

template class Request<vapi_msg_show_lisp_pitr, vapi_msg_show_lisp_pitr_reply>;

using Show_lisp_pitr = Request<vapi_msg_show_lisp_pitr, vapi_msg_show_lisp_pitr_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_show_lisp_pitr_reply>(vapi_msg_show_lisp_pitr_reply *msg)
{
  vapi_msg_show_lisp_pitr_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_lisp_pitr_reply>(vapi_msg_show_lisp_pitr_reply *msg)
{
  vapi_msg_show_lisp_pitr_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_lisp_pitr_reply>()
{
  return ::vapi_msg_id_show_lisp_pitr_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_lisp_pitr_reply>>()
{
  return ::vapi_msg_id_show_lisp_pitr_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_lisp_pitr_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_lisp_pitr_reply>(vapi_msg_id_show_lisp_pitr_reply);
}

template class Msg<vapi_msg_show_lisp_pitr_reply>;

using Show_lisp_pitr_reply = Msg<vapi_msg_show_lisp_pitr_reply>;
}
#endif
