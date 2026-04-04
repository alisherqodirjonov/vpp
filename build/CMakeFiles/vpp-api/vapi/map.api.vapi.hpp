#ifndef __included_hpp_map_api_json
#define __included_hpp_map_api_json

#include <vapi/vapi.hpp>
#include <vapi/map.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_map_add_domain>(vapi_msg_map_add_domain *msg)
{
  vapi_msg_map_add_domain_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_map_add_domain>(vapi_msg_map_add_domain *msg)
{
  vapi_msg_map_add_domain_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_map_add_domain>()
{
  return ::vapi_msg_id_map_add_domain; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_map_add_domain>>()
{
  return ::vapi_msg_id_map_add_domain; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_map_add_domain()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_map_add_domain>(vapi_msg_id_map_add_domain);
}

template <> inline vapi_msg_map_add_domain* vapi_alloc<vapi_msg_map_add_domain>(Connection &con)
{
  vapi_msg_map_add_domain* result = vapi_alloc_map_add_domain(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_map_add_domain>;

template class Request<vapi_msg_map_add_domain, vapi_msg_map_add_domain_reply>;

using Map_add_domain = Request<vapi_msg_map_add_domain, vapi_msg_map_add_domain_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_map_add_domain_reply>(vapi_msg_map_add_domain_reply *msg)
{
  vapi_msg_map_add_domain_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_map_add_domain_reply>(vapi_msg_map_add_domain_reply *msg)
{
  vapi_msg_map_add_domain_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_map_add_domain_reply>()
{
  return ::vapi_msg_id_map_add_domain_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_map_add_domain_reply>>()
{
  return ::vapi_msg_id_map_add_domain_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_map_add_domain_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_map_add_domain_reply>(vapi_msg_id_map_add_domain_reply);
}

template class Msg<vapi_msg_map_add_domain_reply>;

using Map_add_domain_reply = Msg<vapi_msg_map_add_domain_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_map_del_domain>(vapi_msg_map_del_domain *msg)
{
  vapi_msg_map_del_domain_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_map_del_domain>(vapi_msg_map_del_domain *msg)
{
  vapi_msg_map_del_domain_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_map_del_domain>()
{
  return ::vapi_msg_id_map_del_domain; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_map_del_domain>>()
{
  return ::vapi_msg_id_map_del_domain; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_map_del_domain()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_map_del_domain>(vapi_msg_id_map_del_domain);
}

template <> inline vapi_msg_map_del_domain* vapi_alloc<vapi_msg_map_del_domain>(Connection &con)
{
  vapi_msg_map_del_domain* result = vapi_alloc_map_del_domain(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_map_del_domain>;

template class Request<vapi_msg_map_del_domain, vapi_msg_map_del_domain_reply>;

using Map_del_domain = Request<vapi_msg_map_del_domain, vapi_msg_map_del_domain_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_map_del_domain_reply>(vapi_msg_map_del_domain_reply *msg)
{
  vapi_msg_map_del_domain_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_map_del_domain_reply>(vapi_msg_map_del_domain_reply *msg)
{
  vapi_msg_map_del_domain_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_map_del_domain_reply>()
{
  return ::vapi_msg_id_map_del_domain_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_map_del_domain_reply>>()
{
  return ::vapi_msg_id_map_del_domain_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_map_del_domain_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_map_del_domain_reply>(vapi_msg_id_map_del_domain_reply);
}

template class Msg<vapi_msg_map_del_domain_reply>;

using Map_del_domain_reply = Msg<vapi_msg_map_del_domain_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_map_add_del_rule>(vapi_msg_map_add_del_rule *msg)
{
  vapi_msg_map_add_del_rule_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_map_add_del_rule>(vapi_msg_map_add_del_rule *msg)
{
  vapi_msg_map_add_del_rule_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_map_add_del_rule>()
{
  return ::vapi_msg_id_map_add_del_rule; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_map_add_del_rule>>()
{
  return ::vapi_msg_id_map_add_del_rule; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_map_add_del_rule()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_map_add_del_rule>(vapi_msg_id_map_add_del_rule);
}

template <> inline vapi_msg_map_add_del_rule* vapi_alloc<vapi_msg_map_add_del_rule>(Connection &con)
{
  vapi_msg_map_add_del_rule* result = vapi_alloc_map_add_del_rule(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_map_add_del_rule>;

template class Request<vapi_msg_map_add_del_rule, vapi_msg_map_add_del_rule_reply>;

using Map_add_del_rule = Request<vapi_msg_map_add_del_rule, vapi_msg_map_add_del_rule_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_map_add_del_rule_reply>(vapi_msg_map_add_del_rule_reply *msg)
{
  vapi_msg_map_add_del_rule_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_map_add_del_rule_reply>(vapi_msg_map_add_del_rule_reply *msg)
{
  vapi_msg_map_add_del_rule_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_map_add_del_rule_reply>()
{
  return ::vapi_msg_id_map_add_del_rule_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_map_add_del_rule_reply>>()
{
  return ::vapi_msg_id_map_add_del_rule_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_map_add_del_rule_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_map_add_del_rule_reply>(vapi_msg_id_map_add_del_rule_reply);
}

template class Msg<vapi_msg_map_add_del_rule_reply>;

using Map_add_del_rule_reply = Msg<vapi_msg_map_add_del_rule_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_map_domains_get>(vapi_msg_map_domains_get *msg)
{
  vapi_msg_map_domains_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_map_domains_get>(vapi_msg_map_domains_get *msg)
{
  vapi_msg_map_domains_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_map_domains_get>()
{
  return ::vapi_msg_id_map_domains_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_map_domains_get>>()
{
  return ::vapi_msg_id_map_domains_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_map_domains_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_map_domains_get>(vapi_msg_id_map_domains_get);
}

template <> inline vapi_msg_map_domains_get* vapi_alloc<vapi_msg_map_domains_get>(Connection &con)
{
  vapi_msg_map_domains_get* result = vapi_alloc_map_domains_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_map_domains_get>;

template class Stream<vapi_msg_map_domains_get, vapi_msg_map_domains_get_reply, vapi_msg_map_domain_details>;

using Map_domains_get = Stream<vapi_msg_map_domains_get, vapi_msg_map_domains_get_reply, vapi_msg_map_domain_details>;

template <> inline void vapi_swap_to_be<vapi_msg_map_domains_get_reply>(vapi_msg_map_domains_get_reply *msg)
{
  vapi_msg_map_domains_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_map_domains_get_reply>(vapi_msg_map_domains_get_reply *msg)
{
  vapi_msg_map_domains_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_map_domains_get_reply>()
{
  return ::vapi_msg_id_map_domains_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_map_domains_get_reply>>()
{
  return ::vapi_msg_id_map_domains_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_map_domains_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_map_domains_get_reply>(vapi_msg_id_map_domains_get_reply);
}

template class Msg<vapi_msg_map_domains_get_reply>;

using Map_domains_get_reply = Msg<vapi_msg_map_domains_get_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_map_domain_dump>(vapi_msg_map_domain_dump *msg)
{
  vapi_msg_map_domain_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_map_domain_dump>(vapi_msg_map_domain_dump *msg)
{
  vapi_msg_map_domain_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_map_domain_dump>()
{
  return ::vapi_msg_id_map_domain_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_map_domain_dump>>()
{
  return ::vapi_msg_id_map_domain_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_map_domain_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_map_domain_dump>(vapi_msg_id_map_domain_dump);
}

template <> inline vapi_msg_map_domain_dump* vapi_alloc<vapi_msg_map_domain_dump>(Connection &con)
{
  vapi_msg_map_domain_dump* result = vapi_alloc_map_domain_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_map_domain_dump>;

template class Dump<vapi_msg_map_domain_dump, vapi_msg_map_domain_details>;

using Map_domain_dump = Dump<vapi_msg_map_domain_dump, vapi_msg_map_domain_details>;

template <> inline void vapi_swap_to_be<vapi_msg_map_domain_details>(vapi_msg_map_domain_details *msg)
{
  vapi_msg_map_domain_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_map_domain_details>(vapi_msg_map_domain_details *msg)
{
  vapi_msg_map_domain_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_map_domain_details>()
{
  return ::vapi_msg_id_map_domain_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_map_domain_details>>()
{
  return ::vapi_msg_id_map_domain_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_map_domain_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_map_domain_details>(vapi_msg_id_map_domain_details);
}

template class Msg<vapi_msg_map_domain_details>;

using Map_domain_details = Msg<vapi_msg_map_domain_details>;
template <> inline void vapi_swap_to_be<vapi_msg_map_rule_dump>(vapi_msg_map_rule_dump *msg)
{
  vapi_msg_map_rule_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_map_rule_dump>(vapi_msg_map_rule_dump *msg)
{
  vapi_msg_map_rule_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_map_rule_dump>()
{
  return ::vapi_msg_id_map_rule_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_map_rule_dump>>()
{
  return ::vapi_msg_id_map_rule_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_map_rule_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_map_rule_dump>(vapi_msg_id_map_rule_dump);
}

template <> inline vapi_msg_map_rule_dump* vapi_alloc<vapi_msg_map_rule_dump>(Connection &con)
{
  vapi_msg_map_rule_dump* result = vapi_alloc_map_rule_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_map_rule_dump>;

template class Dump<vapi_msg_map_rule_dump, vapi_msg_map_rule_details>;

using Map_rule_dump = Dump<vapi_msg_map_rule_dump, vapi_msg_map_rule_details>;

template <> inline void vapi_swap_to_be<vapi_msg_map_rule_details>(vapi_msg_map_rule_details *msg)
{
  vapi_msg_map_rule_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_map_rule_details>(vapi_msg_map_rule_details *msg)
{
  vapi_msg_map_rule_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_map_rule_details>()
{
  return ::vapi_msg_id_map_rule_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_map_rule_details>>()
{
  return ::vapi_msg_id_map_rule_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_map_rule_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_map_rule_details>(vapi_msg_id_map_rule_details);
}

template class Msg<vapi_msg_map_rule_details>;

using Map_rule_details = Msg<vapi_msg_map_rule_details>;
template <> inline void vapi_swap_to_be<vapi_msg_map_if_enable_disable>(vapi_msg_map_if_enable_disable *msg)
{
  vapi_msg_map_if_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_map_if_enable_disable>(vapi_msg_map_if_enable_disable *msg)
{
  vapi_msg_map_if_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_map_if_enable_disable>()
{
  return ::vapi_msg_id_map_if_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_map_if_enable_disable>>()
{
  return ::vapi_msg_id_map_if_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_map_if_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_map_if_enable_disable>(vapi_msg_id_map_if_enable_disable);
}

template <> inline vapi_msg_map_if_enable_disable* vapi_alloc<vapi_msg_map_if_enable_disable>(Connection &con)
{
  vapi_msg_map_if_enable_disable* result = vapi_alloc_map_if_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_map_if_enable_disable>;

template class Request<vapi_msg_map_if_enable_disable, vapi_msg_map_if_enable_disable_reply>;

using Map_if_enable_disable = Request<vapi_msg_map_if_enable_disable, vapi_msg_map_if_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_map_if_enable_disable_reply>(vapi_msg_map_if_enable_disable_reply *msg)
{
  vapi_msg_map_if_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_map_if_enable_disable_reply>(vapi_msg_map_if_enable_disable_reply *msg)
{
  vapi_msg_map_if_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_map_if_enable_disable_reply>()
{
  return ::vapi_msg_id_map_if_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_map_if_enable_disable_reply>>()
{
  return ::vapi_msg_id_map_if_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_map_if_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_map_if_enable_disable_reply>(vapi_msg_id_map_if_enable_disable_reply);
}

template class Msg<vapi_msg_map_if_enable_disable_reply>;

using Map_if_enable_disable_reply = Msg<vapi_msg_map_if_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_map_summary_stats>(vapi_msg_map_summary_stats *msg)
{
  vapi_msg_map_summary_stats_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_map_summary_stats>(vapi_msg_map_summary_stats *msg)
{
  vapi_msg_map_summary_stats_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_map_summary_stats>()
{
  return ::vapi_msg_id_map_summary_stats; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_map_summary_stats>>()
{
  return ::vapi_msg_id_map_summary_stats; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_map_summary_stats()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_map_summary_stats>(vapi_msg_id_map_summary_stats);
}

template <> inline vapi_msg_map_summary_stats* vapi_alloc<vapi_msg_map_summary_stats>(Connection &con)
{
  vapi_msg_map_summary_stats* result = vapi_alloc_map_summary_stats(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_map_summary_stats>;

template class Request<vapi_msg_map_summary_stats, vapi_msg_map_summary_stats_reply>;

using Map_summary_stats = Request<vapi_msg_map_summary_stats, vapi_msg_map_summary_stats_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_map_summary_stats_reply>(vapi_msg_map_summary_stats_reply *msg)
{
  vapi_msg_map_summary_stats_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_map_summary_stats_reply>(vapi_msg_map_summary_stats_reply *msg)
{
  vapi_msg_map_summary_stats_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_map_summary_stats_reply>()
{
  return ::vapi_msg_id_map_summary_stats_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_map_summary_stats_reply>>()
{
  return ::vapi_msg_id_map_summary_stats_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_map_summary_stats_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_map_summary_stats_reply>(vapi_msg_id_map_summary_stats_reply);
}

template class Msg<vapi_msg_map_summary_stats_reply>;

using Map_summary_stats_reply = Msg<vapi_msg_map_summary_stats_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_map_param_set_fragmentation>(vapi_msg_map_param_set_fragmentation *msg)
{
  vapi_msg_map_param_set_fragmentation_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_map_param_set_fragmentation>(vapi_msg_map_param_set_fragmentation *msg)
{
  vapi_msg_map_param_set_fragmentation_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_map_param_set_fragmentation>()
{
  return ::vapi_msg_id_map_param_set_fragmentation; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_map_param_set_fragmentation>>()
{
  return ::vapi_msg_id_map_param_set_fragmentation; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_map_param_set_fragmentation()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_map_param_set_fragmentation>(vapi_msg_id_map_param_set_fragmentation);
}

template <> inline vapi_msg_map_param_set_fragmentation* vapi_alloc<vapi_msg_map_param_set_fragmentation>(Connection &con)
{
  vapi_msg_map_param_set_fragmentation* result = vapi_alloc_map_param_set_fragmentation(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_map_param_set_fragmentation>;

template class Request<vapi_msg_map_param_set_fragmentation, vapi_msg_map_param_set_fragmentation_reply>;

using Map_param_set_fragmentation = Request<vapi_msg_map_param_set_fragmentation, vapi_msg_map_param_set_fragmentation_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_map_param_set_fragmentation_reply>(vapi_msg_map_param_set_fragmentation_reply *msg)
{
  vapi_msg_map_param_set_fragmentation_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_map_param_set_fragmentation_reply>(vapi_msg_map_param_set_fragmentation_reply *msg)
{
  vapi_msg_map_param_set_fragmentation_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_map_param_set_fragmentation_reply>()
{
  return ::vapi_msg_id_map_param_set_fragmentation_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_map_param_set_fragmentation_reply>>()
{
  return ::vapi_msg_id_map_param_set_fragmentation_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_map_param_set_fragmentation_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_map_param_set_fragmentation_reply>(vapi_msg_id_map_param_set_fragmentation_reply);
}

template class Msg<vapi_msg_map_param_set_fragmentation_reply>;

using Map_param_set_fragmentation_reply = Msg<vapi_msg_map_param_set_fragmentation_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_map_param_set_icmp>(vapi_msg_map_param_set_icmp *msg)
{
  vapi_msg_map_param_set_icmp_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_map_param_set_icmp>(vapi_msg_map_param_set_icmp *msg)
{
  vapi_msg_map_param_set_icmp_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_map_param_set_icmp>()
{
  return ::vapi_msg_id_map_param_set_icmp; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_map_param_set_icmp>>()
{
  return ::vapi_msg_id_map_param_set_icmp; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_map_param_set_icmp()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_map_param_set_icmp>(vapi_msg_id_map_param_set_icmp);
}

template <> inline vapi_msg_map_param_set_icmp* vapi_alloc<vapi_msg_map_param_set_icmp>(Connection &con)
{
  vapi_msg_map_param_set_icmp* result = vapi_alloc_map_param_set_icmp(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_map_param_set_icmp>;

template class Request<vapi_msg_map_param_set_icmp, vapi_msg_map_param_set_icmp_reply>;

using Map_param_set_icmp = Request<vapi_msg_map_param_set_icmp, vapi_msg_map_param_set_icmp_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_map_param_set_icmp_reply>(vapi_msg_map_param_set_icmp_reply *msg)
{
  vapi_msg_map_param_set_icmp_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_map_param_set_icmp_reply>(vapi_msg_map_param_set_icmp_reply *msg)
{
  vapi_msg_map_param_set_icmp_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_map_param_set_icmp_reply>()
{
  return ::vapi_msg_id_map_param_set_icmp_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_map_param_set_icmp_reply>>()
{
  return ::vapi_msg_id_map_param_set_icmp_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_map_param_set_icmp_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_map_param_set_icmp_reply>(vapi_msg_id_map_param_set_icmp_reply);
}

template class Msg<vapi_msg_map_param_set_icmp_reply>;

using Map_param_set_icmp_reply = Msg<vapi_msg_map_param_set_icmp_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_map_param_set_icmp6>(vapi_msg_map_param_set_icmp6 *msg)
{
  vapi_msg_map_param_set_icmp6_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_map_param_set_icmp6>(vapi_msg_map_param_set_icmp6 *msg)
{
  vapi_msg_map_param_set_icmp6_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_map_param_set_icmp6>()
{
  return ::vapi_msg_id_map_param_set_icmp6; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_map_param_set_icmp6>>()
{
  return ::vapi_msg_id_map_param_set_icmp6; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_map_param_set_icmp6()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_map_param_set_icmp6>(vapi_msg_id_map_param_set_icmp6);
}

template <> inline vapi_msg_map_param_set_icmp6* vapi_alloc<vapi_msg_map_param_set_icmp6>(Connection &con)
{
  vapi_msg_map_param_set_icmp6* result = vapi_alloc_map_param_set_icmp6(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_map_param_set_icmp6>;

template class Request<vapi_msg_map_param_set_icmp6, vapi_msg_map_param_set_icmp6_reply>;

using Map_param_set_icmp6 = Request<vapi_msg_map_param_set_icmp6, vapi_msg_map_param_set_icmp6_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_map_param_set_icmp6_reply>(vapi_msg_map_param_set_icmp6_reply *msg)
{
  vapi_msg_map_param_set_icmp6_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_map_param_set_icmp6_reply>(vapi_msg_map_param_set_icmp6_reply *msg)
{
  vapi_msg_map_param_set_icmp6_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_map_param_set_icmp6_reply>()
{
  return ::vapi_msg_id_map_param_set_icmp6_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_map_param_set_icmp6_reply>>()
{
  return ::vapi_msg_id_map_param_set_icmp6_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_map_param_set_icmp6_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_map_param_set_icmp6_reply>(vapi_msg_id_map_param_set_icmp6_reply);
}

template class Msg<vapi_msg_map_param_set_icmp6_reply>;

using Map_param_set_icmp6_reply = Msg<vapi_msg_map_param_set_icmp6_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_map_param_add_del_pre_resolve>(vapi_msg_map_param_add_del_pre_resolve *msg)
{
  vapi_msg_map_param_add_del_pre_resolve_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_map_param_add_del_pre_resolve>(vapi_msg_map_param_add_del_pre_resolve *msg)
{
  vapi_msg_map_param_add_del_pre_resolve_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_map_param_add_del_pre_resolve>()
{
  return ::vapi_msg_id_map_param_add_del_pre_resolve; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_map_param_add_del_pre_resolve>>()
{
  return ::vapi_msg_id_map_param_add_del_pre_resolve; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_map_param_add_del_pre_resolve()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_map_param_add_del_pre_resolve>(vapi_msg_id_map_param_add_del_pre_resolve);
}

template <> inline vapi_msg_map_param_add_del_pre_resolve* vapi_alloc<vapi_msg_map_param_add_del_pre_resolve>(Connection &con)
{
  vapi_msg_map_param_add_del_pre_resolve* result = vapi_alloc_map_param_add_del_pre_resolve(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_map_param_add_del_pre_resolve>;

template class Request<vapi_msg_map_param_add_del_pre_resolve, vapi_msg_map_param_add_del_pre_resolve_reply>;

using Map_param_add_del_pre_resolve = Request<vapi_msg_map_param_add_del_pre_resolve, vapi_msg_map_param_add_del_pre_resolve_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_map_param_add_del_pre_resolve_reply>(vapi_msg_map_param_add_del_pre_resolve_reply *msg)
{
  vapi_msg_map_param_add_del_pre_resolve_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_map_param_add_del_pre_resolve_reply>(vapi_msg_map_param_add_del_pre_resolve_reply *msg)
{
  vapi_msg_map_param_add_del_pre_resolve_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_map_param_add_del_pre_resolve_reply>()
{
  return ::vapi_msg_id_map_param_add_del_pre_resolve_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_map_param_add_del_pre_resolve_reply>>()
{
  return ::vapi_msg_id_map_param_add_del_pre_resolve_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_map_param_add_del_pre_resolve_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_map_param_add_del_pre_resolve_reply>(vapi_msg_id_map_param_add_del_pre_resolve_reply);
}

template class Msg<vapi_msg_map_param_add_del_pre_resolve_reply>;

using Map_param_add_del_pre_resolve_reply = Msg<vapi_msg_map_param_add_del_pre_resolve_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_map_param_set_security_check>(vapi_msg_map_param_set_security_check *msg)
{
  vapi_msg_map_param_set_security_check_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_map_param_set_security_check>(vapi_msg_map_param_set_security_check *msg)
{
  vapi_msg_map_param_set_security_check_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_map_param_set_security_check>()
{
  return ::vapi_msg_id_map_param_set_security_check; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_map_param_set_security_check>>()
{
  return ::vapi_msg_id_map_param_set_security_check; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_map_param_set_security_check()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_map_param_set_security_check>(vapi_msg_id_map_param_set_security_check);
}

template <> inline vapi_msg_map_param_set_security_check* vapi_alloc<vapi_msg_map_param_set_security_check>(Connection &con)
{
  vapi_msg_map_param_set_security_check* result = vapi_alloc_map_param_set_security_check(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_map_param_set_security_check>;

template class Request<vapi_msg_map_param_set_security_check, vapi_msg_map_param_set_security_check_reply>;

using Map_param_set_security_check = Request<vapi_msg_map_param_set_security_check, vapi_msg_map_param_set_security_check_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_map_param_set_security_check_reply>(vapi_msg_map_param_set_security_check_reply *msg)
{
  vapi_msg_map_param_set_security_check_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_map_param_set_security_check_reply>(vapi_msg_map_param_set_security_check_reply *msg)
{
  vapi_msg_map_param_set_security_check_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_map_param_set_security_check_reply>()
{
  return ::vapi_msg_id_map_param_set_security_check_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_map_param_set_security_check_reply>>()
{
  return ::vapi_msg_id_map_param_set_security_check_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_map_param_set_security_check_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_map_param_set_security_check_reply>(vapi_msg_id_map_param_set_security_check_reply);
}

template class Msg<vapi_msg_map_param_set_security_check_reply>;

using Map_param_set_security_check_reply = Msg<vapi_msg_map_param_set_security_check_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_map_param_set_traffic_class>(vapi_msg_map_param_set_traffic_class *msg)
{
  vapi_msg_map_param_set_traffic_class_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_map_param_set_traffic_class>(vapi_msg_map_param_set_traffic_class *msg)
{
  vapi_msg_map_param_set_traffic_class_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_map_param_set_traffic_class>()
{
  return ::vapi_msg_id_map_param_set_traffic_class; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_map_param_set_traffic_class>>()
{
  return ::vapi_msg_id_map_param_set_traffic_class; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_map_param_set_traffic_class()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_map_param_set_traffic_class>(vapi_msg_id_map_param_set_traffic_class);
}

template <> inline vapi_msg_map_param_set_traffic_class* vapi_alloc<vapi_msg_map_param_set_traffic_class>(Connection &con)
{
  vapi_msg_map_param_set_traffic_class* result = vapi_alloc_map_param_set_traffic_class(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_map_param_set_traffic_class>;

template class Request<vapi_msg_map_param_set_traffic_class, vapi_msg_map_param_set_traffic_class_reply>;

using Map_param_set_traffic_class = Request<vapi_msg_map_param_set_traffic_class, vapi_msg_map_param_set_traffic_class_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_map_param_set_traffic_class_reply>(vapi_msg_map_param_set_traffic_class_reply *msg)
{
  vapi_msg_map_param_set_traffic_class_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_map_param_set_traffic_class_reply>(vapi_msg_map_param_set_traffic_class_reply *msg)
{
  vapi_msg_map_param_set_traffic_class_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_map_param_set_traffic_class_reply>()
{
  return ::vapi_msg_id_map_param_set_traffic_class_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_map_param_set_traffic_class_reply>>()
{
  return ::vapi_msg_id_map_param_set_traffic_class_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_map_param_set_traffic_class_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_map_param_set_traffic_class_reply>(vapi_msg_id_map_param_set_traffic_class_reply);
}

template class Msg<vapi_msg_map_param_set_traffic_class_reply>;

using Map_param_set_traffic_class_reply = Msg<vapi_msg_map_param_set_traffic_class_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_map_param_set_tcp>(vapi_msg_map_param_set_tcp *msg)
{
  vapi_msg_map_param_set_tcp_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_map_param_set_tcp>(vapi_msg_map_param_set_tcp *msg)
{
  vapi_msg_map_param_set_tcp_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_map_param_set_tcp>()
{
  return ::vapi_msg_id_map_param_set_tcp; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_map_param_set_tcp>>()
{
  return ::vapi_msg_id_map_param_set_tcp; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_map_param_set_tcp()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_map_param_set_tcp>(vapi_msg_id_map_param_set_tcp);
}

template <> inline vapi_msg_map_param_set_tcp* vapi_alloc<vapi_msg_map_param_set_tcp>(Connection &con)
{
  vapi_msg_map_param_set_tcp* result = vapi_alloc_map_param_set_tcp(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_map_param_set_tcp>;

template class Request<vapi_msg_map_param_set_tcp, vapi_msg_map_param_set_tcp_reply>;

using Map_param_set_tcp = Request<vapi_msg_map_param_set_tcp, vapi_msg_map_param_set_tcp_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_map_param_set_tcp_reply>(vapi_msg_map_param_set_tcp_reply *msg)
{
  vapi_msg_map_param_set_tcp_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_map_param_set_tcp_reply>(vapi_msg_map_param_set_tcp_reply *msg)
{
  vapi_msg_map_param_set_tcp_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_map_param_set_tcp_reply>()
{
  return ::vapi_msg_id_map_param_set_tcp_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_map_param_set_tcp_reply>>()
{
  return ::vapi_msg_id_map_param_set_tcp_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_map_param_set_tcp_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_map_param_set_tcp_reply>(vapi_msg_id_map_param_set_tcp_reply);
}

template class Msg<vapi_msg_map_param_set_tcp_reply>;

using Map_param_set_tcp_reply = Msg<vapi_msg_map_param_set_tcp_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_map_param_get>(vapi_msg_map_param_get *msg)
{
  vapi_msg_map_param_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_map_param_get>(vapi_msg_map_param_get *msg)
{
  vapi_msg_map_param_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_map_param_get>()
{
  return ::vapi_msg_id_map_param_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_map_param_get>>()
{
  return ::vapi_msg_id_map_param_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_map_param_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_map_param_get>(vapi_msg_id_map_param_get);
}

template <> inline vapi_msg_map_param_get* vapi_alloc<vapi_msg_map_param_get>(Connection &con)
{
  vapi_msg_map_param_get* result = vapi_alloc_map_param_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_map_param_get>;

template class Request<vapi_msg_map_param_get, vapi_msg_map_param_get_reply>;

using Map_param_get = Request<vapi_msg_map_param_get, vapi_msg_map_param_get_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_map_param_get_reply>(vapi_msg_map_param_get_reply *msg)
{
  vapi_msg_map_param_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_map_param_get_reply>(vapi_msg_map_param_get_reply *msg)
{
  vapi_msg_map_param_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_map_param_get_reply>()
{
  return ::vapi_msg_id_map_param_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_map_param_get_reply>>()
{
  return ::vapi_msg_id_map_param_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_map_param_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_map_param_get_reply>(vapi_msg_id_map_param_get_reply);
}

template class Msg<vapi_msg_map_param_get_reply>;

using Map_param_get_reply = Msg<vapi_msg_map_param_get_reply>;
}
#endif
