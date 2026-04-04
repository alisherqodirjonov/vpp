#ifndef __included_hpp_stn_api_json
#define __included_hpp_stn_api_json

#include <vapi/vapi.hpp>
#include <vapi/stn.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_stn_add_del_rule>(vapi_msg_stn_add_del_rule *msg)
{
  vapi_msg_stn_add_del_rule_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_stn_add_del_rule>(vapi_msg_stn_add_del_rule *msg)
{
  vapi_msg_stn_add_del_rule_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_stn_add_del_rule>()
{
  return ::vapi_msg_id_stn_add_del_rule; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_stn_add_del_rule>>()
{
  return ::vapi_msg_id_stn_add_del_rule; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_stn_add_del_rule()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_stn_add_del_rule>(vapi_msg_id_stn_add_del_rule);
}

template <> inline vapi_msg_stn_add_del_rule* vapi_alloc<vapi_msg_stn_add_del_rule>(Connection &con)
{
  vapi_msg_stn_add_del_rule* result = vapi_alloc_stn_add_del_rule(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_stn_add_del_rule>;

template class Request<vapi_msg_stn_add_del_rule, vapi_msg_stn_add_del_rule_reply>;

using Stn_add_del_rule = Request<vapi_msg_stn_add_del_rule, vapi_msg_stn_add_del_rule_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_stn_add_del_rule_reply>(vapi_msg_stn_add_del_rule_reply *msg)
{
  vapi_msg_stn_add_del_rule_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_stn_add_del_rule_reply>(vapi_msg_stn_add_del_rule_reply *msg)
{
  vapi_msg_stn_add_del_rule_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_stn_add_del_rule_reply>()
{
  return ::vapi_msg_id_stn_add_del_rule_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_stn_add_del_rule_reply>>()
{
  return ::vapi_msg_id_stn_add_del_rule_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_stn_add_del_rule_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_stn_add_del_rule_reply>(vapi_msg_id_stn_add_del_rule_reply);
}

template class Msg<vapi_msg_stn_add_del_rule_reply>;

using Stn_add_del_rule_reply = Msg<vapi_msg_stn_add_del_rule_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_stn_rules_dump>(vapi_msg_stn_rules_dump *msg)
{
  vapi_msg_stn_rules_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_stn_rules_dump>(vapi_msg_stn_rules_dump *msg)
{
  vapi_msg_stn_rules_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_stn_rules_dump>()
{
  return ::vapi_msg_id_stn_rules_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_stn_rules_dump>>()
{
  return ::vapi_msg_id_stn_rules_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_stn_rules_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_stn_rules_dump>(vapi_msg_id_stn_rules_dump);
}

template <> inline vapi_msg_stn_rules_dump* vapi_alloc<vapi_msg_stn_rules_dump>(Connection &con)
{
  vapi_msg_stn_rules_dump* result = vapi_alloc_stn_rules_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_stn_rules_dump>;

template class Dump<vapi_msg_stn_rules_dump, vapi_msg_stn_rules_details>;

using Stn_rules_dump = Dump<vapi_msg_stn_rules_dump, vapi_msg_stn_rules_details>;

template <> inline void vapi_swap_to_be<vapi_msg_stn_rules_details>(vapi_msg_stn_rules_details *msg)
{
  vapi_msg_stn_rules_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_stn_rules_details>(vapi_msg_stn_rules_details *msg)
{
  vapi_msg_stn_rules_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_stn_rules_details>()
{
  return ::vapi_msg_id_stn_rules_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_stn_rules_details>>()
{
  return ::vapi_msg_id_stn_rules_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_stn_rules_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_stn_rules_details>(vapi_msg_id_stn_rules_details);
}

template class Msg<vapi_msg_stn_rules_details>;

using Stn_rules_details = Msg<vapi_msg_stn_rules_details>;
}
#endif
