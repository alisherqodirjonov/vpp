#ifndef __included_hpp_bond_api_json
#define __included_hpp_bond_api_json

#include <vapi/vapi.hpp>
#include <vapi/bond.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_bond_create>(vapi_msg_bond_create *msg)
{
  vapi_msg_bond_create_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bond_create>(vapi_msg_bond_create *msg)
{
  vapi_msg_bond_create_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bond_create>()
{
  return ::vapi_msg_id_bond_create; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bond_create>>()
{
  return ::vapi_msg_id_bond_create; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bond_create()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bond_create>(vapi_msg_id_bond_create);
}

template <> inline vapi_msg_bond_create* vapi_alloc<vapi_msg_bond_create>(Connection &con)
{
  vapi_msg_bond_create* result = vapi_alloc_bond_create(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bond_create>;

template class Request<vapi_msg_bond_create, vapi_msg_bond_create_reply>;

using Bond_create = Request<vapi_msg_bond_create, vapi_msg_bond_create_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_bond_create_reply>(vapi_msg_bond_create_reply *msg)
{
  vapi_msg_bond_create_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bond_create_reply>(vapi_msg_bond_create_reply *msg)
{
  vapi_msg_bond_create_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bond_create_reply>()
{
  return ::vapi_msg_id_bond_create_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bond_create_reply>>()
{
  return ::vapi_msg_id_bond_create_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bond_create_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bond_create_reply>(vapi_msg_id_bond_create_reply);
}

template class Msg<vapi_msg_bond_create_reply>;

using Bond_create_reply = Msg<vapi_msg_bond_create_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bond_create2>(vapi_msg_bond_create2 *msg)
{
  vapi_msg_bond_create2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bond_create2>(vapi_msg_bond_create2 *msg)
{
  vapi_msg_bond_create2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bond_create2>()
{
  return ::vapi_msg_id_bond_create2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bond_create2>>()
{
  return ::vapi_msg_id_bond_create2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bond_create2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bond_create2>(vapi_msg_id_bond_create2);
}

template <> inline vapi_msg_bond_create2* vapi_alloc<vapi_msg_bond_create2>(Connection &con)
{
  vapi_msg_bond_create2* result = vapi_alloc_bond_create2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bond_create2>;

template class Request<vapi_msg_bond_create2, vapi_msg_bond_create2_reply>;

using Bond_create2 = Request<vapi_msg_bond_create2, vapi_msg_bond_create2_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_bond_create2_reply>(vapi_msg_bond_create2_reply *msg)
{
  vapi_msg_bond_create2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bond_create2_reply>(vapi_msg_bond_create2_reply *msg)
{
  vapi_msg_bond_create2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bond_create2_reply>()
{
  return ::vapi_msg_id_bond_create2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bond_create2_reply>>()
{
  return ::vapi_msg_id_bond_create2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bond_create2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bond_create2_reply>(vapi_msg_id_bond_create2_reply);
}

template class Msg<vapi_msg_bond_create2_reply>;

using Bond_create2_reply = Msg<vapi_msg_bond_create2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bond_delete>(vapi_msg_bond_delete *msg)
{
  vapi_msg_bond_delete_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bond_delete>(vapi_msg_bond_delete *msg)
{
  vapi_msg_bond_delete_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bond_delete>()
{
  return ::vapi_msg_id_bond_delete; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bond_delete>>()
{
  return ::vapi_msg_id_bond_delete; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bond_delete()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bond_delete>(vapi_msg_id_bond_delete);
}

template <> inline vapi_msg_bond_delete* vapi_alloc<vapi_msg_bond_delete>(Connection &con)
{
  vapi_msg_bond_delete* result = vapi_alloc_bond_delete(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bond_delete>;

template class Request<vapi_msg_bond_delete, vapi_msg_bond_delete_reply>;

using Bond_delete = Request<vapi_msg_bond_delete, vapi_msg_bond_delete_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_bond_delete_reply>(vapi_msg_bond_delete_reply *msg)
{
  vapi_msg_bond_delete_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bond_delete_reply>(vapi_msg_bond_delete_reply *msg)
{
  vapi_msg_bond_delete_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bond_delete_reply>()
{
  return ::vapi_msg_id_bond_delete_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bond_delete_reply>>()
{
  return ::vapi_msg_id_bond_delete_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bond_delete_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bond_delete_reply>(vapi_msg_id_bond_delete_reply);
}

template class Msg<vapi_msg_bond_delete_reply>;

using Bond_delete_reply = Msg<vapi_msg_bond_delete_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bond_enslave>(vapi_msg_bond_enslave *msg)
{
  vapi_msg_bond_enslave_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bond_enslave>(vapi_msg_bond_enslave *msg)
{
  vapi_msg_bond_enslave_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bond_enslave>()
{
  return ::vapi_msg_id_bond_enslave; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bond_enslave>>()
{
  return ::vapi_msg_id_bond_enslave; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bond_enslave()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bond_enslave>(vapi_msg_id_bond_enslave);
}

template <> inline vapi_msg_bond_enslave* vapi_alloc<vapi_msg_bond_enslave>(Connection &con)
{
  vapi_msg_bond_enslave* result = vapi_alloc_bond_enslave(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bond_enslave>;

template class Request<vapi_msg_bond_enslave, vapi_msg_bond_enslave_reply>;

using Bond_enslave = Request<vapi_msg_bond_enslave, vapi_msg_bond_enslave_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_bond_enslave_reply>(vapi_msg_bond_enslave_reply *msg)
{
  vapi_msg_bond_enslave_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bond_enslave_reply>(vapi_msg_bond_enslave_reply *msg)
{
  vapi_msg_bond_enslave_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bond_enslave_reply>()
{
  return ::vapi_msg_id_bond_enslave_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bond_enslave_reply>>()
{
  return ::vapi_msg_id_bond_enslave_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bond_enslave_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bond_enslave_reply>(vapi_msg_id_bond_enslave_reply);
}

template class Msg<vapi_msg_bond_enslave_reply>;

using Bond_enslave_reply = Msg<vapi_msg_bond_enslave_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bond_add_member>(vapi_msg_bond_add_member *msg)
{
  vapi_msg_bond_add_member_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bond_add_member>(vapi_msg_bond_add_member *msg)
{
  vapi_msg_bond_add_member_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bond_add_member>()
{
  return ::vapi_msg_id_bond_add_member; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bond_add_member>>()
{
  return ::vapi_msg_id_bond_add_member; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bond_add_member()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bond_add_member>(vapi_msg_id_bond_add_member);
}

template <> inline vapi_msg_bond_add_member* vapi_alloc<vapi_msg_bond_add_member>(Connection &con)
{
  vapi_msg_bond_add_member* result = vapi_alloc_bond_add_member(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bond_add_member>;

template class Request<vapi_msg_bond_add_member, vapi_msg_bond_add_member_reply>;

using Bond_add_member = Request<vapi_msg_bond_add_member, vapi_msg_bond_add_member_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_bond_add_member_reply>(vapi_msg_bond_add_member_reply *msg)
{
  vapi_msg_bond_add_member_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bond_add_member_reply>(vapi_msg_bond_add_member_reply *msg)
{
  vapi_msg_bond_add_member_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bond_add_member_reply>()
{
  return ::vapi_msg_id_bond_add_member_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bond_add_member_reply>>()
{
  return ::vapi_msg_id_bond_add_member_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bond_add_member_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bond_add_member_reply>(vapi_msg_id_bond_add_member_reply);
}

template class Msg<vapi_msg_bond_add_member_reply>;

using Bond_add_member_reply = Msg<vapi_msg_bond_add_member_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bond_detach_slave>(vapi_msg_bond_detach_slave *msg)
{
  vapi_msg_bond_detach_slave_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bond_detach_slave>(vapi_msg_bond_detach_slave *msg)
{
  vapi_msg_bond_detach_slave_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bond_detach_slave>()
{
  return ::vapi_msg_id_bond_detach_slave; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bond_detach_slave>>()
{
  return ::vapi_msg_id_bond_detach_slave; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bond_detach_slave()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bond_detach_slave>(vapi_msg_id_bond_detach_slave);
}

template <> inline vapi_msg_bond_detach_slave* vapi_alloc<vapi_msg_bond_detach_slave>(Connection &con)
{
  vapi_msg_bond_detach_slave* result = vapi_alloc_bond_detach_slave(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bond_detach_slave>;

template class Request<vapi_msg_bond_detach_slave, vapi_msg_bond_detach_slave_reply>;

using Bond_detach_slave = Request<vapi_msg_bond_detach_slave, vapi_msg_bond_detach_slave_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_bond_detach_slave_reply>(vapi_msg_bond_detach_slave_reply *msg)
{
  vapi_msg_bond_detach_slave_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bond_detach_slave_reply>(vapi_msg_bond_detach_slave_reply *msg)
{
  vapi_msg_bond_detach_slave_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bond_detach_slave_reply>()
{
  return ::vapi_msg_id_bond_detach_slave_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bond_detach_slave_reply>>()
{
  return ::vapi_msg_id_bond_detach_slave_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bond_detach_slave_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bond_detach_slave_reply>(vapi_msg_id_bond_detach_slave_reply);
}

template class Msg<vapi_msg_bond_detach_slave_reply>;

using Bond_detach_slave_reply = Msg<vapi_msg_bond_detach_slave_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bond_detach_member>(vapi_msg_bond_detach_member *msg)
{
  vapi_msg_bond_detach_member_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bond_detach_member>(vapi_msg_bond_detach_member *msg)
{
  vapi_msg_bond_detach_member_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bond_detach_member>()
{
  return ::vapi_msg_id_bond_detach_member; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bond_detach_member>>()
{
  return ::vapi_msg_id_bond_detach_member; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bond_detach_member()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bond_detach_member>(vapi_msg_id_bond_detach_member);
}

template <> inline vapi_msg_bond_detach_member* vapi_alloc<vapi_msg_bond_detach_member>(Connection &con)
{
  vapi_msg_bond_detach_member* result = vapi_alloc_bond_detach_member(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bond_detach_member>;

template class Request<vapi_msg_bond_detach_member, vapi_msg_bond_detach_member_reply>;

using Bond_detach_member = Request<vapi_msg_bond_detach_member, vapi_msg_bond_detach_member_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_bond_detach_member_reply>(vapi_msg_bond_detach_member_reply *msg)
{
  vapi_msg_bond_detach_member_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bond_detach_member_reply>(vapi_msg_bond_detach_member_reply *msg)
{
  vapi_msg_bond_detach_member_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bond_detach_member_reply>()
{
  return ::vapi_msg_id_bond_detach_member_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bond_detach_member_reply>>()
{
  return ::vapi_msg_id_bond_detach_member_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bond_detach_member_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bond_detach_member_reply>(vapi_msg_id_bond_detach_member_reply);
}

template class Msg<vapi_msg_bond_detach_member_reply>;

using Bond_detach_member_reply = Msg<vapi_msg_bond_detach_member_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_bond_dump>(vapi_msg_sw_interface_bond_dump *msg)
{
  vapi_msg_sw_interface_bond_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_bond_dump>(vapi_msg_sw_interface_bond_dump *msg)
{
  vapi_msg_sw_interface_bond_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_bond_dump>()
{
  return ::vapi_msg_id_sw_interface_bond_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_bond_dump>>()
{
  return ::vapi_msg_id_sw_interface_bond_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_bond_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_bond_dump>(vapi_msg_id_sw_interface_bond_dump);
}

template <> inline vapi_msg_sw_interface_bond_dump* vapi_alloc<vapi_msg_sw_interface_bond_dump>(Connection &con)
{
  vapi_msg_sw_interface_bond_dump* result = vapi_alloc_sw_interface_bond_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_bond_dump>;

template class Dump<vapi_msg_sw_interface_bond_dump, vapi_msg_sw_interface_bond_details>;

using Sw_interface_bond_dump = Dump<vapi_msg_sw_interface_bond_dump, vapi_msg_sw_interface_bond_details>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_bond_details>(vapi_msg_sw_interface_bond_details *msg)
{
  vapi_msg_sw_interface_bond_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_bond_details>(vapi_msg_sw_interface_bond_details *msg)
{
  vapi_msg_sw_interface_bond_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_bond_details>()
{
  return ::vapi_msg_id_sw_interface_bond_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_bond_details>>()
{
  return ::vapi_msg_id_sw_interface_bond_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_bond_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_bond_details>(vapi_msg_id_sw_interface_bond_details);
}

template class Msg<vapi_msg_sw_interface_bond_details>;

using Sw_interface_bond_details = Msg<vapi_msg_sw_interface_bond_details>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_bond_interface_dump>(vapi_msg_sw_bond_interface_dump *msg)
{
  vapi_msg_sw_bond_interface_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_bond_interface_dump>(vapi_msg_sw_bond_interface_dump *msg)
{
  vapi_msg_sw_bond_interface_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_bond_interface_dump>()
{
  return ::vapi_msg_id_sw_bond_interface_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_bond_interface_dump>>()
{
  return ::vapi_msg_id_sw_bond_interface_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_bond_interface_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_bond_interface_dump>(vapi_msg_id_sw_bond_interface_dump);
}

template <> inline vapi_msg_sw_bond_interface_dump* vapi_alloc<vapi_msg_sw_bond_interface_dump>(Connection &con)
{
  vapi_msg_sw_bond_interface_dump* result = vapi_alloc_sw_bond_interface_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_bond_interface_dump>;

template class Dump<vapi_msg_sw_bond_interface_dump, vapi_msg_sw_bond_interface_details>;

using Sw_bond_interface_dump = Dump<vapi_msg_sw_bond_interface_dump, vapi_msg_sw_bond_interface_details>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_bond_interface_details>(vapi_msg_sw_bond_interface_details *msg)
{
  vapi_msg_sw_bond_interface_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_bond_interface_details>(vapi_msg_sw_bond_interface_details *msg)
{
  vapi_msg_sw_bond_interface_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_bond_interface_details>()
{
  return ::vapi_msg_id_sw_bond_interface_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_bond_interface_details>>()
{
  return ::vapi_msg_id_sw_bond_interface_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_bond_interface_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_bond_interface_details>(vapi_msg_id_sw_bond_interface_details);
}

template class Msg<vapi_msg_sw_bond_interface_details>;

using Sw_bond_interface_details = Msg<vapi_msg_sw_bond_interface_details>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_slave_dump>(vapi_msg_sw_interface_slave_dump *msg)
{
  vapi_msg_sw_interface_slave_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_slave_dump>(vapi_msg_sw_interface_slave_dump *msg)
{
  vapi_msg_sw_interface_slave_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_slave_dump>()
{
  return ::vapi_msg_id_sw_interface_slave_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_slave_dump>>()
{
  return ::vapi_msg_id_sw_interface_slave_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_slave_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_slave_dump>(vapi_msg_id_sw_interface_slave_dump);
}

template <> inline vapi_msg_sw_interface_slave_dump* vapi_alloc<vapi_msg_sw_interface_slave_dump>(Connection &con)
{
  vapi_msg_sw_interface_slave_dump* result = vapi_alloc_sw_interface_slave_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_slave_dump>;

template class Dump<vapi_msg_sw_interface_slave_dump, vapi_msg_sw_interface_slave_details>;

using Sw_interface_slave_dump = Dump<vapi_msg_sw_interface_slave_dump, vapi_msg_sw_interface_slave_details>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_slave_details>(vapi_msg_sw_interface_slave_details *msg)
{
  vapi_msg_sw_interface_slave_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_slave_details>(vapi_msg_sw_interface_slave_details *msg)
{
  vapi_msg_sw_interface_slave_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_slave_details>()
{
  return ::vapi_msg_id_sw_interface_slave_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_slave_details>>()
{
  return ::vapi_msg_id_sw_interface_slave_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_slave_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_slave_details>(vapi_msg_id_sw_interface_slave_details);
}

template class Msg<vapi_msg_sw_interface_slave_details>;

using Sw_interface_slave_details = Msg<vapi_msg_sw_interface_slave_details>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_member_interface_dump>(vapi_msg_sw_member_interface_dump *msg)
{
  vapi_msg_sw_member_interface_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_member_interface_dump>(vapi_msg_sw_member_interface_dump *msg)
{
  vapi_msg_sw_member_interface_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_member_interface_dump>()
{
  return ::vapi_msg_id_sw_member_interface_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_member_interface_dump>>()
{
  return ::vapi_msg_id_sw_member_interface_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_member_interface_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_member_interface_dump>(vapi_msg_id_sw_member_interface_dump);
}

template <> inline vapi_msg_sw_member_interface_dump* vapi_alloc<vapi_msg_sw_member_interface_dump>(Connection &con)
{
  vapi_msg_sw_member_interface_dump* result = vapi_alloc_sw_member_interface_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_member_interface_dump>;

template class Dump<vapi_msg_sw_member_interface_dump, vapi_msg_sw_member_interface_details>;

using Sw_member_interface_dump = Dump<vapi_msg_sw_member_interface_dump, vapi_msg_sw_member_interface_details>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_member_interface_details>(vapi_msg_sw_member_interface_details *msg)
{
  vapi_msg_sw_member_interface_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_member_interface_details>(vapi_msg_sw_member_interface_details *msg)
{
  vapi_msg_sw_member_interface_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_member_interface_details>()
{
  return ::vapi_msg_id_sw_member_interface_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_member_interface_details>>()
{
  return ::vapi_msg_id_sw_member_interface_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_member_interface_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_member_interface_details>(vapi_msg_id_sw_member_interface_details);
}

template class Msg<vapi_msg_sw_member_interface_details>;

using Sw_member_interface_details = Msg<vapi_msg_sw_member_interface_details>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_bond_weight>(vapi_msg_sw_interface_set_bond_weight *msg)
{
  vapi_msg_sw_interface_set_bond_weight_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_bond_weight>(vapi_msg_sw_interface_set_bond_weight *msg)
{
  vapi_msg_sw_interface_set_bond_weight_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_bond_weight>()
{
  return ::vapi_msg_id_sw_interface_set_bond_weight; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_bond_weight>>()
{
  return ::vapi_msg_id_sw_interface_set_bond_weight; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_bond_weight()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_bond_weight>(vapi_msg_id_sw_interface_set_bond_weight);
}

template <> inline vapi_msg_sw_interface_set_bond_weight* vapi_alloc<vapi_msg_sw_interface_set_bond_weight>(Connection &con)
{
  vapi_msg_sw_interface_set_bond_weight* result = vapi_alloc_sw_interface_set_bond_weight(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_set_bond_weight>;

template class Request<vapi_msg_sw_interface_set_bond_weight, vapi_msg_sw_interface_set_bond_weight_reply>;

using Sw_interface_set_bond_weight = Request<vapi_msg_sw_interface_set_bond_weight, vapi_msg_sw_interface_set_bond_weight_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_bond_weight_reply>(vapi_msg_sw_interface_set_bond_weight_reply *msg)
{
  vapi_msg_sw_interface_set_bond_weight_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_bond_weight_reply>(vapi_msg_sw_interface_set_bond_weight_reply *msg)
{
  vapi_msg_sw_interface_set_bond_weight_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_bond_weight_reply>()
{
  return ::vapi_msg_id_sw_interface_set_bond_weight_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_bond_weight_reply>>()
{
  return ::vapi_msg_id_sw_interface_set_bond_weight_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_bond_weight_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_bond_weight_reply>(vapi_msg_id_sw_interface_set_bond_weight_reply);
}

template class Msg<vapi_msg_sw_interface_set_bond_weight_reply>;

using Sw_interface_set_bond_weight_reply = Msg<vapi_msg_sw_interface_set_bond_weight_reply>;
}
#endif
