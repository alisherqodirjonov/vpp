#ifndef __included_hpp_policer_api_json
#define __included_hpp_policer_api_json

#include <vapi/vapi.hpp>
#include <vapi/policer.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_policer_bind>(vapi_msg_policer_bind *msg)
{
  vapi_msg_policer_bind_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_policer_bind>(vapi_msg_policer_bind *msg)
{
  vapi_msg_policer_bind_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_policer_bind>()
{
  return ::vapi_msg_id_policer_bind; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_policer_bind>>()
{
  return ::vapi_msg_id_policer_bind; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_policer_bind()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_policer_bind>(vapi_msg_id_policer_bind);
}

template <> inline vapi_msg_policer_bind* vapi_alloc<vapi_msg_policer_bind>(Connection &con)
{
  vapi_msg_policer_bind* result = vapi_alloc_policer_bind(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_policer_bind>;

template class Request<vapi_msg_policer_bind, vapi_msg_policer_bind_reply>;

using Policer_bind = Request<vapi_msg_policer_bind, vapi_msg_policer_bind_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_policer_bind_reply>(vapi_msg_policer_bind_reply *msg)
{
  vapi_msg_policer_bind_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_policer_bind_reply>(vapi_msg_policer_bind_reply *msg)
{
  vapi_msg_policer_bind_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_policer_bind_reply>()
{
  return ::vapi_msg_id_policer_bind_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_policer_bind_reply>>()
{
  return ::vapi_msg_id_policer_bind_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_policer_bind_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_policer_bind_reply>(vapi_msg_id_policer_bind_reply);
}

template class Msg<vapi_msg_policer_bind_reply>;

using Policer_bind_reply = Msg<vapi_msg_policer_bind_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_policer_bind_v2>(vapi_msg_policer_bind_v2 *msg)
{
  vapi_msg_policer_bind_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_policer_bind_v2>(vapi_msg_policer_bind_v2 *msg)
{
  vapi_msg_policer_bind_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_policer_bind_v2>()
{
  return ::vapi_msg_id_policer_bind_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_policer_bind_v2>>()
{
  return ::vapi_msg_id_policer_bind_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_policer_bind_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_policer_bind_v2>(vapi_msg_id_policer_bind_v2);
}

template <> inline vapi_msg_policer_bind_v2* vapi_alloc<vapi_msg_policer_bind_v2>(Connection &con)
{
  vapi_msg_policer_bind_v2* result = vapi_alloc_policer_bind_v2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_policer_bind_v2>;

template class Request<vapi_msg_policer_bind_v2, vapi_msg_policer_bind_v2_reply>;

using Policer_bind_v2 = Request<vapi_msg_policer_bind_v2, vapi_msg_policer_bind_v2_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_policer_bind_v2_reply>(vapi_msg_policer_bind_v2_reply *msg)
{
  vapi_msg_policer_bind_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_policer_bind_v2_reply>(vapi_msg_policer_bind_v2_reply *msg)
{
  vapi_msg_policer_bind_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_policer_bind_v2_reply>()
{
  return ::vapi_msg_id_policer_bind_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_policer_bind_v2_reply>>()
{
  return ::vapi_msg_id_policer_bind_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_policer_bind_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_policer_bind_v2_reply>(vapi_msg_id_policer_bind_v2_reply);
}

template class Msg<vapi_msg_policer_bind_v2_reply>;

using Policer_bind_v2_reply = Msg<vapi_msg_policer_bind_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_policer_input>(vapi_msg_policer_input *msg)
{
  vapi_msg_policer_input_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_policer_input>(vapi_msg_policer_input *msg)
{
  vapi_msg_policer_input_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_policer_input>()
{
  return ::vapi_msg_id_policer_input; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_policer_input>>()
{
  return ::vapi_msg_id_policer_input; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_policer_input()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_policer_input>(vapi_msg_id_policer_input);
}

template <> inline vapi_msg_policer_input* vapi_alloc<vapi_msg_policer_input>(Connection &con)
{
  vapi_msg_policer_input* result = vapi_alloc_policer_input(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_policer_input>;

template class Request<vapi_msg_policer_input, vapi_msg_policer_input_reply>;

using Policer_input = Request<vapi_msg_policer_input, vapi_msg_policer_input_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_policer_input_reply>(vapi_msg_policer_input_reply *msg)
{
  vapi_msg_policer_input_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_policer_input_reply>(vapi_msg_policer_input_reply *msg)
{
  vapi_msg_policer_input_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_policer_input_reply>()
{
  return ::vapi_msg_id_policer_input_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_policer_input_reply>>()
{
  return ::vapi_msg_id_policer_input_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_policer_input_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_policer_input_reply>(vapi_msg_id_policer_input_reply);
}

template class Msg<vapi_msg_policer_input_reply>;

using Policer_input_reply = Msg<vapi_msg_policer_input_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_policer_input_v2>(vapi_msg_policer_input_v2 *msg)
{
  vapi_msg_policer_input_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_policer_input_v2>(vapi_msg_policer_input_v2 *msg)
{
  vapi_msg_policer_input_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_policer_input_v2>()
{
  return ::vapi_msg_id_policer_input_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_policer_input_v2>>()
{
  return ::vapi_msg_id_policer_input_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_policer_input_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_policer_input_v2>(vapi_msg_id_policer_input_v2);
}

template <> inline vapi_msg_policer_input_v2* vapi_alloc<vapi_msg_policer_input_v2>(Connection &con)
{
  vapi_msg_policer_input_v2* result = vapi_alloc_policer_input_v2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_policer_input_v2>;

template class Request<vapi_msg_policer_input_v2, vapi_msg_policer_input_v2_reply>;

using Policer_input_v2 = Request<vapi_msg_policer_input_v2, vapi_msg_policer_input_v2_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_policer_input_v2_reply>(vapi_msg_policer_input_v2_reply *msg)
{
  vapi_msg_policer_input_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_policer_input_v2_reply>(vapi_msg_policer_input_v2_reply *msg)
{
  vapi_msg_policer_input_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_policer_input_v2_reply>()
{
  return ::vapi_msg_id_policer_input_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_policer_input_v2_reply>>()
{
  return ::vapi_msg_id_policer_input_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_policer_input_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_policer_input_v2_reply>(vapi_msg_id_policer_input_v2_reply);
}

template class Msg<vapi_msg_policer_input_v2_reply>;

using Policer_input_v2_reply = Msg<vapi_msg_policer_input_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_policer_output>(vapi_msg_policer_output *msg)
{
  vapi_msg_policer_output_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_policer_output>(vapi_msg_policer_output *msg)
{
  vapi_msg_policer_output_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_policer_output>()
{
  return ::vapi_msg_id_policer_output; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_policer_output>>()
{
  return ::vapi_msg_id_policer_output; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_policer_output()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_policer_output>(vapi_msg_id_policer_output);
}

template <> inline vapi_msg_policer_output* vapi_alloc<vapi_msg_policer_output>(Connection &con)
{
  vapi_msg_policer_output* result = vapi_alloc_policer_output(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_policer_output>;

template class Request<vapi_msg_policer_output, vapi_msg_policer_output_reply>;

using Policer_output = Request<vapi_msg_policer_output, vapi_msg_policer_output_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_policer_output_reply>(vapi_msg_policer_output_reply *msg)
{
  vapi_msg_policer_output_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_policer_output_reply>(vapi_msg_policer_output_reply *msg)
{
  vapi_msg_policer_output_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_policer_output_reply>()
{
  return ::vapi_msg_id_policer_output_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_policer_output_reply>>()
{
  return ::vapi_msg_id_policer_output_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_policer_output_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_policer_output_reply>(vapi_msg_id_policer_output_reply);
}

template class Msg<vapi_msg_policer_output_reply>;

using Policer_output_reply = Msg<vapi_msg_policer_output_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_policer_output_v2>(vapi_msg_policer_output_v2 *msg)
{
  vapi_msg_policer_output_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_policer_output_v2>(vapi_msg_policer_output_v2 *msg)
{
  vapi_msg_policer_output_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_policer_output_v2>()
{
  return ::vapi_msg_id_policer_output_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_policer_output_v2>>()
{
  return ::vapi_msg_id_policer_output_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_policer_output_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_policer_output_v2>(vapi_msg_id_policer_output_v2);
}

template <> inline vapi_msg_policer_output_v2* vapi_alloc<vapi_msg_policer_output_v2>(Connection &con)
{
  vapi_msg_policer_output_v2* result = vapi_alloc_policer_output_v2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_policer_output_v2>;

template class Request<vapi_msg_policer_output_v2, vapi_msg_policer_output_v2_reply>;

using Policer_output_v2 = Request<vapi_msg_policer_output_v2, vapi_msg_policer_output_v2_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_policer_output_v2_reply>(vapi_msg_policer_output_v2_reply *msg)
{
  vapi_msg_policer_output_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_policer_output_v2_reply>(vapi_msg_policer_output_v2_reply *msg)
{
  vapi_msg_policer_output_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_policer_output_v2_reply>()
{
  return ::vapi_msg_id_policer_output_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_policer_output_v2_reply>>()
{
  return ::vapi_msg_id_policer_output_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_policer_output_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_policer_output_v2_reply>(vapi_msg_id_policer_output_v2_reply);
}

template class Msg<vapi_msg_policer_output_v2_reply>;

using Policer_output_v2_reply = Msg<vapi_msg_policer_output_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_policer_add_del>(vapi_msg_policer_add_del *msg)
{
  vapi_msg_policer_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_policer_add_del>(vapi_msg_policer_add_del *msg)
{
  vapi_msg_policer_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_policer_add_del>()
{
  return ::vapi_msg_id_policer_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_policer_add_del>>()
{
  return ::vapi_msg_id_policer_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_policer_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_policer_add_del>(vapi_msg_id_policer_add_del);
}

template <> inline vapi_msg_policer_add_del* vapi_alloc<vapi_msg_policer_add_del>(Connection &con)
{
  vapi_msg_policer_add_del* result = vapi_alloc_policer_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_policer_add_del>;

template class Request<vapi_msg_policer_add_del, vapi_msg_policer_add_del_reply>;

using Policer_add_del = Request<vapi_msg_policer_add_del, vapi_msg_policer_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_policer_add>(vapi_msg_policer_add *msg)
{
  vapi_msg_policer_add_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_policer_add>(vapi_msg_policer_add *msg)
{
  vapi_msg_policer_add_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_policer_add>()
{
  return ::vapi_msg_id_policer_add; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_policer_add>>()
{
  return ::vapi_msg_id_policer_add; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_policer_add()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_policer_add>(vapi_msg_id_policer_add);
}

template <> inline vapi_msg_policer_add* vapi_alloc<vapi_msg_policer_add>(Connection &con)
{
  vapi_msg_policer_add* result = vapi_alloc_policer_add(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_policer_add>;

template class Request<vapi_msg_policer_add, vapi_msg_policer_add_reply>;

using Policer_add = Request<vapi_msg_policer_add, vapi_msg_policer_add_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_policer_del>(vapi_msg_policer_del *msg)
{
  vapi_msg_policer_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_policer_del>(vapi_msg_policer_del *msg)
{
  vapi_msg_policer_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_policer_del>()
{
  return ::vapi_msg_id_policer_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_policer_del>>()
{
  return ::vapi_msg_id_policer_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_policer_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_policer_del>(vapi_msg_id_policer_del);
}

template <> inline vapi_msg_policer_del* vapi_alloc<vapi_msg_policer_del>(Connection &con)
{
  vapi_msg_policer_del* result = vapi_alloc_policer_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_policer_del>;

template class Request<vapi_msg_policer_del, vapi_msg_policer_del_reply>;

using Policer_del = Request<vapi_msg_policer_del, vapi_msg_policer_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_policer_del_reply>(vapi_msg_policer_del_reply *msg)
{
  vapi_msg_policer_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_policer_del_reply>(vapi_msg_policer_del_reply *msg)
{
  vapi_msg_policer_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_policer_del_reply>()
{
  return ::vapi_msg_id_policer_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_policer_del_reply>>()
{
  return ::vapi_msg_id_policer_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_policer_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_policer_del_reply>(vapi_msg_id_policer_del_reply);
}

template class Msg<vapi_msg_policer_del_reply>;

using Policer_del_reply = Msg<vapi_msg_policer_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_policer_update>(vapi_msg_policer_update *msg)
{
  vapi_msg_policer_update_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_policer_update>(vapi_msg_policer_update *msg)
{
  vapi_msg_policer_update_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_policer_update>()
{
  return ::vapi_msg_id_policer_update; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_policer_update>>()
{
  return ::vapi_msg_id_policer_update; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_policer_update()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_policer_update>(vapi_msg_id_policer_update);
}

template <> inline vapi_msg_policer_update* vapi_alloc<vapi_msg_policer_update>(Connection &con)
{
  vapi_msg_policer_update* result = vapi_alloc_policer_update(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_policer_update>;

template class Request<vapi_msg_policer_update, vapi_msg_policer_update_reply>;

using Policer_update = Request<vapi_msg_policer_update, vapi_msg_policer_update_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_policer_update_reply>(vapi_msg_policer_update_reply *msg)
{
  vapi_msg_policer_update_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_policer_update_reply>(vapi_msg_policer_update_reply *msg)
{
  vapi_msg_policer_update_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_policer_update_reply>()
{
  return ::vapi_msg_id_policer_update_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_policer_update_reply>>()
{
  return ::vapi_msg_id_policer_update_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_policer_update_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_policer_update_reply>(vapi_msg_id_policer_update_reply);
}

template class Msg<vapi_msg_policer_update_reply>;

using Policer_update_reply = Msg<vapi_msg_policer_update_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_policer_reset>(vapi_msg_policer_reset *msg)
{
  vapi_msg_policer_reset_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_policer_reset>(vapi_msg_policer_reset *msg)
{
  vapi_msg_policer_reset_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_policer_reset>()
{
  return ::vapi_msg_id_policer_reset; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_policer_reset>>()
{
  return ::vapi_msg_id_policer_reset; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_policer_reset()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_policer_reset>(vapi_msg_id_policer_reset);
}

template <> inline vapi_msg_policer_reset* vapi_alloc<vapi_msg_policer_reset>(Connection &con)
{
  vapi_msg_policer_reset* result = vapi_alloc_policer_reset(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_policer_reset>;

template class Request<vapi_msg_policer_reset, vapi_msg_policer_reset_reply>;

using Policer_reset = Request<vapi_msg_policer_reset, vapi_msg_policer_reset_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_policer_reset_reply>(vapi_msg_policer_reset_reply *msg)
{
  vapi_msg_policer_reset_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_policer_reset_reply>(vapi_msg_policer_reset_reply *msg)
{
  vapi_msg_policer_reset_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_policer_reset_reply>()
{
  return ::vapi_msg_id_policer_reset_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_policer_reset_reply>>()
{
  return ::vapi_msg_id_policer_reset_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_policer_reset_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_policer_reset_reply>(vapi_msg_id_policer_reset_reply);
}

template class Msg<vapi_msg_policer_reset_reply>;

using Policer_reset_reply = Msg<vapi_msg_policer_reset_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_policer_add_del_reply>(vapi_msg_policer_add_del_reply *msg)
{
  vapi_msg_policer_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_policer_add_del_reply>(vapi_msg_policer_add_del_reply *msg)
{
  vapi_msg_policer_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_policer_add_del_reply>()
{
  return ::vapi_msg_id_policer_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_policer_add_del_reply>>()
{
  return ::vapi_msg_id_policer_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_policer_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_policer_add_del_reply>(vapi_msg_id_policer_add_del_reply);
}

template class Msg<vapi_msg_policer_add_del_reply>;

using Policer_add_del_reply = Msg<vapi_msg_policer_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_policer_add_reply>(vapi_msg_policer_add_reply *msg)
{
  vapi_msg_policer_add_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_policer_add_reply>(vapi_msg_policer_add_reply *msg)
{
  vapi_msg_policer_add_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_policer_add_reply>()
{
  return ::vapi_msg_id_policer_add_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_policer_add_reply>>()
{
  return ::vapi_msg_id_policer_add_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_policer_add_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_policer_add_reply>(vapi_msg_id_policer_add_reply);
}

template class Msg<vapi_msg_policer_add_reply>;

using Policer_add_reply = Msg<vapi_msg_policer_add_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_policer_dump>(vapi_msg_policer_dump *msg)
{
  vapi_msg_policer_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_policer_dump>(vapi_msg_policer_dump *msg)
{
  vapi_msg_policer_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_policer_dump>()
{
  return ::vapi_msg_id_policer_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_policer_dump>>()
{
  return ::vapi_msg_id_policer_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_policer_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_policer_dump>(vapi_msg_id_policer_dump);
}

template <> inline vapi_msg_policer_dump* vapi_alloc<vapi_msg_policer_dump>(Connection &con)
{
  vapi_msg_policer_dump* result = vapi_alloc_policer_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_policer_dump>;

template class Dump<vapi_msg_policer_dump, vapi_msg_policer_details>;

using Policer_dump = Dump<vapi_msg_policer_dump, vapi_msg_policer_details>;

template <> inline void vapi_swap_to_be<vapi_msg_policer_dump_v2>(vapi_msg_policer_dump_v2 *msg)
{
  vapi_msg_policer_dump_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_policer_dump_v2>(vapi_msg_policer_dump_v2 *msg)
{
  vapi_msg_policer_dump_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_policer_dump_v2>()
{
  return ::vapi_msg_id_policer_dump_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_policer_dump_v2>>()
{
  return ::vapi_msg_id_policer_dump_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_policer_dump_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_policer_dump_v2>(vapi_msg_id_policer_dump_v2);
}

template <> inline vapi_msg_policer_dump_v2* vapi_alloc<vapi_msg_policer_dump_v2>(Connection &con)
{
  vapi_msg_policer_dump_v2* result = vapi_alloc_policer_dump_v2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_policer_dump_v2>;

template class Dump<vapi_msg_policer_dump_v2, vapi_msg_policer_details>;

using Policer_dump_v2 = Dump<vapi_msg_policer_dump_v2, vapi_msg_policer_details>;

template <> inline void vapi_swap_to_be<vapi_msg_policer_details>(vapi_msg_policer_details *msg)
{
  vapi_msg_policer_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_policer_details>(vapi_msg_policer_details *msg)
{
  vapi_msg_policer_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_policer_details>()
{
  return ::vapi_msg_id_policer_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_policer_details>>()
{
  return ::vapi_msg_id_policer_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_policer_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_policer_details>(vapi_msg_id_policer_details);
}

template class Msg<vapi_msg_policer_details>;

using Policer_details = Msg<vapi_msg_policer_details>;
}
#endif
