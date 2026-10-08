# Copyright (c) 2018 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

add_vpp_plugin(acl
  SOURCES
  acl.c
  hash_lookup.c
  lookup_context.c
  sess_mgmt_node.c
  dataplane_node.c
  dataplane_node_nonip.c

  MULTIARCH_SOURCES
  dataplane_node.c
  dataplane_node_nonip.c

  API_FILES
  acl.api
  acl_types.api

  API_TEST_SOURCES
  acl_test.c

  INSTALL_HEADERS
  exports.h
  exported_types.h
  acl.h
  fa_node.h
  public_inlines.h
  types.h
  hash_lookup_types.h
  lookup_context.h
  hash_lookup_private.h
)

# Plugins are dlopen()ed independently and are not linked to each other, so a
# direct reference to dp_log's symbols compiles and links cleanly and then
# fails at load time -- taking the whole data plane down with it. Catch it
# here instead. See src/plugins/dp_log/check-plugin-boundary.sh.
add_custom_command(TARGET acl_plugin POST_BUILD
  COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/../dp_log/check-plugin-boundary.sh
          $<TARGET_FILE:acl_plugin> dp_log_
  COMMENT "Checking acl_plugin does not link against dp_log directly"
  VERBATIM
)
