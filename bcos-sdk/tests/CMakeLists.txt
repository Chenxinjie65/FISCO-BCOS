#------------------------------------------------------------------------------
# Top-level CMake file for ut of bcos-rpc
# ------------------------------------------------------------------------------
# Copyright (C) 2021 FISCO BCOS.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ------------------------------------------------------------------------------
file(GLOB_RECURSE SOURCES "unittests/*.cpp" "unittests/*.h" "unittests/*.sol")

set(TEST_BINARY_NAME test-bcos-cpp-sdk)

find_package(Boost REQUIRED log serialization unit_test_framework)

add_executable(${TEST_BINARY_NAME} ${SOURCES})
target_include_directories(${TEST_BINARY_NAME} PRIVATE . ${CMAKE_SOURCE_DIR})

find_package(Boost REQUIRED unit_test_framework)
target_link_libraries(${TEST_BINARY_NAME} ${BCOS_CPP_SDK_TARGET} ${TABLE_TARGET} bcos-utilities ${TARS_PROTOCOL_TARGET} Boost::unit_test_framework)
set_source_files_properties("unittests/main.cpp" PROPERTIES SKIP_UNITY_BUILD_INCLUSION ON)
set_target_properties(${TEST_BINARY_NAME} PROPERTIES UNITY_BUILD "ON")
#add_test(NAME ${TEST_BINARY_NAME} COMMAND ${TEST_BINARY_NAME})
config_test_cases("" "${SOURCES}" ${TEST_BINARY_NAME} "")