project(sandbox)
cmake_minimum_required(VERSION 3.0)

find_package(fmt)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include_directories(${CMAKE_JS_INC})
file(GLOB SOURCE_FILES "native/*.cc" "native/*.h")
add_library(${PROJECT_NAME} SHARED ${SOURCE_FILES} ${CMAKE_JS_SRC})
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "" SUFFIX ".node")

set(JSON_BuildTests OFF CACHE INTERNAL "")

# Include N-API wrappers
execute_process(
  COMMAND node -p "require('node-addon-api').include"
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE NODE_ADDON_API_DIR
)
string(REPLACE "\n" "" NODE_ADDON_API_DIR ${NODE_ADDON_API_DIR})
string(REPLACE "\"" "" NODE_ADDON_API_DIR ${NODE_ADDON_API_DIR})
target_include_directories(${PROJECT_NAME} PRIVATE ${NODE_ADDON_API_DIR})
target_link_libraries(${PROJECT_NAME} ${CMAKE_JS_LIB} fmt::fmt)

# --------------------
# Unit tests (C++)
# --------------------
enable_testing()

add_executable(utils_test
  native/tests/utils_test.cc
  native/utils.cc
)
target_include_directories(utils_test PRIVATE ${CMAKE_SOURCE_DIR}/native)
target_link_libraries(utils_test fmt::fmt)
add_test(NAME utils_test COMMAND utils_test)

add_executable(cgroup_kill_test
  native/tests/cgroup_kill_test.cc
  native/cgroup.cc
  native/utils.cc
)
target_include_directories(cgroup_kill_test PRIVATE ${CMAKE_SOURCE_DIR}/native)
target_link_libraries(cgroup_kill_test fmt::fmt)
add_test(NAME cgroup_kill_test COMMAND cgroup_kill_test)

add_executable(busy
  native/tests/busy.c
)
target_link_libraries(busy -static)
