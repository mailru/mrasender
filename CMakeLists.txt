cmake_minimum_required(VERSION 2.8 FATAL_ERROR)

# project(mrasender C)
project(mrasender C CXX)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}" ${CMAKE_MODULE_PATH})

# Find Tarantool and Lua dependecies
set(TARANTOOL_FIND_REQUIRED ON)
find_package(Tarantool)
include_directories(${TARANTOOL_INCLUDE_DIRS})

# Find other dependecies

# Set CFLAGS
# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall -Wextra")
# Set CXXFLAGS
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall -Wextra")

# Build module
add_subdirectory(mrasender)

enable_testing()

set (LUA_PATH "LUA_PATH=${PROJECT_SOURCE_DIR}/?.lua\\;${PROJECT_SOURCE_DIR}/?/init.lua\\;;")

# add_test(mrasender ${CMAKE_SOURCE_DIR}/test/mrasender.test.lua)
# set_tests_properties(mrasender PROPERTIES ENVIRONMENT "${LUA_PATH}")

# Add `make check`
add_custom_target(check
    WORKING_DIRECTORY ${PROJECT_BUILD_DIR}
    COMMAND ctest -V)
