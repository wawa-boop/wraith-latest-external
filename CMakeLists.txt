cmake_minimum_required(VERSION 3.16)
project(Wraith)

set(CMAKE_CXX_STANDARD 17)

add_library(common STATIC common/crypto.cpp)
target_include_directories(common PUBLIC common)

add_executable(wraith_agent agent/main.cpp)
target_link_libraries(wraith_agent common ws2_32 user32 gdi32 advapi32)
target_compile_options(wraith_agent PRIVATE -O2 -static)

add_executable(wraith_controller controller/main.cpp)
target_link_libraries(wraith_controller common ws2_32)
target_compile_options(wraith_controller PRIVATE -O2 -static)
