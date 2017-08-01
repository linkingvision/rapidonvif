# rapidonvif root CMake

cmake_minimum_required(VERSION 3.0)
project(rapidonvif)

message("CMAKE_SYSTEM_NAME is ${CMAKE_SYSTEM_NAME}")
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake_modules")
add_subdirectory(onvif)
add_subdirectory(3rdparty)