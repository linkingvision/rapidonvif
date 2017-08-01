# live555 CMake rules

cmake_minimum_required(VERSION 3.0)
project(live555)

file(GLOB basic_usage_env_srcs "BasicUsageEnvironment/*.cpp" "BasicUsageEnvironment/*.hpp")
add_library(BasicUsageEnvironment ${basic_usage_env_srcs})
target_include_directories(BasicUsageEnvironment PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/BasicUsageEnvironment/include"
	"${CMAKE_CURRENT_SOURCE_DIR}/UsageEnvironment/include" "${CMAKE_CURRENT_SOURCE_DIR}/groupsock/include")

file(GLOB groupsock_srcs "groupsock/*.cpp" "groupsock/*.hpp" "groupsock/*.c" "groupsock/*.h")
add_library(groupsock ${groupsock_srcs})
target_include_directories(groupsock PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/groupsock/include"
	"${CMAKE_CURRENT_SOURCE_DIR}/UsageEnvironment/include")

file(GLOB liveMedia_srcs "liveMedia/*.cpp" "liveMedia/*.hpp" "liveMedia/*.c" "liveMedia/*.h")
add_library(liveMedia ${liveMedia_srcs})
target_include_directories(liveMedia PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/groupsock/include"
	"${CMAKE_CURRENT_SOURCE_DIR}/UsageEnvironment/include" "${CMAKE_CURRENT_SOURCE_DIR}/liveMedia/include")

file(GLOB usage_env_srcs "UsageEnvironment/*.cpp" "UsageEnvironment/*.hpp")
add_library(UsageEnvironment ${usage_env_srcs})
target_include_directories(UsageEnvironment PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/groupsock/include"
	"${CMAKE_CURRENT_SOURCE_DIR}/UsageEnvironment/include")

if (CMAKE_SYSTEM_NAME MATCHES "Linux")
	target_compile_definitions(groupsock PRIVATE "SOCKLEN_T=socklen_t" "_LARGEFILE_SOURCE=1" "_FILE_OFFSET_BITS=64")
	target_compile_definitions(liveMedia PRIVATE "SOCKLEN_T=socklen_t" "_LARGEFILE_SOURCE=1" "_FILE_OFFSET_BITS=64")
	target_compile_definitions(BasicUsageEnvironment PRIVATE "SOCKLEN_T=socklen_t" "_LARGEFILE_SOURCE=1" "_FILE_OFFSET_BITS=64")
	target_compile_definitions(UsageEnvironment PRIVATE "SOCKLEN_T=socklen_t" "_LARGEFILE_SOURCE=1" "_FILE_OFFSET_BITS=64")
	target_compile_options(groupsock PRIVATE "-fPIC")
	target_compile_options(liveMedia PRIVATE "-fPIC")
	target_compile_options(BasicUsageEnvironment PRIVATE "-fPIC")
	target_compile_options(UsageEnvironment PRIVATE "-fPIC")
endif()

install(TARGETS BasicUsageEnvironment UsageEnvironment groupsock liveMedia DESTINATION "lib")
install(DIRECTORY "BasicUsageEnvironment/include/" "groupsock/include/" "UsageEnvironment/include/" 
	"liveMedia/include/" DESTINATION "include" FILES_MATCHING REGEX ".*\\.(h|hh|hpp)")

file(GLOB live555_dll_srcs "live555/src/*.cpp" "live555/include/*.hpp")
add_library(live555_dll SHARED ${live555_dll_srcs})
target_include_directories(live555_dll PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/groupsock/include"
	"${CMAKE_CURRENT_SOURCE_DIR}/UsageEnvironment/include" "${CMAKE_CURRENT_SOURCE_DIR}/BasicUsageEnvironment/include"
	"${CMAKE_CURRENT_SOURCE_DIR}/liveMedia/include" "${CMAKE_CURRENT_SOURCE_DIR}/live555/include")

include(c_cxx_rt_config)
if (USE_STATIC_RT)
	EnableLinkStaticRT()
endif(USE_STATIC_RT)

add_dependencies(live555_dll BasicUsageEnvironment UsageEnvironment liveMedia groupsock)
target_link_libraries(live555_dll BasicUsageEnvironment UsageEnvironment liveMedia groupsock)
if (MSVC)
	target_compile_definitions(live555_dll PRIVATE "LIVE555_EXPORTS")
	target_link_libraries(live555_dll ws2_32)
endif(MSVC)
install(TARGETS live555_dll DESTINATION "bin")
install(DIRECTORY "live555/include/" DESTINATION "include" FILES_MATCHING PATTERN "*.hpp")


