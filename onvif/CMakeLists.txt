# onvifagent and onvifagentcli CMake

cmake_minimum_required(VERSION 3.0)
project(rapidonvif LANGUAGES CXX C)

include(c_cxx_rt_config)
if (USE_STATIC_RT)
	EnableLinkStaticRT()
endif(USE_STATIC_RT)

file(GLOB onvif_gen_srcs LIST_DIRECTORIES NO "onvifagent/onvifgen/*.cpp" 
	"onvifagent/onvifgen/*.hpp" 
	"onvifagent/onvifgen/*.h")
file(GLOB onvif_includes LIST_DIRECTORIES NO "onvifagent/include/*.hpp")
file(GLOB gsoap_srcs LIST_DIRECTORIES NO "onvifagent/gsoap/gsoap/runtime/*.cpp" 
	"onvifagent/gsoap/gsoap/runtime/*.c" 
	"onvifagent/gsoap/gsoap/runtime/*.hpp" 
	"onvifagent/gsoap/gsoap/runtime/*.h")
	
file(GLOB ipc_defs LIST_DIRECTORIES NO "include/*.pb.cc" "include/*.pb.h")

set(civetweb_embedded_src "${CMAKE_SOURCE_DIR}/3rdparty/civetweb/src/CivetServer.cpp"
	"${CMAKE_SOURCE_DIR}/3rdparty/civetweb/src/civetweb.c")

set(others_src "include/onvifagentcli.hpp" "include/wsclient.hpp")

foreach(gsoap_file ${gsoap_srcs})
	if (${gsoap_file} MATCHES ".*[\\/]mecevp\\.[ch]$")
		list(REMOVE_ITEM gsoap_srcs ${gsoap_file}) 
	endif(${gsoap_file} MATCHES ".*[\\/]mecevp\\.[ch]$")
endforeach()

file(GLOB_RECURSE agent_srcs LIST_DIRECTORIES NO "onvifagent/src/*.cpp" "onvifagent/src/*.hpp")

add_executable(onvifagent ${onvif_gen_srcs} ${onvif_includes} ${gsoap_srcs} ${agent_srcs} 
	${ipc_defs} ${others_src} ${civetweb_embedded_src})

set_source_files_properties("onvifagent/gsoap/gsoap/runtime/wsaapi.c" PROPERTIES LANGUAGE CXX)
set_source_files_properties("onvifagent/gsoap/gsoap/runtime/duration.c" PROPERTIES LANGUAGE CXX)

set_property(TARGET onvifagent PROPERTY CXX_STANDARD 11)
add_dependencies(onvifagent libressl protobuf)
target_compile_definitions(onvifagent PRIVATE "WITH_OPENSSL" "USE_IPV6" "USE_WEBSOCKET" "WITH_DOM" "WITH_PURE_VIRTUAL" "WITH_NONAMESPACES")

if (MSVC)
	if (CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64")
		#EnableMSVCBigObjBuild()
		target_compile_options(onvifagent PRIVATE "/bigobj")
	endif(CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64")
	target_compile_definitions(onvifagent PRIVATE "_WIN32" "UNICODE" "_UNICODE")
endif(MSVC)

target_include_directories(onvifagent PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/onvifagent/gsoap/gsoap/runtime" 
	"${CMAKE_CURRENT_SOURCE_DIR}/../3rdparty/civetweb/include" "${CMAKE_CURRENT_SOURCE_DIR}/onvifagent/onvifgen" 
	"${CMAKE_CURRENT_SOURCE_DIR}/include" "${CMAKE_BINARY_DIR}/libressl-bin/include"
	"${CMAKE_BINARY_DIR}/protobuf-bin/include" "${CMAKE_CURRENT_SOURCE_DIR}/onvifagent/include"
	"${CMAKE_CURRENT_SOURCE_DIR}/onvifagent/src")

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
	set(protobuf_lib "libprotobufd")
else(CMAKE_BUILD_TYPE STREQUAL "Debug")
	set (protobuf_lib "libprotobuf")
endif(CMAKE_BUILD_TYPE STREQUAL "Debug")

if (CMAKE_SYSTEM_NAME MATCHES "Linux")
	target_link_libraries(onvifagent "pthread" "dl")
endif(CMAKE_SYSTEM_NAME MATCHES "Linux")

target_link_libraries(onvifagent 
	"${CMAKE_BINARY_DIR}/protobuf-bin/lib/${protobuf_lib}${CMAKE_STATIC_LIBRARY_SUFFIX}" 
	"${CMAKE_BINARY_DIR}/libressl-bin/lib/${CMAKE_STATIC_LIBRARY_PREFIX}ssl${CMAKE_STATIC_LIBRARY_SUFFIX}" 
	"${CMAKE_BINARY_DIR}/libressl-bin/lib/${CMAKE_STATIC_LIBRARY_PREFIX}tls${CMAKE_STATIC_LIBRARY_SUFFIX}"
	"${CMAKE_BINARY_DIR}/libressl-bin/lib/${CMAKE_STATIC_LIBRARY_PREFIX}crypto${CMAKE_STATIC_LIBRARY_SUFFIX}")

set(example_srcs "example/example.cpp" "example/example.hpp")
file(GLOB_RECURSE ipc_video_srcs "include/*.cpp" "include/*.cc" "include/*.h" "include/*.hpp")

if(CMAKE_SYSTEM_NAME MATCHES "Windows")
	set(cli_main_srcs "src/onvifagentlib.cpp" "src/tinyprocess/process.cpp" "src/tinyprocess/process_win.cpp")
else(CMAKE_SYSTEM_NAME MATCHES "Windows")
	set(cli_main_srcs "src/onvifagentlib.cpp" "src/tinyprocess/process.cpp" "src/tinyprocess/process_unix.cpp")
endif(CMAKE_SYSTEM_NAME MATCHES "Windows")

add_executable(onvifagentcli ${example_srcs} ${ipc_video_srcs} ${civetweb_embedded_src} ${cli_main_srcs})
set_property(TARGET onvifagentcli PROPERTY CXX_STANDARD 11)

target_compile_definitions(onvifagentcli PRIVATE "WITH_OPENSSL" "USE_IPV6" "USE_WEBSOCKET" "WITH_DOM" "WITH_PURE_VIRTUAL")
add_dependencies(onvifagentcli protobuf libressl live555 onvifagent)
target_include_directories(onvifagentcli PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include" 
	"${CMAKE_CURRENT_SOURCE_DIR}/example" "${CMAKE_CURRENT_SOURCE_DIR}/../3rdparty/civetweb/include"
	"${CMAKE_BINARY_DIR}/protobuf-bin/include" "${CMAKE_CURRENT_SOURCE_DIR}/include/video"
	"${CMAKE_BINARY_DIR}/live555-bin/include")
	
if (MSVC)
	target_compile_definitions(onvifagentcli PRIVATE "UNICODE" "_UNICODE" "_CONSOLE")
	target_link_libraries(onvifagentcli "ws2_32.lib")
	target_link_libraries(onvifagentcli
		"${CMAKE_BINARY_DIR}/live555-bin/bin/${CMAKE_STATIC_LIBRARY_PREFIX}live555_dll${CMAKE_STATIC_LIBRARY_SUFFIX}")
endif(MSVC)

if (CMAKE_SYSTEM_NAME MATCHES "Linux")
	target_link_libraries(onvifagentcli "pthread" "dl")
	target_link_libraries(onvifagentcli
		"${CMAKE_BINARY_DIR}/live555-bin/bin/${CMAKE_SHARED_LIBRARY_PREFIX}live555_dll${CMAKE_SHARED_LIBRARY_SUFFIX}")
endif(CMAKE_SYSTEM_NAME MATCHES "Linux")

target_link_libraries(onvifagentcli 
	"${CMAKE_BINARY_DIR}/libressl-bin/lib/${CMAKE_STATIC_LIBRARY_PREFIX}ssl${CMAKE_STATIC_LIBRARY_SUFFIX}" 
	"${CMAKE_BINARY_DIR}/libressl-bin/lib/${CMAKE_STATIC_LIBRARY_PREFIX}tls${CMAKE_STATIC_LIBRARY_SUFFIX}" 
	"${CMAKE_BINARY_DIR}/protobuf-bin/lib/${protobuf_lib}${CMAKE_STATIC_LIBRARY_SUFFIX}"
	"${CMAKE_BINARY_DIR}/live555-bin/lib/${CMAKE_STATIC_LIBRARY_PREFIX}BasicUsageEnvironment${CMAKE_STATIC_LIBRARY_SUFFIX}" 
	"${CMAKE_BINARY_DIR}/live555-bin/lib/${CMAKE_STATIC_LIBRARY_PREFIX}groupsock${CMAKE_STATIC_LIBRARY_SUFFIX}" 
	"${CMAKE_BINARY_DIR}/live555-bin/lib/${CMAKE_STATIC_LIBRARY_PREFIX}liveMedia${CMAKE_STATIC_LIBRARY_SUFFIX}" 
	"${CMAKE_BINARY_DIR}/live555-bin/lib/${CMAKE_STATIC_LIBRARY_PREFIX}UsageEnvironment${CMAKE_STATIC_LIBRARY_SUFFIX}")



