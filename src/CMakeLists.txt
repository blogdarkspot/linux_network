CMAKE_MINIMUM_REQUIRED(VERSION  3.22)

add_library(networklib)
target_sources(networklib PRIVATE socket_raw.cpp)
target_compile_features(networklib PRIVATE cxx_std_20)
target_include_directories(networklib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../include)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(networklib INTERFACE -fprofile-arcs -ftest-coverage -O0)
    target_link_libraries(networklib  INTERFACE Threads::Threads gcov)
else()
	target_link_libraries(networklib INTERFACE Threads::Threads)
endif()

