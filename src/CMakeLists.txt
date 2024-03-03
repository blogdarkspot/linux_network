CMAKE_MINIMUM_REQUIRED(VERSION  3.22)

find_package(Threads REQUIRED)
add_library(networklib INTERFACE)
target_compile_features(networklib INTERFACE cxx_std_20)
target_include_directories(networklib INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/../include)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(networklib INTERFACE -fprofile-arcs -ftest-coverage -O0)
    target_link_libraries(networklib INTERFACE Threads::Threads gcov cap crypt)
else()
    target_link_libraries(networklib INTERFACE Threads::Threads cap crypt)
endif()


add_library(networklib::networklib ALIAS networklib)
