CMAKE_MINIMUM_REQUIRED(VERSION 3.22)

project(NetworkLib VERSION 1.0.0 LANGUAGES CXX C)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
option(PACKAGE_TESTS "Build tests" ON)
add_subdirectory(src)
if(PACKAGE_TESTS)

enable_testing()
add_subdirectory(tests)
endif()
