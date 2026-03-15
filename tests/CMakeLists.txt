cmake_minimum_required(VERSION 3.22)

include(FetchContent)

# Fetch GoogleTest (replace submodule)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.12.1.zip
)
# avoid MSVC CRT mismatch warnings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(ipv4Tests ipv4_tests.cpp)
add_executable(socketRawTests socket_raw_tests.cpp)

# link the targets provided by FetchContent
target_link_libraries(ipv4Tests PRIVATE gtest_main networklib::networklib)
target_link_libraries(socketRawTests PRIVATE gtest_main networklib::networklib)

include(GoogleTest)
gtest_discover_tests(ipv4Tests)
gtest_discover_tests(socketRawTests)