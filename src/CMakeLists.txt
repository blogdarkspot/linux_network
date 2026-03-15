CMAKE_MINIMUM_REQUIRED(VERSION  3.22)

find_package(Threads REQUIRED)
add_library(networklib INTERFACE)
target_compile_features(networklib INTERFACE cxx_std_20)
target_include_directories(networklib INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/../include)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(networklib INTERFACE  -O0)
    target_link_libraries(networklib INTERFACE Threads::Threads libcap::cap crypt)
else()
    target_link_libraries(networklib INTERFACE Threads::Threads libcap::cap crypt)
endif()


add_library(networklib::networklib ALIAS networklib)

# Add multicast client executable
add_executable(multicast_client multicast_client.cpp)

# Link to the project library (adjust target name if different)
target_link_libraries(multicast_client PRIVATE networklib::networklib pthread)

# Ensure C++20 for this target (redundant if set globally, but explicit is fine)
set_target_properties(multicast_client PROPERTIES
  CXX_STANDARD 20
  CXX_STANDARD_REQUIRED ON
  CXX_EXTENSIONS OFF
)

# Install the executable and the test python script
install(TARGETS multicast_client RUNTIME DESTINATION bin)

# Install helper script (make sure it is executable in source tree)
install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/send_multicast.py DESTINATION bin)
