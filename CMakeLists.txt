CMAKE_MINIMUM_REQUIRED(VERSION 3.22)

project(NetworkLib VERSION 1.0.0 LANGUAGES CXX C)

include(FetchContent)

# Force C++20 for the whole project
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Export compile commands for tooling
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Build libcap from source via FetchContent.
set(FETCHCONTENT_UPDATES_DISCONNECTED ON CACHE BOOL "Avoid network updates for FetchContent dependencies")
FetchContent_Declare(
  libcap
  GIT_REPOSITORY https://git.kernel.org/pub/scm/libs/libcap/libcap.git
  GIT_TAG master
  UPDATE_DISCONNECTED TRUE
)
FetchContent_GetProperties(libcap)
if(NOT libcap_POPULATED)
  if(POLICY CMP0169)
    cmake_policy(SET CMP0169 OLD)
  endif()
  FetchContent_Populate(libcap)
endif()

set(LIBCAP_STATIC_LIB "${libcap_SOURCE_DIR}/libcap/libcap.a")
add_custom_command(
  OUTPUT "${LIBCAP_STATIC_LIB}"
  COMMAND ${CMAKE_MAKE_PROGRAM} -C "${libcap_SOURCE_DIR}/libcap" libcap.a
  WORKING_DIRECTORY "${libcap_SOURCE_DIR}"
  COMMENT "Building libcap static library"
  VERBATIM
)

add_custom_target(libcap_build ALL DEPENDS "${LIBCAP_STATIC_LIB}")

add_library(libcap::cap STATIC IMPORTED GLOBAL)
set_target_properties(
  libcap::cap
  PROPERTIES
    IMPORTED_LOCATION "${LIBCAP_STATIC_LIB}"
    INTERFACE_INCLUDE_DIRECTORIES "${libcap_SOURCE_DIR}/libcap/include"
)
add_dependencies(libcap::cap libcap_build)

add_subdirectory(src)
