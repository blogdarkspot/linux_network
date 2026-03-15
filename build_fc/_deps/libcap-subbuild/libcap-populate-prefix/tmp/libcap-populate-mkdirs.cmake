# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

# If CMAKE_DISABLE_SOURCE_CHANGES is set to true and the source directory is an
# existing directory in our source tree, calling file(MAKE_DIRECTORY) on it
# would cause a fatal error, even though it would be a no-op.
if(NOT EXISTS "/home/fsilva/work/linux_network/build_fc/_deps/libcap-src")
  file(MAKE_DIRECTORY "/home/fsilva/work/linux_network/build_fc/_deps/libcap-src")
endif()
file(MAKE_DIRECTORY
  "/home/fsilva/work/linux_network/build_fc/_deps/libcap-build"
  "/home/fsilva/work/linux_network/build_fc/_deps/libcap-subbuild/libcap-populate-prefix"
  "/home/fsilva/work/linux_network/build_fc/_deps/libcap-subbuild/libcap-populate-prefix/tmp"
  "/home/fsilva/work/linux_network/build_fc/_deps/libcap-subbuild/libcap-populate-prefix/src/libcap-populate-stamp"
  "/home/fsilva/work/linux_network/build_fc/_deps/libcap-subbuild/libcap-populate-prefix/src"
  "/home/fsilva/work/linux_network/build_fc/_deps/libcap-subbuild/libcap-populate-prefix/src/libcap-populate-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/home/fsilva/work/linux_network/build_fc/_deps/libcap-subbuild/libcap-populate-prefix/src/libcap-populate-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/home/fsilva/work/linux_network/build_fc/_deps/libcap-subbuild/libcap-populate-prefix/src/libcap-populate-stamp${cfgdir}") # cfgdir has leading slash
endif()
