cmake_minimum_required(VERSION 3.21)
project(nfq_test)

set(CMAKE_CXX_STANDARD 17)

find_package(PkgConfig REQUIRED)
pkg_check_modules(libnetfilter_queue REQUIRED IMPORTED_TARGET libnetfilter_queue)

add_executable(nfq_test nfq_test_main.cc netfilter_queue.h netfilter_queue.cc)
target_link_libraries(nfq_test PUBLIC PkgConfig::libnetfilter_queue)
target_include_directories(nfq_test PUBLIC PkgConfig::libnetfilter_queue)
