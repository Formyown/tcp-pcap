cmake_minimum_required(VERSION 3.14)
project(gtpv2_utrans)

set(CMAKE_CXX_STANDARD 14)


add_executable(gtpv2_utrans src/main.cpp)

target_link_libraries(gtpv2_utrans pcap)

