cmake_minimum_required(VERSION 3.16)

project(AFLMutationFunctions)

set(CMAKE_CXX_STANDARD 20)

add_library(afl-mutation-functions INTERFACE)
target_include_directories(afl-mutation-functions INTERFACE "include")

add_subdirectory(tests)