cmake_minimum_required(VERSION 3.16)

project(AFLMutationFunctions)

set(CMAKE_CXX_STANDARD 20)

add_library(afl-mutation-functions
    "AFLMutationFunctions.cpp" )
target_include_directories(afl-mutation-functions PUBLIC "include")