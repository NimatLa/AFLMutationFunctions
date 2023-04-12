add_library(afl-mutation-functions-compile-tests CompiletimeTests.cpp)
target_link_libraries(afl-mutation-functions-compile-tests PRIVATE afl-mutation-functions)

add_executable(afl-mutation-tests MutationTests.cpp)
target_link_libraries(afl-mutation-tests PRIVATE afl-mutation-functions)