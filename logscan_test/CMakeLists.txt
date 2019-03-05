
set(SOURCES logscan_test.cc)

add_executable(logscan_test ${SOURCES})

target_link_libraries(logscan_test logscan gtest_main gtest pthread)
