cmake_minimum_required(VERSION 2.6)
project(logscan)

enable_testing()
find_package(GTest REQUIRED)

add_subdirectory(logscan)

include_directories("${PROJECT_SOURCE_DIR}/logscan")
add_subdirectory(logscan_test)

add_test(
    NAME logscan_test
    COMMAND logscan_test
)

add_subdirectory(logscan_cli)
