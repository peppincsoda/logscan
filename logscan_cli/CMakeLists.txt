
set(SOURCES logscan_cli.cc)

add_executable(logscan_cli ${SOURCES})

target_link_libraries(logscan_cli logscan)
