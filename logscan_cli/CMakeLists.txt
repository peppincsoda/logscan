
set(SOURCES logscan_cli.cc)

add_executable(logscan_cli ${SOURCES})

target_include_directories(logscan_cli PUBLIC ${PROJECT_SOURCE_DIR})

target_link_libraries(logscan_cli logscan)

if(MSVC)
  target_compile_options(logscan_cli PRIVATE /W4 /WX)
else()
  target_compile_options(logscan_cli PRIVATE -Wall -Wextra -pedantic -Werror)
endif()
