
set(SOURCES logscan_cli.cc)

add_executable(logscan_cli ${SOURCES})

target_include_directories(logscan_cli PUBLIC ${PROJECT_SOURCE_DIR})

find_package(PkgConfig)
if (PKG_CONFIG_FOUND)
  pkg_check_modules(LIBHS "libhs")
  pkg_check_modules(LIBPCRE "libpcre")
  if (LIBHS_FOUND)
    target_include_directories(logscan_cli PUBLIC ${LIBHS_INCLUDE_DIRS})
    target_link_libraries(logscan_cli ${LIBHS_LIBRARIES})
  endif()
  if (LIBPCRE_FOUND)
    target_include_directories(logscan_cli PUBLIC ${LIBPCRE_INCLUDE_DIRS})
    target_link_libraries(logscan_cli ${LIBPCRE_LIBRARIES})
  endif()
endif()

target_link_libraries(logscan_cli logscan)
