
set(SOURCES
    logscan.h
    logscan.cc
    DoubleBuffer.h
    DoubleBuffer.cc
    PatternsDB.h
    PatternsDB.cc
    )

add_library(logscan ${SOURCES})

find_package(PkgConfig)
if (PKG_CONFIG_FOUND)
  pkg_check_modules(LIBHS "libhs")
  pkg_check_modules(LIBPCRE "libpcre")
  if (LIBHS_FOUND)
    target_include_directories(logscan PUBLIC ${LIBHS_INCLUDE_DIRS})
    target_link_libraries(logscan ${LIBHS_LIBRARIES})
  endif()
  if (LIBPCRE_FOUND)
    target_include_directories(logscan PUBLIC ${LIBPCRE_INCLUDE_DIRS})
    target_link_libraries(logscan ${LIBPCRE_LIBRARIES})
  endif()
endif()

set(SOURCES_TEST
    logscan_test.cc
    PatternsDB_test.cc
    )

add_executable(logscan_test ${SOURCES_TEST})

target_link_libraries(logscan_test logscan gtest_main gtest pthread)
