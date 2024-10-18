cmake_minimum_required(VERSION 3.12 FATAL_ERROR)
project(idahost VERSION 1.0.0)

include(GNUInstallDirs)  # Add this to ensure CMAKE_INSTALL_INCLUDEDIR is defined
set(CMAKE_CXX_STANDARD 20)

# Assuming that ida-cmake is properly setup
include($ENV{IDASDK}/ida-cmake/idasdk.cmake)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Windows")
  message(FATAL_ERROR "This project can only be built on Windows.")
endif()

if(NOT DEFINED EA64)
  message(FATAL_ERROR "Must build with EA64 defined")
endif()

add_library(idahost STATIC 
  idahost.cpp 
  pe_mapper.hpp 
  win_utils.hpp
  include/idahost.h
  include/idahost_interface.h
)

target_include_directories(idahost
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
	${IDAPROINCLUDE}  # Include IDA SDK headers	
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_definitions(idahost PUBLIC ${IDAPROPLAT}=1 ${IDAEA64})

target_link_libraries(idahost PUBLIC ${IDALIB})

disable_ida_warnings(idahost)

install(TARGETS idahost
        EXPORT idahostTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(EXPORT idahostTargets
        FILE idahostTargets.cmake
        NAMESPACE idahost::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/idahost)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/idahostConfigVersion.cmake"
    COMPATIBILITY SameMajorVersion
)
configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/Config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/idahostConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/idahost
)
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/idahostConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/idahostConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/idahost
)
