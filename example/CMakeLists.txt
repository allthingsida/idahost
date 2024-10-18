cmake_minimum_required(VERSION 3.12)
project(host_examples)

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Add executable
add_executable(host main.cpp resource.h resource.rc)

# Try to find the installed idahost package
find_package(idahost CONFIG QUIET)

if (idahost_FOUND)
    # Link against the installed idahost library
    target_link_libraries(host PRIVATE idahost::idahost)
else()
    # Link against the local idahost target in developer mode
    target_link_libraries(host PRIVATE idahost)
endif()

get_target_property(CURRENT_TARGET_NAME host NAME)
set_target_properties(host PROPERTIES OUTPUT_NAME "${CURRENT_TARGET_NAME}64")
#target_compile_options(${target} PRIVATE "/wd4267" "/wd4244" "/wd4018" "/wd4146")