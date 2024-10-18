cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

project(idahost)

include($ENV{IDASDK}/ida-cmake/idasdk.cmake)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Windows")
	message(FATAL_ERROR "This project can only be built on Windows.")
endif()

if(NOT DEFINED EA64)
	message(FATAL_ERROR "Must build with EA64 defined")
endif()

set(CMAKE_CXX_STANDARD 20)

# Companion plugin
set(PLUGIN_NAME              idahostplg)
set(PLUGIN_SOURCES           plugin.cpp ../idahost/include/idahost_interface.h)
set(PLUGIN_RUN_ARGS          "-t -z10000") # Debug messages for the debugger
generate()
disable_ida_warnings(idahostplg)
