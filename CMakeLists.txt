cmake_minimum_required(VERSION 3.11)

project(extractJPEG_header VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CONFIGURATION_TYPES "Release" CACHE STRING "" FORCE)
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/scripts")
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

include(ensure_output_path)

if(WIN32)
  set(FLAG_SUFF ${CMAKE_CONFIGURATION_TYPES})
  set(CMAKE_CXX_FLAGS_${FLAG_SUFF} "${CMAKE_CXX_FLAGS_${FLAG_SUFF}} /MD /MP")
  set(CMAKE_CXX_STANDARD 17)
  add_definitions(-DWIN32 -D_WIN32 -DWINDOWS -D_WINDOWS -D_WIN32_WINNT=0x0601)
else()
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")
endif()

if(POLICY CMP0074)
  cmake_policy(SET CMP0074 NEW)
endif()

if(POLICY CMP0076)
  cmake_policy(SET CMP0076 NEW)
endif()

add_subdirectory(src)





