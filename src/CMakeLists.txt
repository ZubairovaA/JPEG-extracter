cmake_minimum_required(VERSION 3.11)

project(extractJPEG)

file(GLOB SOURCE_FILES *.cpp)
file(GLOB HEADER_FILES *.h)

add_executable(${PROJECT_NAME} ${SOURCE_FILES} ${HEADER_FILES})
target_include_directories(${PROJECT_NAME} PRIVATE "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>")
