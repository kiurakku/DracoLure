cmake_minimum_required(VERSION 3.10)
project(CppAnalyzer)

set(CMAKE_CXX_STANDARD 17)

file(GLOB SOURCES *.cpp)

add_executable(cpp_analyzer ${SOURCES})

