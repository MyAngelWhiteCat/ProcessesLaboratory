cmake_minimum_required(VERSION 3.11)

project(ProcessScanner CXX)

set(CMAKE_CXX_STANDARD 20)

add_library(ProcScan
    src/process_scanner.h 
    src/process_scanner.cpp 
    src/domain.h
    src/domain.cpp
)

add_executable(ProcessScanner
    src/main.cpp 
)

target_link_libraries(ProcessScanner PUBLIC 
    ProcScan
)
