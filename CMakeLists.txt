cmake_minimum_required(VERSION 3.11)

project(ProcessScanner CXX)

set(CMAKE_CXX_STANDARD 20)

include(${CMAKE_BINARY_DIR}/conan_toolchain.cmake)
find_package(spdlog REQUIRED)

add_library(Logger 
    src/Logger/logger.h
    src/Logger/logger.cpp
)

target_link_libraries(Logger PUBLIC 
    spdlog::spdlog
)

add_library(ProcScan
    src/ProcessScanner/process_scanner.h 
    src/ProcessScanner/process_scanner.cpp 

    src/Analyzers/analyzer.h
    src/Analyzers/analyzer.cpp

    src/Analyzers/RWX/rwx_analyzer.h
    src/Analyzers/RWX/rwx_analyzer.cpp

    src/Analyzers/HiddenProcesses/hidden_processes_analyzer.h
    src/Analyzers/HiddenProcesses/hidden_processes_analyzer.cpp

    src/domain.h
    src/domain.cpp
)

target_link_libraries(ProcScan PUBLIC 
    Logger
)

add_library(ThreadPool 
    src/ThreadPool/thread_pool.h
    src/ThreadPool/thread_pool.cpp 
)

add_library(Application
    src/application.h 
    src/application.cpp
)

target_link_libraries(Application PUBLIC 
    ProcScan 
    ThreadPool
)

add_executable(ProcessScanner
    src/gui.h
    src/gui.cpp
    src/main.cpp 
)

target_link_libraries(ProcessScanner PRIVATE
    Application
)
