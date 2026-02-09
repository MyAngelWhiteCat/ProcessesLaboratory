cmake_minimum_required(VERSION 3.11)

project(ProcessScanner CXX)

set(CMAKE_CXX_STANDARD 20)

include(${CMAKE_BINARY_DIR}/conan_toolchain.cmake)
find_package(spdlog REQUIRED)

add_library(ProcScan
    src/process_scanner.h 
    src/process_scanner.cpp 

    src/analyzer.h
    src/analyzer.cpp

    src/rwx_analyzer.h
    src/rwx_analyzer.cpp

    src/hidden_processes_analyzer.h
    src/hidden_processes_analyzer.cpp

    src/domain.h
    src/domain.cpp

    src/logger.h
    src/logger.cpp
)

target_link_libraries(ProcScan PUBLIC 
    spdlog::spdlog
)

add_library(Application
    src/application.h 
    src/application.cpp
)

target_link_libraries(Application PUBLIC 
    ProcScan 
)

add_executable(ProcessScanner
    src/main.cpp 
)

target_link_libraries(ProcessScanner PRIVATE
    Application
)
