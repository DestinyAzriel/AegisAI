cmake_minimum_required(VERSION 3.10)
project(AegisAI_Linux_Agent)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler flags
set(CMAKE_CXX_FLAGS "-Wall -Wextra")
set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

# Find required packages
find_package(Threads REQUIRED)

# Check for inotify
include(CheckIncludeFile)
check_include_file(sys/inotify.h HAVE_INOTIFY_H)

if(NOT HAVE_INOTIFY_H)
    message(FATAL_ERROR "inotify header files not found. Required for file monitoring.")
endif()

# Check for proc filesystem support
check_include_file(proc/readproc.h HAVE_READPROC_H)

# Source files
set(SOURCES
    agent.cpp
    security.cpp
    compliance.cpp
    kernel_monitor.cpp
)

# Header files
set(HEADERS
    security.h
    compliance.h
)

# Create executable
add_executable(aegisai-agent ${SOURCES} ${HEADERS})

# Create kernel monitor executable
add_executable(kernel-monitor kernel_monitor.cpp)

# Link libraries for main agent
target_link_libraries(aegisai-agent 
    Threads::Threads
)

# Link libraries for kernel monitor
target_link_libraries(kernel-monitor
    Threads::Threads
)

# Add procps library if available
if(HAVE_READPROC_H)
    target_link_libraries(aegisai-agent procps)
    target_link_libraries(kernel-monitor procps)
endif()

# Include directories
target_include_directories(aegisai-agent PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(kernel-monitor PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Install targets
install(TARGETS aegisai-agent kernel-monitor
    RUNTIME DESTINATION bin
)

# Create systemd service file
configure_file(
    aegisai-agent.service.in
    ${CMAKE_CURRENT_BINARY_DIR}/aegisai-agent.service
)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/aegisai-agent.service
    DESTINATION /etc/systemd/system
)