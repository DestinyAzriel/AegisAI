cmake_minimum_required(VERSION 3.10)
project(AegisAI_macOS_Agent)

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

# Enable Objective-C++ compilation
enable_language(OBJCXX)

# Find required frameworks
find_library(SECURITY_FRAMEWORK Security)
find_library(ENDPOINT_SECURITY_FRAMEWORK EndpointSecurity)
find_library(SYSTEM_CONFIGURATION_FRAMEWORK SystemConfiguration)
find_library(CORE_FOUNDATION_FRAMEWORK CoreFoundation)

# Check if required frameworks are available
if(NOT SECURITY_FRAMEWORK)
    message(FATAL_ERROR "Security framework not found")
endif()

if(NOT ENDPOINT_SECURITY_FRAMEWORK)
    message(FATAL_ERROR "EndpointSecurity framework not found")
endif()

if(NOT SYSTEM_CONFIGURATION_FRAMEWORK)
    message(FATAL_ERROR "SystemConfiguration framework not found")
endif()

if(NOT CORE_FOUNDATION_FRAMEWORK)
    message(FATAL_ERROR "CoreFoundation framework not found")
endif()

# Source files
set(SOURCES
    agent.mm
    security.cpp
    compliance.cpp
)

# Header files
set(HEADERS
    security.h
    compliance.h
)

# Create executable
add_executable(aegisai-agent ${SOURCES} ${HEADERS})

# Link frameworks
target_link_libraries(aegisai-agent
    ${SECURITY_FRAMEWORK}
    ${ENDPOINT_SECURITY_FRAMEWORK}
    ${SYSTEM_CONFIGURATION_FRAMEWORK}
    ${CORE_FOUNDATION_FRAMEWORK}
)

# Compiler options for Objective-C++
set_target_properties(aegisai-agent PROPERTIES
    COMPILE_FLAGS "-fobjc-arc"
)

# Include directories
target_include_directories(aegisai-agent PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Install target
install(TARGETS aegisai-agent
    RUNTIME DESTINATION bin
)

# Create plist file
configure_file(
    aegisai-agent.plist.in
    ${CMAKE_CURRENT_BINARY_DIR}/aegisai-agent.plist
)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/aegisai-agent.plist
    DESTINATION /Library/LaunchDaemons
)