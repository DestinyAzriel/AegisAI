# AegisAI Windows Agent CMakeLists.txt
cmake_minimum_required(VERSION 3.15)
project(AegisAI_Agent VERSION 1.0.0)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add executable for main agent
add_executable(aegisai-agent
    agent.cpp
    security.cpp
    wfp_filter.cpp
)

# Add executable for WFP test
add_executable(test-wfp
    test_wfp.cpp
    security.cpp
    wfp_filter.cpp
)

# Define preprocessor macros to avoid winsock header conflicts
target_compile_definitions(aegisai-agent PRIVATE _WINSOCKAPI_)
target_compile_definitions(test-wfp PRIVATE _WINSOCKAPI_)

# Link Windows libraries for main agent
if(WIN32)
    target_link_libraries(aegisai-agent
        kernel32
        user32
        shell32
        advapi32
        crypt32
        ws2_32
        Fwpuclnt
        Fwpkclnt
    )
    
    target_link_libraries(test-wfp
        kernel32
        user32
        shell32
        advapi32
        crypt32
        ws2_32
        Fwpuclnt
        Fwpkclnt
    )
endif()

# Compiler-specific options for main agent
if(MSVC)
    target_compile_options(aegisai-agent PRIVATE /W4)
    target_compile_options(test-wfp PRIVATE /W4)
else()
    target_compile_options(aegisai-agent PRIVATE -Wall -Wextra -pedantic)
    target_compile_options(test-wfp PRIVATE -Wall -Wextra -pedantic)
endif()

# Installation
install(TARGETS aegisai-agent
    RUNTIME DESTINATION bin
)