@echo off
echo Building AegisAI Windows Agent...
echo.

REM Check if Visual Studio is installed
where cl >nul 2>nul
if %errorlevel% neq 0 (
    echo Error: Microsoft Visual C++ compiler not found.
    echo Please install Visual Studio or Visual Studio Build Tools.
    echo.
    pause
    exit /b 1
)

REM Check if vcpkg is installed (for OpenSSL)
where vcpkg >nul 2>nul
if %errorlevel% neq 0 (
    echo Warning: vcpkg not found. You may need to install OpenSSL manually.
    echo.
)

REM Try to build with CMake first
if exist "CMakeLists.txt" (
    echo Found CMakeLists.txt, building with CMake...
    if not exist "build" mkdir build
    cd build
    cmake .. -G "Visual Studio 16 2019"
    if %errorlevel% neq 0 (
        echo CMake configuration failed.
        cd ..
        goto manual_build
    )
    cmake --build . --config Release
    if %errorlevel% neq 0 (
        echo CMake build failed.
        cd ..
        goto manual_build
    )
    echo.
    echo Build successful with CMake!
    echo Executable location: build\Release\aegisai-agent.exe
    echo Kernel monitor location: build\Release\kernel-monitor.exe
    cd ..
    goto end
)

:manual_build
echo Building manually with cl.exe...

REM Check if OpenSSL is installed
set OPENSSL_ROOT_DIR=
for /f "tokens=*" %%i in ('where openssl 2^>nul') do set OPENSSL_ROOT_DIR=%%i
if "%OPENSSL_ROOT_DIR%"=="" (
    echo Warning: OpenSSL not found in PATH.
    echo Please install OpenSSL development libraries.
    echo.
)

REM Compile the agent with all required files
cl /EHsc /W4 /O2 agent.cpp security.cpp wfp_filter.cpp /link advapi32.lib shell32.lib ole32.lib Fwpuclnt.lib

if %errorlevel% equ 0 (
    echo.
    echo Agent build successful!
    echo aegisai-agent.exe has been created.
) else (
    echo.
    echo Agent build failed!
    echo Please check the compilation errors above.
)

REM Compile the kernel monitor
cl /EHsc /W4 /O2 kernel_monitor.cpp /link advapi32.lib shell32.lib ole32.lib psapi.lib fltLib.lib

if %errorlevel% equ 0 (
    echo.
    echo Kernel monitor build successful!
    echo kernel-monitor.exe has been created.
) else (
    echo.
    echo Kernel monitor build failed!
    echo Please check the compilation errors above.
)

:end
echo.
pause