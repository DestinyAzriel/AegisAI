@echo off
echo Initializing Visual Studio Environment...
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\Common7\Tools\VsDevCmd.bat"
echo.
echo Building AegisAI Kernel Monitor...
cd /d D:\AegisAI\agent\windows

echo Compiling agent.cpp...
cl /EHsc /W4 /O2 /D_WIN32_WINNT=0x0600 agent.cpp /link advapi32.lib shell32.lib ole32.lib ws2_32.lib /OUT:aegisai-agent.exe

echo.
echo Build process completed.
pause