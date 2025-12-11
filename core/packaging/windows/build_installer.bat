@echo off
REM AegisAI Windows Installer Build Script

echo Building AegisAI Windows Installer...

REM Create distribution directory
if not exist "..\..\dist" mkdir "..\..\dist"

REM Copy core files to distribution directory
xcopy "..\.." "..\..\dist\" /E /I /Y /EXCLUDE:exclude.txt

REM Remove unnecessary files
del /Q "..\..\dist\*.pyc" 2>nul
del /Q "..\..\dist\*.pyo" 2>nul
del /Q "..\..\dist\*.log" 2>nul
rd /S /Q "..\..\dist\__pycache__" 2>nul
rd /S /Q "..\..\dist\tests" 2>nul
rd /S /Q "..\..\dist\docs" 2>nul

REM Build installer using Inno Setup
"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" "setup.iss"

echo.
echo Installer build complete!
echo Installer location: Output\aegisai-setup.exe