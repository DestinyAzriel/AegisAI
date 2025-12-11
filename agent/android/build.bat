@echo off
REM AegisAI Android Agent Build Script for Windows

echo Building AegisAI Android Agent...

REM Check if Android SDK is available
if "%ANDROID_HOME%"=="" (
    echo Error: ANDROID_HOME environment variable not set
    exit /b 1
)

REM Use Gradle Wrapper
set GRADLE_CMD=gradlew.bat

REM Clean previous builds
echo Cleaning previous builds...
%GRADLE_CMD% clean

REM Build the APK
echo Building APK...
%GRADLE_CMD% assembleDebug

REM Check if build was successful
if %ERRORLEVEL% EQU 0 (
    echo Build successful!
    echo APK location: app\build\outputs\apk\debug\app-debug.apk
) else (
    echo Build failed!
    exit /b 1
)

REM Optional: Install on connected device
if "%1"=="--install" (
    echo Installing APK on connected device...
    adb install -r app\build\outputs\apk\debug\app-debug.apk
    if %ERRORLEVEL% EQU 0 (
        echo APK installed successfully!
    ) else (
        echo Failed to install APK!
    )
)