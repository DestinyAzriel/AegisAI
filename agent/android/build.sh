#!/bin/bash

# AegisAI Android Agent Build Script

echo "Building AegisAI Android Agent..."

# Check if Android SDK is available
if [ -z "$ANDROID_HOME" ]; then
    echo "Error: ANDROID_HOME environment variable not set"
    exit 1
fi

# Check if Gradle is available
if ! command -v gradle &> /dev/null; then
    echo "Gradle not found, using Gradle Wrapper"
    GRADLE_CMD="./gradlew"
else
    GRADLE_CMD="gradle"
fi

# Clean previous builds
echo "Cleaning previous builds..."
$GRADLE_CMD clean

# Build the APK
echo "Building APK..."
$GRADLE_CMD assembleDebug

# Check if build was successful
if [ $? -eq 0 ]; then
    echo "Build successful!"
    echo "APK location: app/build/outputs/apk/debug/app-debug.apk"
else
    echo "Build failed!"
    exit 1
fi

# Optional: Install on connected device
if [ "$1" = "--install" ]; then
    echo "Installing APK on connected device..."
    adb install -r app/build/outputs/apk/debug/app-debug.apk
    if [ $? -eq 0 ]; then
        echo "APK installed successfully!"
    else
        echo "Failed to install APK!"
    fi
fi