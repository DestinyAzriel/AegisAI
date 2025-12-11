#!/bin/bash
# AegisAI macOS Package Build Script

echo "Building AegisAI macOS Package..."

# Create build directory
mkdir -p ../../build/macos/pkg/root

# Copy files to package root
cp -R ../../dist/* ../../build/macos/pkg/root/

# Create package
pkgbuild --root ../../build/macos/pkg/root \
         --identifier com.aegisai.antivirus \
         --version 1.0.0 \
         --install-location /Applications/AegisAI \
         ../../build/macos/pkg/aegisai.pkg

# Create distribution package
productbuild --package ../../build/macos/pkg/aegisai.pkg \
             --resources ../../packaging/macos/Resources \
             ../../dist/AegisAI-1.0.0.pkg

echo "macOS package build complete!"
echo "Package location: ../../dist/AegisAI-1.0.0.pkg"