#!/bin/bash

# AegisAI Linux Agent Build Script

set -e  # Exit on any error

echo "🚀 Building AegisAI Linux Agent..."

# Create build directory
mkdir -p build
cd build

# Configure with CMake
echo "⚙️  Configuring build..."
cmake .. -DCMAKE_BUILD_TYPE=Release

# Build the agent
echo "🔨 Compiling..."
make -j$(nproc)

# Install the agent (requires sudo)
echo "📦 Installing agent..."
if [ "$EUID" -eq 0 ]; then
    make install
else
    echo "⚠️  Note: Run 'sudo make install' to install the agent system-wide"
fi

echo "✅ Build completed successfully!"

# Show build artifacts
echo "📁 Build artifacts:"
ls -la aegisai-agent

echo ""
echo "🔧 To run the agent:"
echo "  ./aegisai-agent [watch_directory]"
echo ""
echo "📝 To install as a systemd service:"
echo "  sudo make install"
echo "  sudo systemctl enable aegisai-agent"
echo "  sudo systemctl start aegisai-agent"