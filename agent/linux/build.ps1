# AegisAI Linux Agent Build Script (PowerShell)

Write-Host "🚀 Building AegisAI Linux Agent..."

# Create build directory
if (!(Test-Path "build")) {
    New-Item -ItemType Directory -Name "build" | Out-Null
}
Set-Location -Path "build"

# Configure with CMake
Write-Host "⚙️  Configuring build..."
cmake .. -DCMAKE_BUILD_TYPE=Release

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ CMake configuration failed"
    Set-Location -Path ".."
    exit 1
}

# Build the agent
Write-Host "🔨 Compiling..."
cmake --build . --config Release

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Build failed"
    Set-Location -Path ".."
    exit 1
}

Write-Host "✅ Build completed successfully!"

# Show build artifacts
Write-Host "📁 Build artifacts:"
Get-ChildItem -Path "aegisai-agent*" -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "🔧 To run the agent:"
Write-Host "  ./aegisai-agent [watch_directory]"
Write-Host ""
Write-Host "📝 To install as a systemd service (on Linux):"
Write-Host "  sudo make install"
Write-Host "  sudo systemctl enable aegisai-agent"
Write-Host "  sudo systemctl start aegisai-agent"

Set-Location -Path ".."