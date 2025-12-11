# AegisAI Kernel-Level Monitoring Driver Installation Script
# ========================================================

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "This script must be run as Administrator" -ForegroundColor Red
    Write-Host "Please right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

# Check Windows version
$os = Get-WmiObject -Class Win32_OperatingSystem
if ($os.Version -lt "6.0") {
    Write-Host "Windows Vista or later is required for minifilter drivers" -ForegroundColor Red
    exit 1
}

Write-Host "AegisAI Kernel-Level Monitoring Driver Installation" -ForegroundColor Green
Write-Host "=====================================================" -ForegroundColor Green

# Get script directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Write-Host "Script directory: $scriptDir"

# Check if driver files exist
$driverFile = Join-Path $scriptDir "aegisai_filter.sys"
$infFile = Join-Path $scriptDir "aegisai_filter.inf"

if (-not (Test-Path $driverFile)) {
    Write-Host "Driver file not found: $driverFile" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $infFile)) {
    Write-Host "INF file not found: $infFile" -ForegroundColor Red
    exit 1
}

Write-Host "Found driver files:" -ForegroundColor Yellow
Write-Host "  Driver: $driverFile"
Write-Host "  INF: $infFile"

# Stop any existing service
Write-Host "Stopping existing AegisAI filter service (if running)..." -ForegroundColor Yellow
Stop-Service -Name "AegisAIFilter" -Force -ErrorAction SilentlyContinue

# Uninstall existing driver
Write-Host "Uninstalling existing driver (if installed)..." -ForegroundColor Yellow
pnputil /delete-driver oem*.inf /force 2>$null | Out-Null

# Install the driver
Write-Host "Installing AegisAI filter driver..." -ForegroundColor Yellow
try {
    pnputil /add-driver "$infFile" /install
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Driver installed successfully" -ForegroundColor Green
    } else {
        Write-Host "Driver installation failed with exit code: $LASTEXITCODE" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "Error installing driver: $_" -ForegroundColor Red
    exit 1
}

# Start the service
Write-Host "Starting AegisAI filter service..." -ForegroundColor Yellow
try {
    Start-Service -Name "AegisAIFilter" -ErrorAction Stop
    Write-Host "Service started successfully" -ForegroundColor Green
} catch {
    Write-Host "Error starting service: $_" -ForegroundColor Red
    # Try to start manually
    sc start AegisAIFilter
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Manual service start also failed" -ForegroundColor Red
        exit 1
    }
}

# Verify installation
Write-Host "Verifying installation..." -ForegroundColor Yellow
$service = Get-Service -Name "AegisAIFilter" -ErrorAction SilentlyContinue
if ($service) {
    Write-Host "Service status: $($service.Status)" -ForegroundColor Green
    if ($service.Status -eq "Running") {
        Write-Host "✅ AegisAI kernel-level monitoring driver installed and running successfully!" -ForegroundColor Green
    } else {
        Write-Host "⚠️  Driver installed but service is not running" -ForegroundColor Yellow
    }
} else {
    Write-Host "❌ Service not found after installation" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Installation completed!" -ForegroundColor Green
Write-Host "The AegisAI kernel-level monitoring driver is now active." -ForegroundColor Green
Write-Host "It will monitor file system operations in real-time for enhanced threat detection." -ForegroundColor Green

# Pause to allow user to see results
Write-Host ""
Write-Host "Press any key to exit..." -NoNewline
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")