# Funfair QR Code Payment System - Startup Script with Email Configuration
# This script sets up email environment variables and starts the server

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Funfair QR Code Payment System" -ForegroundColor Cyan
Write-Host "Starting with Email Configuration..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Set email environment variables
$env:MAIL_USERNAME = "alnoorautogen@outlook.com"
$env:MAIL_PASSWORD = "Alnoor2025"
$env:MAIL_SERVER = "smtp.office365.com"
$env:MAIL_PORT = "587"

Write-Host "Email configuration set:" -ForegroundColor Green
Write-Host "  Server: $env:MAIL_SERVER" -ForegroundColor Yellow
Write-Host "  Port: $env:MAIL_PORT" -ForegroundColor Yellow
Write-Host "  Username: $env:MAIL_USERNAME" -ForegroundColor Yellow
Write-Host "  Password: [hidden]" -ForegroundColor Yellow
Write-Host ""

# Check if Python is available
try {
    $pythonVersion = python --version 2>&1
    Write-Host "Python found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "Error: Python not found. Please install Python 3.8 or higher." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# Check if Flask-Mail is installed
Write-Host "Checking dependencies..." -ForegroundColor Cyan
$flaskMailCheck = python -c "import flask_mail; print('OK')" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "Installing Flask-Mail..." -ForegroundColor Yellow
    pip install Flask-Mail
}

Write-Host ""
Write-Host "Starting Flask server..." -ForegroundColor Cyan
Write-Host "Server will be available at: http://localhost:5001" -ForegroundColor Green
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Yellow
Write-Host ""

# Start the Flask application
python app_sqlite.py

