@echo off
REM Funfair QR Code Payment System - Startup Script with Email Configuration
REM This script sets up email environment variables and starts the server

echo ========================================
echo Funfair QR Code Payment System
echo Starting with Email Configuration...
echo ========================================
echo.

REM Set email environment variables
set MAIL_USERNAME=alnoorautogen@outlook.com
set MAIL_PASSWORD=Alnoor2025
set MAIL_SERVER=smtp.office365.com
set MAIL_PORT=587

echo Email configuration set:
echo   Server: %MAIL_SERVER%
echo   Port: %MAIL_PORT%
echo   Username: %MAIL_USERNAME%
echo   Password: [hidden]
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python not found. Please install Python 3.8 or higher.
    pause
    exit /b 1
)

REM Check if Flask-Mail is installed
echo Checking dependencies...
python -c "import flask_mail" >nul 2>&1
if errorlevel 1 (
    echo Installing Flask-Mail...
    pip install Flask-Mail
)

echo.
echo Starting Flask server...
echo Server will be available at: http://localhost:5001
echo Press Ctrl+C to stop the server
echo.

REM Start the Flask application
python app_sqlite.py

pause

