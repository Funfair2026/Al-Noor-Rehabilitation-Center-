@echo off
title Funfair QR Code Payment System - One-Click Starter
color 0A

echo.
echo 🎪============================================================🎪
echo 🎪  FUNFAIR QR CODE PAYMENT SYSTEM - ONE-CLICK STARTER  🎪
echo 🎪============================================================🎪
echo.

echo 🐍 Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is not installed or not in PATH
    echo    Please install Python 3.8+ from https://python.org
    echo    Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

echo ✅ Python is installed
echo.

echo 📦 Installing dependencies...
python -m pip install flask qrcode[pil] Pillow Flask-CORS pandas matplotlib openpyxl PyJWT --quiet
if errorlevel 1 (
    echo ⚠️ Warning: Some dependencies might not have installed properly
    echo    The system will try to continue anyway...
)

echo ✅ Dependencies installation completed
echo.

echo 📄 Checking required files...
if not exist "app_sqlite.py" (
    echo ❌ app_sqlite.py not found
    echo    Please ensure all files are in the same directory
    pause
    exit /b 1
)

if not exist "init_sqlite.py" (
    echo ❌ init_sqlite.py not found
    echo    Please ensure all files are in the same directory
    pause
    exit /b 1
)

echo ✅ All required files found
echo.

echo 🗄️ Checking database...
if not exist "funfair.db" (
    echo    Database not found, initializing...
    python init_sqlite.py
    if errorlevel 1 (
        echo ❌ Error initializing database
        echo    The system will try to continue anyway...
    ) else (
        echo ✅ Database initialized successfully
    )
) else (
    echo ✅ Database already exists
)

echo.
echo 🎉============================================================🎉
echo 🎉  EVERYTHING IS READY! STARTING YOUR FUNFAIR SYSTEM!  🎉
echo 🎉============================================================🎉
echo.

echo 🚀 Starting Funfair QR Code Payment System...
echo.
echo 📱 The system will open in your browser at: http://localhost:5001
echo 🔐 Admin login: admin / funfair2025
echo 🛑 Press Ctrl+C to stop the server
echo.

timeout /t 3 /nobreak >nul

echo 🌐 Opening browser...
start http://localhost:5001

echo.
echo 🎪 Starting server...
echo.

python app_sqlite.py

echo.
echo 🛑 Server stopped
pause
