#!/bin/bash

# 🎪 FUNFAIR QR CODE PAYMENT SYSTEM - ONE-CLICK STARTER
# =====================================================
# This script will automatically install everything and start the system

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Clear screen
clear

# Print banner
echo -e "${PURPLE}🎪============================================================🎪${NC}"
echo -e "${PURPLE}🎪  FUNFAIR QR CODE PAYMENT SYSTEM - ONE-CLICK STARTER  🎪${NC}"
echo -e "${PURPLE}🎪============================================================🎪${NC}"
echo

# Check Python installation
echo -e "${BLUE}🐍 Checking Python installation...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python 3 is not installed${NC}"
    echo "   Please install Python 3.8+ from https://python.org"
    echo "   Or use your package manager:"
    echo "   - macOS: brew install python3"
    echo "   - Ubuntu/Debian: sudo apt install python3 python3-pip"
    echo "   - CentOS/RHEL: sudo yum install python3 python3-pip"
    read -p "Press Enter to exit..."
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo -e "${GREEN}✅ Python $PYTHON_VERSION is installed${NC}"
echo

# Install dependencies
echo -e "${BLUE}📦 Installing dependencies...${NC}"
if [ -f "requirements.txt" ]; then
    echo "   Installing from requirements.txt..."
    python3 -m pip install -r requirements.txt --quiet
else
    echo "   Installing core dependencies..."
    python3 -m pip install flask qrcode[pil] Pillow Flask-CORS pandas matplotlib openpyxl PyJWT --quiet
fi

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Dependencies installed successfully${NC}"
else
    echo -e "${YELLOW}⚠️ Warning: Some dependencies might not have installed properly${NC}"
    echo "   The system will try to continue anyway..."
fi
echo

# Check required files
echo -e "${BLUE}📄 Checking required files...${NC}"
if [ ! -f "app_sqlite.py" ]; then
    echo -e "${RED}❌ app_sqlite.py not found${NC}"
    echo "   Please ensure all files are in the same directory"
    read -p "Press Enter to exit..."
    exit 1
fi

if [ ! -f "init_sqlite.py" ]; then
    echo -e "${RED}❌ init_sqlite.py not found${NC}"
    echo "   Please ensure all files are in the same directory"
    read -p "Press Enter to exit..."
    exit 1
fi

echo -e "${GREEN}✅ All required files found${NC}"
echo

# Initialize database
echo -e "${BLUE}🗄️ Checking database...${NC}"
if [ ! -f "funfair.db" ]; then
    echo "   Database not found, initializing..."
    python3 init_sqlite.py
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Database initialized successfully${NC}"
    else
        echo -e "${YELLOW}⚠️ Warning: Error initializing database${NC}"
        echo "   The system will try to continue anyway..."
    fi
else
    echo -e "${GREEN}✅ Database already exists${NC}"
fi

echo
echo -e "${CYAN}🎉============================================================🎉${NC}"
echo -e "${CYAN}🎉  EVERYTHING IS READY! STARTING YOUR FUNFAIR SYSTEM!  🎉${NC}"
echo -e "${CYAN}🎉============================================================🎉${NC}"
echo

echo -e "${WHITE}🚀 Starting Funfair QR Code Payment System...${NC}"
echo
echo -e "${WHITE}📱 The system will open in your browser at: http://localhost:5001${NC}"
echo -e "${WHITE}🔐 Admin login: admin / funfair2025${NC}"
echo -e "${WHITE}🛑 Press Ctrl+C to stop the server${NC}"
echo

# Wait 3 seconds
sleep 3

# Open browser (works on macOS and most Linux distributions)
echo -e "${BLUE}🌐 Opening browser...${NC}"
if command -v open &> /dev/null; then
    # macOS
    open http://localhost:5001
elif command -v xdg-open &> /dev/null; then
    # Linux
    xdg-open http://localhost:5001
else
    echo -e "${YELLOW}⚠️ Could not open browser automatically${NC}"
    echo "   Please manually open: http://localhost:5001"
fi

echo
echo -e "${PURPLE}🎪 Starting server...${NC}"
echo

# Start the Flask application
python3 app_sqlite.py

echo
echo -e "${YELLOW}🛑 Server stopped${NC}"
read -p "Press Enter to exit..."
