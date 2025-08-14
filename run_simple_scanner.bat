@echo off
echo Simple Web Security Scanner
echo ===========================

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Python is not installed. Please install Python first.
    echo Download from: https://www.python.org/downloads/
    pause
    exit /b 1
)

REM Install dependencies
echo Installing dependencies...
pip install -r simple_requirements.txt

REM Run scanner
echo.
echo Running security scanner...
python working_scanner.py %1 %2 %3 %4 %5

echo.
echo Scan completed! Check the generated JSON report file.
pause
