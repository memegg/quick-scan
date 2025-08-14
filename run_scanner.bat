@echo off
echo ========================================
echo Web Application Security Scanner
echo ========================================
echo.
echo WARNING: This tool is for EDUCATIONAL PURPOSES ONLY
echo Only use on websites you own or have explicit permission to test
echo Unauthorized security testing is illegal and unethical
echo.
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.7+ and try again
    pause
    exit /b 1
)

REM Check if requirements are installed
echo Checking dependencies...
pip show requests >nul 2>&1
if errorlevel 1 (
    echo Installing required dependencies...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo ERROR: Failed to install dependencies
        pause
        exit /b 1
    )
)

echo.
echo Dependencies check completed successfully!
echo.
echo Choose your scanner:
echo 1. Basic Security Scanner
echo 2. Advanced Security Scanner
echo.
set /p choice="Enter your choice (1 or 2): "

if "%choice%"=="1" (
    echo.
    echo Running Basic Security Scanner...
    echo.
    set /p url="Enter target URL: "
    set /p username="Enter username (optional, press Enter to skip): "
    set /p password="Enter password (optional, press Enter to skip): "
    
    if "%username%"=="" (
        python web_security_scanner.py "%url%"
    ) else (
        python web_security_scanner.py "%url%" --username "%username%" --password "%password%"
    )
) else if "%choice%"=="2" (
    echo.
    echo Running Advanced Security Scanner...
    echo.
    set /p url="Enter target URL: "
    set /p username="Enter username (optional, press Enter to skip): "
    set /p password="Enter password (optional, press Enter to skip): "
    
    if "%username%"=="" (
        python advanced_scanner.py "%url%"
    ) else (
        python advanced_scanner.py "%url%" --username "%username%" --password "%password%"
    )
) else (
    echo Invalid choice. Please run the script again.
)

echo.
echo Scan completed. Check the generated reports and logs.
pause
