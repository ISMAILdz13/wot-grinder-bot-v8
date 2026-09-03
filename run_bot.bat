@echo off
setlocal enabledelayedexpansion

:: WoT Grinder Bot v8 - Windows Launcher
:: Interactive menu system with credential input and Cuckoo solver compilation

title WoT Grinder Bot v8 - Windows Launcher
color 0A

:MENU
cls
echo.
echo ================================================================
echo           WoT Grinder Bot v8 - Windows Edition
echo ================================================================
echo.
echo   [1] Compile Cuckoo Solver (Windows DLL)
echo   [2] Enter Credentials
echo   [3] Run Bot
echo   [4] Test Connection Only
echo   [5] View Current Settings
echo   [6] Exit
echo.
echo ================================================================

set /p choice="Enter your choice (1-6): "

if "%choice%"=="1" goto COMPILE
if "%choice%"=="2" goto CREDENTIALS
if "%choice%"=="3" goto RUN
if "%choice%"=="4" goto TEST
if "%choice%"=="5" goto SETTINGS
if "%choice%"=="6" goto EXIT

echo Invalid choice! Please try again.
timeout /t 2 >nul
goto MENU

:COMPILE
cls
echo.
echo ================================================================
echo   Compiling Cuckoo Cycle Solver for Windows
echo ================================================================
echo.

:: Check if MinGW is available
where gcc >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] GCC/MinGW not found!
    echo.
    echo Please install MinGW-w64 from:
    echo   https://www.mingw-w64.org/downloads/
    echo.
    echo Or use MSYS2:
    echo   pacman -S mingw-w64-x86_64-gcc
    echo.
    pause
    goto MENU
)

echo [INFO] Found GCC: 
gcc --version | findstr /C:"gcc"
echo.

:: Compile the Cuckoo solver
echo [INFO] Compiling cuckoo_fast.c...
gcc -O3 -shared -o src\cuckoo_fast.dll src\cuckoo_fast.c

if %errorlevel% equ 0 (
    echo.
    echo [SUCCESS] cuckoo_fast.dll compiled successfully!
    echo          Location: src\cuckoo_fast.dll
    echo.
    dir src\cuckoo_fast.dll
) else (
    echo.
    echo [ERROR] Compilation failed!
    echo.
)

echo.
pause
goto MENU

:CREDENTIALS
cls
echo.
echo ================================================================
echo   Enter Your World of Tanks Credentials
echo ================================================================
echo.
echo   WARNING: Your credentials will be stored in credentials.ini
echo            This file should be kept secure!
echo.

set /p WOT_USERNAME="Enter your WoT username/email: "
echo.

:: Mask password input using PowerShell
echo Enter your WoT password:
powershell -Command "$p = New-Object System.Security.SecureString; do { $k = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown'); if ($k.VirtualKeyCode -eq 13) { break }; if ($k.VirtualKeyCode -eq 8 -and $p.Length -gt 0) { $p.Remove($p.Length-1,1); Write-Host -NoNewline "`b `b" }; elseif ($k.Character -ne 0) { $p += $k.Character; Write-Host -NoNewline '*'} } while ($true); $b = New-Object System.Runtime.InteropServices.MarshalBuilder+SecureStringBSTR([System.Security.SecureString]$p); Write-Output $b.ToString()"
set /p WOT_PASSWORD=

:: Alternative simple password input
echo.
echo [NOTE] If password masking didn't work, enter password directly:
set /p WOT_PASSWORD="Password: "

:: Save credentials
echo [username] = %WOT_USERNAME% > credentials.ini
echo [password] = %WOT_PASSWORD% >> credentials.ini

echo.
echo [SUCCESS] Credentials saved to credentials.ini
echo.
echo Username: %WOT_USERNAME%
echo Password: ********
echo.
pause
goto MENU

:RUN
cls
echo.
echo ================================================================
echo   Starting WoT Grinder Bot
echo ================================================================
echo.

:: Check if credentials exist
if not exist credentials.ini (
    echo [WARNING] No credentials found!
    echo.
    set /p create="Do you want to enter credentials now? (Y/N): "
    if /i "%create%"=="Y" goto CREDENTIALS
    echo.
    echo Running with default test credentials...
)

:: Check if Cuckoo solver exists
if not exist src\cuckoo_fast.dll (
    echo [WARNING] Cuckoo solver DLL not found!
    echo.
    set /p compile="Do you want to compile it now? (Y/N): "
    if /i "%compile%"=="Y" goto COMPILE
    echo.
    echo [INFO] Will use slower Python solver...
)

echo [INFO] Starting bot...
echo.
python src\bw_bot.py

if %errorlevel% equ 0 (
    echo.
    echo [SUCCESS] Bot completed successfully!
) else (
    echo.
    echo [ERROR] Bot exited with error code %errorlevel%
)

echo.
pause
goto MENU

:TEST
cls
echo.
echo ================================================================
echo   Testing Network Connection
echo ================================================================
echo.

echo [INFO] Testing connection to WoT EU login server...
echo         Host: login.p1.worldoftanks.eu
echo         Port: 20016
echo.

:: Test with Python
python -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5); print('[OK] UDP socket created'); s.close()"

if %errorlevel% equ 0 (
    echo.
    echo [SUCCESS] Network test passed!
) else (
    echo.
    echo [ERROR] Network test failed!
    echo         Check your firewall/antivirus settings.
)

echo.
pause
goto MENU

:SETTINGS
cls
echo.
echo ================================================================
echo   Current Settings
echo ================================================================
echo.

if exist credentials.ini (
    echo [CREDENTIALS FILE] Found: credentials.ini
    for /f "tokens=2 delims==" %%a in ('findstr "[username]" credentials.ini') do echo   Username: %%a
    echo   Password: ********
) else (
    echo [CREDENTIALS FILE] Not found
)

echo.
if exist src\cuckoo_fast.dll (
    echo [CUCKOO SOLVER] Compiled: YES
    echo                File: src\cuckoo_fast.dll
    dir src\cuckoo_fast.dll | findstr "cuckoo"
) else (
    echo [CUCKOO SOLVER] Compiled: NO
    echo                Will use Python solver (slower)
)

echo.
echo [PROTOCOL VERSION] 17.1.0 (5)
echo [SERVER]           login.p1.worldoftanks.eu:20016
echo [RSA KEY]          Official WoT EU key
echo.
pause
goto MENU

:EXIT
cls
echo.
echo ================================================================
echo   Thank you for using WoT Grinder Bot v8
echo ================================================================
echo.
timeout /t 2 >nul
exit /b 0
