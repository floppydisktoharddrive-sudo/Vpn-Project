@echo off
setlocal EnableExtensions
cd /d "%~dp0"

REM Find a real Python executable BEFORE elevation. After "Run as administrator"
REM the user PATH is often gone, which is why the GUI appeared to "not work".
set "PYEXE="
if defined NETLOCK_PYTHON if exist "%NETLOCK_PYTHON%" set "PYEXE=%NETLOCK_PYTHON%"

if not defined PYEXE (
    where py >nul 2>nul
    if not errorlevel 1 (
        for /f "delims=" %%I in ('py -3 -c "import sys; print(sys.executable)" 2^>nul') do set "PYEXE=%%I"
    )
)
if not defined PYEXE (
    where python >nul 2>nul
    if not errorlevel 1 (
        for /f "delims=" %%I in ('python -c "import sys; print(sys.executable)" 2^>nul') do set "PYEXE=%%I"
    )
)
if not defined PYEXE (
    where python3 >nul 2>nul
    if not errorlevel 1 (
        for /f "delims=" %%I in ('python3 -c "import sys; print(sys.executable)" 2^>nul') do set "PYEXE=%%I"
    )
)

if not defined PYEXE (
    echo Python was not found on PATH.
    echo Install Python and enable "Add python.exe to PATH".
    pause
    exit /b 1
)

net session >nul 2>&1
if errorlevel 1 (
    echo Requesting administrator rights for the GUI...
    echo %PYEXE%> "%TEMP%\netlock_python.txt"
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs -WorkingDirectory '%~dp0'"
    exit /b
)

if exist "%TEMP%\netlock_python.txt" (
    set /p PYEXE=<"%TEMP%\netlock_python.txt"
)

echo Using Python: %PYEXE%
"%PYEXE%" -c "import tkinter" 2>nul
if errorlevel 1 (
    echo Tkinter is missing from this Python install.
    echo Reinstall Python and keep tcl/tk enabled.
    pause
    exit /b 1
)

"%PYEXE%" -c "import cryptography" 2>nul
if errorlevel 1 (
    echo Installing cryptography...
    "%PYEXE%" -m pip install --quiet cryptography
)

if exist "%~dp0libnetlock_net.dll" (
    echo Using C helper: "%~dp0libnetlock_net.dll"
) else if exist "%~dp0netlock_net.dll" (
    echo Using C helper: "%~dp0netlock_net.dll"
) else (
    echo Native helper DLL not found next to start.bat
)

echo.
echo Binding to the working Internet connection, then starting the GUI...
"%PYEXE%" "%~dp0network_boot.py"
if exist "%~dp0vpn_data\need_soft_reset.flag" (
    set /p ADAPTER=<"%~dp0vpn_data\need_soft_reset.flag"
    echo Internet was offline — soft adapter and Winsock reset, no reboot...
    call "%~dp0soft_reset.bat" "%ADAPTER%"
    del "%~dp0vpn_data\need_soft_reset.flag" >nul 2>&1
)
echo Binding and configuring servers ^(secure, stream, parallel, vpn, proxy^)...
"%PYEXE%" "%~dp0bind_servers.py"
echo Wildcard is true only when that bind reports configured and online.
echo.

"%PYEXE%" "%~dp0app_gui.py"
echo.
echo Checking the connection is live before this window closes...
"%PYEXE%" -c "import network_boot; raise SystemExit(0 if network_boot.probe_internet()[0] else 1)"
if errorlevel 1 (
    echo Connection is not live yet. Restoring DHCP and firewall...
    "%PYEXE%" -c "import network_boot; network_boot.restore_original_and_wait()"
)
echo Connection check finished.
pause
