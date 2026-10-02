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
echo.

"%PYEXE%" "%~dp0app_gui.py"
if errorlevel 1 (
    echo.
    echo GUI exited with an error.
    pause
)
