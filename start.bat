@echo off
setlocal EnableExtensions EnableDelayedExpansion
title NetLock + Thox AI
chcp 65001 >nul
cd /d "%~dp0"

REM ===== Elevation first (needed for NetLock) =====
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
    echo Requesting administrator rights...
    echo %PYEXE%> "%TEMP%\netlock_python.txt"
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs -WorkingDirectory '%~dp0'"
    exit /b
)

if exist "%TEMP%\netlock_python.txt" (
    set /p PYEXE=<"%TEMP%\netlock_python.txt"
)

echo Using Python: %PYEXE%

REM ===== Start AI first =====
echo.
echo ============================================================
echo  Starting Thox AI first...
echo ============================================================
echo.

set "THOX_NAME=Thox1-27b-Q1_0.gguf"
set "ROOT=%~dp0"
set "ROOT=%ROOT:~0,-1%"
set "WHEEL_URL=https://github.com/abetlen/llama-cpp-python/releases/download/v0.3.35/llama_cpp_python-0.3.35-py3-none-win_amd64.whl"
set "WHEEL_NAME=llama_cpp_python-0.3.35-py3-none-win_amd64.whl"

set "PATH=%ROOT%;%ROOT%\bin;%PATH%"

call :ScanAndBind "bin"
call :ScanAndBind "gcc"
call :ScanAndBind "include"
call :ScanAndBind "lib"
call :ScanAndBind "lib64"
call :ScanAndBind "llama.cpp-master"
call :ScanAndBind "llama.cpp"
call :ScanAndBind "llama.cpp-master-windows"
call :ScanAndBind "llamacpp"
call :ScanAndBind "memory"
call :ScanAndBind "ming"
call :ScanAndBind "mingw"
call :ScanAndBind "mingw64"
call :AddIfExists "%ROOT%\mingw64"
call :ScanAndBind "minw64"
call :ScanAndBind "MinGW"
call :ScanAndBind "w64devkit"
call :ScanAndBind "msys64"
call :ScanAndBind "models"
call :ScanAndBind "model"
call :ScanAndBind "gguf"
call :ScanAndBind "vendor"
call :ScanAndBind "packages"

call :AddIfExists "%ROOT%\llama.cpp-master\build\bin\Release"
call :AddIfExists "%ROOT%\llama.cpp-master\build\bin"
call :AddIfExists "%ROOT%\llama.cpp-master\bin"
call :AddIfExists "%ROOT%\llama.cpp\build\bin\Release"
call :AddIfExists "%ROOT%\llama.cpp\build\bin"
call :AddIfExists "%ROOT%\gcc\bin"
call :AddIfExists "%ROOT%\ming\bin"
call :AddIfExists "%ROOT%\ming\mingw64\bin"
call :AddIfExists "%ROOT%\ming\usr\bin"
call :AddIfExists "%ROOT%\mingw64\bin"
call :AddIfExists "%ROOT%\minw64\bin"
call :AddIfExists "%ROOT%\w64devkit\bin"

if exist "%ROOT%\include" (
    if defined INCLUDE (set "INCLUDE=%ROOT%\include;%INCLUDE%") else (set "INCLUDE=%ROOT%\include")
    echo [INCLUDE] %ROOT%\include
)
if exist "%ROOT%\lib" (
    if defined LIB (set "LIB=%ROOT%\lib;%LIB%") else (set "LIB=%ROOT%\lib")
    echo [LIB]     %ROOT%\lib
)
if exist "%ROOT%\lib64" (
    if defined LIB (set "LIB=%ROOT%\lib64;%LIB%") else (set "LIB=%ROOT%\lib64")
    echo [LIB]     %ROOT%\lib64
)

echo.
echo [AI] Python / venv ...
set "PY="
where py >nul 2>&1 && set "PY=py -3"
if not defined PY where python >nul 2>&1 && set "PY=python"
if not defined PY (
    echo [ERROR] Python 3 is not on PATH for AI.
    goto :AfterAI
)

if not exist "%ROOT%\.venv\Scripts\python.exe" (
    echo       creating .venv ...
    %PY% -m venv "%ROOT%\.venv"
    if errorlevel 1 (
        echo [ERROR] Could not create .venv
        goto :AfterAI
    )
)

call "%ROOT%\.venv\Scripts\activate.bat"
set "AIPYEXE=%ROOT%\.venv\Scripts\python.exe"
echo       venv : %ROOT%\.venv

echo [AI] Dependencies ...
"%AIPYEXE%" -m pip install --upgrade pip >nul 2>&1
if not exist "%ROOT%\vendor" mkdir "%ROOT%\vendor"

set "LOCAL_WHL="
set "LOCAL_SDIST="
if exist "%ROOT%\%WHEEL_NAME%" set "LOCAL_WHL=%ROOT%\%WHEEL_NAME%"
if not defined LOCAL_WHL if exist "%ROOT%\vendor\%WHEEL_NAME%" set "LOCAL_WHL=%ROOT%\vendor\%WHEEL_NAME%"
if not defined LOCAL_WHL (
    for %%F in ("%ROOT%\llama_cpp_python-*.whl") do if exist "%%~fF" set "LOCAL_WHL=%%~fF"
)
if not defined LOCAL_WHL (
    for %%F in ("%ROOT%\vendor\llama_cpp_python-*.whl") do if exist "%%~fF" set "LOCAL_WHL=%%~fF"
)

set "INSTALLED="
if defined LOCAL_WHL (
    echo       local wheel : !LOCAL_WHL!
    "%AIPYEXE%" -m pip install --upgrade "!LOCAL_WHL!"
    if not errorlevel 1 set "INSTALLED=1"
)

if not defined INSTALLED (
    "%AIPYEXE%" -c "import llama_cpp" 2>nul
    if not errorlevel 1 (
        echo       llama-cpp-python : OK
        set "INSTALLED=1"
    )
)

if not defined INSTALLED (
    echo       downloading official CPU wheel 0.3.35 win_amd64
    "%AIPYEXE%" -c "import urllib.request; urllib.request.urlretrieve(r'%WHEEL_URL%', r'%ROOT%\vendor\%WHEEL_NAME%')" 2>nul
    if exist "%ROOT%\vendor\%WHEEL_NAME%" (
        "%AIPYEXE%" -m pip install --upgrade "%ROOT%\vendor\%WHEEL_NAME%"
        if not errorlevel 1 set "INSTALLED=1"
    )
)

if not defined INSTALLED if exist "%ROOT%\requirements.txt" (
    "%AIPYEXE%" -m pip install -r "%ROOT%\requirements.txt" >nul 2>&1
    if not errorlevel 1 set "INSTALLED=1"
)

if not defined INSTALLED (
    echo [WARN] llama-cpp-python not fully installed - AI may fail
)

set "MODEL="
if exist "%ROOT%\%THOX_NAME%" set "MODEL=%ROOT%\%THOX_NAME%"
if not defined MODEL if exist "%ROOT%\models\%THOX_NAME%" set "MODEL=%ROOT%\models\%THOX_NAME%"
if not defined MODEL if exist "%ROOT%\model\%THOX_NAME%" set "MODEL=%ROOT%\model\%THOX_NAME%"
if not defined MODEL if exist "%ROOT%\gguf\%THOX_NAME%" set "MODEL=%ROOT%\gguf\%THOX_NAME%"

if not exist "%ROOT%\bin" mkdir "%ROOT%\bin"
if not exist "%ROOT%\memory" mkdir "%ROOT%\memory"
if not exist "%ROOT%\workspace" mkdir "%ROOT%\workspace"
if not exist "%ROOT%\models" mkdir "%ROOT%\models"

echo.
echo Starting AI in background window...
if defined MODEL (
    start "Thox AI" "%AIPYEXE%" "%ROOT%\ai.py" --model "%MODEL%"
) else (
    start "Thox AI" "%AIPYEXE%" "%ROOT%\ai.py"
)

:AfterAI
echo AI start issued. Proceeding to NetLock...
echo.

REM ===== Now NetLock =====
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
echo Binding to the working Internet connection, then preloading NetLock...
"%PYEXE%" "%~dp0network_boot.py"
if exist "%~dp0vpn_data\need_soft_reset.flag" (
    set /p ADAPTER=<"%~dp0vpn_data\need_soft_reset.flag"
    echo Internet was offline -- soft adapter and Winsock reset, no reboot...
    call "%~dp0soft_reset.bat" "%ADAPTER%"
    del "%~dp0vpn_data\need_soft_reset.flag" >nul 2>&1
)
echo Binding and configuring servers ^(secure, stream, parallel, vpn, proxy^)...
"%PYEXE%" "%~dp0bind_servers.py"
echo Wildcard is true only when that bind reports configured and online.
echo.

REM Preload NetLock only (do not open GUI)
"%PYEXE%" -c "import netlock; import netlock_net; print('NetLock preloaded successfully.')"
echo.
echo Checking the connection is live before this window closes...
"%PYEXE%" -c "import network_boot; raise SystemExit(0 if network_boot.probe_internet()[0] else 1)"
if errorlevel 1 (
    echo Connection is not live yet. Restoring DHCP and firewall...
    "%PYEXE%" -c "import network_boot; network_boot.restore_original_and_wait()"
)
echo Connection check finished.
pause
exit /b



:ScanAndBind
set "NAME=%~1"
if not exist "%ROOT%\%NAME%\" goto :eof
echo [SCAN] %ROOT%\%NAME%
set "PATH=%ROOT%\%NAME%;%PATH%"
if exist "%ROOT%\%NAME%\bin\"               set "PATH=%ROOT%\%NAME%\bin;%PATH%"
if exist "%ROOT%\%NAME%\bin\Release\"       set "PATH=%ROOT%\%NAME%\bin\Release;%PATH%"
if exist "%ROOT%\%NAME%\build\bin\"         set "PATH=%ROOT%\%NAME%\build\bin;%PATH%"
if exist "%ROOT%\%NAME%\build\bin\Release\" set "PATH=%ROOT%\%NAME%\build\bin\Release;%PATH%"
if exist "%ROOT%\%NAME%\mingw64\bin\"       set "PATH=%ROOT%\%NAME%\mingw64\bin;%PATH%"
if exist "%ROOT%\%NAME%\usr\bin\"           set "PATH=%ROOT%\%NAME%\usr\bin;%PATH%"
goto :eof

:AddIfExists
if exist "%~1\" (
    set "PATH=%~1;%PATH%"
    echo [PATH+] %~1
)
goto :eof
