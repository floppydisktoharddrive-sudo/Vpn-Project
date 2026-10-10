@echo off
setlocal EnableExtensions EnableDelayedExpansion
title Thox local assistant
chcp 65001 >nul
cd /d "%~dp0"

set "THOX_NAME=Thox1-27b-Q1_0.gguf"
set "ROOT=%~dp0"
set "ROOT=%ROOT:~0,-1%"
set "WHEEL_URL=https://github.com/abetlen/llama-cpp-python/releases/download/v0.3.35/llama_cpp_python-0.3.35-py3-none-win_amd64.whl"
set "WHEEL_NAME=llama_cpp_python-0.3.35-py3-none-win_amd64.whl"

echo.
echo ============================================================
echo  Scanning folders next to start.bat and building PATH
echo ============================================================
echo.
echo ROOT = %ROOT%
echo.

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
echo [2/5] Python / venv ...
set "PY="
where py >nul 2>&1 && set "PY=py -3"
if not defined PY where python >nul 2>&1 && set "PY=python"
if not defined PY (
    echo [ERROR] Python 3 is not on PATH.
    echo Install Python 3.10+ from https://www.python.org/downloads/
    echo and tick "Add python.exe to PATH".
    pause
    exit /b 1
)

if not exist "%ROOT%\.venv\Scripts\python.exe" (
    echo       creating .venv ...
    %PY% -m venv "%ROOT%\.venv"
    if errorlevel 1 (
        echo [ERROR] Could not create .venv
        pause
        exit /b 1
    )
)

call "%ROOT%\.venv\Scripts\activate.bat"
set "PYEXE=%ROOT%\.venv\Scripts\python.exe"
echo       venv : %ROOT%\.venv

echo [3/5] Dependencies ...
"%PYEXE%" -m pip install --upgrade pip >nul 2>&1
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
if not defined LOCAL_WHL (
    for %%F in ("%ROOT%\llama-cpp-python-*.whl") do if exist "%%~fF" set "LOCAL_WHL=%%~fF"
)

if exist "%ROOT%\llama_cpp_python-0.3.35.tar.gz" set "LOCAL_SDIST=%ROOT%\llama_cpp_python-0.3.35.tar.gz"
if not defined LOCAL_SDIST if exist "%ROOT%\vendor\llama_cpp_python-0.3.35.tar.gz" set "LOCAL_SDIST=%ROOT%\vendor\llama_cpp_python-0.3.35.tar.gz"
if not defined LOCAL_SDIST if exist "%ROOT%\llama-cpp-python-0.3.35.tar.gz" set "LOCAL_SDIST=%ROOT%\llama-cpp-python-0.3.35.tar.gz"
if not defined LOCAL_SDIST if exist "%ROOT%\vendor\llama-cpp-python-0.3.35.tar.gz" set "LOCAL_SDIST=%ROOT%\vendor\llama-cpp-python-0.3.35.tar.gz"

set "INSTALLED="

if defined LOCAL_WHL (
    echo       local wheel : !LOCAL_WHL!
    "%PYEXE%" -m pip install --upgrade "!LOCAL_WHL!"
    if not errorlevel 1 set "INSTALLED=1"
)

if not defined INSTALLED (
    "%PYEXE%" -c "import llama_cpp" 2>nul
    if not errorlevel 1 (
        echo       llama-cpp-python import check : OK
        set "INSTALLED=1"
    )
)

if not defined INSTALLED if defined LOCAL_SDIST (
    echo       local sdist : !LOCAL_SDIST!
    echo       NOTE - a .tar.gz must be compiled. No Visual Studio nmake was found last run.
    where gcc >nul 2>&1
    if not errorlevel 1 (
        echo       gcc found - trying MinGW Makefiles
        set "CMAKE_GENERATOR=MinGW Makefiles"
        set "CC=gcc"
        set "CXX=g++"
        "%PYEXE%" -m pip install --upgrade "!LOCAL_SDIST!"
        if not errorlevel 1 set "INSTALLED=1"
    ) else (
        echo       no gcc/nmake on PATH - skip compile, use official CPU wheel
    )
)

if not defined INSTALLED (
    if exist "%ROOT%\vendor\%WHEEL_NAME%" (
        echo       using cached official wheel
        "%PYEXE%" -m pip install --upgrade "%ROOT%\vendor\%WHEEL_NAME%"
        if not errorlevel 1 set "INSTALLED=1"
    )
)

if not defined INSTALLED (
    echo       downloading official CPU wheel 0.3.35 win_amd64
    echo       %WHEEL_URL%
    "%PYEXE%" -c "import urllib.request; urllib.request.urlretrieve(r'%WHEEL_URL%', r'%ROOT%\vendor\%WHEEL_NAME%')"
    if exist "%ROOT%\vendor\%WHEEL_NAME%" (
        "%PYEXE%" -m pip install --upgrade "%ROOT%\vendor\%WHEEL_NAME%"
        if not errorlevel 1 set "INSTALLED=1"
    )
)

if not defined INSTALLED if exist "%ROOT%\requirements.txt" (
    echo       falling back to requirements.txt / PyPI
    "%PYEXE%" -m pip install -r "%ROOT%\requirements.txt"
    if not errorlevel 1 set "INSTALLED=1"
)

if not defined INSTALLED (
    echo [ERROR] Could not install llama-cpp-python.
    echo Put a Windows .whl in vendor\ or install Visual Studio Build Tools to compile the .tar.gz.
    pause
    exit /b 1
)

"%PYEXE%" -c "import llama_cpp" 2>nul
if errorlevel 1 (
    echo [ERROR] llama-cpp-python is not importable in the venv.
    echo Install the Visual C++ redistributable if a DLL is missing, then rerun.
    pause
    exit /b 1
)
echo       llama-cpp-python : OK

echo [4/5] Locating %THOX_NAME% ...
set "MODEL="
if exist "%ROOT%\%THOX_NAME%" set "MODEL=%ROOT%\%THOX_NAME%"
if not defined MODEL if exist "%ROOT%\models\%THOX_NAME%" set "MODEL=%ROOT%\models\%THOX_NAME%"
if not defined MODEL if exist "%ROOT%\model\%THOX_NAME%" set "MODEL=%ROOT%\model\%THOX_NAME%"
if not defined MODEL if exist "%ROOT%\gguf\%THOX_NAME%" set "MODEL=%ROOT%\gguf\%THOX_NAME%"
if defined MODEL (
    echo       model : %MODEL%
    set "MODEL_PATH=%MODEL%"
) else (
    echo       not next to the bat - ai.py will search more locations
)

if not exist "%ROOT%\ai.py" (
    echo [ERROR] ai.py is missing next to start.bat
    pause
    exit /b 1
)

if not exist "%ROOT%\bin" mkdir "%ROOT%\bin"
if not exist "%ROOT%\memory" mkdir "%ROOT%\memory"
if not exist "%ROOT%\workspace" mkdir "%ROOT%\workspace"
if not exist "%ROOT%\models" mkdir "%ROOT%\models"

echo.
echo [5/5] Starting ai.py CLI ...
echo.
if defined MODEL (
    "%PYEXE%" "%ROOT%\ai.py" --model "%MODEL%" %*
) else (
    "%PYEXE%" "%ROOT%\ai.py" %*
)
set "RC=%ERRORLEVEL%"
echo.
echo ai.py exited with code %RC%
pause
exit /b %RC%


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
