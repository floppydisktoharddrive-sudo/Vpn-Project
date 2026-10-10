ai-env-windows + ai.py
======================

Double-click start.bat. That is the compiled-program entry point.

It will:
  1. Add local gcc / mingw / llama.cpp folders to PATH
  2. Create .venv if missing
  3. pip install llama-cpp-python
  4. Run ai.py
  5. ai.py writes bin\global_cpu_cores.bin, bin\llama-server.log,
     and memory\memory.jsonl
  6. Leave the window open when the chat ends

Required
--------
- Python 3.10+ on PATH  (https://www.python.org/downloads/  ? tick Add to PATH)
- The approved model file, exact name:

    Thox1-27b-Q1_0.gguf

  Put it in one of:
    ai-env-windows\
    ai-env-windows\models\
    ai-env-windows\model\
    ai-env-windows\gguf\

Optional
--------
  gcc\  ming\  mingw64\  llama.cpp-master\build\bin\llama-server.exe
  ai.py prefers this bundled server because
  the bundled server supports newer GGUF architectures. llama-cpp-python is
  used as a fallback when that server is unavailable.

Chat
----
  Type in the start.bat window.
  exit  or  quit  to stop.

Folders start.bat scans and binds
---------------------------------
  bin, gcc, include, lib, lib64, llama.cpp-master,
  memory, ming, mingw64, minw64, models

  PATH     += folder and common bin/ / build/bin/ subdirs
  INCLUDE  += include\
  LIB      += lib\ and lib64\

  These changes apply only to the start.bat window.
  Then the script creates .venv if needed, installs
  llama-cpp-python, finds the Thox GGUF, and starts ai.py.

Local llama-cpp-python 0.3.35
-----------------------------
The file llama_cpp_python-0.3.35.tar.gz is SOURCE CODE.
Windows cannot build it without Visual Studio Build Tools
(nmake) or a working MinGW gcc on PATH.

start.bat will:
  1. Install a local .whl if you drop one in vendor\
  2. Skip compiling the .tar.gz when nmake/gcc are missing
  3. Download the official CPU wheel:
     llama_cpp_python-0.3.35-py3-none-win_amd64.whl
