@echo off
setlocal EnableExtensions
REM Soft adapter + Winsock reset. Called only when the Internet probe failed.
REM Does not shut down or restart Windows. The desktop session stays logged in.
REM Winsock catalog changes are written now; a later reboot is optional, not required to return to the desktop.

set "ADAPTER=%~1"
if not defined ADAPTER if exist "%~dp0vpn_data\need_soft_reset.flag" set /p ADAPTER=<"%~dp0vpn_data\need_soft_reset.flag"

echo [soft reset] Winsock catalog reset (no reboot issued)...
netsh winsock reset
echo [soft reset] TCP/IP catalog reset (no reboot issued)...
netsh int ip reset
echo [soft reset] WinHTTP proxy cleared...
netsh winhttp reset proxy
echo [soft reset] DNS and ARP flush...
ipconfig /flushdns
netsh interface ip delete arpcache

if defined ADAPTER (
  echo [soft reset] Bouncing "%ADAPTER%" so the link reloads without logging off...
  netsh interface set interface name="%ADAPTER%" admin=disabled
  timeout /t 2 /nobreak >nul
  netsh interface set interface name="%ADAPTER%" admin=enabled
) else (
  echo [soft reset] No adapter name — skipping NIC bounce.
)

echo [soft reset] DHCP renew and DNS client bounce...
ipconfig /release
ipconfig /renew
net stop dnscache >nul 2>&1
net start dnscache >nul 2>&1
echo [soft reset] Done. Desktop left active.
exit /b 0
