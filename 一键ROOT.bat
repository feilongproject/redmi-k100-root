@echo off
chcp 936 >nul
setlocal
title REDMI K100 / HyperOS 4 一键 ROOT (CVE-2026-98260)

echo.
echo  ============================================================
echo   REDMI K100  一键 ROOT  (CVE-2026-98260 -^> KernelSU)
echo  ============================================================
echo.
echo   开始前请确认：
echo    1. 手机已开启 开发者选项 - USB调试，并已授权本机
echo    2. 数据线保持连接，过程中不要拔
echo    3. 系统未被升级（内核必须仍是 6.6.118-...-g0908354dac1b）
echo.
pause

set "PS=pwsh"
where pwsh >nul 2>nul || set "PS=powershell"

"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0root.ps1" %*
set "RC=%ERRORLEVEL%"

echo.
if "%RC%"=="0" (
    echo  [完成] 全部成功。
) else (
    echo  [退出码 %RC%] 请查看上方输出与 log 目录下的日志。
)
echo.
pause
exit /b %RC%