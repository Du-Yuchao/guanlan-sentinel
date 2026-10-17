@echo off
chcp 65001 >nul
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo 请先安装 Node.js 22.12 或更高版本。
  pause
  exit /b 1
)
echo 观澜 AI 安全情报工作台
echo 启动后在浏览器打开 http://127.0.0.1:8787
node --experimental-sqlite --env-file-if-exists=.env server.mjs
pause

