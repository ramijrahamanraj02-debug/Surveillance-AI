@echo off
title SecureVision AI - Surveillance & Security Intelligence System
cls
echo ===============================================================================
echo            SECUREVISION AI - SMART SURVEILLANCE & SECURITY SYSTEM
echo ===============================================================================
echo.
echo  [1/2] Initializing SQLite Database and Relational Storage...
echo  [2/2] Launching Multi-Threaded Web & REST API Server on http://localhost:8000
echo.
start http://localhost:8000
python server.py
pause
