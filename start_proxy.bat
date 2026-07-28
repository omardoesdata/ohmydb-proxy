@echo off
setlocal

if not defined CONFIRMATION_MODE set CONFIRMATION_MODE=popup
if not defined PROXY_PORT set PROXY_PORT=5433
if not defined DB_HOST set DB_HOST=127.0.0.1
if not defined DB_PORT set DB_PORT=5432
if not defined ESTIMATOR_USER set ESTIMATOR_USER=postgres

python main.py
if errorlevel 1 pause
