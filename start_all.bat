@echo off
setlocal EnableDelayedExpansion
title PhishGuard Launcher

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
set "PY=%ROOT%\.venv\Scripts\python.exe"

echo.
echo  [PhishGuard] Demarrage des services...
echo.

if not exist "%ROOT%\data" mkdir "%ROOT%\data"
if not exist "%ROOT%\audit_service\data" mkdir "%ROOT%\audit_service\data"

echo [0/6] Initialisation des comptes (SQLite)...
"%PY%" "%ROOT%\setup_users.py"
echo.

echo [1/6] Compilation des stubs gRPC...
"%PY%" -m grpc_tools.protoc --proto_path="%ROOT%\proto" --python_out="%ROOT%\proto" --grpc_python_out="%ROOT%\proto" "%ROOT%\proto\analysis.proto"
powershell -NoProfile -Command "$f='%ROOT%\proto\analysis_pb2_grpc.py'; (Get-Content $f) -replace 'from \. import analysis_pb2','import analysis_pb2' | Set-Content $f"

echo [2/6] AuthService :8001
start "PhishGuard | Auth :8001" cmd /k "set PYTHONPATH=%ROOT%\proto;%ROOT% && cd /d %ROOT%\auth_service && "%PY%" main.py"
timeout /t 2 /nobreak >nul

echo [3/6] AuditService :8003
start "PhishGuard | Audit :8003" cmd /k "set PYTHONPATH=%ROOT%\proto;%ROOT% && cd /d %ROOT%\audit_service && "%PY%" main.py"
timeout /t 2 /nobreak >nul

echo [4/6] AnalysisService gRPC :50051
start "PhishGuard | Analysis :50051" cmd /k "set PYTHONPATH=%ROOT%\proto;%ROOT% && cd /d %ROOT%\analysis_service && "%PY%" main.py"
timeout /t 4 /nobreak >nul

echo [5/6] API Gateway :8000
start "PhishGuard | Gateway :8000" cmd /k "set PYTHONPATH=%ROOT%\proto;%ROOT% && cd /d %ROOT%\api_gateway && "%PY%" main.py"
timeout /t 3 /nobreak >nul

echo.
echo  Services lances.
echo  Interface : http://localhost:8000/app/index.html
echo  Comptes   : admin@phishguard.com / Admin1234!
echo.
start "" "http://localhost:8000/app/index.html"
