@echo off
echo ================================================================
echo   SECUREVISION AI — LAUNCHING SECURE HTTPS SURVEILLANCE SERVER
echo ================================================================
if not exist cert.pem (
    echo [INFO] SSL certificate not found. Generating self-signed certificate...
    python generate_cert.py
)
echo Starting SecureVision AI over HTTPS on port 8443...
echo Open https://localhost:8443 in your browser
python server.py --https --port 8443
pause
