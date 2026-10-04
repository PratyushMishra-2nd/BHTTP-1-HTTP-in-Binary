@echo off
rem bcurl -v localhost:9000/index.html
python "%~dp0bcurl.py" %*
exit /b %ERRORLEVEL%
