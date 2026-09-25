@echo off
setlocal
set "VENV_EXE=%USERPROFILE%\.portpatrol\venv\Scripts\portpatrol.exe"
if not exist "%VENV_EXE%" goto :module
"%VENV_EXE%" scan
set "PORTPATROL_STATUS=%ERRORLEVEL%"
goto :done

:module
set "PYTHONPATH=%~dp0"
where py >nul 2>nul
if not errorlevel 1 goto :py
python -m portpatrol scan
set "PORTPATROL_STATUS=%ERRORLEVEL%"
goto :done

:py
py -3 -m portpatrol scan
set "PORTPATROL_STATUS=%ERRORLEVEL%"

:done
echo.
echo Press Enter to close...
pause >nul
exit /b %PORTPATROL_STATUS%
