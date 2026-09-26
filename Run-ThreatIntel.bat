@echo off
setlocal

title ThreatIntel
color 0B

cd /d "%~dp0"

echo.
echo ============================================================
echo                    THREATINTEL
echo ============================================================
echo.

REM ============================================================
REM Load persistent OpenAI settings
REM ============================================================

for /f "usebackq delims=" %%A in (`powershell -NoProfile -Command "[Environment]::GetEnvironmentVariable('OPENAI_API_KEY','User')"`) do (
    set "OPENAI_API_KEY=%%A"
)

for /f "usebackq delims=" %%A in (`powershell -NoProfile -Command "[Environment]::GetEnvironmentVariable('OPENAI_MODEL','User')"`) do (
    set "OPENAI_MODEL=%%A"
)

REM ============================================================
REM Environment checks
REM ============================================================

if not exist ".venv\Scripts\python.exe" (
    echo ERROR: Python virtual environment was not found.
    echo.
    pause
    exit /b 1
)

if "%OPENAI_API_KEY%"=="" (
    echo ERROR: OPENAI_API_KEY is not configured.
    echo.
    pause
    exit /b 1
)

if "%OPENAI_MODEL%"=="" (
    echo ERROR: OPENAI_MODEL is not configured.
    echo.
    pause
    exit /b 1
)

REM ============================================================
REM Check mode - does not use OpenAI
REM ============================================================

if /I "%~1"=="--check" (
    echo Environment checks passed.
    echo.
    echo Python environment: OK
    echo OpenAI API key:     OK
    echo OpenAI model:       %OPENAI_MODEL%
    echo.
    exit /b 0
)

REM ============================================================
REM Create a marker showing exactly when this run started
REM ============================================================

set "RUNMARKER=%TEMP%\ThreatIntel-%RANDOM%-%RANDOM%.marker"

type nul > "%RUNMARKER%"

echo Running threat intelligence report...
echo.
echo This run uses OpenAI API credits.
echo.

REM ============================================================
REM Run ThreatIntel
REM ============================================================

".venv\Scripts\python.exe" ".\threatintel.py"

set "THREATINTEL_EXIT=%ERRORLEVEL%"

if not "%THREATINTEL_EXIT%"=="0" (
    echo.
    echo ============================================================
    echo                 THREATINTEL FAILED
    echo ============================================================
    echo.
    echo Review the error shown above.
    echo.
    del "%RUNMARKER%" >nul 2>&1
    pause
    exit /b %THREATINTEL_EXIT%
)

REM ============================================================
REM Find ONLY reports created during this exact run
REM ============================================================

set "DOWNLOADS=%USERPROFILE%\Downloads"
set "LATESTPDF="
set "LATESTJSON="

if not exist "%DOWNLOADS%" (
    mkdir "%DOWNLOADS%"
)

for /f "usebackq delims=" %%F in (`powershell -NoProfile -Command "$m=(Get-Item $env:RUNMARKER).LastWriteTime; $f=Get-ChildItem '.\reports\Threat-Intelligence-*.pdf' -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -gt $m} | Sort-Object LastWriteTime -Descending | Select-Object -First 1; if($f){$f.FullName}"`) do (
    set "LATESTPDF=%%F"
)

for /f "usebackq delims=" %%F in (`powershell -NoProfile -Command "$m=(Get-Item $env:RUNMARKER).LastWriteTime; $f=Get-ChildItem '.\reports\Threat-Intelligence-*.json' -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -gt $m} | Sort-Object LastWriteTime -Descending | Select-Object -First 1; if($f){$f.FullName}"`) do (
    set "LATESTJSON=%%F"
)

REM ============================================================
REM Copy new reports to Downloads
REM ============================================================

set "PDFSTATUS=NOT CREATED"
set "JSONSTATUS=NOT CREATED"

if defined LATESTPDF (
    copy /Y "%LATESTPDF%" "%DOWNLOADS%\" >nul
    set "PDFSTATUS=COPIED"
)

if defined LATESTJSON (
    copy /Y "%LATESTJSON%" "%DOWNLOADS%\" >nul
    set "JSONSTATUS=COPIED"
)

del "%RUNMARKER%" >nul 2>&1

echo.
echo ============================================================
echo                 THREATINTEL COMPLETE
echo ============================================================
echo.
echo Reports folder:
echo %DOWNLOADS%
echo.
echo PDF:  %PDFSTATUS%
echo JSON: %JSONSTATUS%
echo.

if "%PDFSTATUS%"=="NOT CREATED" (
    echo WARNING: This run did not produce a new PDF.
    echo The JSON report was still preserved if shown as COPIED.
    echo.
)

echo Press any key to close.
pause >nul

endlocal
exit /b 0