@echo off
title NetWatch — Network Traffic Anomaly Detector
color 0A
setlocal EnableDelayedExpansion

:: ── Locate Python venv ──────────────────────────────────────────────
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"
set "PYTHON=%SCRIPT_DIR%.venv\Scripts\python.exe"

if not exist "%PYTHON%" (
    color 0C
    echo.
    echo   ERROR: Python virtual environment not found.
    echo   Expected: %PYTHON%
    echo.
    echo   Run these commands first:
    echo     python -m venv .venv
    echo     .venv\Scripts\pip install -r requirements.txt
    echo.
    pause
    exit /b 1
)

:: ── Check for admin ─────────────────────────────────────────────────
net session >nul 2>&1
if %errorlevel% neq 0 (
    color 0E
    echo.
    echo   WARNING: Not running as Administrator.
    echo   Some process details may be unavailable.
    echo   Right-click this file and choose "Run as administrator" for full results.
    echo.
    timeout /t 3 >nul
)

:MENU
cls
color 0A
echo.
echo   ============================================================
echo    _   _      _ __        __    _       _
echo   ^| \ ^| ^| ___^| ^|\ \      / /_ _^| ^|_ ___^| ^|__
echo   ^|  \^| ^|/ _ \ __\ \ /\ / / _` ^| __/ __^| '_ \
echo   ^| ^|\  ^|  __/ ^|_ \ V  V / (_^| ^| ^|^| (__^| ^| ^| ^|
echo   ^|_^| \_^|\___^|\__^| \_/\_/ \__,_^|\__\___^|_^| ^|_^|
echo.
echo    Network Traffic Anomaly Detector  v3.0.0
echo    Threat Intelligence Enhanced ^| GeoIP ^| Notifications
echo   ============================================================
echo.
echo     [1]  Quick Snapshot           - scan now and show results
echo     [2]  Live Monitor             - continuous monitoring
echo     [3]  Timed Monitor            - monitor for N seconds
echo     [4]  DLL Injection Scan       - scan all processes for injected DLLs
echo     [5]  DLL Scan (Single PID)    - scan one process for injected DLLs
echo     [6]  Investigate Process      - deep-dive into a specific PID
echo     [7]  Full Scan + Log          - snapshot with JSON log output
echo     [8]  Live Monitor + Log       - continuous monitor with JSON log
echo     [9]  Update Threat Feeds      - download latest C2 IP/domain blocklists
echo     [S]  Feed Status              - show threat intel feed info
echo     [H]  Hash Lookup              - check SHA256 against MalwareBazaar
echo     [P]  PDF Report               - snapshot + generate PDF report
echo     [W]  HTML Report              - snapshot + generate interactive HTML report
echo     [T]  Top Talkers + Stats      - top processes and network stats
echo     [C]  CSV Export               - export snapshot to CSV files
echo     [N]  Notify Test              - test notification channels
echo     [G]  Full Report Bundle       - PDF + HTML + CSV in one go
echo     [M]  Network Map              - snapshot + process/IP HTML map
echo     [L]  Live Network Map         - auto-refreshing live process/IP map
echo     [A]  Learning Mode            - generate whitelist suggestions
echo     [R]  Task Scheduler Scan      - scan scheduled tasks for persistence
echo     [K]  Kill Critical            - prompt to terminate critical processes
echo     [Q]  Quarantine Critical      - prompt to quarantine critical executables
echo     [O]  OTX Lookup / Import      - AlienVault OTX indicator tools
echo     [V]  VirusTotal Lookup        - check IP/domain/hash reputation
echo.
echo     [0]  Exit
echo.
echo   ============================================================
echo.
set /p "CHOICE=  Select an option [0-9/S/H/P/W/T/C/N/G/M/L/A/R/K/Q/O/V]: "

if "%CHOICE%"=="1" goto SNAPSHOT
if "%CHOICE%"=="2" goto LIVE
if "%CHOICE%"=="3" goto TIMED
if "%CHOICE%"=="4" goto DLL_ALL
if "%CHOICE%"=="5" goto DLL_PID
if "%CHOICE%"=="6" goto INVESTIGATE
if "%CHOICE%"=="7" goto SNAPSHOT_LOG
if "%CHOICE%"=="8" goto LIVE_LOG
if "%CHOICE%"=="9" goto UPDATE_FEEDS
if /i "%CHOICE%"=="S" goto FEED_STATUS
if /i "%CHOICE%"=="H" goto HASH_LOOKUP
if /i "%CHOICE%"=="P" goto PDF_REPORT
if /i "%CHOICE%"=="W" goto HTML_REPORT
if /i "%CHOICE%"=="T" goto TOP_STATS
if /i "%CHOICE%"=="C" goto CSV_EXPORT
if /i "%CHOICE%"=="N" goto NOTIFY_TEST
if /i "%CHOICE%"=="G" goto FULL_BUNDLE
if /i "%CHOICE%"=="M" goto NETWORK_MAP
if /i "%CHOICE%"=="L" goto LIVE_MAP
if /i "%CHOICE%"=="A" goto LEARNING_MODE
if /i "%CHOICE%"=="R" goto TASK_SCAN
if /i "%CHOICE%"=="K" goto KILL_CRITICAL
if /i "%CHOICE%"=="Q" goto QUARANTINE_CRITICAL
if /i "%CHOICE%"=="O" goto OTX_TOOLS
if /i "%CHOICE%"=="V" goto VT_LOOKUP
if "%CHOICE%"=="0" goto EXIT

echo.
echo   Invalid choice. Try again.
timeout /t 2 >nul
goto MENU

:: ── 1. Quick Snapshot ───────────────────────────────────────────────
:SNAPSHOT
cls
echo.
echo   Running quick snapshot...
echo.
"%PYTHON%" -m netwatch --snapshot
echo.
pause
goto MENU

:: ── 2. Live Monitor ─────────────────────────────────────────────────
:LIVE
cls
set /p "INTERVAL=  Poll interval in seconds (default 2): "
if "%INTERVAL%"=="" set "INTERVAL=2"
echo.
echo   Starting live monitor (every %INTERVAL%s) — press Ctrl+C to stop.
echo.
"%PYTHON%" -m netwatch --interval %INTERVAL%
echo.
pause
goto MENU

:: ── 3. Timed Monitor ────────────────────────────────────────────────
:TIMED
cls
set /p "DURATION=  How many seconds to monitor: "
if "%DURATION%"=="" (
    echo   No duration entered.
    timeout /t 2 >nul
    goto MENU
)
set /p "INTERVAL=  Poll interval in seconds (default 2): "
if "%INTERVAL%"=="" set "INTERVAL=2"
echo.
echo   Monitoring for %DURATION% seconds (every %INTERVAL%s)...
echo.
"%PYTHON%" -m netwatch --interval %INTERVAL% --duration %DURATION%
echo.
pause
goto MENU

:: ── 4. DLL Injection Scan (All) ─────────────────────────────────────
:DLL_ALL
cls
echo.
echo   Scanning all processes for injected DLLs...
echo   (This may take a moment)
echo.
"%PYTHON%" -m netwatch --dll-scan
echo.
pause
goto MENU

:: ── 5. DLL Scan (Single PID) ───────────────────────────────────────
:DLL_PID
cls
set /p "PID=  Enter PID to scan: "
if "%PID%"=="" (
    echo   No PID entered.
    timeout /t 2 >nul
    goto MENU
)
echo.
echo   Scanning PID %PID% for injected DLLs...
echo.
"%PYTHON%" -m netwatch --dll-scan-pid %PID%
echo.
pause
goto MENU

:: ── 6. Investigate Process ──────────────────────────────────────────
:INVESTIGATE
cls
set /p "PID=  Enter PID to investigate: "
if "%PID%"=="" (
    echo   No PID entered.
    timeout /t 2 >nul
    goto MENU
)
echo.
echo   Investigating PID %PID%...
echo.
"%PYTHON%" -m netwatch --investigate %PID%
echo.
pause
goto MENU

:: ── 7. Full Scan + Log ─────────────────────────────────────────────
:SNAPSHOT_LOG
cls
set "LOGFILE=%SCRIPT_DIR%alerts_%date:~-4%%date:~4,2%%date:~7,2%_%time:~0,2%%time:~3,2%%time:~6,2%.json"
set "LOGFILE=%LOGFILE: =0%"
echo.
echo   Running snapshot with JSON log...
echo   Log: %LOGFILE%
echo.
"%PYTHON%" -m netwatch --snapshot --log "%LOGFILE%"
echo.
echo   Alerts saved to: %LOGFILE%
echo.
pause
goto MENU

:: ── 8. Live Monitor + Log ──────────────────────────────────────────
:LIVE_LOG
cls
set "LOGFILE=%SCRIPT_DIR%alerts_%date:~-4%%date:~4,2%%date:~7,2%_%time:~0,2%%time:~3,2%%time:~6,2%.json"
set "LOGFILE=%LOGFILE: =0%"
set /p "INTERVAL=  Poll interval in seconds (default 2): "
if "%INTERVAL%"=="" set "INTERVAL=2"
echo.
echo   Starting live monitor with logging — press Ctrl+C to stop.
echo   Log: %LOGFILE%
echo.
"%PYTHON%" -m netwatch --interval %INTERVAL% --log "%LOGFILE%"
echo.
echo   Alerts saved to: %LOGFILE%
echo.
pause
goto MENU

:: -- 9. Update Threat Feeds ------------------------------------------
:UPDATE_FEEDS
cls
echo.
echo   Downloading latest threat intelligence feeds from abuse.ch...
echo.
"%PYTHON%" -m netwatch --update-feeds
echo.
pause
goto MENU

:: -- S. Feed Status ---------------------------------------------------
:FEED_STATUS
cls
echo.
echo   Checking threat intelligence feed status...
echo.
"%PYTHON%" -m netwatch --feed-status
echo.
pause
goto MENU

:: -- H. Hash Lookup ---------------------------------------------------
:HASH_LOOKUP
cls
set /p "API_KEY=  Enter abuse.ch API key (or press Enter to use env var): "
set /p "HASH=  Enter SHA256 hash to look up: "
if "%HASH%"=="" (
    echo   No hash entered.
    timeout /t 2 >nul
    goto MENU
)
echo.
if "%API_KEY%"=="" (
    "%PYTHON%" -m netwatch --hash-lookup %HASH%
) else (
    "%PYTHON%" -m netwatch --hash-lookup %HASH% --api-key %API_KEY%
)
echo.
pause
goto MENU

:: -- P. PDF Report ---------------------------------------------------
:PDF_REPORT
cls
set "PDFFILE=%SCRIPT_DIR%NetWatch_Report_%date:~-4%%date:~4,2%%date:~7,2%_%time:~0,2%%time:~3,2%%time:~6,2%.pdf"
set "PDFFILE=%PDFFILE: =0%"
echo.
echo   Generating PDF security report...
echo   Output: %PDFFILE%
echo.
"%PYTHON%" -m netwatch --snapshot --pdf "%PDFFILE%" --stats
echo.
pause
goto MENU

:: -- T. Top Talkers + Stats ------------------------------------------
:TOP_STATS
cls
set /p "TOPN=  How many top processes to show (default 10): "
if "%TOPN%"=="" set "TOPN=10"
echo.
echo   Scanning network, showing top %TOPN% talkers and stats...
echo.
"%PYTHON%" -m netwatch --snapshot --top %TOPN% --stats
echo.
pause
goto MENU

:: -- C. CSV Export ----------------------------------------------------
:CSV_EXPORT
cls
set "CSVFILE=%SCRIPT_DIR%netwatch_alerts_%date:~-4%%date:~4,2%%date:~7,2%_%time:~0,2%%time:~3,2%%time:~6,2%.csv"
set "CSVFILE=%CSVFILE: =0%"
set "CSVCONN=%SCRIPT_DIR%netwatch_connections_%date:~-4%%date:~4,2%%date:~7,2%_%time:~0,2%%time:~3,2%%time:~6,2%.csv"
set "CSVCONN=%CSVCONN: =0%"
echo.
echo   Running snapshot and exporting to CSV...
echo.
"%PYTHON%" -m netwatch --snapshot --export-csv "%CSVFILE%" --export-connections-csv "%CSVCONN%"
echo.
pause
goto MENU

:: -- W. HTML Report ---------------------------------------------------
:HTML_REPORT
cls
set "HTMLFILE=%SCRIPT_DIR%NetWatch_Report_%date:~-4%%date:~4,2%%date:~7,2%_%time:~0,2%%time:~3,2%%time:~6,2%.html"
set "HTMLFILE=%HTMLFILE: =0%"
echo.
echo   Generating interactive HTML security report...
echo   Output: %HTMLFILE%
echo.
"%PYTHON%" -m netwatch --snapshot --html "%HTMLFILE%" --stats
echo.
pause
goto MENU

:: -- N. Notify Test ---------------------------------------------------
:NOTIFY_TEST
cls
echo.
echo   Running snapshot with notifications enabled...
set /p "WEBHOOK=  Enter Discord or Slack webhook URL: "
if "%WEBHOOK%"=="" (
    echo   No webhook entered.
    timeout /t 2 >nul
    goto MENU
)
echo.
"%PYTHON%" -m netwatch --snapshot --discord-webhook %WEBHOOK% --notify-min-severity LOW
echo.
pause
goto MENU

:: -- G. Full Report Bundle -------------------------------------------
:FULL_BUNDLE
cls
set "TS=%date:~-4%%date:~4,2%%date:~7,2%_%time:~0,2%%time:~3,2%%time:~6,2%"
set "TS=%TS: =0%"
set "PDFFILE=%SCRIPT_DIR%NetWatch_Report_%TS%.pdf"
set "HTMLFILE=%SCRIPT_DIR%NetWatch_Report_%TS%.html"
set "CSVFILE=%SCRIPT_DIR%netwatch_alerts_%TS%.csv"
set "CSVCONN=%SCRIPT_DIR%netwatch_connections_%TS%.csv"
echo.
echo   Generating full report bundle (PDF + HTML + CSV)...
echo.
"%PYTHON%" -m netwatch --snapshot --pdf "%PDFFILE%" --html "%HTMLFILE%" --export-csv "%CSVFILE%" --export-connections-csv "%CSVCONN%" --stats
echo.
echo   Reports saved:
echo     PDF:  %PDFFILE%
echo     HTML: %HTMLFILE%
echo     CSV:  %CSVFILE%
echo     CSV:  %CSVCONN%
echo.
pause
goto MENU

:: -- M. Network Map ---------------------------------------------------
:NETWORK_MAP
cls
set "TS=%date:~-4%%date:~4,2%%date:~7,2%_%time:~0,2%%time:~3,2%%time:~6,2%"
set "TS=%TS: =0%"
set "MAPFILE=%SCRIPT_DIR%NetWatch_Map_%TS%.html"
echo.
echo   Generating process-to-endpoint network map...
echo   Output: %MAPFILE%
echo.
"%PYTHON%" -m netwatch --snapshot --network-map "%MAPFILE%" --stats
echo.
pause
goto MENU

:: -- L. Live Network Map ---------------------------------------------
:LIVE_MAP
cls
set "TS=%date:~-4%%date:~4,2%%date:~7,2%_%time:~0,2%%time:~3,2%%time:~6,2%"
set "TS=%TS: =0%"
set "MAPFILE=%SCRIPT_DIR%NetWatch_Live_Map_%TS%.html"
set /p "DURATION=  How many seconds to monitor (default 60): "
if "%DURATION%"=="" set "DURATION=60"
set /p "INTERVAL=  Poll interval in seconds (default 2): "
if "%INTERVAL%"=="" set "INTERVAL=2"
set /p "REFRESH=  Browser refresh interval in seconds (default 3): "
if "%REFRESH%"=="" set "REFRESH=3"
echo.
echo   Updating live network map for %DURATION% seconds...
echo   Output: %MAPFILE%
echo.
"%PYTHON%" -m netwatch --interval %INTERVAL% --duration %DURATION% --live-map "%MAPFILE%" --map-refresh %REFRESH%
echo.
pause
goto MENU

:: -- A. Learning Mode -------------------------------------------------
:LEARNING_MODE
cls
set "TS=%date:~-4%%date:~4,2%%date:~7,2%_%time:~0,2%%time:~3,2%%time:~6,2%"
set "TS=%TS: =0%"
set "LEARNFILE=%SCRIPT_DIR%learned_whitelist_%TS%.json"
set /p "DURATION=  How many seconds to learn (default 60): "
if "%DURATION%"=="" set "DURATION=60"
set /p "MINCOUNT=  Minimum repeated alert count before learning (default 1): "
if "%MINCOUNT%"=="" set "MINCOUNT=1"
echo.
echo   Learning low-risk whitelist suggestions...
echo   Output: %LEARNFILE%
echo.
"%PYTHON%" -m netwatch --learning-mode "%LEARNFILE%" --learn-duration %DURATION% --learn-min-count %MINCOUNT%
echo.
pause
goto MENU

:: -- R. Task Scheduler Scan ------------------------------------------
:TASK_SCAN
cls
echo.
echo   Scanning Windows scheduled tasks for persistence indicators...
echo.
"%PYTHON%" -m netwatch --task-scan
echo.
pause
goto MENU

:: -- K. Kill Critical -------------------------------------------------
:KILL_CRITICAL
cls
echo.
echo   WARNING: This mode prompts before terminating any process that triggers
echo   a CRITICAL alert. Only continue if you understand the risk.
echo.
set /p "CONFIRM=  Type RUN to continue: "
if /i not "%CONFIRM%"=="RUN" goto MENU
echo.
"%PYTHON%" -m netwatch --snapshot --kill-critical
echo.
pause
goto MENU

:: -- Q. Quarantine Critical ------------------------------------------
:QUARANTINE_CRITICAL
cls
set "QUARDIR=%SCRIPT_DIR%quarantine"
echo.
echo   WARNING: This mode prompts before moving suspicious executables into:
echo   %QUARDIR%
echo.
set /p "CONFIRM=  Type RUN to continue: "
if /i not "%CONFIRM%"=="RUN" goto MENU
echo.
"%PYTHON%" -m netwatch --snapshot --quarantine-critical "%QUARDIR%"
echo.
pause
goto MENU

:: -- O. AlienVault OTX Tools -----------------------------------------
:OTX_TOOLS
cls
echo.
echo   AlienVault OTX
echo.
echo     [1] Indicator lookup
echo     [2] Import subscribed pulses
echo     [0] Back
echo.
set /p "OTXCHOICE=  Select an option [0-2]: "
if "%OTXCHOICE%"=="0" goto MENU
set /p "OTXKEY=  Enter OTX API key (or press Enter to use OTX_API_KEY env var): "
if "%OTXCHOICE%"=="1" (
    set /p "INDICATOR=  Enter IP, domain, or hash: "
    if "!INDICATOR!"=="" (
        echo   No indicator entered.
        timeout /t 2 >nul
        goto MENU
    )
    if "!OTXKEY!"=="" (
        "%PYTHON%" -m netwatch --otx-lookup "!INDICATOR!"
    ) else (
        "%PYTHON%" -m netwatch --otx-lookup "!INDICATOR!" --otx-api-key "!OTXKEY!"
    )
) else if "%OTXCHOICE%"=="2" (
    if "!OTXKEY!"=="" (
        "%PYTHON%" -m netwatch --update-otx-pulses
    ) else (
        "%PYTHON%" -m netwatch --update-otx-pulses --otx-api-key "!OTXKEY!"
    )
) else (
    echo   Invalid choice.
)
echo.
pause
goto MENU

:: -- V. VirusTotal Lookup --------------------------------------------
:VT_LOOKUP
cls
set /p "VTKEY=  Enter VirusTotal API key (or press Enter to use VIRUSTOTAL_API_KEY env var): "
set /p "INDICATOR=  Enter IP, domain, or hash: "
if "%INDICATOR%"=="" (
    echo   No indicator entered.
    timeout /t 2 >nul
    goto MENU
)
echo.
if "%VTKEY%"=="" (
    "%PYTHON%" -m netwatch --vt-lookup "%INDICATOR%"
) else (
    "%PYTHON%" -m netwatch --vt-lookup "%INDICATOR%" --vt-api-key "%VTKEY%"
)
echo.
pause
goto MENU

:: -- Exit -------------------------------------------------------------
:EXIT
cls
echo.
echo   Goodbye.
echo.
timeout /t 1 >nul
exit /b 0
