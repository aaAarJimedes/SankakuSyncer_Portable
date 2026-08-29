@echo off
setlocal
title SankakuSyncer Debug
cd /d "%~dp0"
rem Debug console output does not weaken the production WebEngine policy.
set "ALL_PROXY="
set "HTTP_PROXY="
set "HTTPS_PROXY="
set "NO_PROXY="
set "QTWEBENGINE_CHROMIUM_FLAGS="
set "QTWEBENGINE_DISABLE_SANDBOX="
set "QTWEBENGINE_REMOTE_DEBUGGING="
set "QTWEBENGINE_REMOTE_DEBUGGING_PORT="
set "SSLKEYLOGFILE="
set "QT_SSL_BACKEND=schannel"
if not exist "%~dp0Runtime\python.exe" (
    echo [ERROR] Missing Runtime\python.exe
    pause
    exit /b 1
)
set "PYSIDE_ROOT=%~dp0Runtime\Lib\site-packages\PySide6"
if exist "%PYSIDE_ROOT%\plugins\platforms\qwindows.dll" (
    set "QT_BINARY_DIR=%PYSIDE_ROOT%"
    set "QT_PLUGIN_PATH=%PYSIDE_ROOT%\plugins"
    set "QT_QPA_PLATFORM_PLUGIN_PATH=%PYSIDE_ROOT%\plugins\platforms"
    set "QTWEBENGINEPROCESS_PATH=%PYSIDE_ROOT%\QtWebEngineProcess.exe"
    set "QTWEBENGINE_RESOURCES_PATH=%PYSIDE_ROOT%\resources"
    set "QTWEBENGINE_LOCALES_PATH=%PYSIDE_ROOT%\translations\qtwebengine_locales"
) else if exist "%~dp0Runtime\Library\lib\qt6\plugins\platforms\qwindows.dll" (
    set "QT_BINARY_DIR=%~dp0Runtime\Library\bin"
    set "QT_PLUGIN_PATH=%~dp0Runtime\Library\lib\qt6\plugins"
    set "QT_QPA_PLATFORM_PLUGIN_PATH=%~dp0Runtime\Library\lib\qt6\plugins\platforms"
    set "QTWEBENGINEPROCESS_PATH=%~dp0Runtime\bin\QtWebEngineProcess.exe"
    set "QTWEBENGINE_RESOURCES_PATH=%~dp0Runtime\resources"
    set "QTWEBENGINE_LOCALES_PATH=%~dp0Runtime\translations\qtwebengine_locales"
) else (
    echo [ERROR] Missing a complete PySide6/Qt Runtime layout.
    pause
    exit /b 1
)
if not exist "%QTWEBENGINEPROCESS_PATH%" (
    echo [ERROR] Missing QtWebEngineProcess.exe in the selected Runtime layout.
    pause
    exit /b 1
)
set "PATH=%~dp0Runtime;%~dp0Runtime\bin;%QT_BINARY_DIR%;%PYSIDE_ROOT%;%~dp0Runtime\Lib\site-packages\shiboken6;%~dp0Runtime\DLLs;%~dp0Runtime\Scripts;%SystemRoot%\System32;%SystemRoot%"
set "PYTHONHOME=%~dp0Runtime"
set "PYTHONPATH=%~dp0App"
set "SANKAKU_APP_DIR=%~dp0App"
set "PYTHONNOUSERSITE=1"
set "PYTHONDONTWRITEBYTECODE=1"
"%~dp0Runtime\python.exe" -s -c "import os,runpy,sys;p=os.environ['SANKAKU_APP_DIR'];sys.path.insert(0,p);runpy.run_path(os.path.join(p,'main.py'),run_name='__main__')"
set "EXIT_CODE=%ERRORLEVEL%"
echo.
echo SankakuSyncer exited with code %EXIT_CODE%.
pause
exit /b %EXIT_CODE%
