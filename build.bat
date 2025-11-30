@echo off
REM CS2 Internal Build Script
REM This script automates building the project in different configurations

setlocal enabledelayedexpansion

echo.
echo ========================================
echo CS2 Internal Build Script
echo ========================================
echo.

REM Check if msbuild is available
where msbuild >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo ERROR: MSBuild not found!
    echo Please install Visual Studio 2022 or add MSBuild to PATH
    echo Download: https://visualstudio.microsoft.com/downloads/
    pause
    exit /b 1
)

REM Display menu
echo Select build configuration:
echo.
echo 1) Release x64 (Recommended)
echo 2) Debug x64
echo 3) Release x86
echo 4) Debug x86
echo 5) Build All
echo 6) Clean All
echo 7) Exit
echo.

set /p choice="Enter choice (1-7): "

if "%choice%"=="1" goto build_release_x64
if "%choice%"=="2" goto build_debug_x64
if "%choice%"=="3" goto build_release_x86
if "%choice%"=="4" goto build_debug_x86
if "%choice%"=="5" goto build_all
if "%choice%"=="6" goto clean_all
if "%choice%"=="7" exit /b 0

echo Invalid choice!
pause
goto :eof

:build_release_x64
echo.
echo Building Release x64...
msbuild cs2_internal.sln /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v143
if %ERRORLEVEL% equ 0 (
    echo.
    echo Build successful! Output: cs2_internal\Release\cs2_internal.dll
) else (
    echo.
    echo Build failed! Check error messages above.
)
pause
goto :eof

:build_debug_x64
echo.
echo Building Debug x64...
msbuild cs2_internal.sln /p:Configuration=Debug /p:Platform=x64 /p:PlatformToolset=v143
if %ERRORLEVEL% equ 0 (
    echo.
    echo Build successful! Output: cs2_internal\Debug\cs2_internal.dll
) else (
    echo.
    echo Build failed! Check error messages above.
)
pause
goto :eof

:build_release_x86
echo.
echo Building Release x86...
msbuild cs2_internal.sln /p:Configuration=Release /p:Platform=Win32 /p:PlatformToolset=v143
if %ERRORLEVEL% equ 0 (
    echo.
    echo Build successful! Output: cs2_internal\Release\cs2_internal.dll
) else (
    echo.
    echo Build failed! Check error messages above.
)
pause
goto :eof

:build_debug_x86
echo.
echo Building Debug x86...
msbuild cs2_internal.sln /p:Configuration=Debug /p:Platform=Win32 /p:PlatformToolset=v143
if %ERRORLEVEL% equ 0 (
    echo.
    echo Build successful! Output: cs2_internal\Debug\cs2_internal.dll
) else (
    echo.
    echo Build failed! Check error messages above.
)
pause
goto :eof

:build_all
echo.
echo Building all configurations...
echo.
echo [1/4] Building Release x64...
msbuild cs2_internal.sln /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v143
if %ERRORLEVEL% neq 0 goto build_all_failed

echo.
echo [2/4] Building Debug x64...
msbuild cs2_internal.sln /p:Configuration=Debug /p:Platform=x64 /p:PlatformToolset=v143
if %ERRORLEVEL% neq 0 goto build_all_failed

echo.
echo [3/4] Building Release x86...
msbuild cs2_internal.sln /p:Configuration=Release /p:Platform=Win32 /p:PlatformToolset=v143
if %ERRORLEVEL% neq 0 goto build_all_failed

echo.
echo [4/4] Building Debug x86...
msbuild cs2_internal.sln /p:Configuration=Debug /p:Platform=Win32 /p:PlatformToolset=v143
if %ERRORLEVEL% neq 0 goto build_all_failed

echo.
echo ========================================
echo All builds completed successfully!
echo ========================================
echo.
echo Output files:
echo   x64 Release: cs2_internal\Release\cs2_internal.dll
echo   x64 Debug:   cs2_internal\Debug\cs2_internal.dll
echo.
pause
goto :eof

:build_all_failed
echo.
echo Build failed! Check error messages above.
pause
goto :eof

:clean_all
echo.
echo Cleaning all build artifacts...
msbuild cs2_internal.sln /t:Clean /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v143
msbuild cs2_internal.sln /t:Clean /p:Configuration=Debug /p:Platform=x64 /p:PlatformToolset=v143
msbuild cs2_internal.sln /t:Clean /p:Configuration=Release /p:Platform=Win32 /p:PlatformToolset=v143
msbuild cs2_internal.sln /t:Clean /p:Configuration=Debug /p:Platform=Win32 /p:PlatformToolset=v143
echo Clean completed!
pause
goto :eof
