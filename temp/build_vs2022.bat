@echo off
REM Build script for Visual Studio 2022
REM This script sets up the Visual Studio environment and compiles the shellcode loader

set "MAIN=main2.c"

echo [+] Visual Studio 2022 Build Script for Shellcode Loader
echo [+] ====================================================

REM Try to find and setup Visual Studio 2022 environment
set "VS_YEAR=2022"
set "VS_EDITION="

REM Try different VS editions
for %%e in (Enterprise Professional Community BuildTools) do (
    if exist "C:\Program Files\Microsoft Visual Studio\%VS_YEAR%\%%e\VC\Auxiliary\Build\vcvars64.bat" (
        set "VS_EDITION=%%e"
        goto :found_vs
    )
)

:found_vs
if "%VS_EDITION%"=="" (
    echo [-] Visual Studio 2022 not found in standard locations
    echo [-] Please install Visual Studio 2022 or run this from a Developer Command Prompt
    pause
    exit /b 1
)

echo [+] Found Visual Studio 2022 %VS_EDITION%
echo [+] Setting up build environment...

REM Setup VS environment
call "C:\Program Files\Microsoft Visual Studio\%VS_YEAR%\%VS_EDITION%\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1

if errorlevel 1 (
    echo [-] Failed to setup Visual Studio environment
    pause
    exit /b 1
)

echo [+] Building main loader...
cl /W3 /O2 /MT /nologo /Fe:shellcode_loader.exe %MAIN% kernel32.lib user32.lib

if errorlevel 1 (
    echo [-] Failed to compile main loader
    pause
    exit /b 1
)


REM Generate test shellcode if Python is available
REM where python >nul 2>&1
REM if %errorlevel% equ 0 (
REM     echo [+] Generating test shellcode...
REM     python generate_shellcode.py
REM ) else (
REM     echo [!] Python not found, skipping shellcode generation
REM     echo [!] You can manually create shellcode.bin for testing
REM )

echo.
echo [+] Build complete!
echo [+] Files created:
if exist shellcode_loader.exe echo     - shellcode_loader.exe
if exist shellcode_loader_enhanced.exe echo     - shellcode_loader_enhanced.exe
if exist shellcode.bin echo     - shellcode.bin

echo.
echo [+] Usage:
echo     shellcode_loader.exe
echo.
