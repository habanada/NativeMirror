@echo off
set ROOT=%~dp0..\..
rmdir /s /q "%ROOT%\dcu\NativeMirrorScannerTests" 2>nul
rmdir /s /q "%ROOT%\dcu\NativeMirrorTestTarget" 2>nul
rmdir /s /q "%ROOT%\dcu\NativeMirrorTestTarget32" 2>nul
del /q "%ROOT%\bin\Win64\Debug\NativeMirrorScannerTests.exe" 2>nul
del /q "%ROOT%\bin\Win64\Release\NativeMirrorScannerTests.exe" 2>nul
del /q "%ROOT%\bin\Win64\Debug\NativeMirrorTestTarget.exe" 2>nul
del /q "%ROOT%\bin\Win64\Release\NativeMirrorTestTarget.exe" 2>nul
del /q "%ROOT%\bin\Win32\Debug\NativeMirrorTestTarget32.exe" 2>nul
del /q "%ROOT%\bin\Win32\Release\NativeMirrorTestTarget32.exe" 2>nul
echo ScannerIntegration outputs cleaned.
echo Expected next build marker: 2026-10-02.4
