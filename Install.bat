SET dir=%~dp0
SET PowerShellScriptPath=%dir%Install.ps1
START /Wait PowerShell.exe -Command "& {Start-Process PowerShell.exe -ArgumentList '-ExecutionPolicy Bypass -File ""%PowerShellScriptPath%""' -Verb RunAs}"