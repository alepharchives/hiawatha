@ECHO OFF

ECHO Wigwam:
"C:\Program Files\Hiawatha\bin\wigwam.exe"
IF ERRORLEVEL 1 GOTO ERROR
ECHO.
ECHO Hiawatha:
"C:\Program Files\Hiawatha\bin\hiawatha.exe" -k

:ERROR
ECHO.
PAUSE
