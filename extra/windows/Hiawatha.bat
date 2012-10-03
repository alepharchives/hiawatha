@ECHO OFF

"C:\Program Files\Hiawatha\bin\wigwam.exe" -q
IF ERRORLEVEL 1 GOTO ERROR
"C:\Program Files\Hiawatha\bin\hiawatha.exe" -d
IF ERRORLEVEL 1 GOTO ERROR
GOTO END

:ERROR
PAUSE

:END
