@ECHO OFF
ECHO.
ECHO NoWinUpd.bat,  Version 1.00 for Windows 9x / NT 4 / 2000
ECHO Disable Windows' Update feature.
ECHO.
ECHO Note:
ECHO Use WINUPD.BAT if you want to reenable Windows' Update feature.
ECHO.
ECHO Written by Rob van der Woude
ECHO http://www.robvanderwoude.com
ECHO.
ECHO.
ECHO Press any key to continue, or Ctrl+C to abort . . .
PAUSE >NUL
ECHO.

ECHO Creating temporary file . . .
> "%Temp%.\NoWinUpd.reg" ECHO REGEDIT4
>>"%Temp%.\NoWinUpd.reg" ECHO.

ECHO Checking Current User setting . . .
IF EXIST "%Temp%.\NoWinUpd.dat" DEL "%Temp%.\NoWinUpd.dat"
START /WAIT REGEDIT /E "%Temp%.\NoWinUpd.dat" "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
IF NOT EXIST "%Temp%.\NoWinUpd.dat" GOTO Next
>>"%Temp%.\NoWinUpd.reg" ECHO [HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer]
>>"%Temp%.\NoWinUpd.reg" ECHO "NoWindowsUpdate"=dword:00000001
>>"%Temp%.\NoWinUpd.reg" ECHO.

:Next
ECHO Checking Local Machine setting . . .
IF EXIST "%Temp%.\NoWinUpd.dat" DEL "%Temp%.\NoWinUpd.dat"
START /WAIT REGEDIT /E "%Temp%.\NoWinUpd.dat" "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
IF NOT EXIST "%Temp%.\NoWinUpd.dat" GOTO End
>>"%Temp%.\NoWinUpd.reg" ECHO [HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer]
>>"%Temp%.\NoWinUpd.reg" ECHO "NoWindowsUpdate"=dword:00000001
>>"%Temp%.\NoWinUpd.reg" ECHO.

:End
IF EXIST "%Temp%.\NoWinUpd.dat" DEL "%Temp%.\NoWinUpd.dat"

ECHO Writing changes to registry . . .
START /WAIT REGEDIT /S "%Temp%.\NoWinUpd.reg"
IF EXIST "%Temp%.\NoWinUpd.reg" DEL "%Temp%.\NoWinUpd.reg"
ECHO Done!
