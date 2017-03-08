@ECHO OFF
set arg1=%1
set arg2=%2

echo %arg1%
stlink\ST-LINK_CLI.exe -c SWD -ME
TIMEOUT 1
stlink\ST-LINK_CLI.exe -c SWD -P %arg1% 0x8000000 -Rst -Run
TIMEOUT 6
maple_upload.bat COM4 1 1EAF:0003 %arg2%