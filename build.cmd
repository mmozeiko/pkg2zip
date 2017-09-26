@echo off

call "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\Common7\Tools\VsDevCmd.bat" -arch=amd64 -host_arch=amd64

set CL=/nologo /errorReport:none /Gm- /GF /GS- /MT /W4
set LINK=/errorReport:none /INCREMENTAL:NO

set CL=%CL% /Ox
rem set CL=%CL% /Od /Zi
rem set LINK=%LINK% /DEBUG

cl.exe pkg2zip*.c puff.c /Fepkg2zip.exe
