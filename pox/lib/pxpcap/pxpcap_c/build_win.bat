@echo off
IF NOT EXIST WpdPack GOTO NODIR

python setup.py build
xcopy /y build\lib.win32-2.7\pxpcap.pyd ..

GOTO DONE

:NODIR
echo Please put the WinPcap developer pack directory, WpdPack, in this directory.
echo (You can download it from http://www.winpcap.org/devel.htm)

:DONE