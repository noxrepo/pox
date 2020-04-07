@echo off
IF NOT EXIST WpdPack GOTO NODIR

mkdir ..\windows
echo. > ..\windows\__init__.py

python3 setup.py build
xcopy /y build\lib.win32-2.7\pxpcap.pyd ..
xcopy /y build\lib.win32-2.7\pxpcap.pyd ..\windows

GOTO DONE

:NODIR
echo Please put the WinPcap developer pack directory, WpdPack, in this directory.
echo (You can download it from http://www.winpcap.org/devel.htm)

:DONE
