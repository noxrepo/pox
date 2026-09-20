@echo off

pushd "%~dp0"
IF NOT EXIST WpdPack GOTO NODIR

mkdir ..\windows
echo. > ..\windows\__init__.py

py -3 setup.py build_ext --inplace
xcopy /y pxpcap*.pyd ..\windows\

GOTO DONE

:NODIR
echo Please put the WinPcap developer pack directory, WpdPack, in this directory.
echo (You can download it from http://www.winpcap.org/devel.htm)

:DONE
popd
