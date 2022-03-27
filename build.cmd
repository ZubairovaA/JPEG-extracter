echo off

set model=release
set current=%cd%
md %current%\build
pushd %current%\build

cmake -G "Visual Studio 17 2019" -DCMAKE_CONFIGURATION_TYPE=%model% ..
if errorlevel 1 goto fail

cmake --build . --config %model%
if errorlevel 1 goto fail

echo *********************************************
echo BUILD SUCCEEDED
echo *********************************************

set target=%current%\artifacts\x86_64\%model%\bin
md %target%
copy /Y %current%\stage\bin\%model%\extractJPEG.exe %target%

goto end:

:fail
echo *********************************************
echo BUILD FAILED
echo *********************************************

:end
popd
