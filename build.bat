@echo off
if not exist build mkdir build
cd build
cmake .. -G "MinGW Makefiles"
cmake --build . 
echo.
echo Built: build\wraith_agent.exe  (rename to wraith.exe)
echo Built: build\wraith_controller.exe
pause
