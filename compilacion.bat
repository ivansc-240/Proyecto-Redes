@echo off

:: Configurar rutas de MSYS2 UCRT64 y Npcap
set PATH=C:\msys64\ucrt64\bin;%PATH%
set NPCAP_INCLUDE=C:\msys64\ucrt64\include
set NPCAP_LIB=C:\msys64\ucrt64\lib

echo Compilando sniffer.exe...

g++ -std=c++17 -O2 -Wall ^
    sniffer.cpp ^
    imgui/imgui.cpp ^
    imgui/imgui_draw.cpp ^
    imgui/imgui_widgets.cpp ^
    imgui/imgui_tables.cpp ^
    imgui/imgui_demo.cpp ^
    imgui/backends/imgui_impl_glfw.cpp ^
    imgui/backends/imgui_impl_opengl3.cpp ^
    -I. -I"%NPCAP_INCLUDE%" ^
    -L"%NPCAP_LIB%" ^
    -lglfw3 -lopengl32 -lgdi32 -lwpcap -lws2_32 ^
    -mwindows ^
    -o sniffer.exe

if %ERRORLEVEL% EQU 0 (
    echo Compilacion exitosa.
    start "" sniffer.exe
) else (
    echo Hubo un error en la compilacion.
    pause
)