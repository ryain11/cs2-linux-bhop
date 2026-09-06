LIBFLAGS = -shared -fPIC -L./src/staticlibs/ ./src/staticlibs/libfunchook.a -lpthread -ldl -ldistorm -std=c++20
BINFLAGS = ./src/staticlibs/libglfw3.a -ldl -lpthread -lGL

IMGUI = src/imgui/imgui_draw.cpp src/imgui/imgui.cpp src/imgui/imgui_impl_opengl3.cpp src/imgui/imgui_tables.cpp src/imgui/imgui_impl_glfw.cpp src/imgui/imgui_widgets.cpp

all: builddir library injector

builddir: 
	mkdir -p build

library: src/cs2_bhop.cpp
	g++ src/cs2_bhop.cpp $(LIBFLAGS) -o build/cs2_bhop.so

injector: src/injector.cpp
	g++ -std=c++20 src/injector.cpp $(IMGUI) $(BINFLAGS) -o build/injector
	chmod +x build/injector
