#include <cstring>
#include <iostream>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include "headers/injector.h"
#include "headers/fifo.h"
#include "imgui/imgui.h"
#include "imgui/imgui_impl_glfw.h"
#include "imgui/imgui_impl_opengl3.h"
#include <GLFW/glfw3.h>

static int fd = -1;
static uintptr_t handle = 0;
static bool initialized = false;
static Flags flags;

int inject(const char*& code) {

    pid_t pid = findProcessByName("cs2");

    if (pid == -1) {
        code = "Error: Open CS2 before injecting";
        return 1;
    }

    // Step 1: Resolve remote addresses before attaching
    uintptr_t mmap_addr = get_remote_mmap_address(pid);
    uintptr_t munmap_addr = get_remote_munmap_address(pid);
    uintptr_t dlopen_addr = get_remote_dlopen_address(pid);
    uintptr_t addr = get_remote_dlclose_address(pid);

    if (!mmap_addr || !dlopen_addr || !munmap_addr) {
        code = "Error: Could not find syscall addresses";
        return 1;
    }

    // Step 2: Attach to target process
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        code = "Error: PTRACE_ATTACH failed. Make sure no debugger is attached to cs2";
        return 1;
    }
    waitpid(pid, NULL, 0);

    std::string path = getLibraryDirectory() + "/cs2_bhop.so";
    const char* path_cstr = path.c_str();

    size_t path_len = strlen(path_cstr) + 1;
    uintptr_t allocated_mem = allocate_remote_memory(pid, mmap_addr, path_len);
    if (!allocated_mem) {
        code = "Error: Failed to allocate memory";
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }

    // Step 4: Write library path string into target memory space
    if (!write_to_remote_memory(pid, allocated_mem, path_cstr, path_len)) {
        code = "Error: Failed to write library path to memory";
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }

    // Step 5: Execute remote dlopen
    handle = execute_remote_dlopen(pid, dlopen_addr, allocated_mem);

    if (handle == 0) {
        code = "Error: Could not load shared object";
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }

    deallocate_remote_memory(pid, munmap_addr, allocated_mem, path_len);

    if (mkfifo(FIFO_PATH, 0666) < 0 && errno != EEXIST) {
        code = "Failed to set up pipe";
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }

    fd = open(FIFO_PATH, O_RDWR | O_NONBLOCK);
    if (fd < 0) {
        code = "Failed to open pipe";
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }
    // Step 6: Detach and restore process
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    initialized = true;
    code = "Success!";
    return 0;
}

void uninject(const char*& code) {
    pid_t pid = findProcessByName("cs2");
    if (pid == -1) {
        initialized = false;
        return;
    }
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        code = "Error: PTRACE_ATTACH failed. Make sure no debugger is attached to cs2";
        return;
    }
    waitpid(pid, NULL, 0);
    uintptr_t addr = get_remote_dlclose_address(pid);

    if (handle) execute_remote_dlclose(pid, addr, handle);
    if (fd >= 0) close(fd);
    
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    initialized = false;
    code = "Uninjected!";
    return;
}

static void glfw_error_callback(int error, const char* description)
{
    return;
}

int main()
{
    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit())
        return 0;
 
    const char* glsl_version = "#version 330";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
 
    GLFWwindow* window = glfwCreateWindow(480, 320, "Cs2 Internal Bhop", nullptr, nullptr);
    if (window == nullptr)
        return 0;
 
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // vsync
 
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    (void)io;
 
    ImGui::StyleColorsDark();
 
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    const char* message = "Error codes are printed here";

    while (!glfwWindowShouldClose(window))
    {
        glfwPollEvents();
 
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();
 
        // Make our window fill the GLFW window for a clean, simple look.
        ImGuiViewport* viewport = ImGui::GetMainViewport();
        ImGui::SetNextWindowPos(viewport->WorkPos);
        ImGui::SetNextWindowSize(viewport->WorkSize);
 
        ImGui::Begin("Simple GUI", nullptr,
                      ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
                      ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);
 
        ImGui::Dummy(ImVec2(0.0f, 20.0f));
 
        ImGui::Checkbox("Bhop Enabled", &flags.bhopEnabled);
 
        ImGui::Dummy(ImVec2(0.0f, 20.0f));
 
        // A big button: reserve most of the available width and a tall height.
        ImVec2 button_size(ImGui::GetContentRegionAvail().x, 80.0f);
        if (ImGui::Button("INJECT/UNINJECT", button_size))
        {
            if (!initialized) {
                if (inject(message) != 0) {
                    uninject(message);
                }
            }
            else if (initialized) {uninject(message);}
        }

        ImGui::Dummy(ImVec2(0.0f, 20.0f));

        float window_width = ImGui::GetContentRegionAvail().x;
        float text_width   = ImGui::CalcTextSize(message).x;

        // Set cursor X position to center alignment
        ImGui::SetCursorPosX((window_width - text_width) * 0.5f);
    
        // Colored status text
        ImGui::TextColored(ImVec4(1.0f, 1.0f, 1.0f, 1.0f), "%s", message);

        if (fd >= 0) write(fd, reinterpret_cast<const void*>(&flags), sizeof(Flags));
 
        ImGui::End();
 
        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.12f, 0.12f, 0.14f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
 
        glfwSwapBuffers(window);
    }

    cleanup:

    if (initialized) uninject(message);
    unlink(FIFO_PATH);
 
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
 
    glfwDestroyWindow(window);
    glfwTerminate();
 
    return 0;
}