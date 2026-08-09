#include "../imgui/imgui.h"
#include "../imgui/imgui_impl_glfw.h"
#include "../imgui/imgui_impl_opengl3.h"
#include <GLFW/glfw3.h>
#include <cstdio>

bool uninject = false;
bool bhopEnabled = true;

static void glfw_error_callback(int error, const char* description)
{
    fprintf(stderr, "GLFW Error %d: %s\n", error, description);
}
 
void* drawGui(void* arg)
{
    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit())
        return nullptr;
 
    const char* glsl_version = "#version 330";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
 
    GLFWwindow* window = glfwCreateWindow(480, 320, "Cs2 Internal Bhop", nullptr, nullptr);
    if (window == nullptr)
        return nullptr;
 
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // vsync
 
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    (void)io;
 
    ImGui::StyleColorsDark();
 
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);
 
    bool checkbox_value = false;
    int click_count = 0;
 
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
 
        ImGui::Checkbox("Bhop Enabled", &bhopEnabled);
 
        ImGui::Dummy(ImVec2(0.0f, 20.0f));
 
        // A big button: reserve most of the available width and a tall height.
        ImVec2 button_size(ImGui::GetContentRegionAvail().x, 80.0f);
        if (ImGui::Button("UNINJECT", button_size))
        {
            click_count++;
            uninject = true;
            goto cleanup;
        }
 
        ImGui::Dummy(ImVec2(0.0f, 10.0f));
        ImGui::Text("Checkbox is: %s", checkbox_value ? "ON" : "OFF");
        ImGui::Text("Button clicked %d times", click_count);
 
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
 
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
 
    glfwDestroyWindow(window);
    glfwTerminate();
 
    return nullptr;
}