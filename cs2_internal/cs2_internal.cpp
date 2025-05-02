#define WIN32_LEAN_MEAN
#include <Windows.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <xorstr.hpp>
#include "auth.hpp"
#include "HideModule.h"
#include "sdk.hpp"
#include "overlay.hpp"

#define build_version 14074

using namespace KeyAuth;

std::string name = xorstr_("Athena Development");
std::string ownerid = xorstr_("KVcBaFEZ9z");
std::string version = xorstr_("1.0");
std::string url = xorstr_("https://keyauth.win/api/1.3/");
std::string path = xorstr_("");

api KeyAuthApp(name, ownerid, version, url, path);

enum class login_status
{
    LOGGED_IN,
    REGISTER,
    LOGIN
};


class Functions {
public:
} functions;

class Globals {
public:
    bool show_menu = true;
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    bool streamproof = true;
    bool vsync = true;
    bool initialized = false;
}globals;

login_status status = login_status::LOGIN;
#ifdef _WINDLL
void Initialize(HMODULE Module)
#else
void Initialize()
#endif
{
    if (!globals.initialized)
    {
        if (SDK.UpdateOffsets() == false)
        {
            overlay.logger.error(xorstr_("Failed to auto update. Please Contact Athena Development @ discord.gg/athenadev."));
        }
        Beep(500, 500);

        SDK.process = std::make_shared<pProcess>();
        if (!SDK.process->AttachProcessHj(xorstr_("cs2.exe"), false))
        {
            overlay.logger.error(xorstr_("Failed to attach to process"));
        }

        Beep(500, 500);

        SDK.GetClientBase();
        SDK.GetEngineBase();

        Beep(500, 500);

        int game_version = SDK.process->read<int>(SDK.engine_dll.base + offsets.dwBuildNumber);

        if (game_version < build_version)
        {
            overlay.logger.error((xorstr_("Unsupported Version -> CS2 Build ") + std::to_string(game_version)).c_str());
        }
        else if (game_version > 14074)
        {
            if (overlay.logger.ask((xorstr_("Autoupdated. New Version ") + std::to_string(game_version) + xorstr_(" Proceed?")).c_str()) == IDNO)
            {
#ifdef _WINDLL
                FreeLibraryAndExitThread(Module, 0);
#else
                exit(0);
#endif
            }
        }

        globals.initialized = true;
    }
}

void SetNextWindowCentered(float size_ratio)
{
    float width = globals.width * size_ratio;
    float height = globals.height * size_ratio;

    ImVec2 window_size(width, height);
    ImVec2 window_pos((globals.width - width) * 0.5f, (globals.height - height) * 0.5f);

    ImGui::SetNextWindowSize(window_size, ImGuiCond_Always);
    ImGui::SetNextWindowPos(window_pos, ImGuiCond_Always);
}

void menu(std::string overlay_name)
{
    SetNextWindowCentered(0.5);
    ImGui::Begin(overlay_name.c_str(), NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);
    std::string title = xorstr_("External Overlay -> FPS: ");
    title += std::to_string((int)overlay.get_fps());
    overlay.center_text(title.c_str());
    overlay.spacer();
    ImGui::Separator();
    overlay.center_text(xorstr_("Settings"));
    ImGui::Checkbox(xorstr_("Streamproof"), &globals.streamproof);
    overlay.tooltip(xorstr_("Prevents the overlay from being captured by the anticheats. (Recommended)"));
    ImGui::Checkbox(xorstr_("Vsync"), &globals.vsync);
    overlay.tooltip(xorstr_("Synchronize the overlay framerate to the monitor's refresh rate."));
    ImGui::End();
}

void login(std::string overlay_name)
{
    SetNextWindowCentered(0.1);
    ImGui::Begin(overlay_name.c_str(), nullptr, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);

    overlay.center_text(xorstr_("Athena Development"));
    overlay.spacer();

    static char username[64] = "";
    static char password[64] = "";

    overlay.center_input_text(xorstr_("Username:"), xorstr_("##username"), username, IM_ARRAYSIZE(username), ImGuiInputTextFlags_CharsNoBlank);
    overlay.center_input_text(xorstr_("Password:"), xorstr_("##password"), password, IM_ARRAYSIZE(password), ImGuiInputTextFlags_Password);

    overlay.spacer();
    ImGui::SetCursorPosX((ImGui::GetWindowWidth() - ImGui::CalcTextSize(xorstr_("Login")).x - ImGui::GetStyle().ItemSpacing.x - ImGui::CalcTextSize(xorstr_("Register")).x) * 0.5f);
    
    if (ImGui::Button(xorstr_("Login")))
    {

        KeyAuthApp.login(username, password);
        if (!KeyAuthApp.response.success)
        {
            overlay.logger.error(xorstr_("Username or Password Invalid."));
        }
        else
        {
            status = login_status::LOGGED_IN;
        }
    }

    ImGui::SameLine();
    if (ImGui::Button(xorstr_("Register")))
    {
        status = login_status::REGISTER;
    }

    ImGui::End();
}

void registr(std::string overlay_name)
{
    SetNextWindowCentered(0.13);
    ImGui::Begin(overlay_name.c_str(), nullptr, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);

    overlay.center_text(xorstr_("Register Account"));
    overlay.spacer();

    static char username[64] = "";
    static char password[64] = "";
    static char license[64] = "";

    overlay.center_input_text(xorstr_("Username:"), xorstr_("##reg_username"), username, IM_ARRAYSIZE(username), ImGuiInputTextFlags_CharsNoBlank);
    overlay.center_input_text(xorstr_("Password:"), xorstr_("##reg_password"), password, IM_ARRAYSIZE(password), ImGuiInputTextFlags_Password);
    overlay.center_input_text(xorstr_("License:"), xorstr_("##reg_license"), license, IM_ARRAYSIZE(license), ImGuiInputTextFlags_CharsNoBlank);

    overlay.spacer();
    ImGui::SetCursorPosX((ImGui::GetWindowWidth() - ImGui::CalcTextSize(xorstr_("Submit")).x - ImGui::GetStyle().ItemSpacing.x - ImGui::CalcTextSize(xorstr_("Back")).x) * 0.5f);
    
    if (ImGui::Button(("Submit")))
    {
        KeyAuthApp.regstr(username, password, license);
        if (!KeyAuthApp.response.success)
        {
            overlay.logger.error(xorstr_("Failed to register an account."));
        }
        else
        {
            status = login_status::LOGIN;
        }
    }

    ImGui::SameLine();
    if (ImGui::Button(xorstr_("Back")))
    {
        status = login_status::LOGIN;
    }

    ImGui::End();
}


void background_draw()
{
    std::string text = xorstr_("External Overlay -> FPS: ");
    text += std::to_string((int)overlay.get_fps());
    ImGui::GetBackgroundDrawList()->AddText(ImVec2(10, 10), IM_COL32(255, 255, 255, 255), text.c_str());
}

#ifdef _WINDLL
DWORD MainThread(HMODULE Module)
#else
DWORD MainThread()
#endif
{
#ifdef _WINDLL
    WipePEHeader(Module);
    WipeImportTable(Module);
    WipeDebugDirectory(Module);
    UnlinkModuleFromPEB(Module);
#endif
    KeyAuthApp.init();
    if (!KeyAuthApp.response.success)
    {
        overlay.logger.error(xorstr_("Couldn't connect to server."));
    }

    if (KeyAuthApp.checkblack())
    {
        overlay.logger.error(xorstr_("Account Disabled. Please Contact Athena Development @ discord.gg/athenadev."));
    }
    

    std::string overlay_name = GetRandomString(GetRandomInteger());

    overlay.initialize(xorstr_("Counter-Strike 2"), xorstr_("SDL_app"));

    Beep(500, 1000);

    while (true)
    {
        overlay.set_window_streamproof(globals.streamproof);
        overlay.start_render();
        if (GetAsyncKeyState(VK_END) & 1) overlay.destroy();
        if (GetAsyncKeyState(VK_INSERT) & 1) globals.show_menu = !globals.show_menu;
        overlay.change_input_allowed(globals.show_menu);

        background_draw();

        switch (status)
        {
        case login_status::LOGGED_IN:
#ifdef _WINDLL
            Initialize(Module);
#else
            Initialize();
#endif
            if (globals.show_menu) menu(overlay_name);
            break;
        case login_status::REGISTER:
            if (globals.show_menu) registr(overlay_name);
            break;
        case login_status::LOGIN:
            if (globals.show_menu) login(overlay_name);
            break;
        }

        overlay.present_render(globals.vsync);
    }

#ifdef _WINDLL
    FreeLibraryAndExitThread(Module, 0);
#else
    exit(0);
#endif
}

#ifdef _WINDLL
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule); // disable thread events
        DisableProcessWindowsGhosting(); // Disable ghosting effect when program isnt responding
        /*HANDLE thread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)MainThread, hModule, 0, 0);
        if (thread)
        {
            CloseHandle(thread);
            return TRUE;
        }*/
        CreateHiddenThread((LPTHREAD_START_ROUTINE)MainThread, hModule);
        Beep(200, 1000);
        return TRUE;
    }
}
#else
int main()
{
    FreeConsole();
    MainThread();
}
#endif