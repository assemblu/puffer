








#include <windows.h>
#include <thread>
#include <chrono>
#include <d3d11.h>
#include <dxgi.h>



#include "imgui.h"
#include "backends/imgui_impl_win32.h"
#include "backends/imgui_impl_dx11.h"



#include "minhook.h"
#include "logger.h"

static IDXGISwapChain* g_pSwapChain = nullptr;
static ID3D11Device*   g_pd3dDevice = nullptr;
static ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
static ID3D11RenderTargetView* g_pRTV = nullptr;
static bool            g_ImGuiInitialized = false;



typedef HRESULT(__stdcall* PresentFn)(IDXGISwapChain* pSwapChain, UINT SyncInterval, UINT Flags);
static PresentFn oPresent = nullptr;



static HWND GetCS2Window() {
    

    HWND hWnd = FindWindowW(L"Valve001", nullptr);
    if (!hWnd) hWnd = FindWindowW(L"CBaseWindowClass", nullptr);
    if (!hWnd) hWnd = FindWindowW(nullptr, L"Counter-Strike 2");
    return hWnd;
}



HRESULT __stdcall hkPresent(IDXGISwapChain* pSwapChain, UINT SyncInterval, UINT Flags) {
    static bool firstCall = true;
    static int frameCount = 0;
    frameCount++;
    if (firstCall) {
        OverlayLog(L"[overlay] hkPresent called – first frame");
        firstCall = false;
    }
    

    if (frameCount % 60 == 0) {
        OverlayLog(L"[overlay] hkPresent frame #%d", frameCount);
    }
    if (!g_ImGuiInitialized) {
        

        g_pSwapChain = pSwapChain;
        pSwapChain->GetDevice(__uuidof(ID3D11Device), (void**)&g_pd3dDevice);
        g_pd3dDevice->GetImmediateContext(&g_pd3dDeviceContext);

        

        DXGI_SWAP_CHAIN_DESC scDesc;
        pSwapChain->GetDesc(&scDesc);
        HWND scHwnd = scDesc.OutputWindow;

        

        wchar_t className[64] = {0};
        GetClassNameW(scHwnd, className, _countof(className));
        RECT rc = {0};
        GetClientRect(scHwnd, &rc);
        OverlayLog(L"[overlay] Swapchain HWND: 0x%p, class: %s, parent: 0x%p, clientRect: %dx%d",
                   scHwnd, className, GetParent(scHwnd), rc.right - rc.left, rc.bottom - rc.top);

        

        ID3D11Texture2D* bb = nullptr;
        uint32_t bbW = 0, bbH = 0;
        if (SUCCEEDED(pSwapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), (void**)&bb))) {
            D3D11_TEXTURE2D_DESC texDesc;
            bb->GetDesc(&texDesc);
            bbW = texDesc.Width;
            bbH = texDesc.Height;

            

            g_pd3dDevice->CreateRenderTargetView(bb, nullptr, &g_pRTV);
            OverlayLog(L"[overlay] RTV created: %s", g_pRTV ? L"yes" : L"NO");
        }
        if (bb) { bb->Release(); }
        OverlayLog(L"[overlay] Backbuffer: %ux%u", bbW, bbH);

        

        if (bbW == 0 || bbH == 0) {
            OverlayLog(L"[overlay] Skipping ImGui init – backbuffer size is zero");
            return oPresent(pSwapChain, SyncInterval, Flags);
        }

        

        ImGui::CreateContext();
        ImGuiIO& io = ImGui::GetIO(); (void)io;
        ImGui_ImplWin32_Init(scHwnd);
        ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);
        OverlayLog(L"[overlay] ImGui initialized – DisplaySize: %.0fx%.0f", io.DisplaySize.x, io.DisplaySize.y);
        g_ImGuiInitialized = true;
    }

    

    ImGuiIO& io = ImGui::GetIO();

    

    

    

    {
        ID3D11Texture2D* bb = nullptr;
        if (SUCCEEDED(g_pSwapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), (void**)&bb))) {
            D3D11_TEXTURE2D_DESC texDesc;
            bb->GetDesc(&texDesc);
            io.DisplaySize.x = (float)texDesc.Width;
            io.DisplaySize.y = (float)texDesc.Height;
            bb->Release();
        }
    }

    

    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();

    

    

    

    static bool showOverlay = true;
    static bool delWasDown = false;
    bool delIsDown = (GetAsyncKeyState(VK_DELETE) & 0x8000) != 0;
    if (delIsDown && !delWasDown) {
        showOverlay = !showOverlay;
        OverlayLog(L"[overlay] Overlay toggled: %s", showOverlay ? L"ON" : L"OFF");
    }
    delWasDown = delIsDown;

    if (showOverlay) {
        

        ImGui::SetNextWindowPos(ImVec2(10, 10), ImGuiCond_Always);
        ImGui::Begin("CS2 Overlay", nullptr, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoSavedSettings);
        
        ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "pwned by assemblu");
        ImGui::Separator();
        ImGui::Text("FPS: %.1f", io.Framerate);
        ImGui::Text("Resolution: %.0fx%.0f", io.DisplaySize.x, io.DisplaySize.y);
        ImGui::Text("Delta Time: %.3f ms", io.DeltaTime * 1000.0f);
        ImGui::Separator();
        ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "Press DEL to toggle");
        
        ImGui::End();
    }

    

    ImGui::Render();

    

    if (g_pRTV) {
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_pRTV, nullptr);
    }

    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

    

    if (frameCount <= 3) {
        OverlayLog(L"[overlay] Frame #%d rendered", frameCount);
    }

    

    HRESULT result = oPresent(pSwapChain, SyncInterval, Flags);
    if (frameCount <= 3) {
        OverlayLog(L"[overlay] Frame #%d oPresent returned 0x%08X", frameCount, result);
    }
    return result;
}



void HookThread() {
    

    OverlayLog(L"[overlay] Waiting for client.dll...");
    while (!GetModuleHandleW(L"client.dll")) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    OverlayLog(L"[overlay] client.dll found!");

    

    if (MH_Initialize() != MH_OK) {
        OverlayLog(L"[overlay] MinHook initialization failed");
        return;
    }
    OverlayLog(L"[overlay] MinHook initialized successfully");

    

    

    D3D_FEATURE_LEVEL featureLevel = D3D_FEATURE_LEVEL_11_0;
    ID3D11Device* dev = nullptr;
    ID3D11DeviceContext* ctx = nullptr;
    IDXGISwapChain* tmpSwap = nullptr;
    DXGI_SWAP_CHAIN_DESC scDesc = {};
    scDesc.BufferCount = 1;
    scDesc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    scDesc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    scDesc.OutputWindow = GetCS2Window();
    scDesc.SampleDesc.Count = 1;
    scDesc.Windowed = TRUE;

    

    OverlayLog(L"[overlay] Waiting for CS2 window handle...");
    while (true) {
        HWND hWnd = GetCS2Window();
        if (hWnd && IsWindow(hWnd)) {
            OverlayLog(L"[overlay] Found CS2 window: 0x%p", hWnd);
            scDesc.OutputWindow = hWnd;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    OverlayLog(L"[overlay] Attempting to create temporary DX11 device/swapchain...");
    HRESULT hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
                                      &featureLevel, 1, D3D11_SDK_VERSION,
                                      &scDesc, &tmpSwap, &dev, nullptr, &ctx);
    if (hr != S_OK) {
        OverlayLog(L"[overlay] D3D11CreateDeviceAndSwapChain FAILED (HRESULT: 0x%08X)", hr);
        return;
    }
    OverlayLog(L"[overlay] Temporary DX11 device/swapchain created successfully.");

    

    void** vtbl = *reinterpret_cast<void***>(tmpSwap);
    void* target = vtbl[8];
    OverlayLog(L"[overlay] Present vtable address: 0x%p", target);
    
    tmpSwap->Release();
    dev->Release();
    ctx->Release();

    

    OverlayLog(L"[overlay] Creating MinHook on Present...");
    if (MH_CreateHook(target, &hkPresent, reinterpret_cast<LPVOID*>(&oPresent)) != MH_OK) {
        OverlayLog(L"[overlay] MH_CreateHook FAILED");
        return;
    }
    OverlayLog(L"[overlay] MH_CreateHook succeeded. Enabling hook...");
    if (MH_EnableHook(target) != MH_OK) {
        OverlayLog(L"[overlay] MH_EnableHook FAILED");
        return;
    }
    OverlayLog(L"[overlay] Hook enabled successfully! Waiting for first frame...");
}



BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD  ul_reason_for_call,
                      LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        OverlayLog(L"[overlay] DLL_PROCESS_ATTACH – starting HookThread");
        CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(HookThread), nullptr, 0, nullptr);
        break;
    case DLL_PROCESS_DETACH:
        if (g_pRTV) { g_pRTV->Release(); g_pRTV = nullptr; }
        if (g_ImGuiInitialized) {
            ImGui_ImplDX11_Shutdown();
            ImGui_ImplWin32_Shutdown();
            ImGui::DestroyContext();
        }
        MH_Uninitialize();
        break;
    }
    return TRUE;
}
