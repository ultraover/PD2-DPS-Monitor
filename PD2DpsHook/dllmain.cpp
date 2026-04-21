#include "pch.h"
#include <windows.h>
#include <windowsx.h>
#include <cstdint>
#include <string>
#include <fstream>
#include <mutex>
#include <cstring>
#include <cstdio>

struct DpsState {
    volatile uint32_t hp_total_loss_low = 0;
    volatile uint32_t hp_total_loss_high = 0;
    volatile uint32_t hp_last_loss = 0;
    volatile uint32_t hit_count = 0;

    volatile uint32_t last_old = 0;
    volatile uint32_t last_new = 0;
    volatile uint32_t last_arg18 = 0;

    volatile uint32_t last_eax = 0;
    volatile uint32_t last_ebx = 0;

    volatile uint32_t dps_1s_x100 = 0;
    volatile uint32_t dps_3s_x100 = 0;
    volatile uint32_t dps_5s_x100 = 0;
    volatile uint32_t dps_ema_x100 = 0;

    volatile uint32_t hits_per_sec_x100 = 0;
};

struct OverlayConfig {
    int x = 50;
    int y = 50;
};

static DpsState g_dps;
static OverlayConfig g_overlayConfig;
static std::mutex g_logMutex;

static uintptr_t g_hookAddress = 0;
static BYTE g_originalBytes[15] = {};
static bool g_installed = false;
static void* g_returnAddress = nullptr;

static HMODULE g_hModule = nullptr;
static HWND g_overlayWnd = nullptr;
static HFONT g_overlayFontTitle = nullptr;
static HFONT g_overlayFontValue = nullptr;
static HBITMAP g_handleBitmap = nullptr;

static const COLORREF kOverlayColorKey = RGB(1, 0, 1);

// =========================
// Logging
// =========================
void LogLine(const std::string& text) {
    std::lock_guard<std::mutex> lock(g_logMutex);

    char path[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, path, MAX_PATH);

    std::string fullPath(path);
    size_t pos = fullPath.find_last_of("\\/");
    if (pos != std::string::npos) {
        fullPath = fullPath.substr(0, pos + 1);
    }
    fullPath += "pd2_dps_log.txt";

    std::ofstream file(fullPath, std::ios::app);
    if (!file.is_open()) return;

    file << text << "\n";
}

std::string GetGameDirectory() {
    char path[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, path, MAX_PATH);

    std::string fullPath(path);
    size_t pos = fullPath.find_last_of("\\/");
    if (pos != std::string::npos) {
        fullPath = fullPath.substr(0, pos + 1);
    }
    return fullPath;
}

std::string GetModuleDirectory(HMODULE module) {
    char path[MAX_PATH] = {};
    GetModuleFileNameA(module, path, MAX_PATH);

    std::string fullPath(path);
    size_t pos = fullPath.find_last_of("\\/");
    if (pos != std::string::npos) {
        fullPath = fullPath.substr(0, pos + 1);
    }
    return fullPath;
}

std::string GetOverlayConfigPath() {
    return GetModuleDirectory(g_hModule) + "overlay.ini";
}

void LoadOverlayConfig() {
    std::string iniPath = GetOverlayConfigPath();

    g_overlayConfig.x = GetPrivateProfileIntA("Overlay", "X", 50, iniPath.c_str());
    g_overlayConfig.y = GetPrivateProfileIntA("Overlay", "Y", 50, iniPath.c_str());

    char buf[256] = {};
    sprintf_s(buf, "Overlay config loaded: X=%d Y=%d", g_overlayConfig.x, g_overlayConfig.y);
    LogLine(buf);
}

void SaveOverlayConfig() {
    std::string iniPath = GetOverlayConfigPath();

    char xBuf[32] = {};
    char yBuf[32] = {};
    sprintf_s(xBuf, "%d", g_overlayConfig.x);
    sprintf_s(yBuf, "%d", g_overlayConfig.y);

    WritePrivateProfileStringA("Overlay", "X", xBuf, iniPath.c_str());
    WritePrivateProfileStringA("Overlay", "Y", yBuf, iniPath.c_str());

    char buf[256] = {};
    sprintf_s(buf, "Overlay config saved: X=%d Y=%d", g_overlayConfig.x, g_overlayConfig.y);
    LogLine(buf);
}

// =========================
// Pattern scan
// =========================
uintptr_t PatternScan(HMODULE module, const unsigned char* pattern, const char* mask) {
    if (!module) return 0;

    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<uint8_t*>(module) + dos->e_lfanew
        );
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    DWORD size = nt->OptionalHeader.SizeOfImage;
    auto* base = reinterpret_cast<uint8_t*>(module);
    size_t patternLen = strlen(mask);

    for (DWORD i = 0; i <= size - patternLen; i++) {
        bool found = true;

        for (size_t j = 0; j < patternLen; j++) {
            if (mask[j] == 'x' && pattern[j] != base[i + j]) {
                found = false;
                break;
            }
        }

        if (found) {
            return reinterpret_cast<uintptr_t>(base + i);
        }
    }

    return 0;
}

// =========================
// Hook patching
// =========================
bool HookBytes(void* src, void* dst, size_t len) {
    if (!src || !dst || len < 5) return false;
    if (len > sizeof(g_originalBytes)) return false;

    DWORD oldProtect = 0;
    if (!VirtualProtect(src, len, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }

    memcpy(g_originalBytes, src, len);

    uintptr_t relAddr = (uintptr_t)dst - (uintptr_t)src - 5;

    memset(src, 0x90, len);
    *(BYTE*)src = 0xE9;
    *(uint32_t*)((uintptr_t)src + 1) = (uint32_t)relAddr;

    DWORD temp = 0;
    VirtualProtect(src, len, oldProtect, &temp);
    FlushInstructionCache(GetCurrentProcess(), src, len);
    return true;
}

bool UnhookBytes(void* src, size_t len) {
    if (!src || len > sizeof(g_originalBytes)) return false;

    DWORD oldProtect = 0;
    if (!VirtualProtect(src, len, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }

    memcpy(src, g_originalBytes, len);

    DWORD temp = 0;
    VirtualProtect(src, len, oldProtect, &temp);
    FlushInstructionCache(GetCurrentProcess(), src, len);
    return true;
}

// =========================
// Naked hook
// =========================
__declspec(naked) void HpHook() {
    __asm {
        pushfd
        push edx

        mov ebp, [eax + 04]
        mov ecx, [esp + 1Ch]
        lea edi, [ecx + ebp]

        mov dword ptr[g_dps.last_eax], eax
        mov dword ptr[g_dps.last_ebx], ebx

        mov edx, [esp + 20h]
        mov dword ptr[g_dps.last_arg18], edx

        test edx, edx
        jz not_hp

        cmp dword ptr[edx + 00], 6
        jne not_hp

        mov edx, ebp
        sub edx, edi
        cmp edx, 256
        jle not_hp

        mov dword ptr[g_dps.last_old], ebp
        mov dword ptr[g_dps.last_new], edi
        mov dword ptr[g_dps.hp_last_loss], edx

        lock add dword ptr[g_dps.hp_total_loss_low], edx
        adc dword ptr[g_dps.hp_total_loss_high], 0

        inc dword ptr[g_dps.hit_count]

        not_hp:
        pop edx
            popfd

            test edi, edi
            mov[eax + 04], edi
            jmp g_returnAddress
    }
}

// =========================
// Helpers
// =========================
static unsigned long long ReadTotalLossRaw() {
    uint32_t low1, high1, low2, high2;

    do {
        high1 = g_dps.hp_total_loss_high;
        low1 = g_dps.hp_total_loss_low;
        high2 = g_dps.hp_total_loss_high;
        low2 = g_dps.hp_total_loss_low;
    } while (high1 != high2 || low1 != low2);

    return ((unsigned long long)high1 << 32) | low1;
}

static uint32_t DpsFromTotalsX100(unsigned long long newerRaw, unsigned long long olderRaw, uint32_t seconds) {
    if (newerRaw < olderRaw || seconds == 0) return 0;

    unsigned long long deltaRaw = newerRaw - olderRaw;
    unsigned long long value = (deltaRaw * 100ULL) / (256ULL * seconds);

    if (value > 0xFFFFFFFFULL) value = 0xFFFFFFFFULL;
    return (uint32_t)value;
}

static void DrawShadowTextA(HDC hdc, int x, int y, const char* text) {
    SetBkMode(hdc, TRANSPARENT);

    SetTextColor(hdc, RGB(0, 0, 0));
    TextOutA(hdc, x + 1, y + 1, text, lstrlenA(text));

    SetTextColor(hdc, RGB(255, 255, 255));
    TextOutA(hdc, x, y, text, lstrlenA(text));
}

// =========================
// DPS sampler thread
// =========================
DWORD WINAPI DpsSamplerThread(LPVOID) {
    static unsigned long long totalHistory[6] = {};
    bool initialized = false;

    double ema = 0.0;
    const double alpha = 0.35;

    while (true) {
        Sleep(1000);

        unsigned long long currentTotal = ReadTotalLossRaw();

        if (!initialized) {
            for (int i = 0; i < 6; i++) {
                totalHistory[i] = currentTotal;
            }
            ema = 0.0;
            initialized = true;
        }
        else {
            for (int i = 0; i < 5; i++) {
                totalHistory[i] = totalHistory[i + 1];
            }
            totalHistory[5] = currentTotal;
        }

        uint32_t dps1 = DpsFromTotalsX100(totalHistory[5], totalHistory[4], 1);
        uint32_t dps3 = DpsFromTotalsX100(totalHistory[5], totalHistory[2], 3);
        uint32_t dps5 = DpsFromTotalsX100(totalHistory[5], totalHistory[0], 5);

        double dps1Real = (double)dps1 / 100.0;
        ema = alpha * dps1Real + (1.0 - alpha) * ema;

        if (ema < 0.0) ema = 0.0;
        uint32_t dpsEma = (uint32_t)(ema * 100.0);

        g_dps.dps_1s_x100 = dps1;
        g_dps.dps_3s_x100 = dps3;
        g_dps.dps_5s_x100 = dps5;
        g_dps.dps_ema_x100 = dpsEma;
    }

    return 0;
}

// =========================
// Hits/s sampler thread
// 2-second moving average,
// updated every 0.5s
// =========================
DWORD WINAPI HitsSamplerThread(LPVOID) {
    uint32_t hitHistory[5] = {};
    bool initialized = false;

    while (true) {
        Sleep(500);

        uint32_t currentHits = g_dps.hit_count;

        if (!initialized) {
            for (int i = 0; i < 5; i++) {
                hitHistory[i] = currentHits;
            }
            initialized = true;
        }
        else {
            for (int i = 0; i < 4; i++) {
                hitHistory[i] = hitHistory[i + 1];
            }
            hitHistory[4] = currentHits;
        }

        // 2-second window = 4 intervals of 0.5s
        uint32_t deltaHits = hitHistory[4] - hitHistory[0];

        // hits/s = delta / 2.0
        // *100 => delta * 50
        g_dps.hits_per_sec_x100 = deltaHits * 50;
    }

    return 0;
}

// =========================
// Logger thread
// =========================
DWORD WINAPI LoggerThread(LPVOID) {
    uint32_t lastLoggedHitCount = 0;
    uint32_t lastLoggedDps1 = 0xFFFFFFFF;
    uint32_t lastLoggedDps3 = 0xFFFFFFFF;
    uint32_t lastLoggedDps5 = 0xFFFFFFFF;
    uint32_t lastLoggedDpsEma = 0xFFFFFFFF;
    uint32_t lastLoggedHitsPerSec = 0xFFFFFFFF;

    while (true) {
        Sleep(200);

        uint32_t currentHits = g_dps.hit_count;
        uint32_t dps1 = g_dps.dps_1s_x100;
        uint32_t dps3 = g_dps.dps_3s_x100;
        uint32_t dps5 = g_dps.dps_5s_x100;
        uint32_t dpsEma = g_dps.dps_ema_x100;
        uint32_t hitsPerSec = g_dps.hits_per_sec_x100;

        if (currentHits == lastLoggedHitCount &&
            dps1 == lastLoggedDps1 &&
            dps3 == lastLoggedDps3 &&
            dps5 == lastLoggedDps5 &&
            dpsEma == lastLoggedDpsEma &&
            hitsPerSec == lastLoggedHitsPerSec) {
            continue;
        }

        lastLoggedHitCount = currentHits;
        lastLoggedDps1 = dps1;
        lastLoggedDps3 = dps3;
        lastLoggedDps5 = dps5;
        lastLoggedDpsEma = dpsEma;
        lastLoggedHitsPerSec = hitsPerSec;

        unsigned long long totalRaw = ReadTotalLossRaw();
        unsigned long long totalRealInt = totalRaw / 256ULL;

        uint32_t lastLossRealInt = g_dps.hp_last_loss / 256U;
        uint32_t lastLossRawRemainder = g_dps.hp_last_loss % 256U;

        char buf[768] = {};
        sprintf_s(
            buf,
            "[HP] last_old=%u last_new=%u last_loss_raw=%u last_loss_real=%u.%03u total_raw=%llu total_real=%llu hits=%u hits_per_sec=%u.%02u dps_1s=%u.%02u dps_3s=%u.%02u dps_5s=%u.%02u dps_ema=%u.%02u arg18=%08X eax=%08X ebx=%08X",
            (unsigned)g_dps.last_old,
            (unsigned)g_dps.last_new,
            (unsigned)g_dps.hp_last_loss,
            lastLossRealInt,
            (lastLossRawRemainder * 1000U) / 256U,
            totalRaw,
            totalRealInt,
            (unsigned)g_dps.hit_count,
            hitsPerSec / 100, hitsPerSec % 100,
            dps1 / 100, dps1 % 100,
            dps3 / 100, dps3 % 100,
            dps5 / 100, dps5 % 100,
            dpsEma / 100, dpsEma % 100,
            (unsigned)g_dps.last_arg18,
            (unsigned)g_dps.last_eax,
            (unsigned)g_dps.last_ebx
        );

        LogLine(buf);
    }

    return 0;
}

// =========================
// Overlay
// =========================
LRESULT CALLBACK OverlayWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        SetTimer(hwnd, 1, 100, nullptr);
        return 0;

    case WM_TIMER:
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;

    case WM_ERASEBKGND:
        return 1;

    case WM_NCHITTEST:
    {
        POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
        ScreenToClient(hwnd, &pt);

        if (pt.x >= 4 && pt.x < 54 &&
            pt.y >= 4 && pt.y < 54) {
            return HTCAPTION;
        }

        return HTTRANSPARENT;
    }

    case WM_EXITSIZEMOVE:
    {
        RECT rc;
        if (GetWindowRect(hwnd, &rc)) {
            g_overlayConfig.x = rc.left;
            g_overlayConfig.y = rc.top;
            SaveOverlayConfig();
        }
        return 0;
    }

    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        RECT rc;
        GetClientRect(hwnd, &rc);

        int width = rc.right - rc.left;
        int height = rc.bottom - rc.top;

        HDC memDC = CreateCompatibleDC(hdc);
        HBITMAP memBmp = CreateCompatibleBitmap(hdc, width, height);
        HBITMAP oldBmp = (HBITMAP)SelectObject(memDC, memBmp);

        HBRUSH bg = CreateSolidBrush(kOverlayColorKey);
        FillRect(memDC, &rc, bg);
        DeleteObject(bg);

        SetBkColor(memDC, kOverlayColorKey);

        unsigned long long totalRaw = ReadTotalLossRaw();
        unsigned long long totalReal = totalRaw / 256ULL;

        uint32_t dps1 = g_dps.dps_1s_x100;
        uint32_t dps3 = g_dps.dps_3s_x100;
        uint32_t dps5 = g_dps.dps_5s_x100;
        uint32_t dpsEma = g_dps.dps_ema_x100;
        uint32_t hits = g_dps.hit_count;
        uint32_t hitsPerSec = g_dps.hits_per_sec_x100;
        uint32_t lastLoss = g_dps.hp_last_loss;

        if (g_handleBitmap) {
            HDC imgDC = CreateCompatibleDC(memDC);
            HBITMAP oldImg = (HBITMAP)SelectObject(imgDC, g_handleBitmap);

            BitBlt(memDC, 4, 4, 50, 50, imgDC, 0, 0, SRCCOPY);

            SelectObject(imgDC, oldImg);
            DeleteDC(imgDC);
        }

        char line1[128], line2[128], line3[128], line4[128], line5[128], line6[128], line7[128], line8[128], line9[128];

        sprintf_s(line1, "PD2 DPS");
        sprintf_s(line2, "1s      : %u", dps1 / 100);
        sprintf_s(line3, "3s      : %u", dps3 / 100);
        sprintf_s(line4, "5s      : %u", dps5 / 100);
        sprintf_s(line5, "EMA     : %u", dpsEma / 100);
        sprintf_s(line6, "Hits    : %u", hits);
        sprintf_s(line7, "Hits/s  : %u.%02u", hitsPerSec / 100, hitsPerSec % 100);
        sprintf_s(line8, "Last    : %u", lastLoss / 256U);
        sprintf_s(line9, "Total   : %llu", totalReal);

        int x = 62;
        int y = 8;
        const int lineH = 20;

        SetTextAlign(memDC, TA_LEFT | TA_TOP);

        HFONT oldFont = nullptr;

        HFONT titleFont = g_overlayFontTitle ? g_overlayFontTitle : (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        oldFont = (HFONT)SelectObject(memDC, titleFont);
        DrawShadowTextA(memDC, x, y + lineH * 0, line1);

        HFONT valueFont = g_overlayFontValue ? g_overlayFontValue : (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        SelectObject(memDC, valueFont);

        DrawShadowTextA(memDC, x, y + lineH * 1, line2);
        DrawShadowTextA(memDC, x, y + lineH * 2, line3);
        DrawShadowTextA(memDC, x, y + lineH * 3, line4);
        DrawShadowTextA(memDC, x, y + lineH * 4, line5);
        DrawShadowTextA(memDC, x, y + lineH * 5, line6);
        DrawShadowTextA(memDC, x, y + lineH * 6, line7);
        DrawShadowTextA(memDC, x, y + lineH * 7, line8);
        DrawShadowTextA(memDC, x, y + lineH * 8, line9);

        if (oldFont) {
            SelectObject(memDC, oldFont);
        }

        BitBlt(hdc, 0, 0, width, height, memDC, 0, 0, SRCCOPY);

        SelectObject(memDC, oldBmp);
        DeleteObject(memBmp);
        DeleteDC(memDC);

        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_DESTROY:
        KillTimer(hwnd, 1);
        return 0;
    }

    return DefWindowProc(hwnd, msg, wParam, lParam);
}

DWORD WINAPI OverlayThread(LPVOID) {
    const char* className = "PD2DpsOverlayWindow";

    WNDCLASSEXA wc = {};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = OverlayWndProc;
    wc.hInstance = g_hModule;
    wc.lpszClassName = className;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = nullptr;

    if (!RegisterClassExA(&wc)) {
        LogLine("RegisterClassExA failed for overlay.");
        return 0;
    }

    LoadOverlayConfig();

    g_overlayWnd = CreateWindowExA(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_LAYERED,
        className,
        "PD2 DPS Overlay",
        WS_POPUP | WS_VISIBLE,
        g_overlayConfig.x, g_overlayConfig.y, 320, 215,
        nullptr,
        nullptr,
        g_hModule,
        nullptr
    );

    if (!g_overlayWnd) {
        LogLine("CreateWindowExA failed for overlay.");
        return 0;
    }

    if (!SetLayeredWindowAttributes(g_overlayWnd, kOverlayColorKey, 0, LWA_COLORKEY)) {
        LogLine("SetLayeredWindowAttributes failed.");
    }

    std::string dllDir = GetModuleDirectory(g_hModule);
    std::string exeDir = GetGameDirectory();

    std::string bmpPathDll = dllDir + "renren.bmp";
    std::string bmpPathExe = exeDir + "renren.bmp";

    g_handleBitmap = (HBITMAP)LoadImageA(
        nullptr,
        bmpPathDll.c_str(),
        IMAGE_BITMAP,
        0, 0,
        LR_LOADFROMFILE
    );

    if (!g_handleBitmap) {
        g_handleBitmap = (HBITMAP)LoadImageA(
            nullptr,
            bmpPathExe.c_str(),
            IMAGE_BITMAP,
            0, 0,
            LR_LOADFROMFILE
        );
    }

    if (!g_handleBitmap) {
        LogLine("Failed to load renren.bmp from both the DLL folder and the game folder.");
        LogLine(std::string("Tried DLL path: ") + bmpPathDll);
        LogLine(std::string("Tried EXE path: ") + bmpPathExe);
    }
    else {
        LogLine("renren.bmp loaded successfully.");
    }

    // Try Exocet first; fallback to Tahoma if unavailable
    g_overlayFontTitle = CreateFontA(
        24, 0, 0, 0,
        FW_BOLD,
        FALSE, FALSE, FALSE,
        ANSI_CHARSET,
        OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS,
        ANTIALIASED_QUALITY,
        DEFAULT_PITCH | FF_DONTCARE,
        "Exocet"
    );

    if (!g_overlayFontTitle) {
        g_overlayFontTitle = CreateFontA(
            22, 0, 0, 0,
            FW_NORMAL,
            FALSE, FALSE, FALSE,
            ANSI_CHARSET,
            OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS,
            ANTIALIASED_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE,
            "Tahoma"
        );
        LogLine("Failed to create Exocet font; using Tahoma for title.");
    }
    else {
        LogLine("Exocet title font created successfully.");
    }

    g_overlayFontValue = CreateFontA(
        22, 0, 0, 0,
        FW_NORMAL,
        FALSE, FALSE, FALSE,
        ANSI_CHARSET,
        OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS,
        ANTIALIASED_QUALITY,
        DEFAULT_PITCH | FF_DONTCARE,
        "Exocet"
    );

    if (!g_overlayFontValue) {
        LogLine("CreateFontA failed for overlay value font.");
    }

    SetWindowPos(
        g_overlayWnd,
        HWND_TOPMOST,
        g_overlayConfig.x, g_overlayConfig.y, 320, 215,
        SWP_SHOWWINDOW
    );

    ShowWindow(g_overlayWnd, SW_SHOW);
    UpdateWindow(g_overlayWnd);

    LogLine("Overlay created.");

    MSG msg;
    while (GetMessageA(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    if (g_overlayFontTitle) {
        DeleteObject(g_overlayFontTitle);
        g_overlayFontTitle = nullptr;
    }

    if (g_overlayFontValue) {
        DeleteObject(g_overlayFontValue);
        g_overlayFontValue = nullptr;
    }

    if (g_handleBitmap) {
        DeleteObject(g_handleBitmap);
        g_handleBitmap = nullptr;
    }

    return 0;
}

// =========================
// Main thread
// =========================
DWORD WINAPI MainThread(LPVOID) {
    LogLine("PD2DpsHook loaded.");

    Sleep(1000);

    HMODULE d2common = GetModuleHandleA("D2COMMON.dll");
    if (!d2common) {
        LogLine("D2COMMON.dll not found.");
        return 0;
    }

    const unsigned char pattern[] = {
        0x8B, 0x68, 0x04,
        0x8B, 0x4C, 0x24, 0x14,
        0x8D, 0x3C, 0x29,
        0x85, 0xFF,
        0x89, 0x78, 0x04
    };
    const char* mask = "xxxxxxxxxxxxxxx";

    g_hookAddress = PatternScan(d2common, pattern, mask);
    if (!g_hookAddress) {
        LogLine("Pattern not found.");
        return 0;
    }

    char foundBuf[128] = {};
    sprintf_s(foundBuf, "Pattern found at %p.", (void*)g_hookAddress);
    LogLine(foundBuf);

    constexpr size_t hookLen = 15;
    g_returnAddress = (void*)(g_hookAddress + hookLen);

    if (!HookBytes((void*)g_hookAddress, HpHook, hookLen)) {
        LogLine("HookBytes failed.");
        return 0;
    }

    g_installed = true;
    LogLine("Hook installed.");

    HANDLE hSampler = CreateThread(nullptr, 0, DpsSamplerThread, nullptr, 0, nullptr);
    if (hSampler) {
        CloseHandle(hSampler);
    }
    else {
        LogLine("Failed to create DpsSamplerThread.");
    }

    HANDLE hHits = CreateThread(nullptr, 0, HitsSamplerThread, nullptr, 0, nullptr);
    if (hHits) {
        CloseHandle(hHits);
    }
    else {
        LogLine("Failed to create HitsSamplerThread.");
    }

    HANDLE hLogger = CreateThread(nullptr, 0, LoggerThread, nullptr, 0, nullptr);
    if (hLogger) {
        CloseHandle(hLogger);
    }
    else {
        LogLine("Failed to create LoggerThread.");
    }

    HANDLE hOverlay = CreateThread(nullptr, 0, OverlayThread, nullptr, 0, nullptr);
    if (hOverlay) {
        CloseHandle(hOverlay);
    }
    else {
        LogLine("Failed to create OverlayThread.");
    }

    return 0;
}

// =========================
// DLL entry
// =========================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    {
        g_hModule = hModule;
        DisableThreadLibraryCalls(hModule);

        HANDLE hThread = CreateThread(nullptr, 0, MainThread, nullptr, 0, nullptr);
        if (hThread) {
            CloseHandle(hThread);
        }
        break;
    }

    case DLL_PROCESS_DETACH:
        if (g_overlayWnd) {
            DestroyWindow(g_overlayWnd);
            g_overlayWnd = nullptr;
        }

        if (g_installed && g_hookAddress) {
            UnhookBytes((void*)g_hookAddress, 15);
        }
        break;
    }

    return TRUE;
}