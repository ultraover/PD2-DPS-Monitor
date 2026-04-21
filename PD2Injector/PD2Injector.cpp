#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

DWORD FindProcessId(const std::wstring& processName) {
    DWORD pid = 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snapshot, &pe)) {
        do {
            if (processName == pe.szExeFile) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &pe));
    }

    CloseHandle(snapshot);
    return pid;
}

bool EnableDebugPrivilege() {
    HANDLE hToken = nullptr;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    TOKEN_PRIVILEGES tp{};
    LUID luid{};

    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr)) {
        CloseHandle(hToken);
        return false;
    }

    DWORD err = GetLastError();
    CloseHandle(hToken);

    return err == ERROR_SUCCESS;
}

int wmain() {
    const std::wstring processName = L"Game.exe";

    if (EnableDebugPrivilege()) {
        std::wcout << L"SeDebugPrivilege ativado.\n";
    }
    else {
        std::wcout << L"Nao foi possivel ativar SeDebugPrivilege.\n";
    }

    wchar_t dllPath[MAX_PATH];
    if (!GetFullPathNameW(L"PD2DpsHook.dll", MAX_PATH, dllPath, nullptr)) {
        std::wcout << L"Falha ao resolver caminho da DLL.\n";
        std::wcout << L"Pressione Enter para sair...";
        std::wcin.get();
        return 1;
    }

    std::wcout << L"DLL: " << dllPath << L"\n";

    DWORD pid = FindProcessId(processName);
    if (!pid) {
        std::wcout << L"Processo nao encontrado: " << processName << L"\n";
        std::wcout << L"Pressione Enter para sair...";
        std::wcin.get();
        return 1;
    }

    std::wcout << L"PID encontrado: " << pid << L"\n";

    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD |
        PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE |
        PROCESS_VM_READ,
        FALSE,
        pid
    );

    if (!hProcess) {
        DWORD err = GetLastError();
        std::wcout << L"Falha ao abrir o processo. GetLastError = " << err << L"\n";
        std::wcout << L"Pressione Enter para sair...";
        std::wcin.get();
        return 1;
    }

    SIZE_T dllPathSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);

    LPVOID remoteMem = VirtualAllocEx(hProcess, nullptr, dllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        DWORD err = GetLastError();
        std::wcout << L"Falha no VirtualAllocEx. GetLastError = " << err << L"\n";
        CloseHandle(hProcess);
        std::wcout << L"Pressione Enter para sair...";
        std::wcin.get();
        return 1;
    }

    if (!WriteProcessMemory(hProcess, remoteMem, dllPath, dllPathSize, nullptr)) {
        DWORD err = GetLastError();
        std::wcout << L"Falha no WriteProcessMemory. GetLastError = " << err << L"\n";
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        std::wcout << L"Pressione Enter para sair...";
        std::wcin.get();
        return 1;
    }

    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    if (!loadLibraryAddr) {
        DWORD err = GetLastError();
        std::wcout << L"Falha ao localizar LoadLibraryW. GetLastError = " << err << L"\n";
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        std::wcout << L"Pressione Enter para sair...";
        std::wcin.get();
        return 1;
    }

    HANDLE hThread = CreateRemoteThread(
        hProcess,
        nullptr,
        0,
        (LPTHREAD_START_ROUTINE)loadLibraryAddr,
        remoteMem,
        0,
        nullptr
    );

    if (!hThread) {
        DWORD err = GetLastError();
        std::wcout << L"Falha ao criar thread remota. GetLastError = " << err << L"\n";
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        std::wcout << L"Pressione Enter para sair...";
        std::wcin.get();
        return 1;
    }

    WaitForSingleObject(hThread, INFINITE);

    DWORD remoteResult = 0;
    GetExitCodeThread(hThread, &remoteResult);

    if (remoteResult == 0) {
        std::wcout << L"LoadLibraryW falhou dentro do processo remoto.\n";
    }
    else {
        std::wcout << L"DLL injetada com sucesso.\n";
    }

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    std::wcout << L"Pressione Enter para sair...";
    std::wcin.get();

    return 0;
}