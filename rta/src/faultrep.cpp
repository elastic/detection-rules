#define WIN32_LEAN_AND_MEAN
#include <windows.h>

extern "C" __declspec(dllexport)
DWORD WINAPI WerpInitiateCrashReporting(LPVOID lpParam) {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    LPTSTR cmd = __TEXT("c:\\windows\\system32\\notepad.exe");
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        MessageBox(NULL, "Create Process failed", "Error", NULL);
    }
    auto const address = VirtualAlloc(NULL, 0x10000, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    HANDLE h = LoadLibraryA("ws2_32.dll");
    DWORD old;
    VirtualProtect(address, 0x10, PAGE_READWRITE, &old);
    return 0;
}


extern "C" __declspec(dllexport)
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD ul_reason_for_call,
    LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        CreateThread(NULL, NULL, OIPC_InitPlus, NULL, NULL, NULL);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
