#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
        MessageBox(NULL, "Payload executed successfully.", "Tiny PE payload",
                   MB_OK | MB_ICONWARNING | MB_SYSTEMMODAL);

    return TRUE;
}
