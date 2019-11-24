#include <windows.h>

int main()
{
    if (LoadLibrary("payload.dll") == NULL)
        MessageBox(NULL, "Payload DLL failed to load", "Payload Test", MB_OK | MB_ICONERROR);

    return 0;
}
