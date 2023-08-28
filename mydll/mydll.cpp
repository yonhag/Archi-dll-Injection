#include "Windows.h"
#define DLL_EXPORT
#include "mydll.h"

extern "C"
{
    DECLDIR void Share()
    {
        MessageBox(NULL, L"Hey from Yonatan", L"AAA", MB_OK);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        Share();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}