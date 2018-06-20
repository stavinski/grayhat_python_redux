// dllmain.cpp : Defines the entry point for the DLL application.
#include "windows.h"

#pragma comment(lib, "user32.lib") 

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
      )
{
 switch (ul_reason_for_call)
 {
 case DLL_PROCESS_ATTACH:
        MessageBoxA(NULL,"Hello from the process!","I am inside the process you injected!",MB_OK);
 case DLL_THREAD_ATTACH:
 case DLL_THREAD_DETACH:
 case DLL_PROCESS_DETACH:
  break;
 }
 return TRUE;
}



