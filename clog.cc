#define WIN32_LEAN_AND_MEAN 

#include <windows.h>
#include <iostream>
#include <stdio.h>

#pragma comment(lib, "user32.lib")

//compile with 
//cl /LD clog.cc /link /release

using namespace std; 


DWORD WINAPI DllThreadMain (HMODULE hModule) 
{

    AllocConsole();
    FILE* f = new FILE;
    freopen("CONOUT$", "w", stdout);
    puts("[*] initialized console\n");

    printf("press num_2 to quick clog\n");

    for(;;) 
    {
        
        if (GetAsyncKeyState(VK_NUMPAD2) & 1) 
        {
            puts("[!] K/D preserved...\n");
            abort();
        }
    }
}


BOOL APIENTRY DllMain (HMODULE hModule,    // handle to DLL module
                        DWORD ul_reason_for_call,   // reason for calling function
                        LPVOID lpReserved  //sus
                      )
{

    switch (ul_reason_for_call)
    {
        case 1: //DLL_PROCESS_ATTACH
            CloseHandle(CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)DllThreadMain, 
                                     hModule, 0, nullptr));
            break;
        case 2: //DLL_THREAD_ATTACH
            break;
        case 3: //DLL_THREAD_DETACH
            break;
        case 0: //DLL_PROCESS_DETACH
            break;
    }

    return true;
}

