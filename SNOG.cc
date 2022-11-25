#define WIN32_LEAN_AND_MEAN 

#include <windows.h>
#include <iostream>
#include <cstdlib> 
#include <stdio.h>

#include <intrin.h>

#include "types/asm.h"
#include "types/patch.h"
#include "types/definitions.h"
#include "types/SNOGtypes.h"
#include "types/PE.h"

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "user32.lib")

//compile with 
//cl /LD SNOG.cc /link /release
//only supports x64

using namespace std; 

#include "veh.h"
#include "hook.h"

//accounts for the final unindexed destructor function at the end.
//of the .text section.

#define TEXT_END_OFFSET 0xe

DWORD WINAPI DllThreadMain (HMODULE hModule) 
{

    //this cart...
    //is overed in NOPS
    //HexTenNops HexTenNops HexTenNops
     
    //set up console io
    AllocConsole();
    FILE* f = new FILE;
    freopen("CONOUT$", "w", stdout);
    puts("[*] initialized console\n");

    printf("[*] thread loaded @ 0x%p\n", (void *) &DllThreadMain);

    DWORD ProcessId = GetCurrentProcessId();
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, ProcessId);
    puts("[*] set permission status to PROCESS_ALL_ACCESS\n");

    HMODULE hMod = GetModuleHandleA(TARGET);
    PIMAGE_NT_HEADERS NtHeader = ImageNtHeader(hMod);
    WORD NumSections = NtHeader->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeader);
    _NT_HEADERS HeaderTable(hMod); 

    puts("[*] parsed PE headers\n");
    printf("\n%s base address: 0x%p\n\n", TARGET, hMod);
    puts("program segment data\n=============================================\nName            VA      Raw     Size\n=============================================\n");

     
    for (WORD i = 0; i < NumSections; i++)
    {
        HeaderTable.SetNTHeader(Section);
        printf("%-8s\t%x\t%x\t%x\t%x\n", Section->Name, Section->VirtualAddress,
                Section->PointerToRawData, Section->SizeOfRawData);
        Section++;
    }


    //there is no properly documented way to interface with the SEH exception dir
    //it can't be treated like an array since it is created after compile time...
    //and MSVC doesn't support VLA standards added in C99 

    //but of course you can declare a pointer to a variable length array
    //not really sure why, given any attempt to index it will generate
    //a compile time error that you can't force ignore.

    //and good luck compiling this on gcc (where it would work just fine)

    //SEH_TableSize needs to be set in event that the the entire segment is full

    int SEH_TableSize = HeaderTable.pdata.SECTION_HEADER->SizeOfRawData / sizeof(RUNTIME_FUNCTION); 
    RUNTIME_FUNCTION (* FunctionVaTable)[] = (RUNTIME_FUNCTION (*)[]) HeaderTable.pdata.ProcAddress;


    printf("\nSEH virtual offset table address: 0x%p\nRUNTIME_FUNCTION entries: %d\n\n", 
            hMod + (int) HeaderTable.pdata.SECTION_HEADER->VirtualAddress, 
            SEH_TableSize);


    uintptr_t ModuleBaseAddr = reinterpret_cast<uintptr_t>(hMod);
    uintptr_t DataSection = HeaderTable.data.ProcAddress;
    uintptr_t ExceptionDirEntryAddress;
    uintptr_t FunctionAddress;
    bool pdataFull = true; //it probably is not

    puts("===========================================================================================\nindex     address in table                     RVA                      Function Address\n===========================================================================================\n");

    for (DWORD i = 0; i < SEH_TableSize; i ++)
    {
        
        uintptr_t ExceptionDirEntryAddress =  (__int64)FunctionVaTable + i * EXCEPTION_DIR_ENTRY + BeginAddress;
        DWORD* rva = reinterpret_cast<DWORD*> (ExceptionDirEntryAddress);
        
        //found last entry in the table
        if (*rva == 0x00) {pdataFull; SEH_TableSize = i - 1;pdataFull = false; break;}
        
        FunctionAddress = ModuleBaseAddr + *rva;
        if (i < FunctionDump) {printf("%-10d0x%p\t\t\t0x%-10x\t\t0x%p\n", i, ExceptionDirEntryAddress, *rva, FunctionAddress);}

    }

    SEH_TableSize = SEH_TableSize - (WORD) pdataFull;

    //essentially need to rewind once in the loop
    ExceptionDirEntryAddress =  (__int64)FunctionVaTable + SEH_TableSize * EXCEPTION_DIR_ENTRY + BeginAddress;
    DWORD* rva = reinterpret_cast<DWORD*> (ExceptionDirEntryAddress);
    rva = reinterpret_cast<DWORD*> (ExceptionDirEntryAddress);
    FunctionAddress = ModuleBaseAddr + *rva;
    printf("...\n");
    printf("%-10d0x%p\t\t\t0x%-10x\t\t0x%p\n", SEH_TableSize, ExceptionDirEntryAddress, *rva, FunctionAddress);

    uintptr_t SEH_END =  (__int64)FunctionVaTable + SEH_TableSize * EXCEPTION_DIR_ENTRY + EndAddresss;
    DWORD* end_rva = reinterpret_cast<DWORD*>(SEH_END);
    uintptr_t TextLastByte = ModuleBaseAddr + *end_rva + TEXT_END_OFFSET;
    uintptr_t TextNullBytes = HeaderTable.rdata.ProcAddress - TextLastByte;
    DWORD * WrittenTextEndPtr = reinterpret_cast<DWORD*>(TextLastByte);
    uintptr_t * rdata = reinterpret_cast<uintptr_t*>(HeaderTable.rdata.ProcAddress);

    DWORD * data = reinterpret_cast<DWORD*>(HeaderTable.data.ProcAddress);

    printf("\n[*] ExceptionDir parsed %d function addresses found\n", SEH_TableSize);
    printf("\nalso found 0x%x empty bytes in .text section, starting at 0x%p (0x%x)\n\n", TextNullBytes, TextLastByte, *end_rva);

    printf("[*] parsing symbol database\n");
    
    FILE* file = fopen(SYMBOL_FILE, "r");

    if(!file) {puts("[!] could not load symbols database\nrun getKnownSymbols.py on i64 file"); goto exit;}

    WORD LineNum = 0;
    for (char c = getc(file); c != EOF; c = getc(file)) {if (c == '\n') {LineNum ++;}}
    rewind(file);

    //this needs to run for the VEH handler to work
    knownFunctionTable = new IndexedFunction[LineNum];
    knownFunctionTableSize = LineNum;

    printf ("[*] displaying first %d of %d known function addresses\n\n==========================================================================\nAddress                 Name\n==========================================================================\n\n", KnownSymbolDump, LineNum);
    
    char line [512]; //must use seperate buffer for this to work
    char * name;    
    int n = 0;

    while (fgets(line , sizeof(line ), file)) 
    {
        
        uint64_t relativeAddress = strtoull(line , NULL, 16);
        name = strstr(line , "\t");

        if(n < KnownSymbolDump) {printf("0x%p\t%s", ModuleBaseAddr + relativeAddress, (name + 1));}
        knownFunctionTable[n] = IndexedFunction(ModuleBaseAddr + relativeAddress, string(name + 1));
        n ++;
    
    }
    
    fclose(file);

    printf("[*] initializing Vectored Exception Handler\n\n");

    void* handle = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)veh_handler);AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)veh_handler);

    if (!handle)
    {
        printf("[!] error in hooking vectored exception handler\n");
        goto exit;
    }

    printf("VEH handler set at: 0x%p\n", veh_handler);
    printf("VEH handler set at: 0x%p\n\n", handle);
    printf("[*] VEH initialized\n");

    printf("[*] initializing hooks\n");

    InitializeHooks();

    printf("[*] hooks initialized\n");

    printf("\n[*] initialization complete\n\npress num_0 to display help\n\n");


    for(;;) 
    {

        if (GetAsyncKeyState(VK_NUMPAD0) & 1) 
        {
            puts("[?] available commands\n\t(num_1): cleanly exit the thread, keep the program running.\n\t(num_2): force kill both game and thread\n\t(num_3): display known symbols\n\n");
        }

        if (GetAsyncKeyState(VK_NUMPAD1) & 1) 
        {
            puts("[!] exit key pressed... goodbye\n");
            goto exit;
        }
        
        if (GetAsyncKeyState(VK_NUMPAD2) & 1) 
        {
            puts("[!] combat snog...\n");
            abort();
        }

        if (GetAsyncKeyState(VK_NUMPAD3) & 1)
        {
            printf ("[*] displaying %d known function addresses\n\n===============================================================================\n      Address              Interupt byte   Name\n===============================================================================\n\n", knownFunctionTableSize);

            for (int i = 0; i < LineNum; i ++)
            {
                printf("%4d 0x%p\t0x%x\t\t%s", i, knownFunctionTable[i].FunctionAddress, knownFunctionTable[i].HookInfo.originalByte, knownFunctionTable[i].name.c_str());
            }
        
            puts("\n\n");

        }

        ResetInterrupts();

    }

exit:
    puts("exiting\n");
    fclose(f);
    FreeConsole();
    FreeLibraryAndExitThread(hModule, 0);
    return 0;
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


