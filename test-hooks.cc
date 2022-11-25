#define WIN32_LEAN_AND_MEAN 

//compile with cl test-hooks.cc /link /release

// these macros are usually defined in <definitions.h> and dictate the default
// settings for the debug information that the debug handler sets.

#define STACK_DUMP 24               // QWORDS to dump from the stack
#define SHOW_NAME true              // outputs name of function
#define SHOW_TRACE true             // outputs stack pointer and calling fuction address
#define SHOW_GP true                // outputs general purpose registers
#define SHOW_FPU false              // shows floating point registers (not yet implemented because I am lazy)
#define SHOW_EFLAGS false           // outputs eflags
#define SHOW_SEGMENT_REGS false     // outputs segment registers
#define WATCH_ALL_EXCEPTIONS false  // prints alert when any exception is passed

#include <windows.h>
#include <iostream>
#include <cstdlib> 
#include <stdio.h>

#include <intrin.h>

#include "types/patch.h"
#include "types/asm.h"
#include "types/SNOGtypes.h"
#include "types/PE.h"

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "user32.lib")

#include "veh.h"

using namespace std;

void __fastcall foo (int a1, int a2, int a3, int a4, int a5, int a6) {printf("arg1 %d\narg2 %d\narg3 %d\narg4 %d\narg5 %d\narg6 %d\n\n", a1, a2, a3, a4, a5, a6);}

void __fastcall bar (char * str) 
{
    printf("%s", str);
}

void foo_hook(PCONTEXT ctx)
{

    DWORD64 * stackptr = reinterpret_cast<DWORD64 *>(ctx->Rsp);

    ctx->Rcx = 1;
    ctx->Rdx = 2;        
    ctx->R8 = 3;
    ctx->R9 = 4;
    *(stackptr + 5) = 5;
    *(stackptr + 6) = 6;
}

char replacement_string [] = "overed in SNOG!!!!\n";

void bar_hook(PCONTEXT ctx)
{
    
    // either place the string on the heap
    // or make it a global variable
    // otherwise it will get deinitialized 

    DWORD64 replacement_string_ptr = reinterpret_cast<uintptr_t>(replacement_string);
    ctx->Rcx = replacement_string_ptr;
}

void cart() {}

// hooks set manually here to save time
// knownFunctionTable is a global pointer 
// to an array storing all IndexedFunctions 
// available to be hooked

void init_tests() 
{

    printf("[*] running setup\n");

    // sets the handler function defined in veh.h
    // which outputs debug info, and executes the
    // custom defined hook if one is found.
    //gets executed in the mainthread of SNOG.cc

    void* handle = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)veh_handler);AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)veh_handler);

    knownFunctionTable = new IndexedFunction[3];
    knownFunctionTableSize = 3;

    // setting the knownFunctionTable manually
    // since rerunning the ida analysis script
    // every single time I recompile would be a pain.


    knownFunctionTable[0] = IndexedFunction((uintptr_t) &foo, "foo");
    knownFunctionTable[1] = IndexedFunction((uintptr_t) &bar, "bar");
    knownFunctionTable[2] = IndexedFunction((uintptr_t) &cart, "cart");

    printf("[*] setup complete\n");

}

void reinit_tests() 
{
    ResetInterrupts();      // DO NOT INVOKE MANUALLY for actual game hooks
}                           // the dll handles that itself normally


void reverse_arguments()
{

    printf("[*] RUNNING TEST: reverse_arguments\n");

    // setting the hook
    printf("setting hook\n");
    HookInit("foo", foo_hook, true);
    knownFunctionTable[GetIndexedFunction("foo")].HookInfo.DisplayInfo.SetSilent(); //unsetting default display
    
    printf("calling foo()\n\n");
    foo(6,5,4,3,2,1);

    //uninitializing the hook
    printf("uninitializing hook\n");
    HookDeinit(0);

    printf("interrupt status 0x%x\n", knownFunctionTable[0].HookInfo.isInteruptSet);
    printf("calling foo() again with same args\n\n");

    foo(6,5,4,3,2,1);

}

void set_watch() 
{

    printf("[*] RUNNING TEST: set_watch\n");
    printf("setting hook\n");
    knownFunctionTable[GetIndexedFunction("cart")].HookInfo.DisplayInfo.SetLoud(0x12); // the single optional argument
                                                                                        // overwrites how many QWORDS
                                                                                        // to print from the stack.

    HookInit("cart", nullptr, true); // if you just want to check if the function was called
                                     // and output basic info, just set the hook function pointer
                                     // to null like so

    printf("calling cart()\n");
    cart();

}

void custom_debug_output()
{

    printf("[*] RUNNING TEST: custom_debug_output\n");
    printf("setting debug display info\n");
    
    int FuncIndex = GetIndexedFunction("cart");

    knownFunctionTable[FuncIndex].HookInfo.DisplayInfo.SetSilent();
    knownFunctionTable[FuncIndex].HookInfo.DisplayInfo.ShowName = DISPLAY_OPTION_TRUE;
    knownFunctionTable[FuncIndex].HookInfo.DisplayInfo.ShowTrace = DISPLAY_OPTION_TRUE;
    knownFunctionTable[FuncIndex].HookInfo.DisplayInfo.ShowGP = DISPLAY_OPTION_TRUE;

    knownFunctionTable[FuncIndex].HookInfo.DisplayInfo.ShowEflags = DISPLAY_OPTION_UNSET; //unset will revert to default settings in <definitions.h>
    knownFunctionTable[FuncIndex].HookInfo.DisplayInfo.ShowSegmentRegs = DISPLAY_OPTION_FALSE;

    printf("calling cart()\n");

    cart();

}

void swap_string() // not adding extra printf statements, since you can probably figure out what
{                  // what everything does 

    printf("[*] RUNNING TEST: string swap\n");
    char str [] = "this cart... is\n";
    bar(str);
    HookInit("bar", bar_hook, true);
    knownFunctionTable[GetIndexedFunction("bar")].HookInfo.DisplayInfo.SetSilent();
    bar(str);

}

int main (void)
{
 
    init_tests(); //runs setup

    set_watch();            // sets a "watchpoint" hook...
                            // or a hook with no special function
                            // assigned that just dumps info
    
    
    reinit_tests();
    custom_debug_output();  // shows how to set debug output settings

    reinit_tests();
    reverse_arguments();    // calls foo twice with the same args
                            // sets a hook to arbitrarily modify
                            // argument values.

    reinit_tests();
    swap_string();

    printf("[*] ALL TESTS COMPLETE\n");
    return 0;

}

