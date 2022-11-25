#define WIN32_LEAN_AND_MEAN 

#include <vector>

using namespace std; 

class EXCEPTION_DISPLAY_INFO
{
    #define DISPLAY_OPTION_FALSE 2
    #define DISPLAY_OPTION_TRUE 1
    #define DISPLAY_OPTION_UNSET 0

    public:

        BYTE ShowName;
        BYTE ShowTrace;
        BYTE ShowGP;
        BYTE ShowFPU;
        BYTE ShowEflags;
        BYTE ShowSegmentRegs;
        int StackDump;

        EXCEPTION_DISPLAY_INFO ()
        {
            ShowName = DISPLAY_OPTION_UNSET;
            ShowTrace = DISPLAY_OPTION_UNSET;
            ShowGP = DISPLAY_OPTION_UNSET;
            ShowFPU = DISPLAY_OPTION_UNSET;
            ShowEflags = DISPLAY_OPTION_UNSET;
            ShowSegmentRegs = DISPLAY_OPTION_UNSET;
            StackDump = STACK_DUMP;
        }

        void SetSilent() //sets all automatic exception display options to false
        {
            ShowName = DISPLAY_OPTION_FALSE;
            ShowTrace = DISPLAY_OPTION_FALSE;
            ShowGP = DISPLAY_OPTION_FALSE;
            ShowFPU = DISPLAY_OPTION_FALSE;
            ShowEflags = DISPLAY_OPTION_FALSE;
            ShowSegmentRegs = DISPLAY_OPTION_FALSE;
            StackDump = 0;
        }
        
        void SetLoud(int stackQwords = STACK_DUMP) //sets all automatic exception display options to true
        {
            ShowName = DISPLAY_OPTION_TRUE;
            ShowTrace = DISPLAY_OPTION_TRUE;
            ShowGP = DISPLAY_OPTION_TRUE;
            ShowFPU = DISPLAY_OPTION_TRUE;
            ShowEflags = DISPLAY_OPTION_TRUE;
            ShowSegmentRegs = DISPLAY_OPTION_TRUE;
            StackDump = stackQwords;
        }
};

class HOOK_INFO
{
    public:

        HOOK_INFO () {}

        HOOK_INFO (uint64_t addr)
        {
            hook_addr = addr;
            BYTE * interruptByte = reinterpret_cast<BYTE *>(addr);
            originalByte = *interruptByte;
        }

        bool isActive;
        bool isInteruptSet;
        EXCEPTION_DISPLAY_INFO DisplayInfo;
        
        BYTE originalByte;
        uint64_t hook_addr;
        void (*hook)(PCONTEXT);

};

class IndexedFunction 
{
    public:

        IndexedFunction() {}

        IndexedFunction(uintptr_t ptr, string fname)
        {
            name = fname;
            FunctionAddress = ptr;
            HookInfo = HOOK_INFO(FunctionAddress);
        }

        //vector<HOOK_INFO> HookList;
        HOOK_INFO HookInfo; 
        string name;  
        uintptr_t FunctionAddress;

};

IndexedFunction * knownFunctionTable;
DWORD knownFunctionTableSize;


int GetIndexedFunction(uintptr_t addr) //gets named function from the database given address
{
    for (int i = 0; i < knownFunctionTableSize; i++)
    {
        if (knownFunctionTable[i].FunctionAddress == addr) {return i;}
    } 

    return -1;
}

int GetIndexedFunction(char * name) //gets named function from the database given string name.
{
    for (int i = 0; i < knownFunctionTableSize; i++)
    {
        if (!strcmp(knownFunctionTable[i].name.c_str(), name)) {return i;}
    } 

    return -1;
}

int GetFunctionFromOffset(uintptr_t addr)
{

    int FuncIndex = -1;

    while(FuncIndex == -1)
    {
        FuncIndex = GetIndexedFunction(addr);
        addr --; //search down until function is found
    } 

    return FuncIndex;
}

/*
int GetHookIndex (int index, uintptr_t addr)
{

    int n = 0;

    for(;;)
    {
        if (knownFunctionTable[index].HookList[n].hook_addr == addr) {return n;}
    }
    
}
*/

//POV: you just got a "entry level position"
//and you gotta put that "bachelors of science" to the test
//and show those accessor methods whose boss

void HookInit(char * name, void (*HookAddress)(PCONTEXT), bool status, int offset=0)
{
    int FunctionIndex = GetIndexedFunction(name);

    if(FunctionIndex == -1)
    {
        printf("[!] error initializing hook %s", name);
    }

    knownFunctionTable[FunctionIndex].HookInfo.isActive = status;
    if(status) {set_interupt(knownFunctionTable[FunctionIndex].FunctionAddress);}
    knownFunctionTable[FunctionIndex].HookInfo.isInteruptSet = status;
    knownFunctionTable[FunctionIndex].HookInfo.hook = HookAddress;
}

void HookDeinit(char * name, int offset=0)
{
    int FunctionIndex = GetIndexedFunction(name);

    if(FunctionIndex == -1)
    {
        printf("[!] error deinitializing hook %s", name);
    }

    knownFunctionTable[FunctionIndex].HookInfo.isActive = false;
    knownFunctionTable[FunctionIndex].HookInfo.isInteruptSet = false;
    unset_interupt(knownFunctionTable[FunctionIndex].FunctionAddress, &knownFunctionTable[FunctionIndex].HookInfo.originalByte);
    knownFunctionTable[FunctionIndex].HookInfo.hook = nullptr;
}

void HookInit(int FunctionIndex, void (*HookAddress)(PCONTEXT), bool status, int offset=0)
{
    knownFunctionTable[FunctionIndex].HookInfo.isActive = status;
    if(status) {set_interupt(knownFunctionTable[FunctionIndex].FunctionAddress);}
    knownFunctionTable[FunctionIndex].HookInfo.isInteruptSet = status;
    knownFunctionTable[FunctionIndex].HookInfo.hook = HookAddress;
}

void HookDeinit(int FunctionIndex, int offset=0)
{
    knownFunctionTable[FunctionIndex].HookInfo.isActive = false;
    knownFunctionTable[FunctionIndex].HookInfo.isInteruptSet = false;
    unset_interupt(knownFunctionTable[FunctionIndex].FunctionAddress, &knownFunctionTable[FunctionIndex].HookInfo.originalByte);
    knownFunctionTable[FunctionIndex].HookInfo.hook = nullptr;
}

void HookSet (char * name, int offset=0)
{
    int FunctionIndex = GetIndexedFunction(name);

    if(FunctionIndex == -1)
    {
        printf("[!] error setting hook %s", name);
    }

    knownFunctionTable[FunctionIndex].HookInfo.isActive = true;
    knownFunctionTable[FunctionIndex].HookInfo.isActive = true;
    set_interupt(knownFunctionTable[FunctionIndex].FunctionAddress);
    knownFunctionTable[FunctionIndex].HookInfo.isInteruptSet = true;
}

void HookUnSet (char * name, int offset=0)
{
    int FunctionIndex = GetIndexedFunction(name);

    if(FunctionIndex == -1)
    {
        printf("[!] error unsetting hook %s", name);
    }

    knownFunctionTable[FunctionIndex].HookInfo.isActive = false;
    knownFunctionTable[FunctionIndex].HookInfo.isInteruptSet = false;
    unset_interupt(knownFunctionTable[FunctionIndex].FunctionAddress, &knownFunctionTable[FunctionIndex].HookInfo.originalByte);
}

void HookSet (int FunctionIndex, int offset=0)
{
    knownFunctionTable[FunctionIndex].HookInfo.isActive = true;
    knownFunctionTable[FunctionIndex].HookInfo.isInteruptSet = true;
    set_interupt(knownFunctionTable[FunctionIndex].FunctionAddress);
}

void HookUnSet (int FunctionIndex, int offset=0)
{
    knownFunctionTable[FunctionIndex].HookInfo.isActive = false;
    knownFunctionTable[FunctionIndex].HookInfo.isInteruptSet = false;
    unset_interupt(knownFunctionTable[FunctionIndex].FunctionAddress, &knownFunctionTable[FunctionIndex].HookInfo.originalByte);
}

void ResetInterrupts() //todo... turn this into a vectored queue
{
    for(int i = 0; i < knownFunctionTableSize; i++)
    {
        if(knownFunctionTable[i].HookInfo.isActive && !knownFunctionTable[i].HookInfo.isInteruptSet) 
        {
            set_interupt(knownFunctionTable[i].FunctionAddress);
            knownFunctionTable[i].HookInfo.isInteruptSet = true;
        } 
    }
}