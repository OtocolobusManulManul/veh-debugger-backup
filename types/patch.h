//fun with runtime code modification
#define WIN32_LEAN_AND_MEAN 

#include <windows.h>
#include <memory.h>

//interupt macros
#define OPCODE_INT3 "\xCC"
uintptr_t INT3_int = (uintptr_t) &OPCODE_INT3; 
BYTE * INT3 = reinterpret_cast<BYTE *>(INT3_int); 

void writeMem(BYTE* dst, BYTE* src, unsigned int size)
{
    DWORD oldprotect;
    VirtualProtect(dst, size, PAGE_EXECUTE_READWRITE, &oldprotect);

    memcpy(dst, src, size);
    VirtualProtect(dst, size, oldprotect, &oldprotect);
}

void set_interupt(uintptr_t addr) {BYTE * buf =  reinterpret_cast<BYTE*>(addr); writeMem(buf, INT3, 1);}

void unset_interupt(uintptr_t func, BYTE * originalByte) {BYTE * buf =  reinterpret_cast<BYTE*>(func); writeMem(buf, originalByte, 1);}