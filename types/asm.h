//MSVC 2022 x64 "no inline assembly incident"
//(MY SNOGGED Visual C x64)

#define WIN32_LEAN_AND_MEAN 

//most of this file is deprecated LOL
//but it might be useful later

#include <intrin.h>

//I SWEAR THERE IS NO BETTER WAY TO DO THIS IN MICROSOFT x64 C
//AND I WANT THIS FILE IN THE SAME NAMESPACE (must be .h)
//COPE ABOUT IT

#define nop __nop();
#define TwoNops nop nop
#define FiveNops TwoNops TwoNops nop
#define TenNops FiveNops FiveNops 
#define HexTenNops TenNops FiveNops nop //0x10
#define TwentyNops TenNops TenNops
#define FiftyNops TwentyNops TwentyNops TenNops
#define HundredNops FiftyNops FiftyNops
#define TwoHundredNops HundredNops HundredNops

//want bigger nopsled???
//ITERATIVELY DEFINE MORE NOP MACROS
//by hand... LOL


//assembly macros
//also you don't need to allocate shadow space on the stack

//refer to:
//https://learn.microsoft.com/en-us/cpp/build/x64-software-conventions?view=msvc-170
//x64 asm doesn't include inline asm support
//so I made a workaround

//need to completely preserve all volatiles
//what the definitions would like like in MSVC (for visualization purposes)
//https://badecho.com/index.php/2021/06/07/how-to-push-sse-registers/


//#define PRESERVE_VOLATILES "\x50\x51\x52\x41\x50\x41\x51\x41\x52\x41\x53\x48\x83\xEC\x10\xF3\x0F\x7F\x04\x24\x48\x83\xEC\x10\xF3\x0F\x7F\x0C\x24\x48\x83\xEC\x10\xF3\x0F\x7F\x14\x24\x48\x83\xEC\x10\xF3\x0F\x7F\x1C\x24\x48\x83\xEC\x10\xF3\x0F\x7F\x24\x24\x48\x83\xEC\x10\xF3\x0F\x7F\x2C\x24\x48\x83\xEC\x10\xC5\xFE\x7F\x04\x24\x48\x83\xEC\x10\xC5\xFE\x7F\x0C\x24\x48\x83\xEC\x10\xC5\xFE\x7F\x14\x24\x48\x83\xEC\x10\xC5\xFE\x7F\x1C\x24\x48\x83\xEC\x10\xC5\xFE\x7F\x24\x24\x48\x83\xEC\x10\xC5\xFE\x7F\x2C\x24\x48\x83\xEC\x10\xC5\xFE\x7F\x34\x24\x48\x83\xEC\x10\xC5\xFE\x7F\x3C\x24\x48\x83\xEC\x10\xC5\x7E\x7F\x04\x24\x48\x83\xEC\x10\xC5\x7E\x7F\x0C\x24\x48\x83\xEC\x10\xC5\x7E\x7F\x14\x24\x48\x83\xEC\x10\xC5\x7E\x7F\x1C\x24\x48\x83\xEC\x10\xC5\x7E\x7F\x24\x24\x48\x83\xEC\x10\xC5\x7E\x7F\x2C\x24\x48\x83\xEC\x10\xC5\x7E\x7F\x34\x24\x48\x83\xEC\x10\xC5\x7E\x7F\x3C\x24"
//#define PRESERVE_VOLATILES_BYTES 209
//#define PRESERVE_VOLATILES_silent_NOPS TwoHundredNops FiveNops TwoNops TwoNops nop

/*
#define PRESERVE_VOLATILES_Silent __asm \
{                                       \
    push RAX                            \
    push RCX                            \
    push RDX                            \
    push R8                             \
    push R9                             \
    push R10                            \
    push R11                            \
    sub rsp,0x10                        \
    movdqu [rsp], xmm0                  \
    sub rsp,0x10                        \
    movdqu [rsp], xmm1                  \
    sub rsp,0x10                        \
    movdqu [rsp], xmm2                  \
    sub rsp,0x10                        \
    movdqu [rsp], xmm3                  \
    sub rsp,0x10                        \
    movdqu [rsp], xmm4                  \
    sub rsp,0x10                        \
    movdqu [rsp], xmm5                  \
    sub rsp,0x10                        \
    vmovdqu  [rsp], ymm0                \
    sub rsp,0x10                        \
    vmovdqu  [rsp], ymm1                \
    sub rsp,0x10                        \
    vmovdqu  [rsp], ymm2                \
    sub rsp,0x10                        \
    vmovdqu  [rsp], ymm3                \
    sub rsp,0x10                        \ 
    vmovdqu  [rsp], ymm4                \
    sub rsp,0x10                        \
    vmovdqu  [rsp], ymm5                \
    sub rsp,0x10                        \
    vmovdqu  [rsp], ymm6                \
    sub rsp,0x10                        \
    vmovdqu  [rsp], ymm7                \
    sub rsp,0x10                        \
    vmovdqu  [rsp], ymm8                \
    sub rsp,0x10                        \
    vmovdqu  [rsp], ymm9                \
    sub rsp,0x10                        \
    vmovdqu  [rsp], ymm10               \
    sub rsp,0x10                        \
    vmovdqu  [rsp], ymm11               \
    sub rsp,0x10                        \
    vmovdqu  [rsp], ymm12               \
    sub rsp,0x10                        \
    vmovdqu  [rsp], ymm13               \
    sub rsp,0x10                        \
    vmovdqu  [rsp], ymm14               \
    sub rsp,0x10                        \
    vmovdqu  [rsp], ymm15               \
}                                       \
*/

//#define RETRIEVE_VOLATILES "\xC5\x7E\x6F\x3C\x24\x48\x83\xC4\x10\xC5\x7E\x6F\x34\x24\x48\x83\xC4\x10\xC5\x7E\x6F\x2C\x24\x48\x83\xC4\x10\xC5\x7E\x6F\x24\x24\x48\x83\xC4\x10\xC5\x7E\x6F\x1C\x24\x48\x83\xC4\x10\xC5\x7E\x6F\x14\x24\x48\x83\xC4\x10\xC5\x7E\x6F\x0C\x24\x48\x83\xC4\x10\xC5\x7E\x6F\x0C\x24\x48\x83\xC4\x10\xC5\x7E\x6F\x04\x24\x48\x83\xC4\x10\xC5\xFE\x6F\x3C\x24\x48\x83\xC4\x10\xC5\xFE\x6F\x34\x24\x48\x83\xC4\x10\xC5\xFE\x6F\x2C\x24\x48\x83\xC4\x10\xC5\xFE\x6F\x24\x24\x48\x83\xC4\x10\xC5\xFE\x6F\x1C\x24\x48\x83\xC4\x10\xC5\xFE\x6F\x14\x24\x48\x83\xC4\x10\xC5\xFE\x6F\x0C\x24\x48\x83\xC4\x10\xC5\xFE\x6F\x04\x24\x48\x83\xC4\x10\xF3\x0F\x6F\x2C\x24\x48\x83\xC4\x10\xF3\x0F\x6F\x24\x24\x48\x83\xC4\x10\xF3\x0F\x6F\x1C\x24\x48\x83\xC4\x10\xF3\x0F\x6F\x14\x24\x48\x83\xC4\x10\xF3\x0F\x6F\x0C\x24\x48\x83\xC4\x10\xF3\x0F\x6F\x04\x24\x48\x83\xC4\x10\x41\x5B\x41\x5A\x41\x59\x41\x58\x5A\x59\x58\xc3"
//#define RETRIEVE_VOLATILES_BYTES 219
//#define RETRIEVE_VOLATILES_NOPS TwoHundredNops TenNops FiveNops nop //offset to counteract the generic 

/*
#define RETRIEVE_VOLATILES_silent __asm \
{                                       \
    vmovdqu  ymm15,[rsp]                \
    add rsp,0x10                        \
    vmovdqu  ymm14,[rsp]                \
    add rsp,0x10                        \
    vmovdqu  ymm13,[rsp]                \
    add rsp,0x10                        \
    vmovdqu  ymm12,[rsp]                \
    add rsp,0x10                        \
    vmovdqu  ymm11,[rsp]                \
    add rsp,0x10                        \
    vmovdqu  ymm10,[rsp]                \
    add rsp,0x10                        \
    vmovdqu  ymm9,[rsp]                 \
    add rsp,0x10                        \
    vmovdqu  ymm9,[rsp]                 \
    add rsp,0x10                        \
    vmovdqu  ymm8,[rsp]                 \
    add rsp,0x10                        \
    vmovdqu  ymm7,[rsp]                 \
    add rsp,0x10                        \
    vmovdqu  ymm6,[rsp]                 \
    add rsp,0x10                        \
    vmovdqu  ymm5,[rsp]                 \
    add rsp,0x10                        \
    vmovdqu  ymm4,[rsp]                 \
    add rsp,0x10                        \
    vmovdqu  ymm3,[rsp]                 \
    add rsp,0x10                        \
    vmovdqu  ymm2,[rsp]                 \
    add rsp,0x10                        \
    vmovdqu  ymm1,[rsp]                 \
    add rsp,0x10                        \
    vmovdqu  ymm0,[rsp]                 \
    add rsp,0x10                        \
    movdqu xmm5,[rsp]                   \
    add rsp,0x10                        \
    movdqu xmm4,[rsp]                   \
    add rsp,0x10                        \
    movdqu xmm3,[rsp]                   \
    add rsp,0x10                        \
    movdqu xmm2,[rsp]                   \
    add rsp,0x10                        \
    movdqu xmm1,[rsp]                   \
    add rsp,0x10                        \
    movdqu xmm0,[rsp]                   \
    add rsp,0x10                        \
    pop r11                             \
    pop r10                             \
    pop R9                              \
    pop R8                              \
    pop RDX                             \
    pop RCX                             \
    pop RAX                             \
    ret                                 \
}                                       \
*/
