#define WIN32_LEAN_AND_MEAN

#include <DbgHelp.h>

LONG CALLBACK veh_handler(PEXCEPTION_POINTERS ExceptionInfo)
{

    DWORD code = ExceptionInfo->ExceptionRecord->ExceptionCode;
    PCONTEXT ctx = ExceptionInfo->ContextRecord;


    if(WATCH_ALL_EXCEPTIONS)
    { 
        printf("handler passed exception from 0x%p with code: 0x%x\n", ctx->Rip, code);
    }

    if (code == STATUS_BREAKPOINT)
    {

        int CurrentIndex = GetFunctionFromOffset((uintptr_t) ctx->Rip);

        if (CurrentIndex == -1) //and INT3 exception we didn't trigger intentionally
        {
            printf("ERROR: unknown STATUS_BREAKPOINT exception: 0x%p\n", ctx->Rip);
            return EXCEPTION_CONTINUE_SEARCH;
        }

        DWORD64 * stackptr = reinterpret_cast<DWORD64 *>(ctx->Rsp);

        EXCEPTION_DISPLAY_INFO DisplayInfo = knownFunctionTable[CurrentIndex].HookInfo.DisplayInfo;

        if (DisplayInfo.ShowName == DISPLAY_OPTION_TRUE || (DisplayInfo.ShowName == DISPLAY_OPTION_UNSET && SHOW_NAME))
        {
            printf("===================================\n");
            printf("hooked into: <%s+0x%x> (code: 0x%x)\n", knownFunctionTable[CurrentIndex].name.c_str(), 0, code);
        }

        if(DisplayInfo.ShowTrace == DISPLAY_OPTION_TRUE || (DisplayInfo.ShowTrace == DISPLAY_OPTION_UNSET && SHOW_TRACE))
        {
            printf("\nRSP: 0x%p\nRIP: 0x%p\ncaller address: 0x%p\n\nfastcall registers\n\tRCX: 0x%p\n\tRDX: 0x%p\n\tR8:  0x%p\n\tR9:  0x%p\n\n", ctx->Rsp,ctx->Rip,*stackptr, ctx->Rcx, ctx->Rdx, ctx->R8 ,ctx->R9);
        }

        if(DisplayInfo.ShowGP == DISPLAY_OPTION_TRUE || (DisplayInfo.ShowGP == DISPLAY_OPTION_UNSET && SHOW_GP)) 
        {
            printf("GP registers:\n\tRAX: 0x%p\n\tRBX: 0x%p\n\tRBP: 0x%p\n\tRSI: 0x%p\n\tRDI: 0x%p\n\tR10: 0x%p\n\tR11: 0x%p\n\tR12: 0x%p\n\tR13: 0x%p\n\tR14: 0x%p\n\tR15: 0x%p\n\n", ctx->Rax, ctx->Rbx, ctx->Rbp, ctx->Rsi, ctx->Rdi, ctx->R10, ctx->R11, ctx->R12, ctx->R13, ctx->R14, ctx->R15);
        }

        if(DisplayInfo.ShowFPU == DISPLAY_OPTION_TRUE || (DisplayInfo.ShowFPU == DISPLAY_OPTION_UNSET && SHOW_FPU))
        {
            printf("Floating point registers (TODO)\n\n");
            //printf("\tXMM0: %f", ctx->DUMMYUNIONNAME.DUMMYSTRUCTNAME.Xmm0);
        } 

        if(DisplayInfo.ShowEflags == DISPLAY_OPTION_TRUE || (DisplayInfo.ShowEflags == DISPLAY_OPTION_UNSET && SHOW_EFLAGS))
        {
            printf("eflags\n");
            printf("\t0x%x\n\n", ctx->EFlags);
        }

        if(DisplayInfo.ShowSegmentRegs == DISPLAY_OPTION_TRUE || (DisplayInfo.ShowSegmentRegs == DISPLAY_OPTION_UNSET && SHOW_SEGMENT_REGS))
        {
            printf("Segment registers\n");
            printf("\tCS: 0x%x\n", ctx->SegCs);
            printf("\tDS: 0x%x\n", ctx->SegDs);
            printf("\tES: 0x%x\n", ctx->SegEs);
            printf("\tFS: 0x%x\n", ctx->SegFs);
            printf("\tGS: 0x%x\n", ctx->SegGs);
            printf("\tSs: 0x%x\n\n", ctx->SegSs);
        }
        
        int StackDump = DisplayInfo.StackDump;

        if (StackDump) 
        {
            printf("dumping 0x0%x values off of the stack\n\n", StackDump);
        }


        for(int i = 0; i < StackDump; i ++) {printf("0x%p ", *stackptr); stackptr = stackptr + 1;}

        if (StackDump) {printf("\n");}

        if (DisplayInfo.ShowName == DISPLAY_OPTION_TRUE || (DisplayInfo.ShowName == DISPLAY_OPTION_UNSET && SHOW_NAME))
        {
            printf("===================================\n\n");
        }
        
        if (knownFunctionTable[CurrentIndex].HookInfo.hook) {knownFunctionTable[CurrentIndex].HookInfo.hook(ctx);}

        else if (DisplayInfo.ShowName == DISPLAY_OPTION_TRUE || (DisplayInfo.ShowName == DISPLAY_OPTION_UNSET && SHOW_NAME)) 
        {
            printf("no special hook defined\n");
        }

        //use entry from retrieved function index to avoid recasting
        unset_interupt(knownFunctionTable[CurrentIndex].FunctionAddress, &(knownFunctionTable[CurrentIndex].HookInfo.originalByte));
        
        knownFunctionTable[CurrentIndex].HookInfo.isInteruptSet = false;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;

}
