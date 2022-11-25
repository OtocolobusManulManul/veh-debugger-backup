#define WIN32_LEAN_AND_MEAN

/*
void generic_hook(PCONTEXT ctx)
{

    //access args in this order
    DWORD64 * stackptr = reinterpret_cast<DWORD64 *>(ctx->Rsp);
    
    ctx->Rcx = 1;
    ctx->Rdx = 2;        
    ctx->R8 = 3;
    ctx->R9 = 4;
    *(stackptr + 5) = 5;
    *(stackptr + 6) = 6;
    

}
*/

void tradeMaterial_hook(PCONTEXT ctx)
{
    printf("hooked tradeMaterial\n");

    printf("a1: 0x%p\n", ctx->Rcx);
    printf("a2: %s\n", ctx->Rdx);
    printf("a3: 0x%p\n", ctx->R8);
    printf("\n");
}

void InitializeHooks () 
{

    char game_version [30];
    printf("enter Game version to load hooks from (elite-dangerous-odyssey-64 or elite-dangerous-64): ");
    scanf("%s", game_version); printf("\n");

    if(!strcmp(game_version, "elite-dangerous-odyssey-64"))
    {
        //set ody hooks here
        printf("[*] loading hooks for: %s\n", game_version);

        //set custom hook
        HookInit("tradeMaterial\n", tradeMaterial_hook, true);
        knownFunctionTable[GetIndexedFunction("tradeMaterial\n")].HookInfo.DisplayInfo.SetSilent();

        //set a blank hook that just acts as a watchpoint
        HookInit("collect_mat\n", nullptr, true);
    
    }

    else if(!strcmp(game_version, "elite-dangerous-64"))
    {
        //set horizons hooks here
        printf("[*] loading hooks for: %s\n", game_version);
    }

    else 
    {
        printf ("[!] unknown game version.. exiting\n");
        abort();
    }
}
